use tiberius::{AuthMethod, Client, Config};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

use crate::config::DatabaseConfig;
use crate::protocol::{
    AUTH_BANNED, AUTH_IN_GAME, AUTH_NOT_FOUND, AUTH_OK, LS_LOGIN_REQ, MAX_ID_SIZE, MAX_PW_SIZE,
    read_string2, write_string2,
};

const AUTHORITY_BLOCK_USER: u8 = 255;

pub struct Database {
    config: Config,
}

impl Database {
    pub fn new(db_config: &DatabaseConfig) -> Self {
        let mut config = Config::new();
        config.host(&db_config.host);
        config.port(db_config.port);
        config.database(&db_config.database);
        config.authentication(AuthMethod::sql_server(
            &db_config.username,
            &db_config.password,
        ));
        config.trust_cert();

        Database { config }
    }

    async fn connect(&self) -> Result<Client<tokio_util::compat::Compat<TcpStream>>, String> {
        let tcp = TcpStream::connect(self.config.get_addr())
            .await
            .map_err(|e| format!("TCP connection failed: {}", e))?;

        let client = Client::connect(self.config.clone(), tcp.compat_write())
            .await
            .map_err(|e| format!("SQL Server login failed: {}", e))?;

        Ok(client)
    }

    pub(crate) async fn account_login(&self, account_id: &str, password: &str) -> u8 {
        let mut client = match self.connect().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Database error: {}", e);
                return AUTH_NOT_FOUND;
            }
        };

        let query = "SELECT strPasswd, strAuthority FROM TB_USER WHERE strAccountID = @P1";
        let stream = match client.query(query, &[&account_id]).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Query error: {}", e);
                return AUTH_NOT_FOUND;
            }
        };

        let row = match stream.into_row().await {
            Ok(Some(row)) => row,
            Ok(None) => return AUTH_NOT_FOUND,
            Err(e) => {
                eprintln!("Row fetch error: {}", e);
                return AUTH_NOT_FOUND;
            }
        };

        let db_password: &str = row.get(0).unwrap_or("");
        let authority: u8 = row.get(1).unwrap_or(1);

        // Return AUTH_NOT_FOUND instead of AUTH_INVALID_PW
        // to prevent attackers from identifying real accounts
        if db_password != password {
            return AUTH_NOT_FOUND;
        }

        if authority == AUTHORITY_BLOCK_USER {
            return AUTH_BANNED;
        }

        AUTH_OK
    }

    async fn is_current_user(&self, account_id: &str) -> Option<(String, i16)> {
        let mut client = self.connect().await.ok()?;

        let query = "SELECT strServerIP, nServerNo FROM CURRENTUSER WHERE strAccountID = @P1";
        let stream = client.query(query, &[&account_id]).await.ok()?;

        let row = stream.into_row().await.ok()??;

        let server_ip: &str = row.get(0)?;
        let server_no: i32 = row.get(1)?;

        Some((server_ip.to_string(), server_no as i16))
    }

    async fn load_premium_days(&self, account_id: &str) -> i16 {
        let mut client = match self.connect().await {
            Ok(c) => c,
            Err(_) => return -1,
        };

        let query = "SELECT PremiumExpire FROM TB_USER WHERE strAccountID = @P1";
        let stream = match client.query(query, &[&account_id]).await {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let row = match stream.into_row().await {
            Ok(Some(row)) => row,
            _ => return -1,
        };

        // Calculate days remaining from PremiumExpire
        let expire: Option<chrono::NaiveDateTime> = row.get(0);
        match expire {
            Some(dt) => {
                let now = chrono::Local::now().naive_local();
                let diff = dt.signed_duration_since(now);
                let days = diff.num_days();
                if days > 0 { days as i16 } else { -1 }
            }
            None => -1,
        }
    }

    /// Handles the full LS_LOGIN_REQ flow: validate, authenticate, check current user, premium
    pub async fn handle_login(&self, payload: &[u8]) -> Option<Vec<u8>> {
        let auth_not_found_reply: fn() -> Option<Vec<u8>> =
            || Some(vec![LS_LOGIN_REQ, AUTH_NOT_FOUND]);

        let Some((account_id, offset)) = read_string2(payload, 1) else {
            return auth_not_found_reply();
        };

        let Some((password, _)) = read_string2(payload, offset) else {
            return auth_not_found_reply();
        };

        if account_id.is_empty() || account_id.len() > MAX_ID_SIZE {
            return auth_not_found_reply();
        }

        if password.len() > MAX_PW_SIZE {
            return auth_not_found_reply();
        }

        let auth_result = self.account_login(&account_id, &password).await;

        if auth_result != AUTH_OK {
            return Some(vec![LS_LOGIN_REQ, auth_result]);
        }

        if let Some((server_ip, server_no)) = self.is_current_user(&account_id).await {
            let mut reply: Vec<u8> = Vec::new();
            reply.push(LS_LOGIN_REQ);
            reply.push(AUTH_IN_GAME);
            write_string2(&mut reply, &server_ip);
            reply.extend_from_slice(&server_no.to_le_bytes());
            return Some(reply);
        }

        let premium_days = self.load_premium_days(&account_id).await;
        let mut reply: Vec<u8> = Vec::new();
        reply.push(LS_LOGIN_REQ);
        reply.push(AUTH_OK);
        reply.extend_from_slice(&premium_days.to_le_bytes());
        Some(reply)
    }
}
