use bb8::{Pool, PooledConnection};
use bb8_tiberius::ConnectionManager;
use chrono::{NaiveDateTime, TimeDelta};
use tiberius::{AuthMethod, Config, QueryStream, Row};

use crate::config::DatabaseConfig;
use crate::protocol::{
    AUTH_BANNED, AUTH_FAILED, AUTH_IN_GAME, AUTH_NOT_FOUND, AUTH_OK, LS_LOGIN_REQ, MAX_ID_SIZE,
    MAX_PW_SIZE, read_string2, write_string2,
};

const AUTHORITY_BLOCK_USER: u8 = 255;

pub struct Database {
    pool: Pool<ConnectionManager>,
}

impl Database {
    pub async fn new(db_config: &DatabaseConfig) -> Self {
        let mut config = Config::new();
        config.host(&db_config.host);
        config.port(db_config.port);
        config.database(&db_config.database);
        config.authentication(AuthMethod::sql_server(
            &db_config.username,
            &db_config.password,
        ));
        config.trust_cert();

        let manager = ConnectionManager::new(config);
        let pool: Pool<ConnectionManager> = Pool::builder()
            .max_size(10)
            .build(manager)
            .await
            .expect("Failed to create database connection pool");

        Database { pool }
    }

    pub(crate) async fn account_login(&self, account_id: &str, password: &str) -> u8 {
        let mut conn: PooledConnection<ConnectionManager> = match self.pool.get().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Pool error in account_login: {}", e);
                return AUTH_FAILED;
            }
        };

        let query: &str = "SELECT strPasswd, strAuthority FROM TB_USER WHERE strAccountID = @P1";
        let stream: QueryStream = match conn.query(query, &[&account_id]).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Query error in account_login: {}", e);
                return AUTH_FAILED;
            }
        };

        let row: Row = match stream.into_row().await {
            Ok(Some(row)) => row,
            Ok(None) => return AUTH_NOT_FOUND,
            Err(e) => {
                eprintln!("Row fetch error in account_login: {}", e);
                return AUTH_FAILED;
            }
        };

        let db_password: &str = match row.get(0) {
            Some(pw) => pw,
            None => {
                eprintln!("NULL password for account: {}", account_id);
                return AUTH_FAILED;
            }
        };

        let authority: u8 = match row.get(1) {
            Some(auth) => auth,
            None => {
                eprintln!("NULL authority for account: {}", account_id);
                return AUTH_FAILED;
            }
        };

        if db_password != password {
            return AUTH_NOT_FOUND;
        }

        if authority == AUTHORITY_BLOCK_USER {
            return AUTH_BANNED;
        }

        AUTH_OK
    }

    async fn is_current_user(&self, account_id: &str) -> Option<(String, i16)> {
        let mut conn: PooledConnection<ConnectionManager> = match self.pool.get().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Pool error in is_current_user: {}", e);
                return None;
            }
        };

        let query: &str = "SELECT strServerIP, nServerNo FROM CURRENTUSER WHERE strAccountID = @P1";
        let stream: QueryStream = match conn.query(query, &[&account_id]).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Query error in is_current_user: {}", e);
                return None;
            }
        };

        let row: Row = match stream.into_row().await {
            Ok(Some(row)) => row,
            Ok(None) => return None,
            Err(e) => {
                eprintln!("Row fetch error in is_current_user: {}", e);
                return None;
            }
        };

        let server_ip: &str = match row.get(0) {
            Some(ip) => ip,
            None => {
                eprintln!("NULL server IP for account: {}", account_id);
                return None;
            }
        };

        let server_no_raw: i32 = match row.get(1) {
            Some(no) => no,
            None => {
                eprintln!("NULL server number for account: {}", account_id);
                return None;
            }
        };

        let server_no: i16 = match i16::try_from(server_no_raw) {
            Ok(n) => n,
            Err(_) => {
                eprintln!(
                    "Server number {} out of i16 range for account: {}",
                    server_no_raw, account_id
                );
                return None;
            }
        };

        Some((server_ip.to_string(), server_no))
    }

    async fn load_premium_days(&self, account_id: &str) -> i16 {
        let mut conn: PooledConnection<ConnectionManager> = match self.pool.get().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Pool error in load_premium_days: {}", e);
                return -1;
            }
        };

        let query: &str = "SELECT PremiumExpire FROM TB_USER WHERE strAccountID = @P1";
        let stream: QueryStream = match conn.query(query, &[&account_id]).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Query error in load_premium_days: {}", e);
                return -1;
            }
        };

        let row: Row = match stream.into_row().await {
            Ok(Some(row)) => row,
            Ok(None) => return -1,
            Err(e) => {
                eprintln!("Row fetch error in load_premium_days: {}", e);
                return -1;
            }
        };

        let expire: Option<NaiveDateTime> = row.get(0);
        match expire {
            Some(dt) => {
                let now: NaiveDateTime = chrono::Local::now().naive_local();
                let diff: TimeDelta = dt.signed_duration_since(now);
                let days: i64 = diff.num_days();
                if days > 0 { days as i16 } else { -1 }
            }
            None => -1,
        }
    }

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

        let auth_result: u8 = self.account_login(&account_id, &password).await;

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

        let premium_days: i16 = self.load_premium_days(&account_id).await;
        let mut reply: Vec<u8> = Vec::new();
        reply.push(LS_LOGIN_REQ);
        reply.push(AUTH_OK);
        reply.extend_from_slice(&premium_days.to_le_bytes());
        Some(reply)
    }

    pub async fn load_user_counts(&self) -> Vec<(u8, i16)> {
        let mut conn: PooledConnection<ConnectionManager> = match self.pool.get().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Pool error in load_user_counts: {}", e);
                return vec![];
            }
        };

        let query: &str =
            "SELECT serverid, zone1_count + zone2_count + zone3_count FROM CONCURRENT";
        let stream: QueryStream = match conn.query(query, &[]).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Query error in load_user_counts: {}", e);
                return vec![];
            }
        };

        let rows: Vec<Row> = match stream.into_results().await {
            Ok(mut results) => {
                if results.is_empty() {
                    return vec![];
                }
                results.remove(0)
            }
            Err(e) => {
                eprintln!("Row fetch error in load_user_counts: {}", e);
                return vec![];
            }
        };

        let mut counts: Vec<(u8, i16)> = Vec::new();
        for row in rows {
            let server_id: u8 = match row.get(0) {
                Some(id) => id,
                None => continue,
            };
            let total: i16 = row.get(1).unwrap_or_default();
            counts.push((server_id, total));
        }

        counts
    }
}
