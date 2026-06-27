mod config;
mod db;
mod protocol;

use config::{Config, HandlerContext, PatchEntry, ServerState, SharedServerList};
use db::Database;
use protocol::{FrameResult, LS_LOGIN_REQ, extract_frame, frame, handle};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, RwLockWriteGuard};
use tokio::time::{Duration, Interval, interval};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("ERROR: {info}");
        eprintln!("Press Enter to exit...");
        let _ = std::io::stdin().read_line(&mut String::new());
    }));

    let config_path: PathBuf = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("config.toml")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("config.toml"));

    let config_text: String = fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", config_path.display(), e));

    let config: Config = toml::from_str(&config_text).expect("Failed to parse config.toml");

    let database: Arc<Database> = Arc::new(Database::new(&config.database).await);

    let servers: SharedServerList = Arc::new(RwLock::new(
        config
            .servers
            .iter()
            .map(|s| ServerState {
                id: s.id,
                ip: s.ip.clone(),
                name: s.name.clone(),
                user_count: 0,
                user_limit: s.user_limit,
            })
            .collect(),
    ));

    // Background task: update user counts every 30 seconds
    let bg_db: Arc<Database> = Arc::clone(&database);
    let bg_servers: SharedServerList = Arc::clone(&servers);
    tokio::spawn(async move {
        let mut timer: Interval = interval(Duration::from_secs(30));
        loop {
            timer.tick().await;
            let counts: Vec<(u8, i16)> = bg_db.load_user_counts().await;
            let mut server_list: RwLockWriteGuard<Vec<ServerState>> = bg_servers.write().await;
            for server in server_list.iter_mut() {
                let count: i16 = counts
                    .iter()
                    .find(|(id, _)| *id == server.id)
                    .map(|(_, c)| *c)
                    .unwrap_or(0);
                server.user_count = count;
            }
            println!("Updated user counts: {:?}", counts);
        }
    });

    let bind_addr: String = format!("0.0.0.0:{}", config.general.listen_port);
    let listener: TcpListener = TcpListener::bind(&bind_addr).await?;
    println!("Login Server listening on: {}", bind_addr);

    loop {
        let (mut socket, addr): (TcpStream, SocketAddr) = listener.accept().await?;

        // Snapshot the server list for this connection
        let server_snapshot: Vec<ServerState> = servers.read().await.clone();

        let ctx: HandlerContext = HandlerContext {
            last_version: config.general.last_version,
            servers: server_snapshot,
            news_title: config.news.title.clone(),
            news_message: config.news.message.clone(),
            ftp_url: config.download.ftp_url.clone(),
            ftp_path: config.download.ftp_path.clone(),
            patches: config
                .patches
                .iter()
                .map(|p| PatchEntry {
                    filename: p.filename.clone(),
                    version: p.version,
                })
                .collect(),
        };

        let db: Arc<Database> = Arc::clone(&database);

        tokio::spawn(async move {
            println!("Client connected with IP: {addr}");

            let mut accumulator: Vec<u8> = Vec::new();
            let mut buf: Vec<u8> = vec![0; 16 * 1024];

            loop {
                let bytes_read: usize = match socket.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => n,
                    Err(_) => return,
                };

                accumulator.extend_from_slice(&buf[..bytes_read]);

                if accumulator.len() > 64 * 1024 {
                    eprintln!("Accumulator overflow from {addr}, dropping connection");
                    return;
                }

                loop {
                    match extract_frame(&accumulator) {
                        FrameResult::Packet { payload, consumed } => {
                            accumulator.drain(..consumed);

                            let reply: Option<Vec<u8>> = if payload.first() == Some(&LS_LOGIN_REQ) {
                                db.handle_login(&payload).await
                            } else {
                                handle(&payload, &ctx)
                            };

                            if let Some(reply) = reply {
                                let framed: Vec<u8> = frame(&reply);
                                let _ = socket.write_all(&framed).await;
                            }
                        }
                        FrameResult::Skip { consumed } => {
                            accumulator.drain(..consumed);
                        }
                        FrameResult::NeedMore => break,
                    }
                }
            }
        });
    }
}
