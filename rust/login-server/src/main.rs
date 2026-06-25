mod config;
mod protocol;

use config::{Config, HandlerContext, PatchEntry, ServerState};
use protocol::{deframe, frame, handle};
use std::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("ERROR: {info}");
        eprintln!("Press Enter to exit...");
        let _ = std::io::stdin().read_line(&mut String::new());
    }));

    let config_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("config.toml")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("config.toml"));

    let config_text = fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", config_path.display(), e));

    let config: Config = toml::from_str(&config_text).expect("Failed to parse config.toml");

    let addr = format!("0.0.0.0:{}", config.general.listen_port);
    let listener: TcpListener = TcpListener::bind(&addr).await?;
    println!("Login Server listening on: {}", addr);

    loop {
        let (mut socket, addr) = listener.accept().await?;

        let ctx = HandlerContext {
            last_version: config.general.last_version,
            servers: config
                .servers
                .iter()
                .map(|s| ServerState {
                    ip: s.ip.clone(),
                    name: s.name.clone(),
                    user_count: 0,
                    user_limit: s.user_limit,
                })
                .collect(),
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

        tokio::spawn(async move {
            println!("Client connected with IP: {addr}");
            let mut buf: Vec<u8> = vec![0; 16 * 1024];
            loop {
                let bytes_read = match socket.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => n,
                    Err(_) => return,
                };
                if let Some(payload) = deframe(&buf[..bytes_read])
                    && let Some(reply) = handle(&payload, &ctx)
                {
                    let framed = frame(&reply);
                    let _ = socket.write_all(&framed).await;
                }
            }
        });
    }
}
