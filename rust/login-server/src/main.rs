use serde::Deserialize;
use std::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PACKET_START1: u8 = 0xAA;
const PACKET_START2: u8 = 0x55;
const PACKET_END1: u8 = 0x55;
const PACKET_END2: u8 = 0xAA;

const LS_VERSION_REQ: u8 = 0x01;
const LS_SERVER_LIST: u8 = 0xF5;

#[allow(dead_code)]
#[derive(Deserialize)]
struct Config {
    general: GeneralConfig,
    download: DownloadConfig,
    servers: Vec<ServerConfig>,
}

#[derive(Deserialize)]
struct GeneralConfig {
    listen_port: u16,
    last_version: i16,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct DownloadConfig {
    ftp_url: String,
    ftp_path: String,
}

#[derive(Deserialize)]
struct ServerConfig {
    ip: String,
    name: String,
    user_limit: i16,
}

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

        let last_version = config.general.last_version;
        let servers: Vec<(String, String, i16, i16)> = config
            .servers
            .iter()
            .map(|s| (s.ip.clone(), s.name.clone(), 0_i16, s.user_limit))
            .collect();

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
                    && let Some(reply) = handle(&payload, last_version, &servers)
                {
                    let framed = frame(&reply);
                    let _ = socket.write_all(&framed).await;
                }
            }
        });
    }
}

fn deframe(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 6 {
        return None;
    }
    if data[0] != PACKET_START1 || data[1] != PACKET_START2 {
        return None;
    }
    let len = i16::from_le_bytes([data[2], data[3]]) as usize;
    let end: usize = 4 + len;
    if data.len() < end + 2 {
        return None;
    }
    if data[end] != PACKET_END1 || data[end + 1] != PACKET_END2 {
        return None;
    }
    Some(data[4..end].to_vec())
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as i16;
    let mut out: Vec<u8> = Vec::with_capacity(payload.len() + 6);
    out.push(PACKET_START1);
    out.push(PACKET_START2);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    out.push(PACKET_END1);
    out.push(PACKET_END2);
    out
}

fn handle(
    payload: &[u8],
    last_version: i16,
    servers: &[(String, String, i16, i16)],
) -> Option<Vec<u8>> {
    let opcode = *payload.first()?;
    match opcode {
        LS_VERSION_REQ => {
            let mut reply: Vec<u8> = Vec::new();
            reply.push(LS_VERSION_REQ);
            reply.extend_from_slice(&last_version.to_le_bytes());
            Some(reply)
        }
        LS_SERVER_LIST => {
            let mut reply: Vec<u8> = Vec::new();
            reply.push(LS_SERVER_LIST);
            reply.push(servers.len() as u8);

            for (ip, name, user_count, user_limit) in servers {
                write_string2(&mut reply, ip);
                write_string2(&mut reply, name);

                let count = if *user_count <= *user_limit {
                    *user_count
                } else {
                    -1
                };
                reply.extend_from_slice(&count.to_le_bytes());
            }

            Some(reply)
        }
        other => {
            println!("Unhandled opcode {other:#04X}");
            None
        }
    }
}

fn write_string2(buf: &mut Vec<u8>, str: &str) {
    let len = str.len() as i16;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(str.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::{
        LS_SERVER_LIST, LS_VERSION_REQ, PACKET_END1, PACKET_END2, PACKET_START1, PACKET_START2,
        deframe, frame, handle,
    };

    const TEST_VERSION: i16 = 1298;

    #[test]
    fn deframe_valid_packet() {
        // A valid packet: AA 55 [03 00 = length 3 as LE u16] [01 12 05 = payload] 55 AA
        let data: Vec<u8> = vec![
            PACKET_START1,
            PACKET_START2,
            0x03,
            0x00,
            0x17,
            0x12,
            0x05,
            PACKET_END1,
            PACKET_END2,
        ];
        let result: Option<Vec<u8>> = deframe(&data);
        assert_eq!(result, Some(vec![0x17, 0x12, 0x05]));
    }

    #[test]
    fn deframe_too_short() {
        let data: Vec<u8> = vec![PACKET_START1, PACKET_START2, 0x15];
        let result: Option<Vec<u8>> = deframe(&data);
        assert!(result.is_none());
    }

    #[test]
    fn deframe_wrong_start_markers() {
        let data: Vec<u8> = vec![
            0xBB,
            PACKET_START2,
            0x01,
            0x00,
            0x15,
            PACKET_END1,
            PACKET_END2,
        ];
        let result: Option<Vec<u8>> = deframe(&data);
        assert!(result.is_none());
    }

    #[test]
    fn deframe_wrong_end_markers() {
        let data: Vec<u8> = vec![
            PACKET_START1,
            PACKET_START2,
            0x01,
            0x00,
            0x15,
            PACKET_END1,
            0xBB,
        ];
        let result: Option<Vec<u8>> = deframe(&data);
        assert!(result.is_none());
    }

    #[test]
    fn deframe_empty_payload() {
        let data: Vec<u8> = vec![
            PACKET_START1,
            PACKET_START2,
            0x00,
            0x00,
            PACKET_END1,
            PACKET_END2,
        ];
        let result: Option<Vec<u8>> = deframe(&data);
        assert_eq!(result, Some(vec![]));
    }

    #[test]
    fn frame_valid_payload() {
        let payload: Vec<u8> = vec![0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let result: Vec<u8> = frame(&payload);
        assert_eq!(
            result,
            vec![
                PACKET_START1,
                PACKET_START2,
                0x05,
                0x00,
                0xBB,
                0xCC,
                0xDD,
                0xEE,
                0xFF,
                PACKET_END1,
                PACKET_END2
            ]
        );
    }

    #[test]
    fn handle_version_request() {
        let payload: Vec<u8> = vec![LS_VERSION_REQ, 0xBB];
        let result: Option<Vec<u8>> = handle(&payload, TEST_VERSION, &test_servers());
        assert_eq!(result, Some(vec![LS_VERSION_REQ, 0x12, 0x05]));
    }

    #[test]
    fn handle_server_list() {
        let payload: Vec<u8> = vec![LS_SERVER_LIST];
        let result: Option<Vec<u8>> = handle(&payload, TEST_VERSION, &test_servers());

        let reply: Vec<u8> = result.expect("Should return a reply");

        assert_eq!(reply.len(), 25);
        assert_eq!(&reply[0..2], &[LS_SERVER_LIST, 1]);
        assert_eq!(&reply[2..4], &[0x09, 0x00]);
        assert_eq!(&reply[4..13], b"127.0.0.1");
        assert_eq!(&reply[13..15], &[0x08, 0x00]);
        assert_eq!(&reply[15..23], b"Server 1");
        assert_eq!(&reply[23..25], &[0x00, 0x00]);
    }

    #[test]
    fn handle_unknown_opcode() {
        let payload: Vec<u8> = vec![0x00, 0xBB];
        let result: Option<Vec<u8>> = handle(&payload, TEST_VERSION, &test_servers());
        assert!(result.is_none());
    }

    #[test]
    fn handle_empty_payload() {
        let payload: Vec<u8> = vec![];
        let result: Option<Vec<u8>> = handle(&payload, TEST_VERSION, &test_servers());
        assert!(result.is_none());
    }

    #[test]
    fn frame_roundtrip() {
        let payload: Vec<u8> = vec![0x17, 0x12, 0x05];
        let framed: Vec<u8> = frame(&payload);
        let result: Option<Vec<u8>> = deframe(&framed);
        assert_eq!(result, Some(payload));
    }

    fn test_servers() -> Vec<(String, String, i16, i16)> {
        vec![("127.0.0.1".to_string(), "Server 1".to_string(), 0, 3000)]
    }
}
