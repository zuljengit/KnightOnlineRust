use crate::config::{HandlerContext, PatchEntry};

pub const PACKET_START1: u8 = 0xAA;
pub const PACKET_START2: u8 = 0x55;
pub const PACKET_END1: u8 = 0x55;
pub const PACKET_END2: u8 = 0xAA;

pub const LS_VERSION_REQ: u8 = 0x01;
pub const LS_SERVER_LIST: u8 = 0xF5;
pub const LS_NEWS: u8 = 0xF6;
pub const LS_DOWNLOAD_INFO_REQ: u8 = 0x02;

pub fn deframe(data: &[u8]) -> Option<Vec<u8>> {
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

pub fn frame(payload: &[u8]) -> Vec<u8> {
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

pub fn write_string2(buf: &mut Vec<u8>, str: &str) {
    let len = str.len() as i16;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(str.as_bytes());
}

pub fn read_i16(data: &[u8], offset: usize) -> Option<i16> {
    if data.len() < offset + 2 {
        return None;
    }
    Some(i16::from_le_bytes([data[offset], data[offset + 1]]))
}

pub fn handle(payload: &[u8], ctx: &HandlerContext) -> Option<Vec<u8>> {
    let opcode = *payload.first()?;
    match opcode {
        LS_VERSION_REQ => {
            let mut reply: Vec<u8> = Vec::new();
            reply.push(LS_VERSION_REQ);
            reply.extend_from_slice(&ctx.last_version.to_le_bytes());
            Some(reply)
        }
        LS_DOWNLOAD_INFO_REQ => {
            let client_version = read_i16(payload, 1)?;

            let mut reply: Vec<u8> = Vec::new();
            reply.push(LS_DOWNLOAD_INFO_REQ);
            write_string2(&mut reply, &ctx.ftp_url);
            write_string2(&mut reply, &ctx.ftp_path);

            let needed: Vec<&PatchEntry> = ctx
                .patches
                .iter()
                .filter(|patch| patch.version > client_version)
                .collect();

            reply.extend_from_slice(&(needed.len() as i16).to_le_bytes());

            for patch in needed {
                write_string2(&mut reply, &patch.filename);
            }

            Some(reply)
        }
        LS_SERVER_LIST => {
            let mut reply: Vec<u8> = Vec::new();
            reply.push(LS_SERVER_LIST);
            reply.push(ctx.servers.len() as u8);

            for server in &ctx.servers {
                write_string2(&mut reply, &server.ip);
                write_string2(&mut reply, &server.name);

                let count = if server.user_count <= server.user_limit {
                    server.user_count
                } else {
                    -1
                };
                reply.extend_from_slice(&count.to_le_bytes());
            }

            Some(reply)
        }
        LS_NEWS => {
            let mut reply: Vec<u8> = Vec::new();
            reply.push(LS_NEWS);
            write_string2(&mut reply, &ctx.news_title);
            write_string2(&mut reply, &ctx.news_message);
            Some(reply)
        }
        other => {
            println!("Unhandled opcode {other:#04X}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LS_DOWNLOAD_INFO_REQ, LS_NEWS, LS_SERVER_LIST, LS_VERSION_REQ, PACKET_END1, PACKET_END2,
        PACKET_START1, PACKET_START2, deframe, frame, handle, write_string2,
    };
    use crate::config::{HandlerContext, PatchEntry, ServerState};

    const TEST_SERVER_VERSION: i16 = 1298;
    const TEST_SERVER_IP: &str = "127.0.0.1";
    const TEST_SERVER_NAME: &str = "Server 1";
    const TEST_SERVER_USER_COUNT: i16 = 0;
    const TEST_NEWS_TITLE: &str = "Test Notice";
    const TEST_NEWS_MESSAGE: &str = "Welcome!";
    const TEST_FTP_URL: &str = "ftp.test.com";
    const TEST_FTP_PATH: &str = "/patches";
    const TEST_PATCH_FILENAME: &str = "patch_1298";
    const TEST_PATCH_VERSION: i16 = 1298;

    #[test]
    fn deframe_valid_packet() {
        // AA 55 [03 00 = length 3 as LE u16] [17 12 05 = arbitrary payload] 55 AA
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
                PACKET_END2,
            ]
        );
    }

    #[test]
    fn frame_roundtrip() {
        let payload: Vec<u8> = vec![0x17, 0x12, 0x05];
        let framed: Vec<u8> = frame(&payload);
        let result: Option<Vec<u8>> = deframe(&framed);

        assert_eq!(result, Some(payload));
    }

    #[test]
    fn write_string2_encodes_correctly() {
        let mut buf: Vec<u8> = Vec::new();
        write_string2(&mut buf, "Hello");

        assert_eq!(buf, vec![0x05, 0x00, 0x48, 0x65, 0x6C, 0x6C, 0x6F]);
    }

    #[test]
    fn write_string2_empty_string() {
        let mut buf: Vec<u8> = Vec::new();
        write_string2(&mut buf, "");

        assert_eq!(buf, vec![0x00, 0x00]);
    }

    #[test]
    fn handle_version_request() {
        let payload: Vec<u8> = vec![LS_VERSION_REQ, 0xBB];
        let result: Option<Vec<u8>> = handle(&payload, &test_context(vec![], test_servers()));

        // Response: opcode + version 1298 (0x0512) as LE = [0x12, 0x05]
        assert_eq!(result, Some(vec![LS_VERSION_REQ, 0x12, 0x05]));
    }

    #[test]
    fn handle_server_list() {
        let payload: Vec<u8> = vec![LS_SERVER_LIST];
        let result: Option<Vec<u8>> = handle(&payload, &test_context(vec![], test_servers()));
        let reply: Vec<u8> = result.expect("Should return a reply");

        assert_eq!(&reply[0..2], &[LS_SERVER_LIST, 0x01]);
        assert_eq!(&reply[2..4], &[0x09, 0x00]);
        assert_eq!(&reply[4..13], TEST_SERVER_IP.as_bytes());
        assert_eq!(&reply[13..15], &[0x08, 0x00]);
        assert_eq!(&reply[15..23], TEST_SERVER_NAME.as_bytes());
        assert_eq!(&reply[23..25], TEST_SERVER_USER_COUNT.to_le_bytes());
        assert_eq!(reply.len(), 25);
    }

    #[test]
    fn handle_server_list_when_server_is_full() {
        let full_server: Vec<ServerState> = vec![ServerState {
            ip: TEST_SERVER_IP.to_string(),
            name: TEST_SERVER_NAME.to_string(),
            user_count: 3001,
            user_limit: 3000,
        }];
        let payload: Vec<u8> = vec![LS_SERVER_LIST];
        let reply =
            handle(&payload, &test_context(vec![], full_server)).expect("Should return a reply");

        // User count should be -1 (0xFF, 0xFF as LE i16) when server is full
        assert_eq!(&reply[23..25], &[0xFF, 0xFF]);
    }

    #[test]
    fn handle_news() {
        let payload: Vec<u8> = vec![LS_NEWS];
        let result: Option<Vec<u8>> = handle(&payload, &test_context(vec![], test_servers()));
        let reply: Vec<u8> = result.expect("Should return a reply");

        assert_eq!(reply[0], LS_NEWS);
        assert_eq!(&reply[1..3], &[0x0B, 0x00]);
        assert_eq!(&reply[3..14], TEST_NEWS_TITLE.as_bytes());
        assert_eq!(&reply[14..16], &[0x08, 0x00]);
        assert_eq!(&reply[16..24], TEST_NEWS_MESSAGE.as_bytes());
        assert_eq!(reply.len(), 24);
    }

    #[test]
    fn handle_download_info_returns_only_newer_patches() {
        // Client version 1296 (0x0510) as LE bytes
        // Patches 1295 and 1296 should be excluded
        // Patches 1297 and 1298 should be included
        let payload: Vec<u8> = vec![LS_DOWNLOAD_INFO_REQ, 0x10, 0x05];
        let patches: Vec<PatchEntry> = vec![
            PatchEntry {
                filename: "patch_1295".to_string(),
                version: 1295,
            },
            PatchEntry {
                filename: "patch_1296".to_string(),
                version: 1296,
            },
            PatchEntry {
                filename: "patch_1297".to_string(),
                version: 1297,
            },
            PatchEntry {
                filename: "patch_1298".to_string(),
                version: 1298,
            },
        ];
        let result: Option<Vec<u8>> = handle(&payload, &test_context(patches, test_servers()));
        let reply: Vec<u8> = result.expect("Should return a reply");

        assert_eq!(reply[0], LS_DOWNLOAD_INFO_REQ);
        assert_eq!(&reply[1..3], &[0x0C, 0x00]);
        assert_eq!(&reply[3..15], TEST_FTP_URL.as_bytes());
        assert_eq!(&reply[15..17], &[0x08, 0x00]);
        assert_eq!(&reply[17..25], TEST_FTP_PATH.as_bytes());
        assert_eq!(&reply[25..27], &[0x02, 0x00]); // 2 patches needed
        assert_eq!(&reply[27..29], &[0x0A, 0x00]);
        assert_eq!(&reply[29..39], b"patch_1297");
        assert_eq!(&reply[39..41], &[0x0A, 0x00]);
        assert_eq!(&reply[41..51], b"patch_1298");
        assert_eq!(reply.len(), 51);
    }

    #[test]
    fn handle_download_info_when_client_is_up_to_date() {
        // No patches should be returned since 1298 > 1298 is false (strict greater than)
        let payload: Vec<u8> = vec![LS_DOWNLOAD_INFO_REQ, 0x12, 0x05];
        let patches: Vec<PatchEntry> = vec![PatchEntry {
            filename: TEST_PATCH_FILENAME.to_string(),
            version: TEST_PATCH_VERSION,
        }];
        let result: Option<Vec<u8>> = handle(&payload, &test_context(patches, test_servers()));
        let reply: Vec<u8> = result.expect("Should return a reply");

        assert_eq!(reply[0], LS_DOWNLOAD_INFO_REQ);
        assert_eq!(&reply[25..27], &[0x00, 0x00]); // 0 patches needed
        assert_eq!(reply.len(), 27);
    }

    #[test]
    fn handle_download_info_when_client_is_outdated() {
        // Client version 1297 (0x0511) as LE bytes
        let payload: Vec<u8> = vec![LS_DOWNLOAD_INFO_REQ, 0x11, 0x05];
        let patches: Vec<PatchEntry> = vec![PatchEntry {
            filename: TEST_PATCH_FILENAME.to_string(),
            version: TEST_PATCH_VERSION,
        }];
        let result: Option<Vec<u8>> = handle(&payload, &test_context(patches, test_servers()));
        let reply: Vec<u8> = result.expect("Should return a reply");

        assert_eq!(reply[0], LS_DOWNLOAD_INFO_REQ);
        assert_eq!(&reply[25..27], &[0x01, 0x00]); // 1 patch needed
        assert_eq!(&reply[29..39], TEST_PATCH_FILENAME.as_bytes());
        assert_eq!(reply.len(), 39);
    }

    #[test]
    fn handle_download_info_with_no_patches_configured() {
        // Client version 1297 (0x0511) as LE bytes, but no patches exist
        let payload: Vec<u8> = vec![LS_DOWNLOAD_INFO_REQ, 0x11, 0x05];
        let result: Option<Vec<u8>> = handle(&payload, &test_context(vec![], test_servers()));
        let reply: Vec<u8> = result.expect("Should return a reply");

        assert_eq!(reply[0], LS_DOWNLOAD_INFO_REQ);
        assert_eq!(&reply[25..27], &[0x00, 0x00]); // 0 patches
        assert_eq!(reply.len(), 27);
    }

    #[test]
    fn handle_download_info_when_payload_too_short() {
        let payload: Vec<u8> = vec![LS_DOWNLOAD_INFO_REQ];
        let result: Option<Vec<u8>> = handle(&payload, &test_context(vec![], test_servers()));
        assert!(result.is_none());
    }

    #[test]
    fn handle_unknown_opcode() {
        let payload: Vec<u8> = vec![0x00, 0xBB];
        let result: Option<Vec<u8>> = handle(&payload, &test_context(vec![], test_servers()));

        assert!(result.is_none());
    }

    #[test]
    fn handle_empty_payload() {
        let payload: Vec<u8> = vec![];
        let result: Option<Vec<u8>> = handle(&payload, &test_context(vec![], test_servers()));

        assert!(result.is_none());
    }

    fn test_context(patches: Vec<PatchEntry>, servers: Vec<ServerState>) -> HandlerContext {
        HandlerContext {
            last_version: TEST_SERVER_VERSION,
            servers,
            news_title: TEST_NEWS_TITLE.to_string(),
            news_message: TEST_NEWS_MESSAGE.to_string(),
            ftp_url: TEST_FTP_URL.to_string(),
            ftp_path: TEST_FTP_PATH.to_string(),
            patches,
        }
    }

    fn test_servers() -> Vec<ServerState> {
        vec![ServerState {
            ip: TEST_SERVER_IP.to_string(),
            name: TEST_SERVER_NAME.to_string(),
            user_count: TEST_SERVER_USER_COUNT,
            user_limit: 3000,
        }]
    }
}
