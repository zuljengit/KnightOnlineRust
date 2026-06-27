use crate::config::{HandlerContext, PatchEntry};

pub const PACKET_START1: u8 = 0xAA;
pub const PACKET_START2: u8 = 0x55;
pub const PACKET_END1: u8 = 0x55;
pub const PACKET_END2: u8 = 0xAA;

pub const LS_VERSION_REQ: u8 = 0x01;
pub const LS_SERVER_LIST: u8 = 0xF5;
pub const LS_NEWS: u8 = 0xF6;
pub const LS_DOWNLOAD_INFO_REQ: u8 = 0x02;
pub const LS_LOGIN_REQ: u8 = 0xF3;

pub const AUTH_OK: u8 = 0x01;
pub const AUTH_NOT_FOUND: u8 = 0x02;
#[allow(dead_code)]
pub const AUTH_INVALID_PW: u8 = 0x03;
pub const AUTH_BANNED: u8 = 0x04;
pub const AUTH_IN_GAME: u8 = 0x05;
pub const AUTH_FAILED: u8 = 0xFF;

pub const MAX_ID_SIZE: usize = 20;
pub const MAX_PW_SIZE: usize = 12;
pub const MAX_PACKET_SIZE: usize = 1024 * 8;

#[derive(Debug, PartialEq)]
pub enum FrameResult {
    /// A complete, valid packet. Contains the payload and bytes consumed.
    Packet { payload: Vec<u8>, consumed: usize },
    /// Garbage or a corrupt frame was found. Skip this many bytes and retry.
    Skip { consumed: usize },
    /// Not enough data for a complete frame yet. Wait for more.
    NeedMore,
}

pub fn extract_frame(data: &[u8]) -> FrameResult {
    // Find the next start marker. Anything before it is garbage.
    let start_pos: usize = match data
        .windows(2)
        .position(|w| w[0] == PACKET_START1 && w[1] == PACKET_START2)
    {
        Some(pos) => pos,
        None => {
            return if data.len() > 1 {
                // Drain everything except the last byte, which might be
                // the first half of a start marker (0xAA).
                FrameResult::Skip {
                    consumed: data.len() - 1,
                }
            } else {
                // 0 or 1 bytes — nothing to drain, wait for more.
                FrameResult::NeedMore
            };
        }
    };

    // Drain any leading garbage before the start marker first, so we don't
    // re-scan it on every read while waiting for the rest of the frame.
    if start_pos > 0 {
        return FrameResult::Skip {
            consumed: start_pos,
        };
    }

    // From here, start_pos is 0 — the marker is at the front.
    let header_pos: usize = 2;

    // Need 2 bytes for the length field.
    if data.len() < header_pos + 2 {
        return FrameResult::NeedMore;
    }

    let len = i16::from_le_bytes([data[header_pos], data[header_pos + 1]]) as usize;

    // Reject impossible lengths. Skip past this bogus start marker.
    if len > MAX_PACKET_SIZE {
        return FrameResult::Skip { consumed: 2 };
    }

    let payload_start: usize = header_pos + 2;
    let end_pos: usize = payload_start + len;

    // Need the full payload plus 2 end markers.
    if data.len() < end_pos + 2 {
        return FrameResult::NeedMore;
    }

    // Validate end markers. If wrong, skip and resync on the next start marker.
    if data[end_pos] != PACKET_END1 || data[end_pos + 1] != PACKET_END2 {
        return FrameResult::Skip { consumed: 2 };
    }

    let payload: Vec<u8> = data[payload_start..end_pos].to_vec();
    FrameResult::Packet {
        payload,
        consumed: end_pos + 2,
    }
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

pub fn read_string2(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let len = read_i16(data, offset)? as usize;
    let start: usize = offset + 2;
    let end: usize = start + len;

    if data.len() < end {
        return None;
    }

    let str = String::from_utf8(data[start..end].to_vec()).ok()?;
    if !str.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    Some((str, end))
}

pub fn handle(payload: &[u8], ctx: &HandlerContext) -> Option<Vec<u8>> {
    let opcode: u8 = *payload.first()?;
    match opcode {
        LS_VERSION_REQ => {
            let mut reply: Vec<u8> = Vec::new();
            reply.push(LS_VERSION_REQ);
            reply.extend_from_slice(&ctx.last_version.to_le_bytes());
            Some(reply)
        }
        LS_DOWNLOAD_INFO_REQ => {
            let client_version: i16 = read_i16(payload, 1)?;

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

                let count: i16 = if server.user_count <= server.user_limit {
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
        LS_LOGIN_REQ => {
            // Handled async in main loop via Database::handle_login
            None
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
        FrameResult, LS_DOWNLOAD_INFO_REQ, LS_LOGIN_REQ, LS_NEWS, LS_SERVER_LIST, LS_VERSION_REQ,
        PACKET_END1, PACKET_END2, PACKET_START1, PACKET_START2, extract_frame, frame, handle,
        read_i16, read_string2, write_string2,
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
    fn extract_frame_returns_packet_for_complete_frame() {
        let data: Vec<u8> = vec![
            PACKET_START1,
            PACKET_START2,
            0x01,
            0x00,
            0x99,
            PACKET_END1,
            PACKET_END2,
        ];
        let result: FrameResult = extract_frame(&data);

        assert_eq!(
            result,
            FrameResult::Packet {
                payload: vec![0x99],
                consumed: 7
            }
        );
    }

    #[test]
    fn extract_frame_skips_garbage_when_no_start_marker_found() {
        let data: Vec<u8> = vec![PACKET_START2, 0x01, 0x00, 0x99, PACKET_END1];
        let result: FrameResult = extract_frame(&data);

        assert_eq!(result, FrameResult::Skip { consumed: 4 });
    }

    #[test]
    fn extract_frame_needs_more_when_data_too_short() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty data", vec![]),
            ("single start byte", vec![0xAA]),
            ("single garbage byte", vec![0xFF]),
        ];

        for (name, data) in cases {
            assert!(
                matches!(extract_frame(&data), FrameResult::NeedMore),
                "Expected NeedMore for case: {}",
                name
            );
        }
    }

    #[test]
    fn extract_frame_skips_garbage_before_start_marker() {
        let cases: Vec<(&str, Vec<u8>, usize)> = vec![
            (
                "three garbage bytes",
                vec![0x12, 0x34, 0x56, PACKET_START1, PACKET_START2],
                3,
            ),
            (
                "garbage that looks like a partial marker",
                vec![PACKET_START1, 0xFF, PACKET_START1, PACKET_START2],
                2,
            ),
        ];

        for (name, data, expected_consumed) in cases {
            assert!(
                matches!(extract_frame(&data), FrameResult::Skip { consumed } if consumed == expected_consumed),
                "Expected Skip {{ consumed: {} }} for case: {}",
                expected_consumed,
                name
            );
        }
    }

    #[test]
    fn extract_frame_needs_more_when_data_incomplete_after_start_marker() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("start marker only", vec![PACKET_START1, PACKET_START2]),
            (
                "start marker plus one length byte",
                vec![PACKET_START1, PACKET_START2, 0x01],
            ),
            (
                "valid header but payload not fully arrived",
                vec![PACKET_START1, PACKET_START2, 0x05, 0x00, 0x01, 0x02],
            ),
            (
                "payload complete but missing end markers",
                vec![PACKET_START1, PACKET_START2, 0x01, 0x00, 0x99],
            ),
        ];

        for (name, data) in cases {
            assert!(
                matches!(extract_frame(&data), FrameResult::NeedMore),
                "Expected NeedMore for case: {}",
                name
            );
        }
    }

    #[test]
    fn extract_frame_skips_invalid_start_marker_when_length_exceeds_max_packet_size() {
        // Length field: 0x01, 0x20 = 0x2001 LE = 8193, exceeds MAX_PACKET_SIZE (8192)
        let data: Vec<u8> = vec![
            PACKET_START1,
            PACKET_START2,
            0x01,
            0x20,
            PACKET_END1,
            PACKET_END2,
        ];
        let result: FrameResult = extract_frame(&data);

        assert_eq!(result, FrameResult::Skip { consumed: 2 });
    }

    #[test]
    fn extract_frame_skips_invalid_start_marker_when_end_markers_are_wrong() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "first end marker wrong",
                vec![
                    PACKET_START1,
                    PACKET_START2,
                    0x01,
                    0x00,
                    0x99,
                    0xFF,
                    PACKET_END2,
                ],
            ),
            (
                "second end marker wrong",
                vec![
                    PACKET_START1,
                    PACKET_START2,
                    0x01,
                    0x00,
                    0x99,
                    PACKET_END1,
                    0xFF,
                ],
            ),
            (
                "end markers in wrong order",
                vec![
                    PACKET_START1,
                    PACKET_START2,
                    0x01,
                    0x00,
                    0x99,
                    PACKET_END2,
                    PACKET_END1,
                ],
            ),
        ];

        for (name, data) in cases {
            assert!(
                matches!(extract_frame(&data), FrameResult::Skip { consumed: 2 }),
                "Expected Skip {{ consumed: 2 }} for case: {}",
                name
            );
        }
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
    fn extract_frame_returns_first_packet_when_buffer_has_two() {
        let data: Vec<u8> = vec![
            PACKET_START1,
            PACKET_START2,
            0x01,
            0x00,
            0x99,
            PACKET_END1,
            PACKET_END2,
            PACKET_START1,
            PACKET_START2,
            0x01,
            0x00,
            0x88,
            PACKET_END1,
            PACKET_END2,
        ];
        let result: FrameResult = extract_frame(&data);

        assert_eq!(
            result,
            FrameResult::Packet {
                payload: vec![0x99],
                consumed: 7,
            }
        );
    }

    #[test]
    fn frame_and_extract_round_trip() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("multi byte payload", vec![0x17, 0x12, 0x05]),
            ("empty payload", vec![]),
            (
                "payload containing start marker bytes",
                vec![0xAA, 0x55, 0x01],
            ),
            (
                "payload containing end marker bytes",
                vec![0x55, 0xAA, 0x02],
            ),
        ];

        for (name, payload) in cases {
            let framed: Vec<u8> = frame(&payload);
            let expected_consumed: usize = framed.len();
            let result: FrameResult = extract_frame(&framed);

            assert_eq!(
                result,
                FrameResult::Packet {
                    payload,
                    consumed: expected_consumed,
                },
                "Round trip failed for case: {}",
                name
            );
        }
    }

    #[test]
    fn write_string2_encodes_correctly() {
        let str_to_encode = String::from("Hello world");
        let mut buf: Vec<u8> = Vec::new();
        write_string2(&mut buf, &str_to_encode);

        assert_eq!(buf, [&[0x0B, 0x00][..], str_to_encode.as_bytes()].concat());
    }

    #[test]
    fn write_string2_empty_string() {
        let mut buf: Vec<u8> = Vec::new();
        write_string2(&mut buf, "");

        assert_eq!(buf, vec![0x00, 0x00]);
    }

    #[test]
    fn read_i16_parses_little_endian_value_at_offset() {
        let cases: Vec<(&str, Vec<u8>, usize, Option<i16>)> = vec![
            ("simple value at offset 0", vec![0x05, 0x00], 0, Some(5)),
            (
                "value at offset 1, skipping opcode byte",
                vec![0xFF, 0x12, 0x05],
                1,
                // 0x12 low, 0x05 high = 0x0512 = 1298
                Some(1298),
            ),
            ("negative value", vec![0xFF, 0xFF], 0, Some(-1)),
            ("not enough bytes at offset", vec![0xFF, 0x10], 1, None),
            ("empty data", vec![], 0, None),
            ("offset beyond data length", vec![0x01, 0x02], 5, None),
        ];

        for (name, data, offset, expected) in cases {
            let result: Option<i16> = read_i16(&data, offset);
            assert_eq!(result, expected, "Failed for case: {}", name);
        }
    }

    #[test]
    fn read_string2_decodes_valid_strings() {
        let cases: Vec<(&str, Vec<u8>, usize, &str, usize)> = vec![
            (
                "simple ASCII at offset 1",
                [&[0xFF, 0x08, 0x00][..], b"password"].concat(),
                1,
                "password",
                11,
            ),
            (
                "string with underscore",
                [&[0x05, 0x00][..], b"hello"].concat(),
                0,
                "hello",
                7,
            ),
            (
                "string with numbers",
                [&[0x07, 0x00][..], b"test123"].concat(),
                0,
                "test123",
                9,
            ),
            ("single character", vec![0x01, 0x00, 0x41], 0, "A", 3),
            (
                "mixed case with underscore",
                [&[0x06, 0x00][..], b"Ab_12c"].concat(),
                0,
                "Ab_12c",
                8,
            ),
        ];

        for (name, data, offset, expected_str, expected_end) in cases {
            let result: Option<(String, usize)> = read_string2(&data, offset);
            assert_eq!(
                result,
                Some((expected_str.to_string(), expected_end)),
                "Failed for case: {}",
                name
            );
        }
    }

    #[test]
    fn read_string2_returns_none_for_invalid_data() {
        let cases: Vec<(&str, Vec<u8>, usize)> = vec![
            (
                "special characters rejected",
                [&[0x09, 0x00][..], b"pass$word"].concat(),
                0,
            ),
            ("spaces rejected", [&[0x05, 0x00][..], b"he lo"].concat(), 0),
            ("dash rejected", [&[0x05, 0x00][..], b"he-lo"].concat(), 0),
            (
                "data shorter than declared length",
                vec![0x05, 0x00, 0x41, 0x42],
                0,
            ),
            ("only length field, no string bytes", vec![0x03, 0x00], 0),
            ("not enough bytes for length field", vec![0x05], 0),
            ("empty data", vec![], 0),
            ("offset beyond data", vec![0x01, 0x00, 0x41], 5),
        ];

        for (name, data, offset) in cases {
            let result: Option<(String, usize)> = read_string2(&data, offset);
            assert_eq!(result, None, "Expected None for case: {}", name);
        }
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
            id: 1,
            ip: TEST_SERVER_IP.to_string(),
            name: TEST_SERVER_NAME.to_string(),
            user_count: 3001,
            user_limit: 3000,
        }];
        let payload: Vec<u8> = vec![LS_SERVER_LIST];
        let reply: Vec<u8> =
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
    fn handle_login_request_is_not_handled_by_sync_handler() {
        let payload: Vec<u8> = vec![LS_LOGIN_REQ, 0x05, 0x00, b'a', b'd', b'm', b'i', b'n'];
        let result: Option<Vec<u8>> = handle(&payload, &test_context(vec![], test_servers()));

        // Login is handled async via Database::handle_login, not here
        assert!(result.is_none());
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
            id: 1,
            ip: TEST_SERVER_IP.to_string(),
            name: TEST_SERVER_NAME.to_string(),
            user_count: TEST_SERVER_USER_COUNT,
            user_limit: 3000,
        }]
    }
}
