use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Deserialize)]
pub struct PacketAnalysisRequest {
    pub packet_hex: String,
}

#[derive(Serialize)]
pub struct PacketAnalysisResponse {
    pub format: String,
    pub summary: String,
    pub packet_length: usize,
    pub details: PacketDetails,
}

#[derive(Serialize, Default, Debug, Clone)]
pub struct PacketDetails {
    pub version: Option<u8>,
    pub header_length: Option<u8>,
    pub total_length: Option<u16>,
    pub protocol: Option<String>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub transport: Option<String>,
    pub notes: Option<String>,
}

pub fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();

    if cleaned.len() % 2 != 0 {
        return Err("packet_hex must contain an even number of hex digits".to_string());
    }

    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    for chunk in cleaned.as_bytes().chunks(2) {
        let hi = hex_value(chunk[0])?;
        let lo = hex_value(chunk[1])?;
        bytes.push((hi << 4) | lo);
    }
    Ok(bytes)
}

pub fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex character: {}", byte as char)),
    }
}

pub fn parse_packet(bytes: &[u8]) -> PacketAnalysisResponse {
    let mut details = PacketDetails::default();
    let packet_length = bytes.len();

    if bytes.is_empty() {
        details.notes = Some("packet is empty".to_string());
        return PacketAnalysisResponse {
            format: "empty".to_string(),
            summary: "No packet data provided".to_string(),
            packet_length,
            details,
        };
    }

    let version = bytes[0] >> 4;
    details.version = Some(version);

    match version {
        4 => parse_ipv4_packet(bytes, packet_length, details),
        6 => parse_ipv6_packet(bytes, packet_length, details),
        _ => {
            details.notes = Some("unsupported or unknown IP version".to_string());
            PacketAnalysisResponse {
                format: "unknown".to_string(),
                summary: format!("Unrecognized packet version: {}", version),
                packet_length,
                details,
            }
        }
    }
}

pub fn parse_ipv4_packet(
    bytes: &[u8],
    packet_length: usize,
    mut details: PacketDetails,
) -> PacketAnalysisResponse {
    if bytes.len() < 20 {
        details.notes = Some("packet too short for IPv4 header".to_string());
        return PacketAnalysisResponse {
            format: "ipv4".to_string(),
            summary: "Invalid IPv4 packet".to_string(),
            packet_length,
            details,
        };
    }

    let ihl = bytes[0] & 0x0f;
    details.header_length = Some(ihl * 4);
    details.total_length = Some(u16::from_be_bytes([bytes[2], bytes[3]]));
    let protocol = bytes[9];
    let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    details.source = Some(source.to_string());
    details.destination = Some(destination.to_string());
    details.protocol = Some(protocol_name(protocol).to_string());

    if (ihl as usize) * 4 <= bytes.len() {
        details.transport = parse_transport(&bytes[(ihl as usize) * 4..], protocol);
    }

    let summary = format!(
        "IPv4 packet from {} to {} using {}",
        source,
        destination,
        details.protocol.as_deref().unwrap_or("unknown")
    );

    PacketAnalysisResponse {
        format: "ipv4".to_string(),
        summary,
        packet_length,
        details,
    }
}

pub fn parse_ipv6_packet(
    bytes: &[u8],
    packet_length: usize,
    mut details: PacketDetails,
) -> PacketAnalysisResponse {
    if bytes.len() < 40 {
        details.notes = Some("packet too short for IPv6 header".to_string());
        return PacketAnalysisResponse {
            format: "ipv6".to_string(),
            summary: "Invalid IPv6 packet".to_string(),
            packet_length,
            details,
        };
    }

    details.header_length = Some(40);
    details.total_length = Some(u16::from_be_bytes([bytes[4], bytes[5]]));
    let next_header = bytes[6];
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).unwrap());
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).unwrap());
    details.source = Some(source.to_string());
    details.destination = Some(destination.to_string());
    details.protocol = Some(protocol_name(next_header).to_string());

    if bytes.len() > 40 {
        details.transport = parse_transport(&bytes[40..], next_header);
    }

    let summary = format!(
        "IPv6 packet from {} to {} using {}",
        source,
        destination,
        details.protocol.as_deref().unwrap_or("unknown")
    );

    PacketAnalysisResponse {
        format: "ipv6".to_string(),
        summary,
        packet_length,
        details,
    }
}

pub fn protocol_name(protocol: u8) -> &'static str {
    match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "OTHER",
    }
}

pub fn parse_transport(payload: &[u8], protocol: u8) -> Option<String> {
    match protocol {
        6 if payload.len() >= 4 => {
            let src_port = u16::from_be_bytes([payload[0], payload[1]]);
            let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
            Some(format!("TCP {} -> {}", src_port, dst_port))
        }
        17 if payload.len() >= 4 => {
            let src_port = u16::from_be_bytes([payload[0], payload[1]]);
            let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
            Some(format!("UDP {} -> {}", src_port, dst_port))
        }
        1 if payload.len() >= 2 => Some(format!("ICMP type {} code {}", payload[0], payload[1])),
        58 if payload.len() >= 2 => Some(format!("ICMPv6 type {} code {}", payload[0], payload[1])),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== decode_hex tests =====

    #[test]
    fn test_decode_hex_valid_lowercase() {
        let result = decode_hex("4500003c").unwrap();
        assert_eq!(result, vec![0x45, 0x00, 0x00, 0x3c]);
    }

    #[test]
    fn test_decode_hex_valid_uppercase() {
        let result = decode_hex("4500003C").unwrap();
        assert_eq!(result, vec![0x45, 0x00, 0x00, 0x3c]);
    }

    #[test]
    fn test_decode_hex_valid_mixed_case() {
        let result = decode_hex("45aB00Cc").unwrap();
        assert_eq!(result, vec![0x45, 0xAB, 0x00, 0xCC]);
    }

    #[test]
    fn test_decode_hex_with_whitespace() {
        let result = decode_hex("45 00 00 3c").unwrap();
        assert_eq!(result, vec![0x45, 0x00, 0x00, 0x3c]);
    }

    #[test]
    fn test_decode_hex_with_newlines() {
        let result = decode_hex("4500\n003c").unwrap();
        assert_eq!(result, vec![0x45, 0x00, 0x00, 0x3c]);
    }

    #[test]
    fn test_decode_hex_odd_length() {
        let result = decode_hex("45000");  // 5 characters = odd
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("even number"));
    }

    #[test]
    fn test_decode_hex_invalid_character() {
        let result = decode_hex("45GG003c");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid hex character"));
    }

    #[test]
    fn test_decode_hex_special_characters() {
        let result = decode_hex("45!!003c");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_hex_empty_string() {
        let result = decode_hex("").unwrap();
        assert_eq!(result, vec![]);
    }

    // ===== hex_value tests =====

    #[test]
    fn test_hex_value_digits() {
        assert_eq!(hex_value(b'0').unwrap(), 0);
        assert_eq!(hex_value(b'5').unwrap(), 5);
        assert_eq!(hex_value(b'9').unwrap(), 9);
    }

    #[test]
    fn test_hex_value_lowercase() {
        assert_eq!(hex_value(b'a').unwrap(), 10);
        assert_eq!(hex_value(b'f').unwrap(), 15);
    }

    #[test]
    fn test_hex_value_uppercase() {
        assert_eq!(hex_value(b'A').unwrap(), 10);
        assert_eq!(hex_value(b'F').unwrap(), 15);
    }

    #[test]
    fn test_hex_value_invalid() {
        assert!(hex_value(b'G').is_err());
        assert!(hex_value(b'!').is_err());
        assert!(hex_value(b' ').is_err());
    }

    // ===== protocol_name tests =====

    #[test]
    fn test_protocol_name_icmp() {
        assert_eq!(protocol_name(1), "ICMP");
    }

    #[test]
    fn test_protocol_name_tcp() {
        assert_eq!(protocol_name(6), "TCP");
    }

    #[test]
    fn test_protocol_name_udp() {
        assert_eq!(protocol_name(17), "UDP");
    }

    #[test]
    fn test_protocol_name_icmpv6() {
        assert_eq!(protocol_name(58), "ICMPv6");
    }

    #[test]
    fn test_protocol_name_unknown() {
        assert_eq!(protocol_name(99), "OTHER");
        assert_eq!(protocol_name(255), "OTHER");
    }

    // ===== parse_transport tests =====

    #[test]
    fn test_parse_transport_tcp() {
        let payload = vec![0x00, 0x50, 0x1F, 0x90]; // port 80 -> 8080
        let result = parse_transport(&payload, 6).unwrap();
        assert!(result.contains("TCP"));
        assert!(result.contains("80 -> 8080"));
    }

    #[test]
    fn test_parse_transport_udp() {
        let payload = vec![0x00, 0x35, 0x00, 0x35]; // port 53 -> 53
        let result = parse_transport(&payload, 17).unwrap();
        assert!(result.contains("UDP"));
        assert!(result.contains("53 -> 53"));
    }

    #[test]
    fn test_parse_transport_icmp() {
        let payload = vec![0x08, 0x00]; // echo request, code 0
        let result = parse_transport(&payload, 1).unwrap();
        assert!(result.contains("ICMP"));
        assert!(result.contains("type 8 code 0"));
    }

    #[test]
    fn test_parse_transport_icmpv6() {
        let payload = vec![0x80, 0x00]; // echo request, code 0
        let result = parse_transport(&payload, 58).unwrap();
        assert!(result.contains("ICMPv6"));
        assert!(result.contains("type 128 code 0"));
    }

    #[test]
    fn test_parse_transport_tcp_insufficient_data() {
        let payload = vec![0x00, 0x50]; // only 2 bytes
        let result = parse_transport(&payload, 6);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_transport_udp_insufficient_data() {
        let payload = vec![0x00]; // only 1 byte
        let result = parse_transport(&payload, 17);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_transport_unknown_protocol() {
        let payload = vec![0x00, 0x50, 0x1F, 0x90];
        let result = parse_transport(&payload, 99);
        assert!(result.is_none());
    }

    // ===== parse_packet tests =====

    #[test]
    fn test_parse_packet_empty() {
        let bytes: Vec<u8> = vec![];
        let response = parse_packet(&bytes);
        assert_eq!(response.format, "empty");
        assert_eq!(response.packet_length, 0);
        assert!(response.details.notes.is_some());
    }

    #[test]
    fn test_parse_packet_ipv4_version() {
        // IPv4 packet starts with version 4
        let bytes = vec![0x45, 0x00, 0x00, 0x3c];
        let response = parse_packet(&bytes);
        assert_eq!(response.details.version, Some(4));
    }

    #[test]
    fn test_parse_packet_ipv6_version() {
        // IPv6 packet starts with version 6
        let bytes = vec![0x60, 0x00, 0x00, 0x00];
        let response = parse_packet(&bytes);
        assert_eq!(response.details.version, Some(6));
    }

    #[test]
    fn test_parse_packet_unknown_version() {
        // Unknown version
        let bytes = vec![0xF5, 0x00, 0x00, 0x00];
        let response = parse_packet(&bytes);
        assert_eq!(response.format, "unknown");
        assert_eq!(response.details.version, Some(15));
    }

    // ===== parse_ipv4_packet tests =====

    #[test]
    fn test_parse_ipv4_valid_packet() {
        // Minimal valid IPv4 header (20 bytes)
        let bytes = vec![
            0x45, 0x00, 0x00, 0x1c, // version, IHL, DSCP, total length
            0x00, 0x01, 0x00, 0x00, // ID, flags, fragment offset
            0x40, 0x06, 0x00, 0x00, // TTL, protocol (TCP), checksum
            0xc0, 0xa8, 0x00, 0x01, // source: 192.168.0.1
            0xc0, 0xa8, 0x00, 0x02, // dest: 192.168.0.2
        ];
        let response = parse_ipv4_packet(&bytes, 20, PacketDetails::default());
        assert_eq!(response.format, "ipv4");
        assert_eq!(response.packet_length, 20);
        assert_eq!(response.details.protocol, Some("TCP".to_string()));
        assert_eq!(response.details.source, Some("192.168.0.1".to_string()));
        assert_eq!(response.details.destination, Some("192.168.0.2".to_string()));
    }

    #[test]
    fn test_parse_ipv4_truncated() {
        // Less than 20 bytes
        let bytes = vec![0x45, 0x00, 0x00, 0x0c];
        let response = parse_ipv4_packet(&bytes, 4, PacketDetails::default());
        assert_eq!(response.format, "ipv4");
        assert!(response.details.notes.is_some());
        assert!(response.details.notes.as_ref().unwrap().contains("too short"));
    }

    #[test]
    fn test_parse_ipv4_protocol_udp() {
        // IPv4 with UDP protocol (17)
        let bytes = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
            0x40, 0x11, 0x00, 0x00, // protocol = 17 (UDP)
            0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02,
        ];
        let response = parse_ipv4_packet(&bytes, 20, PacketDetails::default());
        assert_eq!(response.details.protocol, Some("UDP".to_string()));
    }

    #[test]
    fn test_parse_ipv4_protocol_icmp() {
        // IPv4 with ICMP protocol (1)
        let bytes = vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00,
            0x40, 0x01, 0x00, 0x00, // protocol = 1 (ICMP)
            0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02,
        ];
        let response = parse_ipv4_packet(&bytes, 20, PacketDetails::default());
        assert_eq!(response.details.protocol, Some("ICMP".to_string()));
    }

    // ===== parse_ipv6_packet tests =====

    #[test]
    fn test_parse_ipv6_valid_packet() {
        // Valid IPv6 header (40 bytes minimum)
        let mut bytes = vec![
            0x60, 0x00, 0x00, 0x00, // version, DSCP, ECN, flow label
            0x00, 0x00, 0x06, 0x40, // payload length, next header (TCP), hop limit
        ];
        // Add 32 bytes for source and destination addresses
        bytes.extend_from_slice(&[0xfe; 16]); // source
        bytes.extend_from_slice(&[0x20; 16]); // destination
        
        let response = parse_ipv6_packet(&bytes, 40, PacketDetails::default());
        assert_eq!(response.format, "ipv6");
        assert_eq!(response.details.protocol, Some("TCP".to_string()));
        assert_eq!(response.details.header_length, Some(40));
    }

    #[test]
    fn test_parse_ipv6_truncated() {
        // Less than 40 bytes
        let bytes = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x40];
        let response = parse_ipv6_packet(&bytes, 8, PacketDetails::default());
        assert_eq!(response.format, "ipv6");
        assert!(response.details.notes.is_some());
        assert!(response.details.notes.as_ref().unwrap().contains("too short"));
    }

    #[test]
    fn test_parse_ipv6_with_udp() {
        // IPv6 with UDP (next header = 17)
        let mut bytes = vec![
            0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x40, // next header = 17 (UDP)
        ];
        bytes.extend_from_slice(&[0xfe; 16]); // source
        bytes.extend_from_slice(&[0x20; 16]); // destination
        
        let response = parse_ipv6_packet(&bytes, 40, PacketDetails::default());
        assert_eq!(response.details.protocol, Some("UDP".to_string()));
    }

    // ===== integration tests =====

    #[test]
    fn test_end_to_end_ipv4_tcp_packet() {
        let hex = "4500001c000100004006000000000000c0a80001c0a80002";
        let bytes = decode_hex(hex).unwrap();
        let response = parse_packet(&bytes);
        
        assert_eq!(response.format, "ipv4");
        assert_eq!(response.details.protocol, Some("TCP".to_string()));
        assert!(response.summary.contains("IPv4 packet"));
    }

    #[test]
    fn test_end_to_end_empty_packet() {
        let hex = "";
        let bytes = decode_hex(hex).unwrap();
        let response = parse_packet(&bytes);
        
        assert_eq!(response.format, "empty");
        assert_eq!(response.packet_length, 0);
    }

    #[test]
    fn test_end_to_end_invalid_hex_then_error() {
        let hex = "45GG";
        let result = decode_hex(hex);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_end_to_end_ipv4_with_options() {
        // IPv4 with IHL = 6 (24 bytes header)
        let hex = "46000018000100004006c0a80001c0a800020000000000000000";
        let bytes = decode_hex(hex).unwrap();
        let response = parse_packet(&bytes);
        
        assert_eq!(response.format, "ipv4");
        assert_eq!(response.details.header_length, Some(24));
    }
}
