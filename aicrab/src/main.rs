use axum::{
    extract::Json,
    http::StatusCode,
    routing::{get, post},
    serve,
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::TcpListener;

#[derive(Deserialize)]
struct PacketAnalysisRequest {
    packet_hex: String,
}

#[derive(Serialize)]
struct PacketAnalysisResponse {
    format: String,
    summary: String,
    packet_length: usize,
    details: PacketDetails,
}

#[derive(Serialize, Default)]
struct PacketDetails {
    version: Option<u8>,
    header_length: Option<u8>,
    total_length: Option<u16>,
    protocol: Option<String>,
    source: Option<String>,
    destination: Option<String>,
    transport: Option<String>,
    notes: Option<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root))
        .route("/analyze", post(analyze_packet));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Listening on http://{}", addr);

    let listener = TcpListener::bind(addr)
        .await
        .expect("failed to bind address");

    serve(listener, app)
        .await
        .expect("failed to start server");
}

async fn root() -> &'static str {
    "POST JSON to /analyze with { \"packet_hex\": \"...\" }"
}

async fn analyze_packet(
    Json(payload): Json<PacketAnalysisRequest>,
) -> Result<Json<PacketAnalysisResponse>, (StatusCode, Json<ErrorResponse>)> {
    match decode_hex(&payload.packet_hex) {
        Ok(bytes) => Ok(Json(parse_packet(&bytes))),
        Err(err) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: err }),
        )),
    }
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
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

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex character: {}", byte as char)),
    }
}

fn parse_packet(bytes: &[u8]) -> PacketAnalysisResponse {
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

fn parse_ipv4_packet(
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

fn parse_ipv6_packet(
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

fn protocol_name(protocol: u8) -> &'static str {
    match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "OTHER",
    }
}

fn parse_transport(payload: &[u8], protocol: u8) -> Option<String> {
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
