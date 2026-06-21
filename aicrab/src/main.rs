use axum::{
    extract::Json,
    http::StatusCode,
    routing::{get, post},
    serve,
    Router,
};
use aicrab::{decode_hex, parse_packet, PacketAnalysisRequest, PacketAnalysisResponse};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[derive(serde::Serialize)]
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
