// Shardnet - Serverless peer-to-peer encrypted file storage and messaging
// Copyright (C) 2026 Anthony Clicheroux
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
use axum::{
    Router,
    extract::{
        Multipart,
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, patch, post},
};
use std::sync::atomic::Ordering;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::Deserialize;
use serde_json::json;
use std::{net::SocketAddr, path::Path};
use tokio::sync::broadcast::error::RecvError;
use tracing::warn;

use crate::config::ConfigFile;
use crate::context::Node;

static INDEX_HTML: &str = include_str!("gui/index.html");

// ── AppState ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub node: Node,
    pub storage_path: String,
    pub is_seed: bool,
}

// ── Router builder ────────────────────────────────────────────────────────────

pub fn build_app(node: Node, storage_path: String, is_seed: bool) -> Router {
    let state = AppState { node, storage_path, is_seed };
    Router::new()
        .route("/", get(index_handler))
        .route("/health", get(health_handler))
        .route("/ws", get(ws_handler))
        .route("/api/status", get(status_handler))
        .route("/api/peers", get(peers_handler))
        .route("/api/bootstrap", post(bootstrap_handler))
        .route("/api/chat/join", post(chat_join_handler))
        .route("/api/chat/leave", post(chat_leave_handler))
        .route("/api/chat/send", post(chat_send_handler))
        .route("/api/files/upload", post(upload_handler))
        .route("/api/files/download", post(download_handler))
        .route("/api/files/preview", post(preview_handler))
        .route("/api/config", patch(config_patch_handler))
        .route("/api/sleep", post(sleep_handler))
        .route("/api/wake", post(wake_handler))
        .route("/api/reconnect", post(reconnect_handler))
        .with_state(state)
}

// ── Return type helpers ───────────────────────────────────────────────────────

type ApiResult = std::result::Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)>;

fn api_err(status: StatusCode, msg: impl std::fmt::Display) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(json!({ "error": msg.to_string() })))
}

// ── Request body structs ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct BootstrapReq { addr: String }

#[derive(Deserialize)]
struct ConfigPatchReq {
    quota_bytes:          Option<u64>,
    retention_sec:        Option<u64>,
    cleanup_interval_sec: Option<u64>,
}

#[derive(Deserialize)]
struct JoinReq { room: String }

#[derive(Deserialize)]
struct SendReq { content: String }

#[derive(Deserialize)]
struct DownloadReq { magnet: String }

#[derive(Deserialize)]
struct PreviewReq { magnet: String }

// ── Static handlers ───────────────────────────────────────────────────────────

async fn index_handler() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(json!({ "ok": true }))
}

// ── GUI-004: status ───────────────────────────────────────────────────────────

async fn status_handler(State(state): State<AppState>) -> ApiResult {
    let node = &state.node;
    let node_id = hex::encode(node.id().0);
    let bound_addr = node.endpoint.local_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let peers_count = node.inner.routing_table.read().await.get_all_nodes().len();
    let in_room = node.inner.active_room.read().await.clone();
    let storage_used  = node.inner.storage.disk_used_bytes();
    let storage_max   = node.inner.storage.max_storage_bytes();
    let (retention_sec, cleanup_sec) = {
        let cfg = node.inner.storage_config.read().await;
        (cfg.retention_period_sec, cfg.cleanup_interval_sec)
    };
    Ok(Json(json!({
        "node_id":        node_id,
        "bound_addr":     bound_addr,
        "peers_count":    peers_count,
        "in_room":        in_room,
        "is_seed":        state.is_seed,
        "storage_path":   state.storage_path,
        "storage_used":   storage_used,
        "storage_max":    storage_max,
        "retention_sec":  retention_sec,
        "cleanup_sec":    cleanup_sec,
    })))
}

async fn peers_handler(State(state): State<AppState>) -> ApiResult {
    let peers: Vec<_> = state.node.inner.routing_table.read().await
        .get_all_nodes()
        .into_iter()
        .map(|n| json!({
            "addr": n.address.to_string(),
            "node_id": hex::encode(n.id.0),
        }))
        .collect();
    Ok(Json(json!(peers)))
}

// ── GUI-005: bootstrap ────────────────────────────────────────────────────────

async fn bootstrap_handler(
    State(state): State<AppState>,
    Json(req): Json<BootstrapReq>,
) -> ApiResult {
    let addr: SocketAddr = req.addr.parse()
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, e))?;

    // Refuse self-connection before attempting QUIC (gives a clear error instead
    // of a confusing "Failed to send packet" from the transport layer).
    if state.node.endpoint.local_addr().ok() == Some(addr) {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "cannot bootstrap to self — use a remote peer address",
        ));
    }

    state.node.bootstrap(addr).await
        .map_err(|e| api_err(StatusCode::SERVICE_UNAVAILABLE, e))?;
    let peers = state.node.inner.routing_table.read().await.get_all_nodes().len();
    Ok(Json(json!({ "connected": true, "peers": peers })))
}

// ── GUI-006: chat ─────────────────────────────────────────────────────────────

async fn chat_join_handler(
    State(state): State<AppState>,
    Json(req): Json<JoinReq>,
) -> ApiResult {
    state.node.join_room(req.room.clone()).await;
    Ok(Json(json!({ "joined": req.room })))
}

async fn chat_leave_handler(State(state): State<AppState>) -> ApiResult {
    state.node.leave_room().await;
    Ok(Json(json!({ "left": true })))
}

async fn chat_send_handler(
    State(state): State<AppState>,
    Json(req): Json<SendReq>,
) -> ApiResult {
    state.node.broadcast_chat(req.content).await
        .map_err(|e| api_err(StatusCode::SERVICE_UNAVAILABLE, e))?;
    Ok(Json(json!({ "sent": true })))
}

// ── GUI-007: files ────────────────────────────────────────────────────────────

async fn upload_handler(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> ApiResult {
    let mut tmp_path: Option<std::path::PathBuf> = None;

    while let Some(field) = multipart.next_field().await
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, e))?
    {
        if field.name() != Some("file") {
            continue;
        }

        let safe_name = field.file_name()
            .and_then(|n| Path::new(n).file_name())
            .and_then(|n| n.to_str())
            .map(|n| n.to_string())
            .unwrap_or_else(|| "upload".to_string());

        let data = field.bytes().await
            .map_err(|e| api_err(StatusCode::BAD_REQUEST, e))?;

        let mut rng_bytes = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut rng_bytes);
        let tmp = std::env::temp_dir()
            .join(format!("shard_{}_{}", hex::encode(rng_bytes), safe_name));

        std::fs::write(&tmp, &data)
            .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, e))?;

        tmp_path = Some(tmp);
        break;
    }

    let path = tmp_path
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "missing 'file' field"))?;
    let path_str = path.to_str().unwrap_or_default().to_string();

    let result = state.node.send_file_stream(&path_str).await;
    let _ = std::fs::remove_file(&path);

    let (fid, key) = result.map_err(|e| api_err(StatusCode::SERVICE_UNAVAILABLE, e))?;

    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&fid);
    combined.extend_from_slice(&key);
    let magnet = BASE64_URL_SAFE_NO_PAD.encode(&combined);

    Ok(Json(json!({ "magnet": magnet })))
}

async fn download_handler(
    State(state): State<AppState>,
    Json(req): Json<DownloadReq>,
) -> ApiResult {
    let combined = BASE64_URL_SAFE_NO_PAD.decode(&req.magnet)
        .map_err(|_| api_err(StatusCode::BAD_REQUEST, "invalid magnet link"))?;
    if combined.len() != 64 {
        return Err(api_err(StatusCode::BAD_REQUEST, "invalid magnet link (expected 64-byte key)"));
    }

    let mut fid = [0u8; 32];
    let mut key = [0u8; 32];
    fid.copy_from_slice(&combined[0..32]);
    key.copy_from_slice(&combined[32..64]);

    let out_dir = Path::new(&state.storage_path).join("downloads");
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let out_str = out_dir.to_str().unwrap_or(".").to_string();

    state.node.fetch_file_stream(fid, key, &out_str).await
        .map_err(|e| api_err(StatusCode::SERVICE_UNAVAILABLE, e))?;

    Ok(Json(json!({ "path": out_str })))
}

// ── GUI-BRW-01: markdown preview ─────────────────────────────────────────────

const PREVIEW_SIZE_LIMIT: u64 = 512 * 1024; // 512 KB

async fn preview_handler(
    State(state): State<AppState>,
    Json(req): Json<PreviewReq>,
) -> ApiResult {
    let combined = BASE64_URL_SAFE_NO_PAD.decode(&req.magnet)
        .map_err(|_| api_err(StatusCode::BAD_REQUEST, "invalid magnet"))?;
    if combined.len() != 64 {
        return Err(api_err(StatusCode::BAD_REQUEST, "invalid magnet (expected 64 bytes)"));
    }
    let mut fid = [0u8; 32];
    let mut key = [0u8; 32];
    fid.copy_from_slice(&combined[0..32]);
    key.copy_from_slice(&combined[32..64]);

    let mut rng_bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut rng_bytes);
    let tmp_dir = std::env::temp_dir()
        .join(format!("shard_preview_{}", hex::encode(rng_bytes)));
    std::fs::create_dir_all(&tmp_dir)
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let out = tmp_dir.to_str().unwrap_or(".").to_string();
    let fetch = state.node.fetch_file_stream(fid, key, &out).await;

    let result = (|| {
        fetch.map_err(|e| api_err(StatusCode::SERVICE_UNAVAILABLE, e))?;

        let entry = std::fs::read_dir(tmp_dir.join("downloads"))
            .ok().and_then(|mut d| d.next()).and_then(|e| e.ok())
            .ok_or_else(|| api_err(StatusCode::INTERNAL_SERVER_ERROR, "download produced no file"))?;

        let path = entry.path();
        let ext = path.extension()
            .and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        if ext != "md" && ext != "markdown" {
            return Err(api_err(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                format!("not a markdown file (.{ext})")
            ));
        }

        let size = std::fs::metadata(&path)
            .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, e))?.len();
        if size > PREVIEW_SIZE_LIMIT {
            return Err(api_err(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("file exceeds 512 KB ({size} bytes)")
            ));
        }

        let content = std::fs::read_to_string(&path)
            .map_err(|_| api_err(StatusCode::UNPROCESSABLE_ENTITY, "content is not valid UTF-8"))?;

        Ok(Json(json!({ "content": content })))
    })();

    let _ = std::fs::remove_dir_all(&tmp_dir);
    result
}

// ── MOB-021: sleep / wake ─────────────────────────────────────────────────────

async fn sleep_handler(State(state): State<AppState>) -> ApiResult {
    state.node.inner.sleeping.store(true, Ordering::Relaxed);
    Ok(Json(json!({ "sleeping": true })))
}

async fn wake_handler(State(state): State<AppState>) -> ApiResult {
    state.node.inner.sleeping.store(false, Ordering::Relaxed);
    Ok(Json(json!({ "sleeping": false })))
}

// ── MOB-023: reconnect after network change ───────────────────────────────────

async fn reconnect_handler(State(state): State<AppState>) -> ApiResult {
    let node_id = state.node.id();
    state.node.iterative_lookup(node_id, 3).await;
    Ok(Json(json!({ "reconnecting": true })))
}

// ── CORE-003: runtime config patch ───────────────────────────────────────────

async fn config_patch_handler(
    State(state): State<AppState>,
    Json(req): Json<ConfigPatchReq>,
) -> ApiResult {
    const MIN_QUOTA:   u64 = 10_000_000; // 10 MB
    const MIN_RET:     u64 = 3_600;      // 1 hour
    const MIN_CLEANUP: u64 = 60;         // 1 minute

    if req.quota_bytes.map_or(false,          |v| v < MIN_QUOTA)   {
        return Err(api_err(StatusCode::BAD_REQUEST, "quota_bytes must be ≥ 10 000 000 (10 MB)"));
    }
    if req.retention_sec.map_or(false,        |v| v < MIN_RET)     {
        return Err(api_err(StatusCode::BAD_REQUEST, "retention_sec must be ≥ 3600 (1 hour)"));
    }
    if req.cleanup_interval_sec.map_or(false, |v| v < MIN_CLEANUP) {
        return Err(api_err(StatusCode::BAD_REQUEST, "cleanup_interval_sec must be ≥ 60 (1 minute)"));
    }

    let node = &state.node;

    // Apply live
    if let Some(q) = req.quota_bytes {
        node.inner.storage.set_max_storage_bytes(q);
    }
    {
        let mut cfg = node.inner.storage_config.write().await;
        if let Some(q) = req.quota_bytes          { cfg.max_storage_bytes    = q; }
        if let Some(r) = req.retention_sec        { cfg.retention_period_sec = r; }
        if let Some(c) = req.cleanup_interval_sec { cfg.cleanup_interval_sec = c; }
    }

    // Persist to config.toml
    let config_path = std::path::Path::new(&state.storage_path).join("config.toml");
    let updated_storage = node.inner.storage_config.read().await.clone();
    let file_config = ConfigFile {
        network: node.inner.config.network.clone(),
        storage: updated_storage,
        mining:  node.inner.config.mining.clone(),
    };
    let toml_str = toml::to_string_pretty(&file_config)
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    std::fs::write(&config_path, toml_str)
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(json!({ "ok": true })))
}

// ── WebSocket ─────────────────────────────────────────────────────────────────

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state.node))
}

async fn handle_socket(mut socket: WebSocket, node: Node) {
    let mut rx = node.subscribe();
    loop {
        tokio::select! {
            incoming = socket.recv() => {
                match incoming {
                    None | Some(Ok(Message::Close(_))) => break,
                    Some(Err(_)) => break,
                    Some(Ok(Message::Ping(d))) => { let _ = socket.send(Message::Pong(d)).await; }
                    _ => {} // Text pings and other frames are ignored
                }
            }
            result = rx.recv() => {
                match result {
                    Ok(event) => {
                        match serde_json::to_string(&event) {
                            Ok(json) => {
                                if socket.send(Message::Text(json)).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => warn!("WS: failed to serialise event: {}", e),
                        }
                    }
                    Err(RecvError::Lagged(n)) => warn!("WS client lagged {} event(s)", n),
                    Err(RecvError::Closed) => break,
                }
            }
        }
    }
}
