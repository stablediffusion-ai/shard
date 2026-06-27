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
//! GUI-013 — REST integration tests for the shard-gui HTTP API.
//!
//! Each test builds an in-process Router via `shard::gui_server::build_app`
//! and calls it with `tower::ServiceExt::oneshot` — no TCP socket needed.
//! Multiple sequential requests within a test clone the Router; because
//! `AppState::node` is `Arc<InnerNode>`, state mutations (room joins, etc.)
//! are shared across clones.

use axum::body::Body;
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

use shard::gui_server::build_app;
use shard::{ShardConfig, context::Node};

// ── Test helpers ──────────────────────────────────────────────────────────────

async fn make_node(tmp: &TempDir) -> Node {
    std::fs::create_dir_all(tmp.path().join("sys")).unwrap();
    let mut config = ShardConfig::load_or_create(tmp.path().to_str().unwrap()).unwrap();
    config.mining.difficulty = 1;
    Node::new(config, "127.0.0.1:0", tmp.path().to_str().unwrap(), "")
        .await
        .unwrap()
}

/// Issue a request and return (status, parsed JSON body).
async fn req(app: axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let resp = app.oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// GET /health → 200 {"ok": true}
#[tokio::test]
async fn health_ok() {
    let tmp = TempDir::new().unwrap();
    let app = build_app(make_node(&tmp).await, tmp.path().to_str().unwrap().to_string());

    let (status, json) = req(app, get("/health")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["ok"], true);
}

/// GET /api/status → 200 with required fields on a fresh node.
#[tokio::test]
async fn status_fields_present() {
    let tmp = TempDir::new().unwrap();
    let app = build_app(make_node(&tmp).await, tmp.path().to_str().unwrap().to_string());

    let (status, json) = req(app, get("/api/status")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["node_id"].is_string(), "node_id must be a string");
    assert!(!json["node_id"].as_str().unwrap().is_empty());
    assert!(json["bound_addr"].is_string(), "bound_addr must be a string");
    assert_eq!(json["peers_count"], 0, "no peers on a fresh node");
    assert_eq!(json["in_room"], Value::Null, "not in any room initially");
}

/// GET /api/peers → 200 empty array on a fresh node.
#[tokio::test]
async fn peers_empty_initially() {
    let tmp = TempDir::new().unwrap();
    let app = build_app(make_node(&tmp).await, tmp.path().to_str().unwrap().to_string());

    let (status, json) = req(app, get("/api/peers")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json, Value::Array(vec![]), "peer list must be empty");
}

/// POST /api/chat/join → 200 {"joined": <room>}; status reflects the new room.
#[tokio::test]
async fn chat_join_sets_room() {
    let tmp = TempDir::new().unwrap();
    let app = build_app(make_node(&tmp).await, tmp.path().to_str().unwrap().to_string());

    let (status, json) = req(app.clone(), post_json("/api/chat/join", r#"{"room":"general"}"#)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["joined"], "general");

    // Follow-up status must show the joined room.
    let (status2, json2) = req(app, get("/api/status")).await;
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(json2["in_room"], "general");
}

/// join → leave → status shows null room.
#[tokio::test]
async fn chat_leave_clears_room() {
    let tmp = TempDir::new().unwrap();
    let app = build_app(make_node(&tmp).await, tmp.path().to_str().unwrap().to_string());

    req(app.clone(), post_json("/api/chat/join", r#"{"room":"lobby"}"#)).await;

    let (status, json) = req(app.clone(), post_json("/api/chat/leave", "{}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["left"], true);

    let (_, status_json) = req(app, get("/api/status")).await;
    assert_eq!(status_json["in_room"], Value::Null);
}

/// POST /api/chat/send without joining a room → 503 with error message.
#[tokio::test]
async fn chat_send_without_room_is_error() {
    let tmp = TempDir::new().unwrap();
    let app = build_app(make_node(&tmp).await, tmp.path().to_str().unwrap().to_string());

    let (status, json) = req(app, post_json("/api/chat/send", r#"{"content":"hi"}"#)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(json["error"].is_string(), "must include error field");
    assert!(
        json["error"].as_str().unwrap().contains("room"),
        "error must mention 'room'"
    );
}

/// join room, then send → 200 {"sent": true}.
#[tokio::test]
async fn chat_send_in_room_succeeds() {
    let tmp = TempDir::new().unwrap();
    let app = build_app(make_node(&tmp).await, tmp.path().to_str().unwrap().to_string());

    req(app.clone(), post_json("/api/chat/join", r#"{"room":"general"}"#)).await;

    let (status, json) = req(app, post_json("/api/chat/send", r#"{"content":"hello"}"#)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["sent"], true);
}

/// POST /api/bootstrap with a malformed address → 400 Bad Request.
#[tokio::test]
async fn bootstrap_invalid_addr_is_bad_request() {
    let tmp = TempDir::new().unwrap();
    let app = build_app(make_node(&tmp).await, tmp.path().to_str().unwrap().to_string());

    let (status, json) = req(app, post_json("/api/bootstrap", r#"{"addr":"not::valid::addr"}"#)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json["error"].is_string());
}

/// POST /api/bootstrap with a valid but unreachable address → 503.
#[tokio::test]
async fn bootstrap_unreachable_addr_is_503() {
    let tmp = TempDir::new().unwrap();
    let app = build_app(make_node(&tmp).await, tmp.path().to_str().unwrap().to_string());

    // Port 1 is privileged and will be refused immediately.
    let (status, json) = req(app, post_json("/api/bootstrap", r#"{"addr":"127.0.0.1:1"}"#)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(json["error"].is_string());
}

/// POST /api/files/upload with no "file" field → 400 Bad Request.
#[tokio::test]
async fn upload_missing_file_field_is_bad_request() {
    let tmp = TempDir::new().unwrap();
    let app = build_app(make_node(&tmp).await, tmp.path().to_str().unwrap().to_string());

    let boundary = "boundaryx123";
    // Multipart with a field named "other", not "file"
    let body = format!(
        "--{b}\r\nContent-Disposition: form-data; name=\"other\"\r\n\r\nvalue\r\n--{b}--\r\n",
        b = boundary
    );
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/files/upload")
        .header("content-type", format!("multipart/form-data; boundary={}", boundary))
        .body(Body::from(body))
        .unwrap();

    let (status, json) = req(app, request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json["error"].as_str().unwrap_or("").contains("file"));
}

/// POST /api/files/download with a malformed magnet → 400 Bad Request.
#[tokio::test]
async fn download_invalid_magnet_is_bad_request() {
    let tmp = TempDir::new().unwrap();
    let app = build_app(make_node(&tmp).await, tmp.path().to_str().unwrap().to_string());

    let (status, json) = req(app, post_json("/api/files/download", r#"{"magnet":"notbase64!!!"}"#)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json["error"].is_string());
}
