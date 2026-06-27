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
use std::net::SocketAddr;
use tempfile::TempDir;
use tokio::time::{timeout, Duration};

use shard::context::Node;
use shard::{ShardConfig, ShardEvent};

// ── helpers ──────────────────────────────────────────────────────────────────

async fn make_test_node(tmp: &TempDir) -> Node {
    std::fs::create_dir_all(tmp.path().join("sys")).unwrap();
    let mut config = ShardConfig::load_or_create(tmp.path().to_str().unwrap()).unwrap();
    config.mining.difficulty = 1;
    Node::new(config, "127.0.0.1:0", tmp.path().to_str().unwrap(), "")
        .await
        .unwrap()
}

fn spawn_run(node: Node) {
    tokio::spawn(async move { let _ = node.run().await; });
}

// bootstrap A → B, return B's listen address for callers that need it
async fn connect(a: &Node, b: &Node) -> SocketAddr {
    let b_addr = b.endpoint.local_addr().unwrap();
    a.bootstrap(b_addr).await.unwrap();
    b_addr
}

// ── functional tests ─────────────────────────────────────────────────────────

/// Happy path: A broadcasts a signed message → B receives it as a ShardEvent.
///
/// This exercises the full wire path:
///   broadcast_chat → bincode serialize → QUIC stream → bincode deserialize
///   → Ed25519 verify → room check → ShardEvent::ChatMessage emitted.
#[tokio::test]
async fn a_broadcasts_b_receives() {
    let tmp_a = TempDir::new().unwrap();
    let tmp_b = TempDir::new().unwrap();
    let node_a = make_test_node(&tmp_a).await;
    let node_b = make_test_node(&tmp_b).await;

    spawn_run(node_a.clone());
    spawn_run(node_b.clone());

    // Subscribe before any traffic so we don't miss the event.
    let mut rx_b = node_b.subscribe();

    node_a.join_room("general".to_string()).await;
    node_b.join_room("general".to_string()).await;

    connect(&node_a, &node_b).await;

    node_a.broadcast_chat("hello from A".to_string()).await.unwrap();

    let event = timeout(Duration::from_secs(5), rx_b.recv())
        .await
        .expect("B must receive a ChatMessage event within 5 s")
        .expect("event channel must stay open");

    match event {
        ShardEvent::ChatMessage { room, content, .. } => {
            assert_eq!(room, "general");
            assert_eq!(content, "hello from A");
        }
        other => panic!("expected ChatMessage, got {:?}", other),
    }
}

/// B is in a different room: broadcast from A must not produce an event on B.
///
/// The packet still arrives (signature verifies), but the room-membership check
/// inside handle_chat_message should swallow it silently.
#[tokio::test]
async fn room_mismatch_no_event() {
    let tmp_a = TempDir::new().unwrap();
    let tmp_b = TempDir::new().unwrap();
    let node_a = make_test_node(&tmp_a).await;
    let node_b = make_test_node(&tmp_b).await;

    spawn_run(node_a.clone());
    spawn_run(node_b.clone());

    let mut rx_b = node_b.subscribe();

    node_a.join_room("general".to_string()).await;
    node_b.join_room("sports".to_string()).await; // different room

    connect(&node_a, &node_b).await;

    node_a.broadcast_chat("should not arrive on B".to_string()).await.unwrap();

    assert!(
        timeout(Duration::from_millis(500), rx_b.recv()).await.is_err(),
        "B must not emit an event for a message destined for a different room"
    );
}

/// B has not joined any room: broadcast from A must not produce an event on B.
#[tokio::test]
async fn node_without_room_no_event() {
    let tmp_a = TempDir::new().unwrap();
    let tmp_b = TempDir::new().unwrap();
    let node_a = make_test_node(&tmp_a).await;
    let node_b = make_test_node(&tmp_b).await;

    spawn_run(node_a.clone());
    spawn_run(node_b.clone());

    let mut rx_b = node_b.subscribe();

    node_a.join_room("general".to_string()).await;
    // node_b never calls join_room — active_room stays None

    connect(&node_a, &node_b).await;

    node_a.broadcast_chat("should not arrive on B".to_string()).await.unwrap();

    assert!(
        timeout(Duration::from_millis(500), rx_b.recv()).await.is_err(),
        "B must not emit an event when it has not joined any room"
    );
}
