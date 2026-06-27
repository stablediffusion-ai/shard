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

use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use tempfile::TempDir;
use tokio::time::{timeout, Duration};

use shard::context::Node;
use shard::handlers::handle_chat_message;
use shard::packet::{ChatMessage, DspPacket, PacketType};
use shard::{ShardConfig, ShardEvent};

// ── helpers ──────────────────────────────────────────────────────────────────

async fn make_test_node(tmp: &TempDir) -> Node {
    // The CLI creates sys/ before Node::new; reproduce that here.
    std::fs::create_dir_all(tmp.path().join("sys")).unwrap();

    let mut config = ShardConfig::load_or_create(tmp.path().to_str().unwrap()).unwrap();
    // 1-bit difficulty: ~2 Argon2id hashes on average — fast enough for tests.
    config.mining.difficulty = 1;

    Node::new(config, "127.0.0.1:0", tmp.path().to_str().unwrap(), "")
        .await
        .unwrap()
}

fn signed_packet(key: &SigningKey, room: &str, sender_id: &str, content: &str, nonce: u64) -> DspPacket {
    let mut to_sign = Vec::new();
    to_sign.extend_from_slice(room.as_bytes());
    to_sign.extend_from_slice(sender_id.as_bytes());
    to_sign.extend_from_slice(&nonce.to_le_bytes());
    to_sign.extend_from_slice(content.as_bytes());

    let msg = ChatMessage {
        room_name: room.to_string(),
        sender_id: sender_id.to_string(),
        content: content.to_string(),
        nonce,
        sender_pubkey: key.verifying_key().to_bytes().to_vec(),
        signature: key.sign(&to_sign).to_bytes().to_vec(),
    };

    DspPacket::new(PacketType::ChatMessage, 0, 0, bincode::serialize(&msg).unwrap())
}

const DUMMY_SRC: &str = "127.0.0.1:9999";

fn src() -> SocketAddr {
    DUMMY_SRC.parse().unwrap()
}

// ── SEC-003 unit: sign/verify roundtrip (no Node required) ───────────────────

#[test]
fn sign_verify_roundtrip() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key = {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        SigningKey::from_bytes(&secret)
    };
    let room = "general";
    let sender_id = "aabbccdd";
    let content = "hello world";
    let nonce: u64 = 1;

    let mut to_sign = Vec::new();
    to_sign.extend_from_slice(room.as_bytes());
    to_sign.extend_from_slice(sender_id.as_bytes());
    to_sign.extend_from_slice(&nonce.to_le_bytes());
    to_sign.extend_from_slice(content.as_bytes());
    let sig = key.sign(&to_sign);

    let pubkey_bytes: [u8; 32] = key.verifying_key().to_bytes();
    let vk = VerifyingKey::from_bytes(&pubkey_bytes).unwrap();
    let signature = Signature::from_bytes(&sig.to_bytes());

    assert!(vk.verify(&to_sign, &signature).is_ok(), "valid signature must verify");
}

// ── integration tests (async, real Node) ─────────────────────────────────────

#[tokio::test]
async fn valid_message_emits_event() {
    let tmp = TempDir::new().unwrap();
    let node = make_test_node(&tmp).await;
    node.join_room("general".to_string()).await;

    let mut rx = node.subscribe();
    let key = {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        SigningKey::from_bytes(&secret)
    };
    let pkt = signed_packet(&key, "general", "aabbccdd", "hello", 1);

    handle_chat_message(&node, pkt, src()).await;

    let event = timeout(Duration::from_millis(200), rx.recv())
        .await
        .expect("event must arrive within 200 ms")
        .expect("broadcast channel must not close");

    match event {
        ShardEvent::ChatMessage { room, content, .. } => {
            assert_eq!(room, "general");
            assert_eq!(content, "hello");
        }
        other => panic!("unexpected event variant: {:?}", other),
    }
}

#[tokio::test]
async fn tampered_content_dropped() {
    let tmp = TempDir::new().unwrap();
    let node = make_test_node(&tmp).await;
    node.join_room("general".to_string()).await;

    let mut rx = node.subscribe();
    let key = {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        SigningKey::from_bytes(&secret)
    };

    // Build a packet signed over "hello", then swap the content field.
    let mut to_sign = Vec::new();
    to_sign.extend_from_slice("general".as_bytes());
    to_sign.extend_from_slice("aabbccdd".as_bytes());
    to_sign.extend_from_slice(&1u64.to_le_bytes());
    to_sign.extend_from_slice("hello".as_bytes());

    let tampered = ChatMessage {
        room_name: "general".to_string(),
        sender_id: "aabbccdd".to_string(),
        content: "INJECTED".to_string(), // not what was signed
        nonce: 1,
        sender_pubkey: key.verifying_key().to_bytes().to_vec(),
        signature: key.sign(&to_sign).to_bytes().to_vec(),
    };
    let pkt = DspPacket::new(PacketType::ChatMessage, 0, 0, bincode::serialize(&tampered).unwrap());

    handle_chat_message(&node, pkt, src()).await;

    assert!(
        timeout(Duration::from_millis(200), rx.recv()).await.is_err(),
        "tampered message must be dropped — no event should be emitted"
    );
}

#[tokio::test]
async fn tampered_sender_id_dropped() {
    let tmp = TempDir::new().unwrap();
    let node = make_test_node(&tmp).await;
    node.join_room("general".to_string()).await;

    let mut rx = node.subscribe();
    let key = {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        SigningKey::from_bytes(&secret)
    };

    // Sign as "alice", then claim to be "bob".
    let mut to_sign = Vec::new();
    to_sign.extend_from_slice("general".as_bytes());
    to_sign.extend_from_slice("alice".as_bytes()); // actual signer
    to_sign.extend_from_slice(&1u64.to_le_bytes());
    to_sign.extend_from_slice("hello".as_bytes());

    let tampered = ChatMessage {
        room_name: "general".to_string(),
        sender_id: "bob".to_string(), // impersonation attempt
        content: "hello".to_string(),
        nonce: 1,
        sender_pubkey: key.verifying_key().to_bytes().to_vec(),
        signature: key.sign(&to_sign).to_bytes().to_vec(),
    };
    let pkt = DspPacket::new(PacketType::ChatMessage, 0, 0, bincode::serialize(&tampered).unwrap());

    handle_chat_message(&node, pkt, src()).await;

    assert!(
        timeout(Duration::from_millis(200), rx.recv()).await.is_err(),
        "impersonation attempt must be dropped — sender_id is part of the signed payload"
    );
}

#[tokio::test]
async fn message_for_different_room_not_emitted() {
    let tmp = TempDir::new().unwrap();
    let node = make_test_node(&tmp).await;
    node.join_room("general".to_string()).await;

    let mut rx = node.subscribe();
    let key = {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        SigningKey::from_bytes(&secret)
    };
    // Valid signature, but for a room the node is not in.
    let pkt = signed_packet(&key, "other-room", "aabbccdd", "hello", 1);

    handle_chat_message(&node, pkt, src()).await;

    assert!(
        timeout(Duration::from_millis(200), rx.recv()).await.is_err(),
        "message for a room we are not in must not emit an event"
    );
}
