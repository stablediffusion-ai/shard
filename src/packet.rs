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
use serde::{Serialize, Deserialize};
use std::net::SocketAddr;
use crate::context::MAX_PACKET_SIZE;

pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketType {
    Fragment = 1,
    FragmentRequest = 2,
    DhtQuery = 3,
    DhtResponse = 4,
    ChatMessage = 7,
    // --- NAT TRAVERSAL & RELAY EXTENSIONS ---
    StunRequest = 10,           // "Who am I?"
    StunResponse = 11,          // "You are IP:Port"
    NatPunchRequest = 12,       // Initiator asks Relay to coordinate connection
    NatPunchRendezvous = 13,    // Relay triggers Simultaneous Open on both peers
    KeepAlive = 14,             // Heartbeat to keep NAT mapping active
    RelayData = 15,             // Fallback: Data wrapped to be forwarded via DHT
}

impl PacketType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(PacketType::Fragment),
            2 => Some(PacketType::FragmentRequest),
            3 => Some(PacketType::DhtQuery),
            4 => Some(PacketType::DhtResponse),
            7 => Some(PacketType::ChatMessage),
            10 => Some(PacketType::StunRequest),
            11 => Some(PacketType::StunResponse),
            12 => Some(PacketType::NatPunchRequest),
            13 => Some(PacketType::NatPunchRendezvous),
            14 => Some(PacketType::KeepAlive),
            15 => Some(PacketType::RelayData),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DspPacket {
    pub msg_type: PacketType,
    pub version: u8,
    pub reserved: u16,
    pub payload: Vec<u8>,
}

impl DspPacket {
    pub fn new(msg_type: PacketType, version: u8, reserved: u16, payload: Vec<u8>) -> Self {
        Self {
            msg_type,
            version,
            reserved,
            payload,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, std::io::Error> {
        // Header format: [Type:1][Ver:1][Res:2][Len:4] = 8 bytes
        let mut bytes = Vec::with_capacity(8 + self.payload.len());
        bytes.push(self.msg_type as u8);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.reserved.to_le_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, std::io::Error> {
        // 1. Basic header size check
        if data.len() < 8 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Packet too short for header"));
        }

        let msg_type = PacketType::from_u8(data[0])
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid packet type"))?;

        let version = data[1];
        if version > PROTOCOL_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unsupported protocol version {}; max supported is {}", version, PROTOCOL_VERSION),
            ));
        }
        
        // unwrap is safe here because we checked data.len() >= 8
        let reserved_bytes: [u8; 2] = data[2..4].try_into().unwrap();
        let reserved = u16::from_le_bytes(reserved_bytes);

        let len_bytes: [u8; 4] = data[4..8].try_into().unwrap();
        let payload_len = u32::from_le_bytes(len_bytes) as usize;

        // 2. [SECURITY] Protocol Limit Check (DoS Prevention)
        // Prevent allocation of massive buffers from malicious headers
        if payload_len > MAX_PACKET_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData, 
                format!("Payload size {} exceeds protocol limit {}", payload_len, MAX_PACKET_SIZE)
            ));
        }

        // 3. [SECURITY] Buffer Bounds Check
        // Ensure the buffer actually contains the data claimed in the header
        // Use checked_add to prevent integer overflow on 32-bit systems
        let expected_total_size = 8usize.checked_add(payload_len)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Size overflow"))?;

        if data.len() < expected_total_size {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Buffer shorter than declared payload"));
        }

        // Safe allocation after validation
        let payload = data[8..expected_total_size].to_vec();

        Ok(Self {
            msg_type,
            version,
            reserved,
            payload,
        })
    }
}

// --- PAYLOAD STRUCTURES ---

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChatMessage {
    pub room_name: String,
    pub sender_id: String,    // Hex-encoded node ID (for display)
    pub content: String,
    pub nonce: u64,           // Anti-loop deduplication
    pub sender_pubkey: Vec<u8>, // Raw 32-byte Ed25519 public key
    pub signature: Vec<u8>,    // 64-byte Ed25519 signature over (room || sender_id || nonce || content)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DhtQueryPayload {
    pub node_id: Vec<u8>,
    pub lan_address: Option<SocketAddr>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NatPunchReqPayload {
    pub target_id: Vec<u8>,
    pub local_hint: Option<SocketAddr>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RendezvousInfo {
    pub peer_id: Vec<u8>,
    pub peer_addr: SocketAddr, // Public IP
    pub peer_local_hint: Option<SocketAddr>, // LAN IP hint
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RelayPayload {
    pub target_id: Vec<u8>,
    pub inner_packet: Vec<u8>, // Serialized DspPacket
    pub ttl: u8,               // Max remaining hops; dropped when it reaches 0
}
