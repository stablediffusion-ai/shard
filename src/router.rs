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
use std::time::Duration;
use tracing::debug;
use tokio::time::sleep;

use crate::context::Node;
use crate::packet::DspPacket;
use crate::dht::NodeId;
use crate::error::{Result, ShardError};
use crate::transport;

pub async fn send_packet(node: &Node, packet: DspPacket, target: SocketAddr, target_id: Option<NodeId>) -> Result<()> {
    let serialized_data = packet.serialize()?;
    
    // We rely on Transport's increased timeout (10s) to handle the handshake retries.
    // We do NOT remove the connection on failure here to prevent Port Shifting.
    let conn_result = transport::get_or_connect(node, target, target_id).await;

    match conn_result {
        Ok(connection) => {
            match connection.open_uni().await {
                Ok(mut stream) => {
                    if let Err(e) = stream.write_all(&serialized_data).await {
                        debug!("Write failed to {}: {}", target, e);
                    } else {
                        if let Err(e) = stream.finish() {
                            debug!("Finish stream failed to {}: {}", target, e);
                        } else {
                            return Ok(());
                        }
                    }
                },
                Err(_e) => {
                    // debug!("Open stream failed to {}: {}", target, _e);
                }
            }
        },
        Err(_) => {
            // debug!("Connection failed to {}", target);
        }
    }

    // Do NOT remove the connection here. 
    // Let the background maintenance task clean up truly dead peers.
    Err(ShardError::Network(format!("Failed to send packet to {}", target)))
}

pub async fn send_packet_reliable(node: &Node, packet: DspPacket, target: SocketAddr, target_id: Option<NodeId>) -> Result<()> {
    // 1. FAST PATH: Try Direct Send (Short Timeout)
    // If connection exists and is open, this works instantly.
    let direct_result = tokio::time::timeout(
        Duration::from_millis(500), 
        send_packet(node, packet.clone(), target, target_id)
    ).await;

    match direct_result {
        Ok(Ok(_)) => return Ok(()),
        Ok(Err(_)) => {}, 
        Err(_) => {}, // Timeout
    }

    debug!("Direct send failed to {}. Initiating Hole Punch strategy...", target);

    // 2. STRATEGY: Simultaneous Open (Hole Punching)
    if let Some(tid) = target_id {
        let closest_nodes = node.inner.routing_table.read().await.find_closest_nodes(&tid, crate::dht::K_PARAM);
        
        let relays: Vec<&crate::dht::Node> = closest_nodes.iter()
            .filter(|n| !transport::is_same_node(n.address, target))
            .take(3)
            .collect();

        if relays.is_empty() {
            debug!("No relays found for {}", target);
            return Err(ShardError::Network("No relays available".to_string()));
        }

        // A. START LOCAL PUNCH (Simultaneous Open)
        // Each attempt is bounded to 800ms to avoid the internal QUIC timeout
        // of get_or_connect (10s) blocking 5×10s = 50s+.
        let node_clone = node.clone();
        let packet_clone = packet.clone();
        let tid_clone = Some(tid);

        let punch_task = tokio::spawn(async move {
            for _ in 0..5 {
                let attempt = tokio::time::timeout(
                    Duration::from_millis(800),
                    send_packet(&node_clone, packet_clone.clone(), target, tid_clone),
                ).await;
                if let Ok(Ok(_)) = attempt {
                    debug!("Hole punch delivery success to {}", target);
                    return true;
                }
                sleep(Duration::from_millis(200)).await;
            }
            false
        });

        // B. SIGNAL RELAYS (Parallel)
        for relay in &relays {
            let relay_addr = transport::resolve_peer_addr(node, relay).await;
            let _ = initiate_nat_punch(node, tid, relay_addr).await;
        }

        if let Ok(true) = punch_task.await {
            return Ok(());
        }

        // Short window to let the handshake complete on the relay side
        sleep(Duration::from_millis(500)).await;

        // Check if connection was established
        {
            let conns = node.inner.connections.read().await;
            if let Some(conn) = conns.get(&target) {
                if conn.close_reason().is_none() {
                    return Ok(());
                }
            }
        }

        // 3. FALLBACK: Relay Tunneling
        debug!("NAT Punch failed. Tunneling data via relays...");
        for relay in &relays {
            let relay_addr = transport::resolve_peer_addr(node, relay).await;
            if send_via_relay(node, packet.clone(), tid, relay_addr).await.is_ok() {
                debug!("Relayed delivery success via {}", relay_addr);
                return Ok(());
            }
        }
    }
    
    // Clean up only on total failure
    node.remove_peer(target).await;
    Err(ShardError::Network(format!("Reliable delivery failed to {}", target)))
}

async fn initiate_nat_punch(node: &Node, target_id: NodeId, relay_addr: SocketAddr) -> Result<()> {
    let local_hint = *node.inner.public_address.read().await;

    let payload = bincode::serialize(&crate::packet::NatPunchReqPayload {
        target_id: target_id.0.to_vec(),
        local_hint,
    })?;
    let pkt = DspPacket::new(crate::packet::PacketType::NatPunchRequest, 0, 0, payload);
    
    send_packet(node, pkt, relay_addr, None).await
}

async fn send_via_relay(node: &Node, packet: DspPacket, target_id: NodeId, relay_addr: SocketAddr) -> Result<()> {
    let inner_data = packet.serialize()?;
    let payload = bincode::serialize(&crate::packet::RelayPayload {
        target_id: target_id.0.to_vec(),
        inner_packet: inner_data,
        ttl: 3,
    })?;
    let wrapper = DspPacket::new(crate::packet::PacketType::RelayData, 0, 0, payload);
    send_packet(node, wrapper, relay_addr, None).await
}
