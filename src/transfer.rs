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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Semaphore;
use sha2::{Sha256, Digest};
use rand::RngCore;
use tracing::{info, debug};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine}; 
use crate::events::ShardEvent;

use crate::context::Node;
use crate::dht::NodeId;
use crate::packet::{DspPacket, PacketType};
use crate::crypto::FileCipher;
use crate::sharding::ShardManager;
use crate::transport;
use crate::router;
use crate::error::{Result, ShardError};

const MAX_CONCURRENT_TRANSFERS: usize = 5;
const BLOCK_ALIGNMENT: u64 = 1024 * 1024;

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect()
}

fn align_size(size: u64) -> u64 {
    ((size + BLOCK_ALIGNMENT - 1) / BLOCK_ALIGNMENT) * BLOCK_ALIGNMENT
}

pub async fn send_file_stream(node: &Node, path: &str) -> Result<([u8; 32], [u8; 32])> {
    let mut file = tokio::fs::File::open(path).await?;
    let metadata = file.metadata().await?;
    let real_file_size = metadata.len();
    
    let filename = Path::new(path).file_name()
        .ok_or_else(|| ShardError::Storage("Invalid filename".to_string()))?
        .to_str()
        .ok_or_else(|| ShardError::Storage("Non-UTF8 filename".to_string()))?;
        
    let filename_bytes = filename.as_bytes();
    if filename_bytes.len() > 512 { return Err(ShardError::Storage("Filename too long".to_string())); }

    let name_len = (filename_bytes.len() as u16).to_le_bytes();
    let header_overhead = 8 + 2 + filename_bytes.len() as u64;
    let raw_data_size = header_overhead + real_file_size;
    let padded_total_size = align_size(raw_data_size);

    let master_key = FileCipher::generate_key();
    let mut file_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut file_id);

    let mut header_buffer = Vec::new();
    header_buffer.extend_from_slice(&real_file_size.to_le_bytes());
    header_buffer.extend_from_slice(&name_len);
    header_buffer.extend_from_slice(filename_bytes);

    let chunk_size = 1024 * 1024;
    let mut chunk_index: u32 = 0;
    let mut stream_cursor: u64 = 0;
    
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_TRANSFERS));
    let mut rng = rand::rngs::OsRng;

    debug!(file_id = %hex::encode(file_id), padded_size = padded_total_size, "Starting secure upload");

    loop {
        let mut buffer = vec![0u8; chunk_size];
        let mut buffer_pos = 0;

        if stream_cursor < header_buffer.len() as u64 {
            let rem = header_buffer.len() as u64 - stream_cursor;
            let to_copy = std::cmp::min(rem as usize, chunk_size);
            buffer[0..to_copy].copy_from_slice(&header_buffer[stream_cursor as usize..(stream_cursor as usize + to_copy)]);
            buffer_pos += to_copy;
            stream_cursor += to_copy as u64;
        }

        if buffer_pos < chunk_size && stream_cursor < raw_data_size {
            let needed = chunk_size - buffer_pos;
            let n = file.read(&mut buffer[buffer_pos..buffer_pos+needed]).await?;
            buffer_pos += n;
            stream_cursor += n as u64;
        }

        if buffer_pos < chunk_size && stream_cursor < padded_total_size {
            let needed = chunk_size - buffer_pos;
            rng.fill_bytes(&mut buffer[buffer_pos..buffer_pos+needed]);
            stream_cursor += needed as u64;
        } else {
            buffer.truncate(buffer_pos);
        }

        if buffer.is_empty() { break; }

        let (encrypted_chunk, nonce) = FileCipher::encrypt(&buffer, &master_key)
            .map_err(|e| ShardError::Crypto(e.to_string()))?;
            
        let payload_len = (nonce.len() + encrypted_chunk.len()) as u32;
        let mut payload_with_nonce = payload_len.to_le_bytes().to_vec();
        payload_with_nonce.extend(nonce);
        payload_with_nonce.extend(encrypted_chunk);

        let packets = ShardManager::shred_file(&payload_with_nonce, 10, 5)
            .map_err(|e| ShardError::Other(e.to_string()))?;

        // Warmup connections
        let mut target_peers = HashSet::new();
        let self_addr = node.endpoint.local_addr()?;
        
        for (shard_index, _) in packets.iter().enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(file_id);
            hasher.update(chunk_index.to_le_bytes());
            hasher.update((shard_index as u32).to_le_bytes());
            let target_hash = hasher.finalize();
            let target_node_id = NodeId::new(target_hash.into());
            
            let storage_nodes = node.inner.routing_table.read().await.find_closest_nodes(&target_node_id, crate::dht::K_PARAM);
            for peer in storage_nodes.iter().take(3) {
                 target_peers.insert(peer.clone());
            }
        }

        let mut warm_up_handles = Vec::new();
        for peer in target_peers {
            let n = node.clone();
            let s_addr = self_addr;
            warm_up_handles.push(tokio::spawn(async move {
                let resolved_addr = transport::resolve_peer_addr(&n, &peer).await;
                if transport::is_same_node(resolved_addr, s_addr) { return; }
                let _ = tokio::time::timeout(Duration::from_secs(2), 
                    transport::get_or_connect(&n, resolved_addr, Some(peer.id))
                ).await;
            }));
        }
        for handle in warm_up_handles { let _ = handle.await; }

        let mut tasks = Vec::new();
        let shard_confirmed = Arc::new(
            (0..packets.len()).map(|_| AtomicBool::new(false)).collect::<Vec<_>>()
        );

        for (shard_index, packet) in packets.iter().enumerate() {
            tokio::time::sleep(Duration::from_millis(5)).await;

            let mut hasher = Sha256::new();
            hasher.update(file_id);
            hasher.update(chunk_index.to_le_bytes());
            hasher.update((shard_index as u32).to_le_bytes());
            let target_hash = hasher.finalize();
            let target_node_id = NodeId::new(target_hash.into());

            let mut prefixed_payload = target_hash.to_vec();
            prefixed_payload.extend_from_slice(&[0u8; 4]);
            prefixed_payload.extend_from_slice(&packet.payload);
            let final_pkt = DspPacket::new(PacketType::Fragment, 0, 0, prefixed_payload);

            let storage_nodes: Vec<crate::dht::Node> = node.inner.routing_table.read().await.find_closest_nodes(&target_node_id, crate::dht::K_PARAM);

            for peer in storage_nodes.iter().take(3) {
                let resolved_addr = transport::resolve_peer_addr(node, peer).await;
                if transport::is_same_node(resolved_addr, self_addr) { continue; }

                let permit = semaphore.clone().acquire_owned().await.ok();
                let n = node.clone();
                let p = final_pkt.clone();
                let pid = peer.id;
                let confirmed = shard_confirmed.clone();

                tasks.push(tokio::spawn(async move {
                    let _permit = permit;
                    if router::send_packet_reliable(&n, p, resolved_addr, Some(pid)).await.is_ok() {
                        confirmed[shard_index].store(true, Ordering::Relaxed);
                    }
                }));
            }
        }

        for t in tasks { let _ = t.await; }

        // unique_stored counts confirmed shard *indices*, not unique peers.
        // All 15 shards can land on a single peer — minimum network size is 2 nodes
        // (uploader + 1 peer). Fault tolerance improves with more peers: a file
        // survives as long as any 10 of its 15 shards remain accessible.
        let unique_stored = shard_confirmed.iter().filter(|b| b.load(Ordering::Relaxed)).count();
        if unique_stored < 10 {
            return Err(ShardError::Network(format!("Upload failed: Only {}/15 unique fragments stored.", unique_stored)));
        }

        // Fixed: Emit event instead of print
        node.emit(ShardEvent::TransferProgress {
            filename: sanitize_filename(filename),
            current_chunk: chunk_index + 1,
            total_chunks: (padded_total_size as f64 / chunk_size as f64).ceil() as u32,
            is_upload: true
        });

        chunk_index += 1;
        if stream_cursor >= padded_total_size { break; }
    }

    let mut combined_secret = Vec::with_capacity(64);
    combined_secret.extend_from_slice(&file_id);
    combined_secret.extend_from_slice(&master_key);
    
    node.emit(ShardEvent::TransferComplete {
        filename: path.to_string(),
        magnet: Some(BASE64_URL_SAFE_NO_PAD.encode(&combined_secret)),
        path: None
    });
    
    info!("Secure Upload complete. Padded size: {}", padded_total_size);
    Ok((file_id, master_key))
}

pub async fn fetch_file_stream(node: &Node, file_id: [u8; 32], key: [u8; 32], base_dir: &str) -> Result<()> {
    let chunk_size = 1024 * 1024;
    let mut total_chunks = 1; 
    let mut current_chunk: u32 = 0;
    
    let self_addr = node.endpoint.local_addr()?;
    let mut file_handle: Option<tokio::fs::File> = None;
    let mut real_file_size: u64 = 0;
    let mut header_parsed = false;
    
    let mut final_dest_path = String::new();

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_TRANSFERS));

    debug!(file_id = %hex::encode(file_id), "Starting secure download (Size hidden)");

    // If completely isolated (routing table + hints empty), attempt emergency
    // re-bootstrap to the default seed before giving up.
    {
        let rt_size     = node.inner.routing_table.read().await.get_all_nodes().len();
        let hints_size  = node.inner.unverified_hints.read().await.len();
        let pub_addr    = *node.inner.public_address.read().await;
        debug!("Download pre-check: routing_table={} hints={} public_addr={:?}", rt_size, hints_size, pub_addr);
        let rt_empty    = rt_size == 0;
        let hints_empty = hints_size == 0;

        if rt_empty && hints_empty {
            debug!("Fully isolated — emergency re-bootstrap to default seed");
            if let Ok(mut addrs) = tokio::net::lookup_host("sh4rd.net:9100").await {
                if let Some(addr) = addrs.next() {
                    let _ = node.bootstrap(addr).await;
                }
            }
            // Second round: bootstrap populates hints from seed's response;
            // a second lookup queries those hints and promotes peers to routing_table.
            node.iterative_lookup(node.inner.id, 2).await;
        } else if rt_empty {
            debug!("Routing table empty at download start — refreshing DHT from hints");
            node.iterative_lookup(node.inner.id, 1).await;
        }
    }

    while current_chunk < total_chunks {
        let mut fragment_locations = HashMap::new();

        for i in 0..15 {
            let mut hasher = Sha256::new();
            hasher.update(file_id);
            hasher.update(current_chunk.to_le_bytes());
            hasher.update((i as u32).to_le_bytes());
            let target_hash_bytes: [u8; 32] = hasher.finalize().into();

            // Build candidate pool from routing table + unverified hints.
            // In a sparse network the routing table may only contain the seed (which
            // holds no fragments), while the actual storage node is still in hints
            // (TLS promotion pending). Merge both pools so every known peer is tried.
            let rt_candidates = node.inner.routing_table.read().await
                .find_closest_nodes(&NodeId::new(target_hash_bytes), crate::dht::K_PARAM);
            let hint_candidates: Vec<crate::dht::Node> = node.inner.unverified_hints.read().await
                .values().cloned().collect();
            // Also include active QUIC connections — peers may be connected but not yet
            // promoted to routing_table (e.g. seed that has no peers to return in DHT response).
            let conn_candidates: Vec<crate::dht::Node> = node.inner.connections.read().await
                .iter()
                .filter(|(_, c)| c.close_reason().is_none())
                .map(|(addr, _)| crate::dht::Node {
                    id: NodeId::new([0u8; 32]),
                    address: *addr,
                    lan_address: None,
                    rtt_ms: 0,
                })
                .collect();

            let mut seen = std::collections::HashSet::new();
            let mut candidates: Vec<crate::dht::Node> = Vec::new();
            for n in rt_candidates.into_iter().chain(hint_candidates).chain(conn_candidates) {
                if seen.insert(n.address) {
                    candidates.push(n);
                }
            }

            if !candidates.is_empty() {
                fragment_locations.insert(i, (target_hash_bytes, candidates));
            }
        }

        if fragment_locations.is_empty() {
            return Err(ShardError::Network(
                "NO PEERS FOUND for any fragment — routing table and hints are both empty".to_string()
            ));
        }

        let mut recovered_packets = Vec::new();
        let mut found_indices = HashSet::new();
        let mut success = false;

        for attempt in 1..=5 {
             for i in 0..15 {
                if found_indices.contains(&i) { continue; }
                let mut hasher = Sha256::new();
                hasher.update(file_id);
                hasher.update(current_chunk.to_le_bytes());
                hasher.update((i as u32).to_le_bytes());
                let target_hash = hasher.finalize();
                let key_hex = hex::encode(&target_hash);
                
                let inner = node.inner.clone();
                let maybe_data: Option<Vec<u8>> = tokio::task::spawn_blocking(move || {
                    inner.storage.retrieve_by_hash(key_hex.as_bytes()).ok()
                }).await.unwrap_or(None);

                if let Some(data) = maybe_data {
                    if !data.is_empty() {
                        recovered_packets.push(DspPacket::new(PacketType::Fragment, i as u8, 15, data));
                        found_indices.insert(i);
                    }
                }
            }

            if found_indices.len() >= 10 { success = true; break; }

             let mut tasks = Vec::new();
             
             let mut download_targets = HashSet::new();
             for i in 0..15 {
                 if found_indices.contains(&i) { continue; }
                 if let Some((_, nodes)) = fragment_locations.get(&i) {
                     for peer in nodes {
                         download_targets.insert(peer.clone());
                     }
                 }
             }
             
             let mut warm_up_handles = Vec::new();
             for peer in download_targets {
                  let n = node.clone();
                  let s_addr = self_addr;
                  warm_up_handles.push(tokio::spawn(async move {
                      let resolved_addr = transport::resolve_peer_addr(&n, &peer).await;
                      if transport::is_same_node(resolved_addr, s_addr) { return; }
                      let _ = tokio::time::timeout(Duration::from_secs(2),
                        transport::get_or_connect(&n, resolved_addr, Some(peer.id))
                      ).await;
                  }));
             }
             for handle in warm_up_handles { let _ = handle.await; }

             for i in 0..15 {
                if found_indices.contains(&i) { continue; }
                if let Some((hash, nodes)) = fragment_locations.get(&i) {
                    for peer in nodes {
                        let resolved_addr = transport::resolve_peer_addr(node, peer).await;
                        if transport::is_same_node(resolved_addr, self_addr) { continue; }

                        let permit = semaphore.clone().acquire_owned().await.ok();
                        let node_ref = node.clone();
                        let h_vec = hash.to_vec();
                        let pkt = DspPacket::new(PacketType::FragmentRequest, 0, 0, h_vec);
                        let nid = peer.id;

                        tasks.push(tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = router::send_packet_reliable(&node_ref, pkt, resolved_addr, Some(nid)).await {
                                debug!("Fetch req failed: {}", e);
                            }
                        }));
                    }
                }
            }
            
            for t in tasks { let _ = t.await; }
            
            if found_indices.len() < 10 && attempt < 5 {
                tokio::time::sleep(Duration::from_millis(500 * attempt as u64)).await;
            }
        }

        if !success { 
            return Err(ShardError::Network(format!("Chunk {} download failed (not enough fragments)", current_chunk))); 
        }

        node.emit(ShardEvent::TransferProgress {
            filename: "downloading...".to_string(), 
            current_chunk: current_chunk + 1,
            total_chunks: total_chunks,
            is_upload: false
        });

        let raw_data_padded = ShardManager::assemble_file(recovered_packets)
             .map_err(|e| ShardError::Other(e.to_string()))?;

        // Cooperative repair: if any shard indices were missing during this download,
        // regenerate them from the now-complete RS data and push to DHT peers.
        let missing: Vec<usize> = (0..15).filter(|i| !found_indices.contains(i)).collect();
        if !missing.is_empty() {
            let rn = node.clone();
            let rd = raw_data_padded.clone();
            let sa = self_addr;
            tokio::spawn(async move {
                repair_missing_shards(&rn, file_id, current_chunk, &rd, &missing, sa).await;
            });
        }

        let size_slice = raw_data_padded.get(0..4)
            .ok_or_else(|| ShardError::Protocol("Data too short for length header".to_string()))?;
            
        let real_len = u32::from_le_bytes(size_slice.try_into().unwrap()) as usize;
        let raw_data_with_nonce = &raw_data_padded[4..4 + real_len];
        
        if raw_data_with_nonce.len() < 12 {
             return Err(ShardError::Protocol("Data too short for nonce".to_string()));
        }
        
        let (nonce_bytes, ciphertext) = raw_data_with_nonce.split_at(12);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(nonce_bytes);
        
        let plaintext = FileCipher::decrypt(ciphertext, &key, &nonce)
            .map_err(|e| ShardError::Crypto(e.to_string()))?;
            
        let mut data_to_write = plaintext.as_slice();

        if !header_parsed {
            if current_chunk != 0 { return Err(ShardError::Protocol("Header missing in first chunk".to_string())); }
            if data_to_write.len() < 10 { return Err(ShardError::Protocol("Stream too short for header".to_string())); }
            
            let size_bytes: [u8; 8] = data_to_write[0..8].try_into()
                .map_err(|_| ShardError::Protocol("Invalid size header".to_string()))?;
            real_file_size = u64::from_le_bytes(size_bytes);
            
            let name_len = u16::from_le_bytes(data_to_write[8..10].try_into().unwrap()) as usize;
            if data_to_write.len() < 10 + name_len { return Err(ShardError::Protocol("Header too short for filename".to_string())); }
            
            let filename_bytes = &data_to_write[10..10+name_len];
            let filename_raw = String::from_utf8_lossy(filename_bytes);
            let safe_filename = sanitize_filename(&filename_raw);
            
            let header_overhead = 8 + 2 + name_len as u64;
            let raw_data_size = header_overhead + real_file_size;
            let padded_total_size = align_size(raw_data_size);
            
            total_chunks = (padded_total_size as f64 / chunk_size as f64).ceil() as u32;
            
            debug!("Secure Header Decrypted. Real Size: {}. Padded: {}. Chunks: {}", 
                  real_file_size, padded_total_size, total_chunks);

            let download_dir = Path::new(base_dir).join("downloads");
            if !download_dir.exists() { tokio::fs::create_dir_all(&download_dir).await?; }
            
            let mut dest_path = download_dir.join(&safe_filename);
            let mut stem = Path::new(&safe_filename).file_stem().and_then(|s| s.to_str()).unwrap_or("file").to_string();
            let extension = Path::new(&safe_filename).extension().and_then(|s| s.to_str()).unwrap_or("").to_string();
            
            while dest_path.exists() {
                stem = format!("{}-copy", stem);
                let new_name = if extension.is_empty() { stem.clone() } else { format!("{}.{}", stem, extension) };
                dest_path = download_dir.join(new_name);
            }
            
            // Capture final path for event
            final_dest_path = dest_path.to_string_lossy().to_string();

            file_handle = Some(tokio::fs::File::create(&dest_path).await?);
            data_to_write = &data_to_write[10+name_len..];
            header_parsed = true;
        }

        if let Some(f) = file_handle.as_mut() {
            f.write_all(data_to_write).await?;
        }

        current_chunk += 1;
    }

    if let Some(f) = file_handle.as_mut() {
        f.set_len(real_file_size).await?;
        f.sync_all().await?;
    }

    node.emit(ShardEvent::TransferComplete {
        filename: "downloaded_file".to_string(),
        magnet: None,
        path: Some(final_dest_path)
    });

    info!("Download complete & Padding removed.");
    Ok(())
}

// Regenerate missing shard indices from the fully reconstructed chunk payload and
// push them to the 3 DHT-closest peers for each index. Called from a detached
// tokio::spawn — all errors are logged at debug level and silently dropped.
async fn repair_missing_shards(
    node: &Node,
    file_id: [u8; 32],
    chunk_index: u32,
    raw_data_padded: &[u8],
    missing_indices: &[usize],
    self_addr: std::net::SocketAddr,
) {
    if node.inner.routing_table.read().await.get_all_nodes().is_empty() {
        return;
    }

    let all_shards = match ShardManager::shred_file(raw_data_padded, 10, 5) {
        Ok(pkts) => pkts,
        Err(e) => { debug!("Repair: re-shred failed: {}", e); return; }
    };

    let mut pushed = 0usize;
    for &shard_index in missing_indices {
        let packet = match all_shards.get(shard_index) {
            Some(p) => p,
            None    => continue,
        };

        let mut hasher = Sha256::new();
        hasher.update(file_id);
        hasher.update(chunk_index.to_le_bytes());
        hasher.update((shard_index as u32).to_le_bytes());
        let target_hash = hasher.finalize();
        let target_node_id = NodeId::new(target_hash.into());

        let mut prefixed_payload = target_hash.to_vec();
        prefixed_payload.extend_from_slice(&[0u8; 4]);
        prefixed_payload.extend_from_slice(&packet.payload);
        let pkt = DspPacket::new(PacketType::Fragment, 0, 0, prefixed_payload);

        let peers = node.inner.routing_table.read().await
            .find_closest_nodes(&target_node_id, crate::dht::K_PARAM);

        for peer in peers.iter().take(3) {
            let resolved = transport::resolve_peer_addr(node, peer).await;
            if transport::is_same_node(resolved, self_addr) { continue; }
            if router::send_packet_reliable(node, pkt.clone(), resolved, Some(peer.id)).await.is_ok() {
                pushed += 1;
                break;
            }
        }
    }

    debug!("Repair: re-pushed {}/{} missing shard(s) for chunk {}",
        pushed, missing_indices.len(), chunk_index);
}
