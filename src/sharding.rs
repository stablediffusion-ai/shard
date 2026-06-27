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
use reed_solomon_erasure::galois_8::ReedSolomon;
use crate::packet::{DspPacket, PacketType};
use crate::error::{Result, ShardError};

// Hard Limit for reconstruction buffer (16MB).
// Prevents OOM attacks where malicious headers claim huge shard counts.
const MAX_RECONSTRUCTION_SIZE: usize = 16 * 1024 * 1024; 

pub struct ShardManager;

impl ShardManager {
    pub fn shred_file(data: &[u8], data_shards: usize, parity_shards: usize) -> Result<Vec<DspPacket>> {
        let r = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| ShardError::Other(e.to_string()))?;
            
        let total_shards = data_shards + parity_shards;
        let mut shards: Vec<Vec<u8>> = vec![vec![0u8; 0]; total_shards];

        // Split logic (Simple padding)
        let shard_len = (data.len() + data_shards - 1) / data_shards;
        
        for i in 0..data_shards {
            let start = i * shard_len;
            if start < data.len() {
                let end = std::cmp::min(start + shard_len, data.len());
                shards[i] = data[start..end].to_vec();
            }
            if shards[i].len() < shard_len {
                shards[i].resize(shard_len, 0);
            }
        }
        for i in data_shards..total_shards {
            shards[i] = vec![0u8; shard_len];
        }

        r.encode(&mut shards).map_err(|e| ShardError::Other(e.to_string()))?;

        let mut packets = Vec::new();
        for (i, shard) in shards.into_iter().enumerate() {
            packets.push(DspPacket::new(
                PacketType::Fragment,
                i as u8,
                total_shards as u16,
                shard
            ));
        }
        Ok(packets)
    }

    pub fn assemble_file(packets: Vec<DspPacket>) -> Result<Vec<u8>> {
        if packets.is_empty() { return Err(ShardError::Protocol("No packets to assemble".to_string())); }

        let total_shards = packets[0].reserved as usize;

        // Validate the shard geometry carried in the packet header.
        // The protocol uses a fixed 2:1 data-to-parity ratio; total must be divisible by 3.
        if total_shards == 0 || total_shards % 3 != 0 || total_shards > 255 {
            return Err(ShardError::Protocol(format!(
                "Invalid total_shards {} in packet header (must be non-zero, divisible by 3, ≤255)",
                total_shards
            )));
        }
        let data_shards = (total_shards * 2) / 3;
        let parity_shards = total_shards - data_shards;

        let mut shards: Vec<Option<Vec<u8>>> = vec![None; total_shards];
        let mut shard_len = 0;

        for p in packets {
            let idx = p.version as usize;
            if idx >= total_shards { continue; }
            
            // Determine shard length from the first valid packet
            if shard_len == 0 { 
                shard_len = p.payload.len();
                
                // [FIX] Security Check: Detect Memory Exhaustion Attack
                let estimated_size = shard_len.checked_mul(total_shards).unwrap_or(usize::MAX);
                if estimated_size > MAX_RECONSTRUCTION_SIZE {
                    return Err(ShardError::Protocol(
                        format!("Reconstruction size too large ({} bytes). Limit is {}.", estimated_size, MAX_RECONSTRUCTION_SIZE)
                    ));
                }
            } else if p.payload.len() != shard_len {
                return Err(ShardError::Protocol("Inconsistent shard lengths".to_string()));
            }

            shards[idx] = Some(p.payload);
        }

        if shard_len == 0 {
             return Err(ShardError::Protocol("No valid payload found".to_string()));
        }

        let r = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| ShardError::Other(e.to_string()))?;
            
        r.reconstruct(&mut shards).map_err(|e| ShardError::Other(e.to_string()))?;

        let mut result = Vec::with_capacity(data_shards * shard_len);
        for i in 0..data_shards {
            if let Some(shard) = &shards[i] {
                result.extend_from_slice(shard);
            } else {
                return Err(ShardError::Protocol("Reconstruction failed to produce data shards".to_string()));
            }
        }
        Ok(result)
    }
}
