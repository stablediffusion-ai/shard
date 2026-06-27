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
use argon2::{
    password_hash::{
        PasswordHasher, SaltString
    },
    Argon2
};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use rand::RngCore;

use crate::error::{Result, ShardError};

pub struct FileCipher;

impl FileCipher {
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
        let cipher = Aes256Gcm::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| ShardError::Crypto(format!("Encryption failed: {}", e)))?;

        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    pub fn decrypt(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(nonce);

        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| ShardError::Crypto("Decryption failed / Invalid Tag".to_string()))?;

        Ok(plaintext)
    }
}

/// Derives a deterministic 32-byte identity from `secret` and a caller-supplied `salt`.
/// The salt must be stored alongside the output — passing a different salt yields a
/// different identity. Use `SaltString::generate(&mut OsRng)` for new identities and
/// persist the resulting salt string for future calls.
pub fn derive_identity(secret: &[u8], salt: &SaltString) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();

    match argon2.hash_password(secret, salt) {
        Ok(hash) => {
            let output = hash.hash.ok_or_else(|| {
                ShardError::Crypto("Argon2 produced an empty hash".to_string())
            })?;

            let mut result = [0u8; 32];
            let len = std::cmp::min(result.len(), output.len());
            result[0..len].copy_from_slice(&output.as_bytes()[0..len]);

            Ok(result)
        },
        Err(e) => {
            tracing::error!("CRITICAL: Argon2 hashing failed. System incompatible.");
            Err(ShardError::Crypto(format!("Argon2 failure: {}. Aborting startup.", e)))
        }
    }
}

// Used for PoW mining verification
pub fn hash_argon2_pow(input: &[u8], nonce: &[u8]) -> Result<[u8; 32]> {
    let argon2 = Argon2::default();
    
    // Construct salt from nonce to ensure reproducibility for verification
    let salt_str = BASE64_URL_SAFE_NO_PAD.encode(nonce);
    let salt = SaltString::from_b64(&salt_str).map_err(|e| 
        ShardError::Crypto(format!("Invalid salt generation: {}", e))
    )?;

    match argon2.hash_password(input, &salt) {
        Ok(hash) => {
            let output = hash.hash.ok_or_else(|| ShardError::Crypto("Empty PoW hash".to_string()))?;
            let mut result = [0u8; 32];
            let len = std::cmp::min(result.len(), output.len());
            result[0..len].copy_from_slice(&output.as_bytes()[0..len]);
            Ok(result)
        },
        Err(e) => {
            tracing::error!("CRITICAL: Argon2 PoW failed.");
            Err(ShardError::Crypto(format!("Argon2 PoW failure: {}", e)))
        }
    }
}
