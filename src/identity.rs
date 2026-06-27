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
use rcgen::{CertificateParams, KeyPair, DnType, IsCa};
use rcgen::DistinguishedName as RcgenDn;

use rustls::{ClientConfig, ServerConfig, DistinguishedName};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime, PrivatePkcs8KeyDer};
use std::sync::Arc;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use tracing::{info, warn};
use argon2::{Argon2, Algorithm, Version, Params};
use rand::RngCore;
use x509_parser::prelude::*;

use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Key, Nonce};
use sha2::{Sha256, Digest};
use rsntp::SntpClient;

#[cfg(not(target_os = "android"))]
use machine_uid;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::DecodePrivateKey;

use crate::dht::NodeId;
use crate::error::{Result, ShardError};
use crate::config::SecurityConfig;

#[derive(Debug, Clone, Copy)]
enum TimeOffset {
    None,
    Add(Duration),
    Sub(Duration),
}

// Configure TLS with Bit-Level Difficulty
pub fn configure_quic_tls(
    storage_path: &str,
    config: &SecurityConfig,
    difficulty_bits: usize,
) -> Result<(ServerConfig, ClientConfig, NodeId, SigningKey)> {
    
    let cert_path = Path::new(storage_path).join("sys").join("node_cert.der");
    let key_path = Path::new(storage_path).join("sys").join("node_key.enc");

    let time_offset = get_ntp_offset();

    let (cert, key) = if cert_path.exists() && key_path.exists() {
        let cert_bytes = fs::read(&cert_path)?;
        let encrypted_key_bytes = fs::read(&key_path)?;

        let key_bytes = decrypt_key_with_machine_binding(&encrypted_key_bytes, storage_path)
            .map_err(|e| ShardError::Crypto(format!("Failed to decrypt identity: {}", e)))?;

        let cert = CertificateDer::from(cert_bytes);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes));

        // Validate existing cert against CURRENT bit difficulty
        if !verify_pow_logic(&cert, config, difficulty_bits) {
             warn!("Loaded identity does not meet current PoW difficulty ({} bits). Consider regenerating.", difficulty_bits);
        }

        (cert, key)
    } else {
        info!("Generating new Identity (Target: {} zero bits), please wait ...", difficulty_bits);
        let (c, k) = mine_identity(config, difficulty_bits)?;

        fs::write(&cert_path, c.as_ref())?;

        let encrypted_key = encrypt_key_with_machine_binding(k.secret_der(), storage_path)
            .map_err(|e| ShardError::Crypto(format!("Encryption failed: {}", e)))?;

        fs::write(&key_path, encrypted_key)?;

        (c, k)
    };

    let node_id = NodeId::new(calculate_id_hash(&cert, config));

    // Extract the Ed25519 signing key from the PKCS8 DER before it is consumed by TLS.
    let pkcs8_bytes = match &key {
        PrivateKeyDer::Pkcs8(p) => p.secret_pkcs8_der().to_vec(),
        _ => return Err(ShardError::Crypto("Expected PKCS8 key format".to_string())),
    };
    let signing_key = SigningKey::from_pkcs8_der(&pkcs8_bytes)
        .map_err(|e| ShardError::Crypto(format!("Failed to parse signing key: {}", e)))?;

    let verifier = Arc::new(PeerVerifier::new(config.clone(), time_offset, difficulty_bits));

    let mut server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier.clone())
        .with_single_cert(vec![cert.clone()], key.clone_key())
        .map_err(|e| ShardError::Crypto(e.to_string()))?;

    let alpn = b"shard-v1".to_vec();
    server_config.alpn_protocols = vec![alpn.clone()];

    let mut client_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert], key)
        .map_err(|e| ShardError::Crypto(e.to_string()))?;

    client_config.alpn_protocols = vec![alpn];

    Ok((server_config, client_config, node_id, signing_key))
}

// --- NTP LOGIC ---

fn get_ntp_offset() -> TimeOffset {
    info!("Synchronizing time with pool.ntp.org...");
    let client = SntpClient::new();

    match client.synchronize("pool.ntp.org") {
        Ok(sync_result) => {
            let offset_secs = sync_result.clock_offset().as_secs_f64();
            let abs_secs = offset_secs.abs();
            let duration = Duration::from_secs_f64(abs_secs);

            if offset_secs > 0.001 { 
                info!("Time correction: +{:.3}s", offset_secs);
                TimeOffset::Add(duration)
            } else if offset_secs < -0.001 {
                info!("Time correction: {:.3}s", offset_secs);
                TimeOffset::Sub(duration)
            } else {
                TimeOffset::None
            }
        },
        Err(e) => {
            warn!("NTP Synchronization failed ({}). Using system time (risky).", e);
            TimeOffset::None
        }
    }
}

// Layout: [salt:32][nonce:12][ciphertext:...]
// The salt is random per-encryption so SHA256(machine_id || salt) is non-deterministic
// even when the machine ID is known or guessable.

// Returns a stable identifier for this machine/installation.
// On Android there is no /etc/machine-id; generate a UUID once and persist it.
fn get_machine_id(storage_path: &str) -> std::result::Result<String, String> {
    #[cfg(target_os = "android")]
    {
        let id_path = Path::new(storage_path).join("sys").join("device_id");
        if id_path.exists() {
            return fs::read_to_string(&id_path)
                .map(|s| s.trim().to_string())
                .map_err(|e| e.to_string());
        }
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        let id = hex::encode(bytes);
        fs::write(&id_path, &id).map_err(|e| e.to_string())?;
        Ok(id)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = storage_path;
        machine_uid::get()
            .map_err(|e| format!("CRITICAL: Could not retrieve Machine ID. Binding failed: {}", e))
    }
}

fn derive_machine_key(salt: &[u8; 32], storage_path: &str) -> std::result::Result<Key<Aes256Gcm>, String> {
    let machine_id = get_machine_id(storage_path)?;

    let mut hasher = Sha256::new();
    hasher.update(machine_id.as_bytes());
    hasher.update(salt);
    let key_bytes = hasher.finalize();
    Ok(*Key::<Aes256Gcm>::from_slice(&key_bytes))
}

fn encrypt_key_with_machine_binding(plaintext: &[u8], storage_path: &str) -> std::result::Result<Vec<u8>, String> {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_machine_key(&salt, storage_path)?;
    let cipher = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| e.to_string())?;

    let mut output = Vec::with_capacity(32 + 12 + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend(ciphertext);
    Ok(output)
}

fn decrypt_key_with_machine_binding(encrypted_data: &[u8], storage_path: &str) -> std::result::Result<Vec<u8>, String> {
    // salt(32) + nonce(12) + ciphertext(≥1)
    if encrypted_data.len() < 45 { return Err("Data too short".to_string()); }

    let salt: [u8; 32] = encrypted_data[0..32].try_into().unwrap();
    let nonce_bytes = &encrypted_data[32..44];
    let ciphertext = &encrypted_data[44..];

    let key = derive_machine_key(&salt, storage_path)?;
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed. Machine ID mismatch or corrupted key.".to_string())
}

// --- MINING & POW ---

fn mine_identity(config: &SecurityConfig, difficulty_bits: usize) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let alg = &rcgen::PKCS_ED25519;
    let key_pair = KeyPair::generate_for(alg).map_err(|e| ShardError::Crypto(e.to_string()))?;
    let mut rng = rand::thread_rng();

    loop {
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        let salt_hex = hex::encode(salt);

        let mut params = CertificateParams::new(vec!["shard-node".to_string()])
            .map_err(|e| ShardError::Crypto(e.to_string()))?;

        params.distinguished_name = RcgenDn::new();
        params.distinguished_name.push(DnType::CommonName, "Shard Node");
        params.distinguished_name.push(DnType::OrganizationalUnitName, &salt_hex);
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let cert = params.self_signed(&key_pair).map_err(|e| ShardError::Crypto(e.to_string()))?;
        let cert_der = cert.der().to_vec();

        let hash = calculate_hash_internal(&cert_der, &salt, config);

        if check_hash_difficulty_bits(&hash, difficulty_bits) {
            let pk_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
            return Ok((CertificateDer::from(cert_der), pk_der));
        }
    }
}

fn calculate_id_hash(cert: &CertificateDer, config: &SecurityConfig) -> [u8; 32] {
    if let Some(salt) = extract_salt_from_cert(cert.as_ref()) {
        calculate_hash_internal(cert.as_ref(), &salt, config)
    } else {
        [0xFF; 32]
    }
}

fn calculate_hash_internal(data: &[u8], salt: &[u8], config: &SecurityConfig) -> [u8; 32] {
    let params = Params::new(config.argon_memory, config.argon_iterations, config.argon_parallelism, Some(32))
        .unwrap_or_else(|_| Params::default());
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0u8; 32];
    hasher.hash_password_into(data, salt, &mut output).unwrap();
    output
}

// Bit-level granularity check
fn check_hash_difficulty_bits(hash: &[u8], difficulty_bits: usize) -> bool {
    let full_bytes = difficulty_bits / 8;
    let remaining_bits = difficulty_bits % 8;

    if full_bytes > hash.len() { return false; }

    // 1. Check full bytes are all zero
    for i in 0..full_bytes {
        if hash[i] != 0 { return false; }
    }

    // 2. Check remaining bits in the next byte
    if remaining_bits > 0 && full_bytes < hash.len() {
        let byte = hash[full_bytes];
        // Shift right to keep only the top 'remaining_bits'. Result must be 0.
        // Example: need 3 bits 0. byte is 00011111. 8-3=5. byte >> 5 = 0. OK.
        // Example: need 3 bits 0. byte is 00100000. 8-3=5. byte >> 5 = 1. FAIL.
        if (byte >> (8 - remaining_bits)) != 0 {
            return false;
        }
    }

    true
}

fn extract_salt_from_cert(cert_der: &[u8]) -> Option<[u8; 32]> {
    let (_, x509) = X509Certificate::from_der(cert_der).ok()?;
    for rdn in x509.subject().iter() {
        for attr in rdn.iter() {
            if attr.attr_type() == &x509_parser::oid_registry::OID_X509_ORGANIZATIONAL_UNIT {
                let s = attr.as_str().ok()?;
                if let Ok(bytes) = hex::decode(s) {
                    return bytes.try_into().ok();
                }
            }
        }
    }
    None
}

fn verify_pow_logic(cert: &CertificateDer, config: &SecurityConfig, difficulty_bits: usize) -> bool {
    if let Some(salt) = extract_salt_from_cert(cert.as_ref()) {
        let hash = calculate_hash_internal(cert.as_ref(), &salt, config);
        check_hash_difficulty_bits(&hash, difficulty_bits)
    } else {
        warn!("PoW Verification: No salt found.");
        false
    }
}

// --- VERIFIER ---

#[derive(Debug)]
struct PeerVerifier {
    config: SecurityConfig,
    time_offset: TimeOffset,
    difficulty_bits: usize, // Stored as bits
}

impl PeerVerifier {
    fn new(config: SecurityConfig, time_offset: TimeOffset, difficulty_bits: usize) -> Self {
        Self { config, time_offset, difficulty_bits }
    }

    fn get_corrected_time(&self) -> SystemTime {
        let now = SystemTime::now();
        match self.time_offset {
            TimeOffset::None => now,
            TimeOffset::Add(d) => now + d,
            TimeOffset::Sub(d) => now.checked_sub(d).unwrap_or(now),
        }
    }

    fn verify_cert_internal(&self, cert: &CertificateDer) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // 1. Verify Proof-of-Work with bit precision
        if !verify_pow_logic(cert, &self.config, self.difficulty_bits) {
            warn!("TLS: PoW check failed (Need {} zero bits).", self.difficulty_bits);
            return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure));
        }

        // 2. Verify Time
        if let Ok((_, x509)) = X509Certificate::from_der(cert.as_ref()) {
            let corrected_now = self.get_corrected_time();
            let now_secs = corrected_now.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs() as i64;
            let validity = x509.validity();

            if now_secs < validity.not_before.timestamp() {
                return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidYet));
            }
            if now_secs > validity.not_after.timestamp() {
                return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Expired));
            }
        } else {
            return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding));
        }

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
}

// Rustls Boilerplate
impl rustls::client::danger::ServerCertVerifier for PeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.verify_cert_internal(end_entity)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl rustls::server::danger::ClientCertVerifier for PeerVerifier {
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        self.verify_cert_internal(end_entity).map(|_| rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] { &[] }
}
