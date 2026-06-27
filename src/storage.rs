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
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, Duration};

pub struct LocalStorage {
    pub root_path: PathBuf,
    max_storage_bytes: AtomicU64,
}

impl LocalStorage {
    pub fn new(root_path: &str, max_storage_bytes: u64) -> Result<Self, io::Error> {
        let path = PathBuf::from(root_path);
        fs::create_dir_all(&path)?;
        Ok(Self { root_path: path, max_storage_bytes: AtomicU64::new(max_storage_bytes) })
    }

    pub fn max_storage_bytes(&self) -> u64 { self.max_storage_bytes.load(Ordering::Relaxed) }

    pub fn set_max_storage_bytes(&self, val: u64) {
        self.max_storage_bytes.store(val, Ordering::Relaxed);
    }

    pub fn disk_used_bytes(&self) -> u64 {
        let mut total = 0u64;
        if let Ok(entries) = fs::read_dir(&self.root_path) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.path().metadata() {
                    if meta.is_file() { total += meta.len(); }
                }
            }
        }
        total
    }

    pub fn store_named(&self, key: &[u8], data: &[u8], _expiration: Option<Duration>) -> Result<(), io::Error> {
        let filename = validate_hex_key(key)?;
        self.enforce_limit(data.len() as u64)?;
        let path = self.root_path.join(filename);
        let mut file = File::create(path)?;
        file.write_all(data)?;
        Ok(())
    }

    pub fn retrieve_by_hash(&self, key: &[u8]) -> Result<Vec<u8>, io::Error> {
        let filename = validate_hex_key(key)?;
        let path = self.root_path.join(filename);
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    pub fn list_all_keys(&self) -> Vec<Vec<u8>> {
        let mut keys = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.root_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name == "sys" || name.starts_with('.') { continue; }
                        
                        if let Ok(key_bytes) = hex::decode(name) {
                            if key_bytes.len() == 32 {
                                keys.push(key_bytes);
                            }
                        }
                    }
                }
            }
        }
        keys
    }

    pub fn cleanup_expired(&self, ttl: Duration) {
        if let Ok(entries) = fs::read_dir(&self.root_path) {
            let now = SystemTime::now();
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name == "sys" { continue; }
                    }

                    if let Ok(metadata) = fs::metadata(&path) {
                        if let Ok(modified) = metadata.modified() {
                            if let Ok(age) = now.duration_since(modified) {
                                if age > ttl {
                                    let _ = fs::remove_file(path);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn enforce_limit(&self, new_bytes: u64) -> Result<(), io::Error> {
        let mut current_size = 0;
        let mut files = Vec::new();

        if let Ok(entries) = fs::read_dir(&self.root_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name == "sys" { continue; }
                    }

                    if let Ok(metadata) = fs::metadata(&path) {
                        current_size += metadata.len();
                        if let Ok(modified) = metadata.modified() {
                            files.push((path, modified));
                        }
                    }
                }
            }
        }

        if current_size + new_bytes > self.max_storage_bytes.load(Ordering::Relaxed) {
            files.sort_by(|a, b| a.1.cmp(&b.1));
            
            for (path, _) in files {
                if current_size + new_bytes <= self.max_storage_bytes.load(Ordering::Relaxed) { break; }
                if let Ok(metadata) = fs::metadata(&path) {
                    let len = metadata.len();
                    if fs::remove_file(&path).is_ok() {
                        current_size -= len;
                    }
                }
            }
        }
        
        if current_size + new_bytes > self.max_storage_bytes.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::Other, "Storage full"));
        }

        Ok(())
    }
}

fn validate_hex_key(key: &[u8]) -> Result<String, io::Error> {
    if key.len() != 64 || !key.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "key must be a 64-char lowercase hex string"));
    }
    Ok(String::from_utf8_lossy(key).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_storage() -> (TempDir, LocalStorage) {
        let dir = TempDir::new().unwrap();
        let s = LocalStorage::new(dir.path().to_str().unwrap(), 10 * 1024 * 1024).unwrap();
        (dir, s)
    }

    // SHA-256 of empty string — a real valid key
    const VALID_KEY: &[u8] = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    // ── DSP-007 : validate_hex_key ──

    #[test]
    fn valid_key_roundtrip() {
        let (_dir, s) = make_storage();
        s.store_named(VALID_KEY, b"payload", None).unwrap();
        let data = s.retrieve_by_hash(VALID_KEY).unwrap();
        assert_eq!(data, b"payload");
    }

    #[test]
    fn rejects_path_traversal() {
        let (_dir, s) = make_storage();
        // "../" pattern — not hex, not 64 chars
        let err = s.store_named(b"../../etc/passwd", b"x", None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn rejects_short_key() {
        let (_dir, s) = make_storage();
        let err = s.store_named(b"deadbeef", b"x", None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn rejects_long_key() {
        let (_dir, s) = make_storage();
        let long_key = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855ff";
        let err = s.store_named(long_key, b"x", None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn rejects_uppercase_hex() {
        // hex::encode always emits lowercase — uppercase is never a valid shard key
        let (_dir, s) = make_storage();
        let upper = b"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        let err = s.store_named(upper, b"x", None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn rejects_non_hex_chars() {
        let (_dir, s) = make_storage();
        // 64 chars but contains 'g' and spaces
        let bad = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8gg";
        let err = s.store_named(bad, b"x", None).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn retrieve_missing_key_returns_error() {
        let (_dir, s) = make_storage();
        let result = s.retrieve_by_hash(VALID_KEY);
        assert!(result.is_err());
    }
}
