//! Reads keys the verifier appends to `found_keys.csv`.
//!
//! The verifier writes and flushes one CSV row per confirmed key while a block
//! is being scanned. Rather than threading a channel through the verifier, the
//! engine tails the file from a saved offset: the on-disk format stays the single
//! source of truth, and a client restart cannot silently re-report old keys.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::coord::protocol::KeyRecord;

pub const DEFAULT_KEYS_FILE: &str = "found_keys.csv";

pub struct KeyTail {
    path: PathBuf,
    offset: u64,
}

impl KeyTail {
    /// Tail `path`, starting after whatever is already in it.
    pub fn new(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let offset = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        KeyTail { path, offset }
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Return rows appended since the last call.
    ///
    /// Only complete lines are consumed, so a partially written row is picked up
    /// on the next call instead of being reported broken.
    pub fn read_new(&mut self) -> Vec<KeyRecord> {
        let len = match std::fs::metadata(&self.path) {
            Ok(meta) => meta.len(),
            Err(_) => return Vec::new(),
        };
        if len <= self.offset {
            return Vec::new();
        }

        let mut file = match File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        if file.seek(SeekFrom::Start(self.offset)).is_err() {
            return Vec::new();
        }
        let mut buf = Vec::new();
        if file.read_to_end(&mut buf).is_err() {
            return Vec::new();
        }

        let text = String::from_utf8_lossy(&buf);
        let mut consumed = 0usize;
        let mut out = Vec::new();
        for line in text.split_inclusive('\n') {
            if !line.ends_with('\n') {
                break; // partial row, wait for the rest
            }
            consumed += line.len();
            if let Some(record) = parse_row(line.trim_end()) {
                out.push(record);
            }
        }
        self.offset += consumed as u64;
        out
    }
}

fn parse_row(line: &str) -> Option<KeyRecord> {
    if line.is_empty() {
        return None;
    }
    let mut fields = line.splitn(6, ',');
    let confirmed = fields.next()?;
    let ip = fields.next()?.to_string();
    let key = fields.next()?.to_string();
    let provider = fields.next().unwrap_or_default().to_string();
    let category = fields.next().unwrap_or_default().to_string();
    let timestamp = fields.next().unwrap_or_default().to_string();

    if confirmed.eq_ignore_ascii_case("confirmed") {
        return None; // header row
    }
    if key.trim().is_empty() {
        return None;
    }

    Some(KeyRecord {
        confirmed: confirmed.eq_ignore_ascii_case("true") || confirmed == "1",
        ip,
        key,
        provider,
        category,
        timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn tails_only_complete_new_rows() {
        let dir = std::env::temp_dir().join(format!("zorp-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("found_keys.csv");

        let mut file = File::create(&path).unwrap();
        writeln!(file, "confirmed,ip_address,api_key,provider,category,timestamp").unwrap();
        writeln!(file, "true,1.2.3.4,sk_old,stripe,payment,2026-01-01T00:00:00Z").unwrap();
        file.flush().unwrap();
        drop(file);

        // Existing rows are not re-reported.
        let mut tail = KeyTail::new(&path);
        assert!(tail.read_new().is_empty());

        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        write!(file, "true,5.6.7.8,sk_new,openai,llm,2026-01-02T00:00:00Z").unwrap();
        file.flush().unwrap();
        // No trailing newline yet: nothing is consumed.
        assert!(tail.read_new().is_empty());

        writeln!(file).unwrap();
        file.flush().unwrap();
        let rows = tail.read_new();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].key, "sk_new");
        assert_eq!(rows[0].provider, "openai");
        assert!(rows[0].confirmed);

        // Consumed exactly once.
        assert!(tail.read_new().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
