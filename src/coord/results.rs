//! Result sink: the controller's own copies of what clients found.
//!
//! Clients keep their own `found_keys.csv` for local inspection; the controller
//! owns the authoritative copy so a client can be replaced, restarted or killed
//! without losing findings. Both files are appended and flushed per batch, and
//! both are de-duplicated in memory against what is already on disk, so a client
//! retrying a delivery cannot inflate the results.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use super::protocol::KeyRecord;
use super::set4::format_ip;

pub const HITS_FILE: &str = "open_ports.csv";
pub const KEYS_FILE: &str = "found_keys.csv";

const HITS_HEADER: &str = "ip,port,client,job,timestamp";
const KEYS_HEADER: &str = "confirmed,ip_address,api_key,provider,category,timestamp";

pub struct Results {
    dir: PathBuf,
    hits_seen: HashSet<(u32, u16)>,
    keys_seen: HashSet<String>,
    hits_written: u64,
    keys_written: u64,
}

impl Results {
    /// Open (or create) both result files, seeding the de-duplication sets from
    /// whatever is already there.
    pub fn open(dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("results dir {}: {}", dir.display(), e))?;

        let hits_path = dir.join(HITS_FILE);
        let keys_path = dir.join(KEYS_FILE);

        let hits_seen = load_hits(&hits_path);
        let keys_seen = load_keys(&keys_path);

        ensure_header(&hits_path, HITS_HEADER)?;
        ensure_header(&keys_path, KEYS_HEADER)?;

        Ok(Results {
            dir: dir.to_path_buf(),
            hits_seen,
            keys_seen,
            hits_written: 0,
            keys_written: 0,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn totals(&self) -> (u64, u64) {
        (self.hits_written, self.keys_written)
    }

    /// Append hits that have not been recorded yet. Returns `(accepted, dupes)`.
    pub fn add_hits(&mut self, client: &str, job: u64, hits: &[(u32, u16)]) -> (u64, u64) {
        if hits.is_empty() {
            return (0, 0);
        }

        let path = self.dir.join(HITS_FILE);
        let mut file = match open_append(&path) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("[results] cannot append {}: {}", path.display(), e);
                return (0, 0);
            }
        };

        let timestamp = timestamp();
        let mut accepted = 0u64;
        let mut dupes = 0u64;
        for (ip, port) in hits {
            if !self.hits_seen.insert((*ip, *port)) {
                dupes += 1;
                continue;
            }
            if writeln!(file, "{},{},{},{},{}", format_ip(*ip), port, client, job, timestamp).is_ok() {
                accepted += 1;
            }
        }
        let _ = file.flush();
        self.hits_written += accepted;
        (accepted, dupes)
    }

    /// Append keys that have not been recorded yet. Returns `(accepted, dupes)`.
    pub fn add_keys(&mut self, keys: &[KeyRecord]) -> (u64, u64) {
        if keys.is_empty() {
            return (0, 0);
        }

        let path = self.dir.join(KEYS_FILE);
        let mut file = match open_append(&path) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("[results] cannot append {}: {}", path.display(), e);
                return (0, 0);
            }
        };

        let mut accepted = 0u64;
        let mut dupes = 0u64;
        for key in keys {
            if key.key.trim().is_empty() {
                continue;
            }
            if !self.keys_seen.insert(key.key.clone()) {
                dupes += 1;
                continue;
            }
            let timestamp = if key.timestamp.is_empty() {
                timestamp()
            } else {
                key.timestamp.clone()
            };
            let row = format!(
                "{},{},{},{},{},{}",
                key.confirmed, key.ip, key.key, key.provider, key.category, timestamp
            );
            if writeln!(file, "{}", row).is_ok() {
                accepted += 1;
            }
            log::info!("[results] KEY {} {} ({})", key.key, key.provider, key.ip);
        }
        let _ = file.flush();
        self.keys_written += accepted;
        (accepted, dupes)
    }
}

fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn ensure_header(path: &Path, header: &str) -> Result<(), String> {
    let needs_header = match std::fs::metadata(path) {
        Ok(meta) => meta.len() == 0,
        Err(_) => true,
    };
    if !needs_header {
        return Ok(());
    }
    let mut file = open_append(path).map_err(|e| format!("{}: {}", path.display(), e))?;
    writeln!(file, "{}", header).map_err(|e| format!("{}: {}", path.display(), e))?;
    file.flush().map_err(|e| format!("{}: {}", path.display(), e))?;
    Ok(())
}

fn load_hits(path: &Path) -> HashSet<(u32, u16)> {
    let mut seen = HashSet::new();
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return seen,
    };
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let mut fields = line.split(',');
        let ip = fields.next().unwrap_or_default();
        let port = fields.next().unwrap_or_default();
        if let (Some(ip), Ok(port)) = (super::set4::parse_ipv4(ip), port.parse::<u16>()) {
            seen.insert((ip, port));
        }
    }
    seen
}

fn load_keys(path: &Path) -> HashSet<String> {
    let mut seen = HashSet::new();
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return seen,
    };
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        // confirmed,ip_address,api_key,provider,category,timestamp
        let mut fields = line.split(',');
        let _confirmed = fields.next();
        let _ip = fields.next();
        if let Some(key) = fields.next() {
            if !key.is_empty() {
                seen.insert(key.to_string());
            }
        }
    }
    seen
}

pub fn timestamp() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zorp-results-test-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn hits_are_deduped_across_batches_and_reopen() {
        let dir = temp_dir("hits");
        {
            let mut results = Results::open(&dir).unwrap();
            let hits = vec![(0x01020304u32, 80u16), (0x01020305, 443)];
            assert_eq!(results.add_hits("c1", 1, &hits), (2, 0));
            assert_eq!(results.add_hits("c1", 1, &hits), (0, 2));
        }
        // A reopened sink must not re-accept what is already on disk.
        let mut results = Results::open(&dir).unwrap();
        assert_eq!(results.add_hits("c2", 2, &[(0x01020304, 80)]), (0, 1));
        assert_eq!(results.add_hits("c2", 2, &[(0x01020306, 80)]), (1, 0));

        let body = std::fs::read_to_string(dir.join(HITS_FILE)).unwrap();
        assert_eq!(body.lines().count(), 1 + 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keys_are_deduped_by_secret_value() {
        let dir = temp_dir("keys");
        let mut results = Results::open(&dir).unwrap();
        let key = KeyRecord {
            confirmed: true,
            ip: "1.2.3.4".into(),
            key: "sk_live_abc".into(),
            provider: "stripe".into(),
            category: "payment".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
        };
        assert_eq!(results.add_keys(std::slice::from_ref(&key)), (1, 0));
        assert_eq!(results.add_keys(std::slice::from_ref(&key)), (0, 1));

        // Blank keys are rejected outright.
        let blank = KeyRecord {
            key: "   ".into(),
            ..key
        };
        assert_eq!(results.add_keys(&[blank]), (0, 0));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
