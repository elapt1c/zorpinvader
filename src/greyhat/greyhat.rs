//! Core API key scanner: pattern registry, deduplication cache, extraction, and filtering.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use crate::data::smack::{Smack, SmackCase, SmackFlags, SmackSearchState, SMACK_NOT_FOUND};
use crate::massip::addr::IpAddress;

use super::verifier::Verifier;

// ---------------------------------------------------------------------------
// Pattern identifiers for Smack
// ---------------------------------------------------------------------------
const ID_KEY: usize = 1;

// ---------------------------------------------------------------------------
// Key pattern registry
// ---------------------------------------------------------------------------

/// A single API key prefix pattern with validation constraints.
#[derive(Debug, Clone)]
pub struct KeyPattern {
    /// Prefix string that identifies the key type (e.g. `"AKIA"`, `"ghp_"`).
    pub prefix: &'static str,
    /// Minimum acceptable key length (inclusive).
    pub min_len: usize,
    /// Maximum acceptable key length (inclusive). 0 = unbounded.
    pub max_len: usize,
    /// Human-readable provider name (e.g. `"AWS Access Key ID"`).
    pub provider: &'static str,
    /// Machine-readable category tag (e.g. `"aws"`, `"github"`).
    pub category: &'static str,
    /// Whether this key type is designed to be public/client-side.
    /// Safe keys (e.g. Stripe publishable keys) are only detected when
    /// `--include-safe` is passed.
    pub safe: bool,
}

/// The complete registry of known API key prefixes.
///
/// Each entry maps a distinctive prefix to its expected key length range,
/// human-readable provider description, and a short category tag.
pub static KEY_PATTERNS: &[KeyPattern] = &[
    // AWS
    KeyPattern { prefix: "AKIA", min_len: 16, max_len: 25, provider: "AWS Access Key ID", category: "aws", safe: false },
    KeyPattern { prefix: "ASIA", min_len: 16, max_len: 25, provider: "AWS Temporary Access Key", category: "aws", safe: false },
    // Google
    KeyPattern { prefix: "AIzaSy", min_len: 16, max_len: 60, provider: "Google API Key", category: "google", safe: false },
    KeyPattern { prefix: "ya29.", min_len: 20, max_len: 500, provider: "Google OAuth2 Token", category: "google", safe: false },
    // GitHub
    KeyPattern { prefix: "ghp_", min_len: 16, max_len: 100, provider: "GitHub Personal Access Token", category: "github", safe: false },
    KeyPattern { prefix: "gho_", min_len: 16, max_len: 100, provider: "GitHub OAuth Token", category: "github", safe: false },
    KeyPattern { prefix: "ghu_", min_len: 16, max_len: 100, provider: "GitHub User-to-Server Token", category: "github", safe: false },
    KeyPattern { prefix: "ghs_", min_len: 16, max_len: 100, provider: "GitHub Server-to-Server Token", category: "github", safe: false },
    KeyPattern { prefix: "github_pat_", min_len: 16, max_len: 200, provider: "GitHub Fine-Grained PAT", category: "github", safe: false },
    // Stripe
    KeyPattern { prefix: "sk_live_", min_len: 16, max_len: 100, provider: "Stripe Secret Key (Live)", category: "stripe", safe: false },
    KeyPattern { prefix: "sk_test_", min_len: 16, max_len: 100, provider: "Stripe Secret Key (Test)", category: "stripe", safe: false },
    KeyPattern { prefix: "pk_live_", min_len: 16, max_len: 100, provider: "Stripe Publishable Key (Live)", category: "stripe", safe: true },
    KeyPattern { prefix: "rk_live_", min_len: 16, max_len: 100, provider: "Stripe Restricted Key (Live)", category: "stripe", safe: false },
    KeyPattern { prefix: "rk_test_", min_len: 16, max_len: 100, provider: "Stripe Restricted Key (Test)", category: "stripe", safe: false },
    KeyPattern { prefix: "whsec_", min_len: 16, max_len: 80, provider: "Stripe Webhook Secret", category: "stripe", safe: false },
    KeyPattern { prefix: "cus_", min_len: 16, max_len: 80, provider: "Stripe Customer ID", category: "stripe", safe: true },
    // CircleCI
    KeyPattern { prefix: "cci_", min_len: 16, max_len: 80, provider: "CircleCI API Token", category: "circleci", safe: false },
    // Twitter / X
    KeyPattern { prefix: "AAAAAAAA", min_len: 20, max_len: 200, provider: "Twitter Bearer Token", category: "twitter", safe: false },
    // Groq
    KeyPattern { prefix: "gsk_", min_len: 16, max_len: 80, provider: "Groq API Key", category: "groq", safe: false },
    // DigitalOcean
    KeyPattern { prefix: "dop_v1_", min_len: 30, max_len: 150, provider: "DigitalOcean API Token", category: "digitalocean", safe: false },
    KeyPattern { prefix: "doa_", min_len: 16, max_len: 150, provider: "DigitalOcean OAuth Token", category: "digitalocean", safe: false },
    // GitLab
    KeyPattern { prefix: "glpat-", min_len: 16, max_len: 80, provider: "GitLab Personal Access Token", category: "gitlab", safe: false },
    KeyPattern { prefix: "glft-", min_len: 16, max_len: 80, provider: "GitLab Feed Token", category: "gitlab", safe: false },
    KeyPattern { prefix: "GR1348941", min_len: 16, max_len: 80, provider: "GitLab Runner Token", category: "gitlab", safe: false },
    // SendGrid
    KeyPattern { prefix: "SG.", min_len: 16, max_len: 120, provider: "SendGrid API Key", category: "sendgrid", safe: false },
    // Fastly
    KeyPattern { prefix: "FASTLY_", min_len: 16, max_len: 80, provider: "Fastly API Token", category: "fastly", safe: false },
    // Cohere
    KeyPattern { prefix: "cohere-", min_len: 16, max_len: 80, provider: "Cohere API Key", category: "cohere", safe: false },
    // Fireworks
    KeyPattern { prefix: "fireworks-", min_len: 16, max_len: 80, provider: "Fireworks AI Token", category: "fireworks", safe: false },
    // Mistral
    KeyPattern { prefix: "mistral-", min_len: 16, max_len: 80, provider: "Mistral AI API Key", category: "mistral", safe: false },
    // Nvidia
    KeyPattern { prefix: "nvapi-", min_len: 16, max_len: 80, provider: "Nvidia NIM API Key", category: "nvidia", safe: false },
    // Together
    KeyPattern { prefix: "together-", min_len: 16, max_len: 80, provider: "Together AI API Key", category: "together", safe: false },
    // Azure / JWT
    KeyPattern { prefix: "0.AAA", min_len: 16, max_len: 200, provider: "Azure AD Token", category: "azure", safe: false },
    // Alibaba
    KeyPattern { prefix: "LTAI", min_len: 12, max_len: 60, provider: "Alibaba Cloud Access Key", category: "alibaba", safe: false },
    // Cloudflare
    KeyPattern { prefix: "cloudflare_", min_len: 16, max_len: 80, provider: "Cloudflare API Token", category: "cloudflare", safe: false },
    // Heroku
    KeyPattern { prefix: "HRKU", min_len: 16, max_len: 80, provider: "Heroku API Key", category: "heroku", safe: false },
    // PyPI
    KeyPattern { prefix: "pypi-", min_len: 16, max_len: 100, provider: "PyPI API Token", category: "pypi", safe: false },
    // ElevenLabs
    KeyPattern { prefix: "elevenlabs-", min_len: 16, max_len: 80, provider: "ElevenLabs API Key", category: "elevenlabs", safe: false },
    // Square
    KeyPattern { prefix: "sq0atp-", min_len: 10, max_len: 50, provider: "Square Access Token", category: "square", safe: false },
    KeyPattern { prefix: "sq0csp-", min_len: 16, max_len: 100, provider: "Square Application Secret", category: "square", safe: false },
    // Linear
    KeyPattern { prefix: "lin_api_", min_len: 16, max_len: 80, provider: "Linear API Key", category: "linear", safe: false },
    // Sentry
    KeyPattern { prefix: "sntrys_", min_len: 16, max_len: 100, provider: "Sentry Auth Token", category: "sentry", safe: false },
    // NPM
    KeyPattern { prefix: "npm_", min_len: 16, max_len: 100, provider: "NPM Access Token", category: "npm", safe: false },
    // RubyGems
    KeyPattern { prefix: "rubygems_", min_len: 16, max_len: 80, provider: "RubyGems API Key", category: "rubygems", safe: false },
    // Flutterwave
    KeyPattern { prefix: "FLWSECK_", min_len: 16, max_len: 80, provider: "Flutterwave Secret Key", category: "flutterwave", safe: false },
    // AssemblyAI
    KeyPattern { prefix: "assemblyai_", min_len: 16, max_len: 80, provider: "AssemblyAI API Key", category: "assemblyai", safe: false },
    // Vercel
    KeyPattern { prefix: "vercel_", min_len: 10, max_len: 80, provider: "Vercel API Token", category: "vercel", safe: false },
    // Voyage
    KeyPattern { prefix: "voyage-", min_len: 16, max_len: 80, provider: "Voyage AI API Key", category: "voyage", safe: false },
    // PayPal
    KeyPattern { prefix: "A21A", min_len: 16, max_len: 80, provider: "PayPal Client ID", category: "paypal", safe: false },
    // Meta / Facebook
    KeyPattern { prefix: "EAAC", min_len: 20, max_len: 500, provider: "Facebook Access Token", category: "meta", safe: false },
    KeyPattern { prefix: "EAAG", min_len: 20, max_len: 500, provider: "Facebook Graph API Token", category: "meta", safe: false },
    KeyPattern { prefix: "EAAE", min_len: 20, max_len: 500, provider: "Facebook Enterprise Token", category: "meta", safe: false },
    // DashScope / Alibaba Cloud AI
    KeyPattern { prefix: "sk-ws-", min_len: 80, max_len: 200, provider: "DashScope API Key", category: "dashscope", safe: false },
    KeyPattern { prefix: "sk-sp-", min_len: 80, max_len: 200, provider: "DashScope Code Plan Key", category: "dashscope", safe: false },
    // Stripe publishable test (safe — designed for client-side use)
    KeyPattern { prefix: "pk_test_", min_len: 16, max_len: 100, provider: "Stripe Publishable Key (Test)", category: "stripe", safe: true },
];

// ---------------------------------------------------------------------------
// Deduplication cache
// ---------------------------------------------------------------------------

/// Size of the open-addressing hash cache used to deduplicate (ip, key) pairs.
const CACHE_SIZE: usize = 16384;

/// A single slot in the dedup cache.
#[derive(Default, Clone)]
struct SeenEntry {
    valid: bool,
    hash: u64,
    ip: String,
    key: String,
}

/// Ring-buffer-style deduplication cache keyed on `(ip, key)`.
///
/// Uses open addressing with DJB2-style hashing. Collisions silently evict
/// the previous occupant, which is acceptable because dedup is best-effort.
struct SeenCache {
    entries: Vec<SeenEntry>,
}

impl SeenCache {
    fn new() -> Self {
        Self {
            entries: vec![SeenEntry::default(); CACHE_SIZE],
        }
    }

    fn hash(ip: &str, key: &str) -> u64 {
        let mut h: u64 = 5381;
        for b in ip.bytes() {
            h = h.wrapping_mul(33).wrapping_add(b as u64);
        }
        for b in key.bytes() {
            h = h.wrapping_mul(33).wrapping_add(b as u64);
        }
        h
    }

    /// Returns `true` if this (ip, key) pair has already been recorded.
    fn is_duplicate(&self, ip: &str, key: &str) -> bool {
        let h = Self::hash(ip, key);
        let idx = (h as usize) % CACHE_SIZE;
        let entry = &self.entries[idx];
        entry.valid && entry.hash == h && entry.ip == ip && entry.key == key
    }

    /// Record an (ip, key) pair.
    fn insert(&mut self, ip: &str, key: &str) {
        let h = Self::hash(ip, key);
        let idx = (h as usize) % CACHE_SIZE;
        self.entries[idx] = SeenEntry {
            valid: true,
            hash: h,
            ip: ip.to_string(),
            key: key.to_string(),
        };
    }
}

// ---------------------------------------------------------------------------
// Scanner stats (shared atomics)
// ---------------------------------------------------------------------------

/// Global counters shared across the scanner pipeline.
pub struct ScannerStats {
    pub total_sites_checked: AtomicU64,
    pub total_html_sites: AtomicU64,
    pub total_potential_keys: AtomicU64,
    pub total_keys_found: AtomicU64,
    pub last_html_time: AtomicU64,
}

impl Default for ScannerStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ScannerStats {
    pub fn new() -> Self {
        Self {
            total_sites_checked: AtomicU64::new(0),
            total_html_sites: AtomicU64::new(0),
            total_potential_keys: AtomicU64::new(0),
            total_keys_found: AtomicU64::new(0),
            last_html_time: AtomicU64::new(0),
        }
    }
}

// ---------------------------------------------------------------------------
// Extracted candidate key
// ---------------------------------------------------------------------------

/// A candidate key extracted from scanned data, ready for verification.
#[derive(Debug, Clone)]
pub struct CandidateKey {
    pub ip: String,
    pub key: String,
    pub provider: String,
    pub category: String,
}

// ---------------------------------------------------------------------------
// Greyhat scanner
// ---------------------------------------------------------------------------

/// The main API-key scanner.
///
/// Wraps an Aho-Corasick (`Smack`) engine loaded with all known key prefixes,
/// a deduplication cache, and heuristic filters for false-positive rejection.
pub struct GreyhatScanner {
    smack: Smack,
    cache: Mutex<SeenCache>,
    stats: ScannerStats,
}

impl GreyhatScanner {
    /// Build a new scanner with registered key patterns loaded.
    ///
    /// When `include_safe` is `false` (the default), patterns marked as
    /// `safe: true` (e.g. Stripe publishable keys, customer IDs) are
    /// excluded since they are designed to be public/client-side.
    pub fn new(include_safe: bool) -> Self {
        let mut smack = Smack::create("greyhat", SmackCase::Sensitive);
        let mut loaded = 0usize;
        for pattern in KEY_PATTERNS {
            if !include_safe && pattern.safe {
                continue;
            }
            smack.add_pattern(
                pattern.prefix.as_bytes(),
                ID_KEY,
                SmackFlags::NONE,
            );
            loaded += 1;
        }
        smack.compile();
        log::info!("[scanner] {} patterns loaded ({} safe patterns {})",
            loaded,
            KEY_PATTERNS.len() - loaded,
            if include_safe { "included" } else { "excluded" });

        Self {
            smack,
            cache: Mutex::new(SeenCache::new()),
            stats: ScannerStats::new(),
        }
    }

    /// Borrow the shared statistics counters.
    pub fn stats(&self) -> &ScannerStats {
        &self.stats
    }

    /// Scan a response body for API key patterns and submit candidates to the
    /// given [`Verifier`].
    ///
    /// `ip` is the source IP address of the response.
    /// `px` is the raw response body bytes.
    pub fn scan(&self, ip: IpAddress, px: &[u8], verifier: &Verifier) {
        let ip_str = ip.to_string();
        self.stats.total_sites_checked.fetch_add(1, Ordering::Relaxed);

        // Track HTML sites
        if px.len() > 10 {
            let lower = to_lowercase_lossy(&px[..px.len().min(4096)]);
            if lower.contains("<script")
                || lower.contains("<style")
                || lower.contains("<html")
            {
                self.stats.total_html_sites.fetch_add(1, Ordering::Relaxed);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                self.stats.last_html_time.store(now, Ordering::Relaxed);
            }
        }

        // Aho-Corasick search
        let mut state = SmackSearchState::new();
        let mut offset = 0usize;
        while offset < px.len() {
            let id = self.smack.search_next(&mut state, px, &mut offset);
            if id != SMACK_NOT_FOUND {
                self.extract_and_submit(&ip_str, px, offset, id, verifier);
            }
        }
    }

    // ------------------------------------------------------------------
    // Key extraction and filtering
    // ------------------------------------------------------------------

    /// Check if a byte is a valid API-key character.
    fn is_valid_key_char(c: u8) -> bool {
        c.is_ascii_alphanumeric()
            || c == b'-'
            || c == b'_'
            || c == b'.'
            || c == b'+'
            || c == b'/'
            || c == b'='
    }

    /// Extract the key token starting from the match position, apply heuristic
    /// filters, and submit valid candidates to the verifier.
    fn extract_and_submit(
        &self,
        ip_str: &str,
        px: &[u8],
        match_offset: usize,
        _id: usize,
        verifier: &Verifier,
    ) {
        // Walk backwards from the match to find the start of the key token
        let mut start = match_offset.saturating_sub(1);
        while start > 0 && Self::is_valid_key_char(px[start - 1]) {
            start -= 1;
        }

        // Extract the key token forward from `start`
        let mut key_bytes = Vec::with_capacity(256);
        for i in start..px.len() {
            if Self::is_valid_key_char(px[i]) {
                if key_bytes.len() < 511 {
                    key_bytes.push(px[i]);
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        let key = match std::str::from_utf8(&key_bytes) {
            Ok(s) => s,
            Err(_) => return,
        };
        let key_len = key.len();

        // --- Heuristic rejection filters ---
        if !self.passes_filters(ip_str, key) {
            return;
        }

        // --- Pattern matching ---
        let mut detected_provider = "Unknown";
        let mut detected_category = "unknown";
        let mut pass = false;

        for pattern in KEY_PATTERNS {
            if key.starts_with(pattern.prefix) && key_len >= pattern.min_len {
                pass = true;
                detected_provider = pattern.provider;
                detected_category = pattern.category;
                break;
            }
        }

        // JWT heuristic: tokens starting with "ey" that look like base64url-encoded
        // three-part dot-separated tokens (header.payload.signature).
        if !pass && key.starts_with("ey") && key_len >= 60 {
            if let Some((provider, category)) = detect_jwt(key) {
                pass = true;
                detected_provider = provider;
                detected_category = category;
            }
        }

        if !pass {
            return;
        }

        // Dedup: skip if we've already seen this (ip, key) pair
        {
            let mut cache = self.cache.lock();
            if cache.is_duplicate(ip_str, key) {
                return;
            }
            cache.insert(ip_str, key);
        }

        self.stats.total_potential_keys.fetch_add(1, Ordering::Relaxed);
        self.stats.total_keys_found.fetch_add(1, Ordering::Relaxed);

        log::info!("FOUND: {:<20} [{}]", &key[..key_len.min(20)], detected_provider);

        verifier.submit(
            ip_str,
            key,
            detected_provider,
            detected_category,
        );
    }

    /// Apply heuristic filters to reject known false positives.
    fn passes_filters(&self, ip_str: &str, key: &str) -> bool {
        let key_len = key.len();

        // Too short to be meaningful
        if key_len < 10 {
            return false;
        }

        // AWS example key
        if key.contains("AKIAIOSFODNN7EXAMPLE") {
            return false;
        }

        // Base64-encoded image headers (PNG, GIF, JPEG)
        if key.starts_with("iVBOR") || key.starts_with("R0lGOD") || key.starts_with("/9j/") {
            return false;
        }

        // Long base64 blobs that look like DER/PEM certificates
        if key.starts_with("MII") && key_len > 100 {
            return false;
        }

        // Data URIs, URLs, PEM blocks
        if key.starts_with("data:")
            || key.starts_with("http://")
            || key.starts_with("https://")
            || key.starts_with("-----BEGIN")
        {
            return false;
        }

        // Monotonous strings (all same character)
        let first = key.as_bytes()[0];
        if key.bytes().all(|b| b == first) {
            return false;
        }

        // For longer keys, reject if >80% of characters are the same character
        if key_len > 20 {
            let bytes = key.as_bytes();
            let mut max_count = 0usize;
            for i in 0..key_len {
                let target = bytes[i];
                let count = bytes[i..].iter().filter(|&&b| b == target).count();
                if count > max_count {
                    max_count = count;
                }
            }
            if max_count * 100 / key_len > 80 {
                return false;
            }
        }

        true
    }
}

impl Default for GreyhatScanner {
    fn default() -> Self {
        Self::new(false)
    }
}

// ---------------------------------------------------------------------------
// JWT detection helper
// ---------------------------------------------------------------------------

/// Detect whether `key` looks like a JWT token (three base64url-encoded,
/// dot-separated parts each at least 10 chars).
///
/// Returns `Some(("JWT Token", "jwt"))` if valid, `None` otherwise.
fn detect_jwt(key: &str) -> Option<(&'static str, &'static str)> {
    let bytes = key.as_bytes();
    let mut dot_positions = Vec::with_capacity(5);

    for (i, &b) in bytes.iter().enumerate() {
        if b == b'.' {
            dot_positions.push(i);
        } else if !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'=') {
            return None; // invalid base64url character
        }
    }

    if dot_positions.len() < 2 {
        return None;
    }

    let part1_len = dot_positions[0];
    let part2_len = dot_positions[1] - dot_positions[0] - 1;
    let part3_len = key.len() - dot_positions[1] - 1;

    if part1_len < 10 || part2_len < 10 || part3_len < 10 {
        return None;
    }

    // Reject source maps which also have dot-separated base64 segments
    let source_map_markers = [
        "mappings", "sources", "webpack", "sourceMappingURL", "names", "file\"",
    ];
    for marker in &source_map_markers {
        if key.contains(marker) {
            return None;
        }
    }

    Some(("JWT Token", "jwt"))
}

// ---------------------------------------------------------------------------
// Utility: ASCII lowercasing for non-UTF8 bytes
// ---------------------------------------------------------------------------

/// Lowercase ASCII bytes, replacing non-ASCII with `?`. Used only for
/// quick HTML-marker detection on response headers/bodies.
fn to_lowercase_lossy(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii() {
                (b as char).to_ascii_lowercase()
            } else {
                '?'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seen_cache_dedup() {
        let mut cache = SeenCache::new();
        assert!(!cache.is_duplicate("1.2.3.4", "AKIA1234567890ABCDEF"));
        cache.insert("1.2.3.4", "AKIA1234567890ABCDEF");
        assert!(cache.is_duplicate("1.2.3.4", "AKIA1234567890ABCDEF"));
        // Different IP → not duplicate
        assert!(!cache.is_duplicate("5.6.7.8", "AKIA1234567890ABCDEF"));
    }

    #[test]
    fn test_filter_rejects_known_false_positives() {
        let scanner = GreyhatScanner::new(true);
        assert!(!scanner.passes_filters("1.1.1.1", "AKIAIOSFODNN7EXAMPLE1"));
        assert!(!scanner.passes_filters("1.1.1.1", "iVBORw0KGgoAAAANSUhEUgAAAA"));
        assert!(!scanner.passes_filters("1.1.1.1", "R0lGODlhAQABAIAAAAAAAP"));
        assert!(!scanner.passes_filters("1.1.1.1", "/9j/4AAQSkZJRgABAQEASABIAAD"));
        assert!(!scanner.passes_filters("1.1.1.1", "https://example.com"));
        assert!(!scanner.passes_filters("1.1.1.1", "-----BEGINCERTIFICATE-----"));
        assert!(!scanner.passes_filters("1.1.1.1", "short"));
        assert!(!scanner.passes_filters("1.1.1.1", "AAAAAAAAAAAAAAAAAAAAAA")); // monotonous
    }

    #[test]
    fn test_filter_accepts_real_keys() {
        let scanner = GreyhatScanner::new(true);
        assert!(scanner.passes_filters("1.1.1.1", "ghp_aBcDeFgHiJkLmNoPqRsT"));
        assert!(scanner.passes_filters("1.1.1.1", "gsk_TestAbcdefghijklmnopqrstuvwxyz12345"));
    }

    #[test]
    fn test_jwt_detection() {
        // Valid-looking JWT
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP04sLbKE";
        assert_eq!(detect_jwt(jwt), Some(("JWT Token", "jwt")));

        // Source map content in token body → rejected
        let sm = "eyJhbGciOiJIUzI1NiJ9.eyJzb3VyY2VzIjpbXX0.sources_webpack_mapping_data";
        assert!(detect_jwt(sm).is_none());

        // Too short parts → rejected
        let short = "abc.def.ghi";
        assert!(detect_jwt(short).is_none());
    }
}

/// Initialize the greyhat detection system.
pub fn init() {
    // TODO: implement
}
