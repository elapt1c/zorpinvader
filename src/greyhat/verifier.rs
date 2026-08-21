//! Provider verification, heuristic context scoring, CSV output, and key-scan log.
//!
//! The verifier receives candidate API keys from the scanner and either:
//! 1. **Confirms** them by calling the provider's API (HTTP status / body check)
//! 2. **Scores** them heuristically by analysing the surrounding context in the
//!    response body (positive signals: JSON syntax, variable assignments, config
//!    files; negative signals: binary data, high entropy, base64 image blobs)
//! 3. Writes confirmed/exhausted keys to a CSV file for downstream analysis

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crossbeam_queue::ArrayQueue;
use parking_lot::{Condvar, Mutex};

// ---------------------------------------------------------------------------
// Verification result codes
// ---------------------------------------------------------------------------

/// Outcome of verifying a candidate key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyResult {
    /// Provider API confirmed the key is valid.
    Confirmed,
    /// Provider API rejected the key.
    Rejected,
    /// Key is unverified (provider has no live verifier) but was detected
    /// with a known prefix.
    Detected,
    /// Key was confirmed but the provider account is exhausted / rate-limited.
    Exhausted,
}

impl VerifyResult {
    fn as_i32(self) -> i32 {
        match self {
            Self::Confirmed => 1,
            Self::Rejected => 0,
            Self::Exhausted => 3,
            Self::Detected => 2,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Confirmed => "CONFIRMED",
            Self::Rejected => "REJECTED",
            Self::Exhausted => "EXHAUSTED",
            Self::Detected => "DETECTED",
        }
    }
}

// ---------------------------------------------------------------------------
// Verify job
// ---------------------------------------------------------------------------

/// A candidate key awaiting verification.
#[derive(Debug, Clone)]
struct VerifyJob {
    ip: String,
    key: String,
    provider: String,
    category: String,
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/// Atomic counters for verifier activity.
pub struct VerifierStats {
    pub valid: AtomicU64,
    pub invalid: AtomicU64,
    pub pending: AtomicI64,
}

impl Default for VerifierStats {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifierStats {
    pub fn new() -> Self {
        Self {
            valid: AtomicU64::new(0),
            invalid: AtomicU64::new(0),
            pending: AtomicI64::new(0),
        }
    }
}

// ---------------------------------------------------------------------------
// Key scan log (ring buffer for TUI)
// ---------------------------------------------------------------------------

const KEY_LOG_SIZE: usize = 12;

/// A small ring buffer holding the most recent key-scan results for
/// display in the TUI.
pub struct KeyScanLog {
    entries: Mutex<[String; KEY_LOG_SIZE]>,
    ptr: Mutex<usize>,
}

impl KeyScanLog {
    fn new() -> Self {
        Self {
            entries: Mutex::new(std::array::from_fn(|_| String::new())),
            ptr: Mutex::new(0),
        }
    }

    /// Append a result entry.
    fn push(&self, result: VerifyResult, ip: &str, key: &str, provider: &str) {
        let short_key = truncate_key(key, 36);
        let short_prov = truncate_str(provider, 32);
        let entry = format!(
            "[{}] {:<36} | {}",
            result.label(),
            short_key,
            short_prov,
        );

        let mut ptr = self.ptr.lock();
        let mut entries = self.entries.lock();
        entries[*ptr] = entry;
        *ptr = (*ptr + 1) % KEY_LOG_SIZE;
    }

    /// Snapshot the ring buffer for display.
    pub fn snapshot(&self) -> (Vec<String>, usize) {
        let entries = self.entries.lock();
        let ptr = *self.ptr.lock();
        (entries.to_vec(), ptr)
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers (curl subprocess)
// ---------------------------------------------------------------------------

/// URL-encode characters that are unsafe in shell arguments.
fn escape_url(url: &str) -> String {
    let mut out = String::with_capacity(url.len() + 16);
    for c in url.bytes() {
        match c {
            b'(' | b')' | b'{' | b'}' | b'[' | b']'
            | b'&' | b';' | b'|' | b'<' | b'>' | b' '
            | b'$' | b'`' | b'"' => {
                out.push_str(&format!("%{:02X}", c));
            }
            _ => out.push(c as char),
        }
    }
    out
}

/// Issue an HTTP request via `curl` and return the status code.
fn http_status(url: &str, method: &str, headers: &[String]) -> u16 {
    let escaped = escape_url(url);
    let mut cmd = Command::new("/usr/bin/curl");
    cmd.args([
        "-s", "-o", "/dev/null",
        "-w", "%{http_code}",
        "-m", "10",
        "--connect-timeout", "5",
    ]);
    if method != "GET" {
        cmd.args(["-X", method]);
    }
    for h in headers {
        cmd.args(["-H", h]);
    }
    cmd.arg(&escaped);
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());

    match cmd.output() {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out.stdout);
            s.trim().parse().unwrap_or(0)
        }
        Err(_) => 0,
    }
}

/// Issue an HTTP request via `curl` and return both status code and body.
fn http_body(url: &str, headers: &[String], max_body: usize) -> (u16, String) {
    let escaped = escape_url(url);
    let mut cmd = Command::new("/usr/bin/curl");
    cmd.args(["-s", "-w", "\n%{http_code}", "-m", "10", "--connect-timeout", "5"]);
    for h in headers {
        cmd.args(["-H", h]);
    }
    cmd.arg(&escaped);
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());

    match cmd.output() {
        Ok(out) => {
            let raw = String::from_utf8_lossy(&out.stdout).into_owned();
            let mut body = raw;
            let mut status = 0u16;
            if let Some(nl) = body.rfind('\n') {
                let code_str = body[nl + 1..].trim();
                status = code_str.parse().unwrap_or(0);
                body.truncate(nl);
            }
            body.truncate(max_body);
            (status, body)
        }
        Err(_) => (0, String::new()),
    }
}

/// Issue an HTTP POST with a JSON body via `curl`.
fn http_post_json(url: &str, json: &str, headers: &[String], max_body: usize) -> (u16, String) {
    let escaped = escape_url(url);
    let tmp_path = format!("/tmp/zorp_post_{}.json", std::process::id());

    // Write JSON body to temp file to avoid shell quoting issues
    if let Err(_) = std::fs::write(&tmp_path, json) {
        return (0, String::new());
    }

    let mut cmd = Command::new("/usr/bin/curl");
    cmd.args([
        "-s", "-w", "\n%{http_code}",
        "-m", "10", "--connect-timeout", "5",
        "-X", "POST",
    ]);
    for h in headers {
        cmd.args(["-H", h]);
    }
    cmd.args(["-d", &format!("@{}", tmp_path)]);
    cmd.arg(&escaped);
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());

    let result = match cmd.output() {
        Ok(out) => {
            let raw = String::from_utf8_lossy(&out.stdout).into_owned();
            let mut body = raw;
            let mut status = 0u16;
            if let Some(nl) = body.rfind('\n') {
                let code_str = body[nl + 1..].trim();
                status = code_str.parse().unwrap_or(0);
                body.truncate(nl);
            }
            body.truncate(max_body);
            (status, body)
        }
        Err(_) => (0, String::new()),
    };

    let _ = std::fs::remove_file(&tmp_path);
    result
}

/// HTTP basic auth request via curl.
fn http_status_basic(url: &str, user: &str, pass: &str) -> u16 {
    let mut cmd = Command::new("/usr/bin/curl");
    cmd.args([
        "-s", "-o", "/dev/null",
        "-w", "%{http_code}",
        "-m", "10", "--connect-timeout", "5",
        "-u", &format!("{}:{}", user, pass),
        url,
    ]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());

    match cmd.output() {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out.stdout);
            s.trim().parse().unwrap_or(0)
        }
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// Provider verifier functions
// ---------------------------------------------------------------------------

/// Type alias for a provider-specific verification function.
///
/// Takes the API key and returns `true` if the provider confirmed it.
type VerifyFn = fn(key: &str) -> VerifyResult;

fn verify_unsupported(_key: &str) -> VerifyResult {
    VerifyResult::Rejected
}

fn verify_unverifiable(_key: &str) -> VerifyResult {
    VerifyResult::Detected
}

// -- Individual provider verifiers ----------------------------------------

fn verify_openai(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://api.openai.com/v1/models", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_google(key: &str) -> VerifyResult {
    let url = format!(
        "https://www.googleapis.com/youtube/v3/videos?part=snippet&id=dQw4w4WgXcQ&key={}",
        key
    );
    if http_status(&url, "GET", &[]) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_github(key: &str) -> VerifyResult {
    let auth = format!("Authorization: token {}", key);
    let headers = [auth, "Accept: application/vnd.github.v3+json".to_string()];
    if http_status("https://api.github.com", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_stripe(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    let (_status, body) = http_body("https://api.stripe.com/v1/account", &headers, 1024);
    if body.contains("secret_key_required")
        || body.contains("invalid_api_key")
        || body.contains("\"object\"")
    {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_slack(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    let (_status, body) = http_body("https://slack.com/api/auth.test", &headers, 256);
    if body.contains("\"ok\":true") {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_datadog(key: &str) -> VerifyResult {
    let auth = format!("DD-API-KEY: {}", key);
    let headers = [auth];
    if http_status("https://api.datadoghq.com/api/v1/user", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_circleci(key: &str) -> VerifyResult {
    let auth = format!("Circle-Token: {}", key);
    let headers = [auth];
    if http_status("https://circleci.com/api/v2/me", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_huggingface(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://huggingface.co/api/whoami-v2", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_discord(key: &str) -> VerifyResult {
    let auth = format!("Authorization: {}", key);
    let headers = [auth];
    if http_status("https://discord.com/api/users/@me", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_twitter(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    let s = http_status(
        "https://api.twitter.com/2/tweets/search/recent?query=hello&max_results=1",
        "GET",
        &headers,
    );
    if s == 200 || s == 403 || s == 429 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_groq(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://api.groq.com/openai/v1/models", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_anthropic(key: &str) -> VerifyResult {
    let auth = format!("x-api-key: {}", key);
    let headers = [auth, "anthropic-version: 2023-06-01".to_string()];
    let s = http_status("https://api.anthropic.com/v1/models", "GET", &headers);
    if s == 200 || s == 400 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_digitalocean(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://api.digitalocean.com/v2/account", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_gitlab(key: &str) -> VerifyResult {
    let auth = format!("PRIVATE-TOKEN: {}", key);
    let headers = [auth];
    if http_status("https://gitlab.com/api/v4/user", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_sendgrid(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://api.sendgrid.com/v3/user", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_fastly(key: &str) -> VerifyResult {
    let auth = format!("Fastly-Key: {}", key);
    let headers = [auth];
    if http_status("https://api.fastly.com/currentuser", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_cohere(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://api.cohere.ai/v1/models", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_deepseek(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://api.deepseek.com/user", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_fireworks(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://api.fireworks.ai/inference/v1/models", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_mistral(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://api.mistral.ai/v1/models", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_nvidia(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://integrate.api.nvidia.com/v1/models", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_together(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://api.together.xyz/v1/models", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_azure(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status(
        "https://management.azure.com/subscriptions?api-version=2022-12-01",
        "GET",
        &headers,
    ) == 200
    {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_alibaba(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status(
        "https://dashscope.aliyuncs.com/compatible-mode/v1/models",
        "GET",
        &headers,
    ) == 200
    {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_cloudflare(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status(
        "https://api.cloudflare.com/client/v4/user/tokens/verify",
        "GET",
        &headers,
    ) == 200
    {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_heroku(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [
        auth,
        "Accept: application/vnd.heroku+json; version=3".to_string(),
    ];
    if http_status("https://api.heroku.com/account", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_replicate(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://api.replicate.com/v1/user", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_elevenlabs(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://api.elevenlabs.io/v1/user", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_square(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://connect.squareup.com/v2/locations", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_linear(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://api.linear.app/graphql", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_sentry(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://sentry.io/api/0/", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_npm(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://registry.npmjs.org/-/npm/v1/user", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_rubygems(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://rubygems.org/api/v1/profiles/me.json", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_flutterwave(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://api.flutterwave.com/v3/balances", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_assemblyai(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://api.assemblyai.com/v1/user", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_vercel(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://api.vercel.com/v2/user", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_openrouter(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [
        auth,
        "HTTP-Referer: http://zorpinvader.local".to_string(),
        "X-Title: ZorpInvader".to_string(),
    ];
    if http_status("https://openrouter.ai/api/v1/auth/key", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_voyage(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth];
    if http_status("https://api.voyageai.com/v1/models", "GET", &headers) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_paypal(key: &str) -> VerifyResult {
    let url = format!(
        "https://api-m.paypal.com/v1/oauth2/token?grant_type=client_credentials&client_id={}",
        key
    );
    let s = http_status(&url, "POST", &[]);
    if s == 200 || s == 401 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_meta(key: &str) -> VerifyResult {
    let url = format!("https://graph.facebook.com/me?access_token={}", key);
    if http_status(&url, "GET", &[]) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_twilio(key: &str) -> VerifyResult {
    if http_status_basic("https://api.twilio.com/2010-04-01/Accounts.json", key, "") == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_pypi(key: &str) -> VerifyResult {
    if http_status_basic("https://pypi.org/_/api/accounts/me/", key, "token") == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_mailgun(key: &str) -> VerifyResult {
    if http_status_basic("https://api.mailgun.net/v3/domains", "api", key) == 200 {
        VerifyResult::Confirmed
    } else {
        VerifyResult::Rejected
    }
}

fn verify_dashscope(key: &str) -> VerifyResult {
    let auth = format!("Authorization: Bearer {}", key);
    let headers = [auth, "Content-Type: application/json".to_string()];
    let json = r#"{"model":"qwen-turbo","messages":[{"role":"user","content":"hi"}]}"#;
    let (status, _body) = http_post_json(
        "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
        json,
        &headers,
        2048,
    );
    match status {
        200 => VerifyResult::Confirmed,
        400 => VerifyResult::Exhausted,
        _ => VerifyResult::Rejected,
    }
}

// ---------------------------------------------------------------------------
// Provider → verifier lookup
// ---------------------------------------------------------------------------

/// Build the mapping from provider category to its verification function.
fn build_verifier_map() -> HashMap<&'static str, VerifyFn> {
    let mut m = HashMap::new();
    let entries: &[(&str, VerifyFn)] = &[
        ("openai", verify_openai),
        ("google", verify_google),
        ("github", verify_github),
        ("stripe", verify_stripe),
        ("slack", verify_slack),
        ("datadog", verify_datadog),
        ("circleci", verify_circleci),
        ("huggingface", verify_huggingface),
        ("hf", verify_huggingface),
        ("discord", verify_discord),
        ("twitter", verify_twitter),
        ("groq", verify_groq),
        ("anthropic", verify_anthropic),
        ("twilio", verify_twilio),
        ("digitalocean", verify_digitalocean),
        ("gitlab", verify_gitlab),
        ("sendgrid", verify_sendgrid),
        ("fastly", verify_fastly),
        ("cohere", verify_cohere),
        ("deepseek", verify_deepseek),
        ("fireworks", verify_fireworks),
        ("mistral", verify_mistral),
        ("nvidia", verify_nvidia),
        ("together", verify_together),
        ("azure", verify_azure),
        ("jwt", verify_azure),
        ("alibaba", verify_alibaba),
        ("cloudflare", verify_cloudflare),
        ("heroku", verify_heroku),
        ("pypi", verify_pypi),
        ("mailgun", verify_mailgun),
        ("replicate", verify_replicate),
        ("elevenlabs", verify_elevenlabs),
        ("square", verify_square),
        ("linear", verify_linear),
        ("sentry", verify_sentry),
        ("npm", verify_npm),
        ("rubygems", verify_rubygems),
        ("flutterwave", verify_flutterwave),
        ("assemblyai", verify_assemblyai),
        ("vercel", verify_vercel),
        ("openrouter", verify_openrouter),
        ("voyage", verify_voyage),
        ("paypal", verify_paypal),
        ("meta", verify_meta),
        ("dashscope", verify_dashscope),
        // Unverifiable providers — no live API check
        ("aws", verify_unverifiable),
        ("databricks", verify_unverifiable),
        // Skipped providers — contextual/unknown labels
        ("Contextual (label match)", verify_unverifiable),
        ("Unknown", verify_unverifiable),
    ];
    for &(name, f) in entries {
        m.insert(name, f);
    }
    m
}

// ---------------------------------------------------------------------------
// Heuristic context-based verification scoring
// ---------------------------------------------------------------------------

/// Analyse the context surrounding a detected key within a response body to
/// produce a confidence score. Positive signals indicate the key appears in
/// source code or configuration; negative signals indicate binary data or
/// high-entropy noise.
///
/// Returns a score in the range `[-100, +100]`.
/// - **Positive** scores suggest a legitimate key in structured context
/// - **Negative** scores suggest a false positive (binary data, base64 blob)
pub fn context_score(key: &str, surrounding: &[u8]) -> i32 {
    let mut score: i32 = 0;

    // --- Positive signals: structured / code context ---

    // Key appears in quotes: "key" or 'key'
    if surrounding.contains(&b'"') || surrounding.contains(&b'\'') {
        score += 10;
    }

    // JSON-style context: "key": "value" or "apikey": "..."
    let lower = ascii_lower(surrounding);
    let json_markers = [
        "api_key", "apikey", "api-key", "token", "secret",
        "auth", "credential", "access_key", "private_key",
    ];
    for marker in &json_markers {
        if lower.contains(marker) {
            score += 15;
            break;
        }
    }

    // Variable assignment patterns
    let assign_markers = [
        "const ", "let ", "var ", "export ", "import ",
        "process.env.", "os.environ", "ENV[",
        "config.", "settings.",
    ];
    for marker in &assign_markers {
        if lower.contains(marker) {
            score += 20;
            break;
        }
    }

    // Config file indicators
    let config_markers = [
        ".env", ".ini", "[section]", "[default]",
        "key =", "key:", "password:",
    ];
    for marker in &config_markers {
        if lower.contains(marker) {
            score += 15;
            break;
        }
    }

    // --- Negative signals: binary / noise ---

    // Null bytes → binary data
    let null_count = surrounding[..surrounding.len().min(256)]
        .iter()
        .filter(|&&b| b == 0)
        .count();
    if null_count > 0 {
        score -= 30;
    }

    // High proportion of non-printable bytes → binary
    let non_print = surrounding[..surrounding.len().min(256)]
        .iter()
        .filter(|&&b| b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t')
        .count();
    let sample_len = surrounding.len().min(256);
    if sample_len > 0 && non_print * 100 / sample_len > 40 {
        score -= 25;
    }

    // Key itself has very high character repetition → noise
    let key_bytes = key.as_bytes();
    if key_bytes.len() > 20 {
        let mut max_freq = 0usize;
        for i in 0..key_bytes.len() {
            let target = key_bytes[i];
            let count = key_bytes.iter().filter(|&&b| b == target).count();
            if count > max_freq {
                max_freq = count;
            }
        }
        let pct = max_freq * 100 / key_bytes.len();
        if pct > 60 {
            score -= 20;
        } else if pct > 40 {
            score -= 10;
        }
    }

    score.clamp(-100, 100)
}

// ---------------------------------------------------------------------------
// CSV writer
// ---------------------------------------------------------------------------

/// Thread-safe CSV writer for confirmed keys.
struct CsvWriter {
    file: Mutex<Option<File>>,
}

impl CsvWriter {
    fn open(path: &Path) -> Self {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok();

        // Write header if file is new / empty
        if let Some(ref f) = file {
            if let Ok(meta) = f.metadata() {
                if meta.len() == 0 {
                    let mut f = f.try_clone().ok();
                    if let Some(ref mut f) = f {
                        let _ = writeln!(
                            f,
                            "confirmed,ip_address,api_key,provider,category,timestamp"
                        );
                        let _ = f.flush();
                    }
                }
            }
        }

        Self {
            file: Mutex::new(file),
        }
    }

    /// Write a row. `confirmed` is the numeric code from `VerifyResult::as_i32`.
    fn write_row(
        &self,
        confirmed: i32,
        ip: &str,
        key: &str,
        provider: &str,
        category: &str,
    ) {
        // Dedup: check if key already exists in file
        if self.key_exists_in_file(key) {
            return;
        }

        let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");

        let mut guard = self.file.lock();
        if let Some(ref mut f) = *guard {
            let _ = writeln!(f, "{},{},{},{},{},{}", confirmed, ip, key, provider, category, ts);
            let _ = f.flush();
        }
    }

    fn key_exists_in_file(&self, key: &str) -> bool {
        let guard = self.file.lock();
        // We need to re-read the file from disk to check, since the file handle
        // is opened in append mode and we can't seek to read.
        // This is a best-effort check; race conditions are acceptable.
        drop(guard); // release before reading

        if let Ok(file) = File::open("found_keys.csv") {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(line) = line {
                    if line.contains(key) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// No-op verifier (used when scanning doesn't need verification)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Multi-threaded API key verifier with CSV output.
///
/// Receives candidate keys, verifies them against provider APIs, and writes
/// confirmed keys to `found_keys.csv`.
pub struct Verifier {
    queue: Arc<ArrayQueue<VerifyJob>>,
    stats: Arc<VerifierStats>,
    key_log: Arc<KeyScanLog>,
    csv: Arc<CsvWriter>,
    verifier_map: Arc<HashMap<&'static str, VerifyFn>>,
    running: Arc<(parking_lot::Mutex<bool>, Condvar)>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Verifier {
    /// Create a no-op verifier that discards all submissions.
    /// Used when the scanner needs to run without verification (e.g. in tests
    /// or when only scanning is needed).
    pub fn noop() -> Self {
        let queue = Arc::new(ArrayQueue::new(4096));
        let stats = Arc::new(VerifierStats::new());
        let key_log = Arc::new(KeyScanLog::new());
        let csv = Arc::new(CsvWriter { file: Mutex::new(None) });
        let verifier_map = Arc::new(build_verifier_map());
        let running = Arc::new((parking_lot::Mutex::new(false), Condvar::new()));

        Self {
            queue,
            stats,
            key_log,
            csv,
            verifier_map,
            running,
            threads: Vec::new(),
        }
    }

    /// Create and start the verifier with `worker_count` threads.
    /// If `worker_count <= 0`, auto-detect based on CPU cores (1–8 workers).
    pub fn new(worker_count: i32) -> Self {
        let n = if worker_count <= 0 {
            let cpus = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4);
            (cpus / 2).clamp(1, 8)
        } else {
            worker_count as usize
        };

        let queue = Arc::new(ArrayQueue::<VerifyJob>::new(4096));
        let stats = Arc::new(VerifierStats::new());
        let key_log = Arc::new(KeyScanLog::new());
        let csv = Arc::new(CsvWriter::open(Path::new("found_keys.csv")));
        let verifier_map = Arc::new(build_verifier_map());
        let running = Arc::new((parking_lot::Mutex::new(true), Condvar::new()));

        let mut threads = Vec::with_capacity(n);
        for _ in 0..n {
            let q = Arc::clone(&queue);
            let s = Arc::clone(&stats);
            let kl = Arc::clone(&key_log);
            let c = Arc::clone(&csv);
            let vm = Arc::clone(&verifier_map);
            let rf = Arc::clone(&running);
            threads.push(std::thread::spawn(move || {
                verifier_worker(q, s, kl, c, vm, rf);
            }));
        }

        log::info!("[verifier] {} worker threads started", n);

        Self {
            queue,
            stats,
            key_log,
            csv,
            verifier_map,
            running,
            threads,
        }
    }

    /// Submit a candidate key for verification.
    pub fn submit(&self, ip: &str, key: &str, provider: &str, category: &str) {
        let job = VerifyJob {
            ip: ip.to_string(),
            key: key.to_string(),
            provider: provider.to_string(),
            category: category.to_string(),
        };

        // Best-effort push; drop oldest if full
        if self.queue.push(job).is_err() {
            let _ = self.queue.pop();
            // retry after dropping
            let job2 = VerifyJob {
                ip: ip.to_string(),
                key: key.to_string(),
                provider: provider.to_string(),
                category: category.to_string(),
            };
            let _ = self.queue.push(job2);
        }

        self.stats.pending.fetch_add(1, Ordering::Relaxed);

        // Wake a worker
        let (lock, cvar) = &*self.running;
        let _guard = lock.lock();
        cvar.notify_one();
    }

    /// Verify a key synchronously (for external callers).
    pub fn verify_api_key(&self, provider: &str, key: &str) -> VerifyResult {
        let fn_opt = self.verifier_map.get(provider).copied();
        fn_opt.map(|f| f(key)).unwrap_or(VerifyResult::Detected)
    }

    /// Borrow the verifier statistics.
    pub fn stats(&self) -> &VerifierStats {
        &self.stats
    }

    /// Borrow the key scan log.
    pub fn key_log(&self) -> &KeyScanLog {
        &self.key_log
    }

    /// Shut down all worker threads.
    pub fn shutdown(mut self) {
        {
            let (lock, cvar) = &*self.running;
            let mut flag = lock.lock();
            *flag = false;
            cvar.notify_all();
        }
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
        log::info!(
            "[verifier] shutdown: {} valid, {} invalid",
            self.stats.valid.load(Ordering::Relaxed),
            self.stats.invalid.load(Ordering::Relaxed),
        );
    }
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

fn verifier_worker(
    queue: Arc<ArrayQueue<VerifyJob>>,
    stats: Arc<VerifierStats>,
    key_log: Arc<KeyScanLog>,
    csv: Arc<CsvWriter>,
    verifier_map: Arc<HashMap<&'static str, VerifyFn>>,
    running: Arc<(parking_lot::Mutex<bool>, Condvar)>,
) {
    loop {
        let job = loop {
            if let Some(j) = queue.pop() {
                break j;
            }
            let (lock, cvar) = &*running;
            let guard = lock.lock();
            if !*guard {
                return;
            }
            let _ = cvar.wait_for(&mut { guard }, Duration::from_millis(100));
        };

        stats.pending.fetch_sub(1, Ordering::Relaxed);

        // Look up verifier: first by category, then by provider name
        let verify_fn = verifier_map
            .get(job.category.as_str())
            .or_else(|| verifier_map.get(job.provider.as_str()))
            .copied();

        let result = verify_fn
            .map(|f| f(&job.key))
            .unwrap_or(VerifyResult::Detected);

        match result {
            VerifyResult::Confirmed => {
                csv.write_row(
                    result.as_i32(),
                    &job.ip,
                    &job.key,
                    &job.provider,
                    &job.category,
                );
                stats.valid.fetch_add(1, Ordering::Relaxed);
                key_log.push(result, &job.ip, &job.key, &job.provider);
            }
            VerifyResult::Rejected => {
                stats.invalid.fetch_add(1, Ordering::Relaxed);
                key_log.push(result, &job.ip, &job.key, &job.provider);
            }
            VerifyResult::Exhausted => {
                csv.write_row(
                    result.as_i32(),
                    &job.ip,
                    &job.key,
                    &job.provider,
                    &job.category,
                );
                stats.valid.fetch_add(1, Ordering::Relaxed);
                key_log.push(result, &job.ip, &job.key, &job.provider);
            }
            VerifyResult::Detected => {
                csv.write_row(
                    result.as_i32(),
                    &job.ip,
                    &job.key,
                    &job.provider,
                    &job.category,
                );
                stats.valid.fetch_add(1, Ordering::Relaxed);
                key_log.push(result, &job.ip, &job.key, &job.provider);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Truncate a key for display: if longer than `max`, show first 15 and last 15 chars.
fn truncate_key(key: &str, max: usize) -> String {
    if key.len() > max {
        let (head, tail) = key.split_at(15);
        let tail_start = tail.len().saturating_sub(15);
        format!("{}...{}", head, &tail[tail_start..])
    } else {
        key.to_string()
    }
}

/// Truncate a string to at most `max` characters.
fn truncate_str(s: &str, max: usize) -> &str {
    if s.len() > max { &s[..max] } else { s }
}

/// Lowercase ASCII bytes into a String (lossy).
fn ascii_lower(bytes: &[u8]) -> String {
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
    fn test_verify_result_codes() {
        assert_eq!(VerifyResult::Confirmed.as_i32(), 1);
        assert_eq!(VerifyResult::Rejected.as_i32(), 0);
        assert_eq!(VerifyResult::Detected.as_i32(), 2);
        assert_eq!(VerifyResult::Exhausted.as_i32(), 3);
    }

    #[test]
    fn test_truncate_key_short() {
        assert_eq!(truncate_key("ghp_short", 36), "ghp_short");
    }

    #[test]
    fn test_truncate_key_long() {
        let long = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let result = truncate_key(long, 36);
        assert!(result.contains("..."));
        assert!(result.starts_with("ghp_aaaaaaaaaaa"));
    }

    #[test]
    fn test_context_score_code() {
        let surrounding = br#"const API_KEY = "sk_live_abc123";"#;
        let score = context_score("sk_live_abc123", surrounding);
        // Should be positive: has quotes + variable assignment
        assert!(score > 0, "code context should score positive, got {}", score);
    }

    #[test]
    fn test_context_score_binary() {
        let mut surrounding = vec![0u8; 128]; // all null bytes
        surrounding.extend_from_slice(b"sk_live_abc123");
        let score = context_score("sk_live_abc123", &surrounding);
        // Should be negative: null bytes
        assert!(score < 0, "binary context should score negative, got {}", score);
    }

    #[test]
    fn test_context_score_json_config() {
        let surrounding = br#"{"api_key": "sk_live_abc123", "env": "production"}"#;
        let score = context_score("sk_live_abc123", surrounding);
        assert!(score > 0, "JSON config should score positive, got {}", score);
    }

    #[test]
    fn test_verifier_map_coverage() {
        let map = build_verifier_map();
        // Spot-check some critical providers
        assert!(map.contains_key("openai"));
        assert!(map.contains_key("github"));
        assert!(map.contains_key("stripe"));
        assert!(map.contains_key("aws"));
        assert!(map.contains_key("jwt"));
    }

    #[test]
    fn test_escape_url() {
        assert_eq!(escape_url("https://api.example.com/path?q=hello"), "https://api.example.com/path?q=hello");
        assert_eq!(escape_url("https://x.com/a b"), "https://x.com/a%20b");
        assert_eq!(escape_url("url(1)"), "url%281%29");
    }
}
