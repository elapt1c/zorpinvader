//! Wire protocol shared by the controller and its clients.
//!
//! Everything is JSON over HTTP/1.1. Being ordinary HTTP means the controller
//! can sit behind any reverse proxy or tunnel (`cloudflared`, Caddy, nginx) and
//! clients can reach it as either `http://` or `https://` without the binary
//! needing its own TLS stack.
//!
//! Two invariants hold for every message here:
//!
//! * A client never decides *what* to scan — the controller sends the block, the
//!   ports, the rate cap and the settings. A client decides only *how* (its
//!   adapter, its own thread pool).
//! * Results are delivered independently of scheduling. A block can be marked
//!   complete while results are retried, and results for an expired lease are
//!   still accepted — losing a found key because a lease timed out would be
//!   indefensible.

use serde::{Deserialize, Serialize};

/// Protocol version. Bumped on breaking changes; the controller rejects
/// mismatched clients with a clear message instead of misparsing them.
pub const API_VERSION: u32 = 1;

pub const PATH_JOIN: &str = "/api/v1/join";
pub const PATH_CLAIM: &str = "/api/v1/claim";
pub const PATH_PROGRESS: &str = "/api/v1/progress";
pub const PATH_RESULTS: &str = "/api/v1/results";
pub const PATH_COMPLETE: &str = "/api/v1/complete";
pub const PATH_RELEASE: &str = "/api/v1/release";
pub const PATH_STATUS: &str = "/api/v1/status";
pub const PATH_COVERAGE: &str = "/api/v1/coverage";
pub const PATH_HEALTH: &str = "/healthz";

/// A discovered open port, as reported by a client.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HitRecord {
    pub ip: String,
    pub port: u16,
}

/// A confirmed API key, as written by the verifier to `found_keys.csv`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRecord {
    #[serde(default)]
    pub confirmed: bool,
    #[serde(default)]
    pub ip: String,
    pub key: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Join
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct JoinRequest {
    #[serde(default)]
    pub api_version: u32,
    #[serde(default)]
    pub name: String,
    /// The client's own rate ceiling; 0 means "whatever the controller says".
    #[serde(default)]
    pub pps_cap: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinResponse {
    pub api_version: u32,
    pub client_id: String,
    pub server_version: String,
    pub ports: String,
    pub block_size: u64,
    pub blocks_total: u64,
    pub lease_s: u64,
    pub include_safe: bool,
    pub tpc: usize,
}

// ---------------------------------------------------------------------------
// Claim
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimRequest {
    pub client_id: String,
    #[serde(default)]
    pub pps_cap: f64,
}

/// One unit of work handed to a client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobWire {
    pub job_id: u64,
    pub begin: u32,
    pub end: u32,
    pub cidr: String,
    pub ports: String,
    pub rate: f64,
    /// Resume offset within the block's probe space (0 = from the start).
    pub resume_pos: u64,
    pub lease_s: u64,
    pub include_safe: bool,
    pub tpc: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimResponse {
    pub job: Option<JobWire>,
    /// Aggregate-rate share this client should currently use.
    pub rate: f64,
    /// True when every block is covered; the client should exit.
    pub done: bool,
    pub blocks_remaining: u64,
}

// ---------------------------------------------------------------------------
// Progress
// ---------------------------------------------------------------------------

/// Client telemetry. Sent every few seconds; this is what the controller's
/// dashboard renders, so it carries enough for a live per-node view rather than
/// only the scheduler's bookkeeping.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProgressRequest {
    pub client_id: String,
    pub job_id: u64,
    #[serde(default)]
    pub pos: u64,
    #[serde(default)]
    pub syns: u64,
    #[serde(default)]
    pub synacks: u64,
    /// Probes in the current block.
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub hits: u64,
    #[serde(default)]
    pub keys: u64,
    /// Client-measured packets per second.
    #[serde(default)]
    pub rate: f64,
    /// Current block, for display (e.g. `10.4.5.0/24`).
    #[serde(default)]
    pub block: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProgressResponse {
    /// Updated rate share (the controller rebalances as clients come and go).
    pub rate: f64,
    /// Set when this job is no longer assigned here (lease expired, block
    /// reassigned); the client should stop and claim something new.
    pub cancel: bool,
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResultsRequest {
    pub client_id: String,
    #[serde(default)]
    pub job_id: u64,
    #[serde(default)]
    pub hits: Vec<HitRecord>,
    #[serde(default)]
    pub keys: Vec<KeyRecord>,
    #[serde(default)]
    pub syns: u64,
    #[serde(default)]
    pub synacks: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResultsResponse {
    pub accepted_hits: u64,
    pub accepted_keys: u64,
    pub duplicate_hits: u64,
    pub duplicate_keys: u64,
}

// ---------------------------------------------------------------------------
// Complete / release
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CompleteRequest {
    pub client_id: String,
    pub job_id: u64,
    #[serde(default)]
    pub pos: u64,
    /// Final counters for the block; the controller accounts for them here so a
    /// block with no hits still contributes to the rate and progress totals.
    #[serde(default)]
    pub syns: u64,
    #[serde(default)]
    pub synacks: u64,
    /// Also the block's final telemetry. Blocks are often shorter than the
    /// progress interval (a /16 at 160k pps is under two seconds), so without
    /// this the dashboard never sees a position, a rate or a hit count.
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub hits: u64,
    #[serde(default)]
    pub keys: u64,
    #[serde(default)]
    pub rate: f64,
    #[serde(default)]
    pub block: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CompleteResponse {
    pub ok: bool,
    /// True when the block was already recorded as complete.
    pub duplicate: bool,
    pub blocks_remaining: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ReleaseRequest {
    pub client_id: String,
    pub job_id: u64,
    #[serde(default)]
    pub pos: u64,
    #[serde(default)]
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Status / coverage
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClientSnapshot {
    pub id: String,
    pub name: String,
    pub job_id: Option<u64>,
    pub pps: f64,
    pub syns: u64,
    pub synacks: u64,
    pub idle_s: u64,
    #[serde(default)]
    pub block: String,
    #[serde(default)]
    pub pos: u64,
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub hits: u64,
    #[serde(default)]
    pub keys: u64,
    /// Blocks this node has finished, so a row shows progress even when the
    /// current block is shorter than the telemetry interval.
    #[serde(default)]
    pub blocks: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StatusResponse {
    pub api_version: u32,
    pub running: bool,
    pub ports: String,
    pub blocks_total: u64,
    pub blocks_done: u64,
    pub blocks_inflight: u64,
    pub blocks_partial: u64,
    pub blocks_remaining: u64,
    pub addresses_total: u64,
    pub addresses_done: u64,
    pub targets: Vec<String>,
    pub done_cidrs: Vec<String>,
    pub remaining_cidrs: Vec<String>,
    pub percent: f64,
    pub syns: u64,
    pub synacks: u64,
    pub hits: u64,
    pub keys: u64,
    pub rate_pps: f64,
    pub elapsed_s: u64,
    pub eta_s: u64,
    pub clients: Vec<ClientSnapshot>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CoverageResponse {
    pub addresses_total: u64,
    pub addresses_done: u64,
    pub percent: f64,
    pub done_cidrs: Vec<String>,
    pub remaining_cidrs: Vec<String>,
    pub blocks_total: u64,
    pub blocks_done: u64,
    pub blocks_partial: u64,
    pub blocks_inflight: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl ErrorResponse {
    pub fn new(msg: impl Into<String>) -> Self {
        ErrorResponse { error: msg.into() }
    }
}
