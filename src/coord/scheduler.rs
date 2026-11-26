//! The scheduler: transport-agnostic work allocation and progress accounting.
//!
//! The same object drives all three modes — a controller behind HTTP, a client's
//! local view (via the protocol), and standalone scanning, where the scheduler is
//! called in-process with no server at all. That is deliberate: resume semantics,
//! block accounting and result de-duplication exist once, so `--resume` behaves
//! identically whether the scan ran locally or across ten machines.
//!
//! Model:
//!
//! * A **plan** divides the target set into CIDR-aligned blocks.
//! * **Coverage** is a set of addresses, not a cursor. Resuming means
//!   `targets - covered`, which is exact even if the block size or the client
//!   count changed between runs.
//! * Blocks are **leased**, not assigned. A client that stops reporting gets its
//!   block back after the lease expires, resuming where it stopped, so a dead
//!   machine costs at most one lease interval of duplicated work.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::plan::{fingerprint_hex, shuffle_order, Plan};
use super::protocol::{ClientSnapshot, CoverageResponse, KeyRecord, StatusResponse, API_VERSION};
use super::results::Results;
use super::set4::RangeSet4;

pub const STATE_VERSION: u32 = 1;

/// Seconds a block stays leased without a progress report before it is handed
/// back to the pool.
pub const DEFAULT_LEASE_S: u64 = 180;

/// A client that has not been heard from for this long is dropped from the
/// status view and from the rate split.
const CLIENT_TTL_S: u64 = 90;

#[derive(Clone, Debug)]
pub struct Options {
    pub state_path: PathBuf,
    pub results_dir: PathBuf,
    pub lease_s: u64,
    pub include_safe: bool,
    pub tpc: usize,
    /// Aggregate packet rate for the whole scan; 0 means uncapped.
    pub target_rate: f64,
    /// Start over even if `state_path` holds a scan.
    pub reset: bool,
}

/// A unit of work as handed out to a client.
#[derive(Clone, Debug)]
pub struct JobSpec {
    pub job_id: u64,
    pub begin: u32,
    pub end: u32,
    pub cidr: String,
    pub ports: String,
    pub rate: f64,
    pub resume_pos: u64,
    pub lease_s: u64,
    pub include_safe: bool,
    pub tpc: usize,
}

/// One confirmed key, as shown in the controller's key log.
#[derive(Clone, Debug)]
pub struct KeyEvent {
    pub at: String,
    pub key: String,
    pub provider: String,
    pub client: String,
    pub ip: String,
}

/// How clients reach this controller. Written into the progress file so a worker
/// can be started by copying one line out of it.
#[derive(Clone, Debug, Default)]
pub struct ConnectionInfo {
    pub listen: String,
    pub onion: Option<String>,
    pub url: String,
    pub token: String,
    pub connect: String,
}

#[derive(Clone, Debug)]
pub enum Claim {
    Job(Box<JobSpec>),
    /// Work exists but everything is currently leased elsewhere.
    Waiting,
    /// Every block is covered.
    Done,
}

#[derive(Default, Clone, Copy)]
struct Stats {
    syns: u64,
    synacks: u64,
}

struct Inflight {
    client: String,
    lease_until: Instant,
    pos: u64,
    reported_syns: u64,
    reported_synacks: u64,
    last_syns: u64,
    last_sample: Instant,
    pps: f64,
}

struct ClientEntry {
    name: String,
    last_seen: Instant,
    job: Option<u64>,
    pps: f64,
    syns: u64,
    synacks: u64,
    /// Telemetry for the dashboard, reported by the client.
    block: String,
    pos: u64,
    total: u64,
    hits: u64,
    keys: u64,
}

/// Durable slice of a scheduler.
#[derive(Serialize, Deserialize)]
struct StateFile {
    version: u32,
    created: String,
    saved: String,
    fingerprint: String,
    ports: String,
    targets: Vec<String>,
    chunk: u64,
    seed: u64,
    next_ptr: usize,
    done: Vec<String>,
    partial: Vec<(u64, u64)>,
    inflight: Vec<(u64, u64, String)>,
    syns: u64,
    synacks: u64,
    #[serde(default)]
    onion: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    listen: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    connect: String,
}

pub struct Scheduler {
    pub plan: Plan,
    opts: Options,
    done: RangeSet4,
    partial: BTreeMap<u64, u64>,
    inflight: BTreeMap<u64, Inflight>,
    order: Vec<u64>,
    seed: u64,
    next_ptr: usize,
    stats: Stats,
    clients: HashMap<String, ClientEntry>,
    results: Results,
    started: Instant,
    created: String,
    dirty: bool,
    rate_pps: f64,
    last_rate_sample: (Instant, u64),
    connection: Option<ConnectionInfo>,
    keys_log: VecDeque<KeyEvent>,
    key_log_cap: usize,
}

impl Scheduler {
    /// Open an existing scan or start a new one, enforcing plan identity.
    pub fn load_or_create(plan: Plan, opts: Options) -> Result<Self, String> {
        if opts.reset && opts.state_path.exists() {
            std::fs::remove_file(&opts.state_path)
                .map_err(|e| format!("cannot remove {}: {}", opts.state_path.display(), e))?;
        }

        let results = Results::open(&opts.results_dir)?;

        let mut scheduler = Scheduler {
            order: plan.order.clone(),
            seed: plan.seed,
            plan,
            opts,
            done: RangeSet4::new(),
            partial: BTreeMap::new(),
            inflight: BTreeMap::new(),
            next_ptr: 0,
            stats: Stats::default(),
            clients: HashMap::new(),
            results,
            started: Instant::now(),
            created: super::results::timestamp(),
            dirty: false,
            rate_pps: 0.0,
            last_rate_sample: (Instant::now(), 0),
            connection: None,
            keys_log: VecDeque::new(),
            key_log_cap: 200,
        };

        // Resuming is the default: a progress file in the working directory is
        // the scan in progress. A different plan is a hard error rather than a
        // silent restart, because silently discarding coverage is worse than
        // one flag.
        if scheduler.opts.state_path.exists() && !scheduler.opts.reset {
            scheduler.apply_state()?;
        } else if !scheduler.opts.reset {
            log::info!(
                "[state] no state at {}, starting a fresh scan plan",
                scheduler.opts.state_path.display()
            );
        }

        Ok(scheduler)
    }

    fn apply_state(&mut self) -> Result<(), String> {
        let path = &self.opts.state_path;
        let body = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
        let state: StateFile = serde_json::from_str(&body)
            .map_err(|e| format!("{} is not a valid state file: {}", path.display(), e))?;

        if state.version != STATE_VERSION {
            return Err(format!(
                "{} was written by state format v{} (this build uses v{}); pass --reset to start over",
                path.display(),
                state.version,
                STATE_VERSION
            ));
        }

        let ours = fingerprint_hex(self.plan.fingerprint);
        if state.fingerprint != ours {
            return Err(format!(
                "{} belongs to a different scan plan (state {}, current {}). \
                 Ports or target ranges changed: pass --reset to start this scan \
                 over, or --state <other-file> to keep both.",
                path.display(),
                state.fingerprint,
                ours
            ));
        }

        self.done = RangeSet4::from_cidrs(&state.done).unwrap_or_default();
        self.created = state.created;
        self.stats.syns = state.syns;
        self.stats.synacks = state.synacks;

        // Coverage is stored per address, so a changed block size keeps every
        // completed address complete — only in-block resume offsets become
        // meaningless and are dropped.
        if state.chunk == self.plan.chunk {
            self.partial = state.partial.into_iter().collect();
            for (id, pos, _client) in state.inflight {
                // A controller restart invalidates the lease, not the work: the
                // block goes back to the pool and resumes from where it stopped.
                self.partial.entry(id).or_insert(pos);
            }
            self.next_ptr = state.next_ptr.min(self.order.len());
        } else {
            log::warn!(
                "[state] block size changed ({:#x} -> {:#x} bytes of address space); \
                 dropping in-block resume offsets, keeping completed addresses",
                state.chunk,
                self.plan.chunk
            );
        }

        // A resumed scan keeps the block order it started with, otherwise
        // next_ptr would point into a different permutation.
        self.seed = state.seed;
        self.order = shuffle_order(self.plan.blocks_len(), state.seed);
        self.last_rate_sample = (Instant::now(), self.stats.syns);

        log::info!(
            "[state] resumed {}: {} blocks done, {} partial, next ptr {}/{}",
            path.display(),
            self.blocks_done(),
            self.partial.len(),
            self.next_ptr,
            self.order.len()
        );
        Ok(())
    }

    pub fn save(&mut self) -> Result<(), String> {
        let state = StateFile {
            version: STATE_VERSION,
            created: self.created.clone(),
            saved: super::results::timestamp(),
            fingerprint: fingerprint_hex(self.plan.fingerprint),
            ports: self.plan.ports.clone(),
            targets: self.plan.targets.to_cidrs(),
            chunk: self.plan.chunk,
            seed: self.seed,
            next_ptr: self.next_ptr,
            done: self.done.to_cidrs(),
            partial: self.partial.iter().map(|(id, pos)| (*id, *pos)).collect(),
            inflight: self
                .inflight
                .iter()
                .map(|(id, c)| (*id, c.pos, c.client.clone()))
                .collect(),
            syns: self.stats.syns,
            synacks: self.stats.synacks,
            onion: self
                .connection
                .as_ref()
                .and_then(|c| c.onion.clone())
                .unwrap_or_default(),
            url: self
                .connection
                .as_ref()
                .map(|c| c.url.clone())
                .unwrap_or_default(),
            listen: self
                .connection
                .as_ref()
                .map(|c| c.listen.clone())
                .unwrap_or_default(),
            token: self
                .connection
                .as_ref()
                .map(|c| c.token.clone())
                .unwrap_or_default(),
            connect: self
                .connection
                .as_ref()
                .map(|c| c.connect.clone())
                .unwrap_or_default(),
        };

        let body = serde_json::to_string_pretty(&state).map_err(|e| e.to_string())?;
        let tmp = self.opts.state_path.with_extension("tmp");
        if let Some(parent) = tmp.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("{}: {}", parent.display(), e))?;
            }
        }
        std::fs::write(&tmp, body).map_err(|e| format!("{}: {}", tmp.display(), e))?;
        std::fs::rename(&tmp, &self.opts.state_path)
            .map_err(|e| format!("{}: {}", self.opts.state_path.display(), e))?;
        // The progress file holds the control token once a controller publishes
        // itself; keep it private.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &self.opts.state_path,
                std::fs::Permissions::from_mode(0o600),
            );
        }
        self.dirty = false;
        Ok(())
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Record how clients should reach this controller. Saved with the state so
    /// the progress file alone is enough to start a worker.
    pub fn set_connection(&mut self, info: ConnectionInfo) {
        self.connection = Some(info);
        self.dirty = true;
    }

    pub fn connection(&self) -> Option<&ConnectionInfo> {
        self.connection.as_ref()
    }

    /// Most recent confirmed keys, oldest first.
    pub fn key_events(&self) -> &VecDeque<KeyEvent> {
        &self.keys_log
    }

    // -----------------------------------------------------------------------
    // Scheduling
    // -----------------------------------------------------------------------

    pub fn claim(&mut self, client_id: &str) -> Claim {
        self.reap();
        self.touch(client_id);

        let rate = self.client_rate();

        // Interrupted blocks first: finishing a block already in progress keeps
        // coverage contiguous and avoids re-walking addresses.
        if let Some((id, pos)) = self.partial.iter().next().map(|(id, pos)| (*id, *pos)) {
            self.partial.remove(&id);
            if let Some(block) = self.plan.block(id) {
                self.lease(id, client_id, pos);
                return Claim::Job(Box::new(self.job_spec(block.id, pos, rate)));
            }
        }

        while self.next_ptr < self.order.len() {
            let id = self.order[self.next_ptr];
            self.next_ptr += 1;
            let block = match self.plan.block(id) {
                Some(b) => b,
                None => continue,
            };
            if self.is_covered(block.begin) || self.inflight.contains_key(&id) {
                continue;
            }
            self.lease(id, client_id, 0);
            self.dirty = true;
            return Claim::Job(Box::new(self.job_spec(block.id, 0, rate)));
        }

        if self.inflight.is_empty() && self.partial.is_empty() {
            Claim::Done
        } else {
            Claim::Waiting
        }
    }

    fn lease(&mut self, id: u64, client: &str, pos: u64) {
        let now = Instant::now();
        self.inflight.insert(
            id,
            Inflight {
                client: client.to_string(),
                lease_until: now + Duration::from_secs(self.opts.lease_s),
                pos,
                reported_syns: 0,
                reported_synacks: 0,
                last_syns: 0,
                last_sample: now,
                pps: 0.0,
            },
        );
        let block = self.plan.block(id);
        if let Some(entry) = self.clients.get_mut(client) {
            entry.job = Some(id);
            entry.block = block.map(|b| b.cidr()).unwrap_or_default();
            entry.pos = pos;
            entry.total = block
                .map(|b| b.len().saturating_mul(self.plan.ports_count()))
                .unwrap_or(0);
            entry.hits = 0;
            entry.keys = 0;
        }
        self.dirty = true;
    }

    fn job_spec(&self, id: u64, pos: u64, rate: f64) -> JobSpec {
        let block = self.plan.block(id).expect("job_spec on unknown block");
        JobSpec {
            job_id: id,
            begin: block.begin,
            end: block.end,
            cidr: block.cidr(),
            ports: self.plan.ports.clone(),
            rate,
            resume_pos: pos,
            lease_s: self.opts.lease_s,
            include_safe: self.opts.include_safe,
            tpc: self.opts.tpc,
        }
    }

    /// Record client progress and renew its lease.
    /// Record client telemetry and renew its lease.
    #[allow(clippy::too_many_arguments)]
    pub fn progress(
        &mut self,
        client_id: &str,
        job_id: u64,
        pos: u64,
        syns: u64,
        synacks: u64,
        total: u64,
        hits: u64,
        keys: u64,
        rate: f64,
        block: &str,
    ) -> (f64, bool) {
        self.touch(client_id);
        let now = Instant::now();

        let mut cancel = false;
        let mut delta_syns = 0u64;
        let mut delta_synacks = 0u64;
        let mut pps = 0.0f64;
        let mut reporting = false;

        if let Some(entry) = self.inflight.get_mut(&job_id) {
            if entry.client != client_id {
                // The lease expired and the block moved on; tell this client to
                // stop burning packets on it.
                cancel = true;
            } else {
                entry.pos = pos;
                entry.lease_until = now + Duration::from_secs(self.opts.lease_s);

                let dt = now.duration_since(entry.last_sample).as_secs_f64();
                let instant = syns.saturating_sub(entry.last_syns) as f64 / dt.max(1e-3);
                if dt > 0.2 {
                    entry.pps = if entry.pps > 0.0 {
                        entry.pps * 0.7 + instant * 0.3
                    } else {
                        instant
                    };
                    entry.last_syns = syns;
                    entry.last_sample = now;
                }

                // The client reports counters for the current job, so the delta
                // is against the previous report for this job and resets
                // naturally when the client moves to the next block.
                if syns > entry.reported_syns {
                    delta_syns = syns - entry.reported_syns;
                    entry.reported_syns = syns;
                }
                if synacks > entry.reported_synacks {
                    delta_synacks = synacks - entry.reported_synacks;
                    entry.reported_synacks = synacks;
                }

                pps = if rate > 0.0 { rate } else { entry.pps };
                entry.pps = pps;
                reporting = true;
            }
        }

        if reporting {
            self.stats.syns += delta_syns;
            self.stats.synacks += delta_synacks;
            if let Some(client) = self.clients.get_mut(client_id) {
                client.syns += delta_syns;
                client.synacks += delta_synacks;
                client.pps = pps;
                if total > 0 {
                    client.total = total;
                }
                client.pos = pos;
                client.hits = client.hits.max(hits);
                client.keys = client.keys.max(keys);
                if !block.is_empty() {
                    client.block = block.to_string();
                }
            }
            if delta_syns > 0 {
                self.dirty = true;
            }
        }

        (self.client_rate(), cancel)
    }

    /// Credit a client's cumulative block counters, adding only the change since
    /// the last report. Progress reports, results and completion all funnel
    /// through here, so any of them can be the first to carry a block's counters
    /// without double counting.
    fn account_counters(&mut self, client_id: &str, job_id: u64, syns: u64, synacks: u64) {
        let mut delta_syns = 0u64;
        let mut delta_synacks = 0u64;
        if let Some(entry) = self.inflight.get_mut(&job_id) {
            if entry.client == client_id {
                if syns > entry.reported_syns {
                    delta_syns = syns - entry.reported_syns;
                    entry.reported_syns = syns;
                }
                if synacks > entry.reported_synacks {
                    delta_synacks = synacks - entry.reported_synacks;
                    entry.reported_synacks = synacks;
                }
            }
        }
        if delta_syns > 0 || delta_synacks > 0 {
            self.stats.syns += delta_syns;
            self.stats.synacks += delta_synacks;
            if let Some(client) = self.clients.get_mut(client_id) {
                client.syns += delta_syns;
                client.synacks += delta_synacks;
            }
            self.dirty = true;
        }
    }

    /// Merge client results. Result delivery never depends on the job still
    /// being leased: a slow delivery must not lose a key.
    pub fn submit_results(
        &mut self,
        client_id: &str,
        job_id: u64,
        hits: &[(u32, u16)],
        keys: &[KeyRecord],
        syns: u64,
        synacks: u64,
    ) -> (u64, u64, u64, u64) {
        self.touch(client_id);

        // Results carry the block's final counters. Short blocks may finish
        // before a single progress report, so account for them here too.
        self.account_counters(client_id, job_id, syns, synacks);

        let (accepted_hits, dup_hits) = self.results.add_hits(client_id, job_id, hits);
        let (accepted_keys, dup_keys) = self.results.add_keys(keys);

        if accepted_keys > 0 {
            let name = self
                .clients
                .get(client_id)
                .map(|c| c.name.clone())
                .unwrap_or_else(|| client_id.to_string());
            for key in keys {
                let seen = self.key_events().iter().any(|e| e.key == key.key);
                if seen {
                    continue;
                }
                let event = KeyEvent {
                    at: chrono::Local::now().format("%H:%M:%S").to_string(),
                    key: key.key.clone(),
                    provider: key.provider.clone(),
                    client: name.clone(),
                    ip: key.ip.clone(),
                };
                self.keys_log.push_back(event);
                while self.keys_log.len() > self.key_log_cap {
                    self.keys_log.pop_front();
                }
            }
        }
        if accepted_hits > 0 || accepted_keys > 0 {
            self.dirty = true;
        }
        (accepted_hits, accepted_keys, dup_hits, dup_keys)
    }

    /// Mark a block fully covered.
    pub fn complete(
        &mut self,
        client_id: &str,
        job_id: u64,
        _pos: u64,
        syns: u64,
        synacks: u64,
    ) -> Result<bool, String> {
        self.touch(client_id);
        let block = self
            .plan
            .block(job_id)
            .ok_or_else(|| format!("unknown job {}", job_id))?;

        self.account_counters(client_id, job_id, syns, synacks);

        let duplicate = self.is_covered(block.begin);
        self.done.add(block.begin, block.end);
        self.partial.remove(&job_id);
        self.inflight.remove(&job_id);
        if let Some(entry) = self.clients.get_mut(client_id) {
            if entry.job == Some(job_id) {
                entry.job = None;
            }
        }
        self.dirty = true;
        Ok(duplicate)
    }

    /// Give a block back without completing it (client shutting down).
    ///
    /// A client that stopped *after* emitting every probe reports `pos` at the
    /// block's end; that block is covered even if the client never sent the
    /// completion call, so it is recorded as done rather than re-scanned.
    pub fn release(&mut self, client_id: &str, job_id: u64, pos: u64) {
        let owned = self
            .inflight
            .get(&job_id)
            .map(|e| e.client == client_id)
            .unwrap_or(false);
        if owned {
            self.inflight.remove(&job_id);
            // `pos` counts probes (addresses × ports), not addresses.
            let block_len = self
                .plan
                .block(job_id)
                .map(|b| b.len().saturating_mul(self.plan.ports_count()))
                .unwrap_or(0);
            if block_len > 0 && pos >= block_len {
                if let Some(block) = self.plan.block(job_id) {
                    self.done.add(block.begin, block.end);
                }
            } else if pos > 0 {
                self.partial.insert(job_id, pos);
            }
            self.dirty = true;
        }
        if let Some(entry) = self.clients.get_mut(client_id) {
            if entry.job == Some(job_id) {
                entry.job = None;
            }
        }
    }

    /// Reclaim blocks whose lease expired.
    pub fn reap(&mut self) {
        let now = Instant::now();
        let expired: Vec<u64> = self
            .inflight
            .iter()
            .filter(|(_, e)| e.lease_until <= now)
            .map(|(id, _)| *id)
            .collect();

        for id in expired {
            if let Some(entry) = self.inflight.remove(&id) {
                log::warn!(
                    "[sched] lease expired for block {} (client {}) at pos {}",
                    id,
                    entry.client,
                    entry.pos
                );
                if let Some(client) = self.clients.get_mut(&entry.client) {
                    if client.job == Some(id) {
                        client.job = None;
                    }
                }
                self.partial.insert(id, entry.pos);
                self.dirty = true;
            }
        }

        // Forget clients that have gone quiet.
        let stale: Vec<String> = self
            .clients
            .iter()
            .filter(|(id, c)| {
                c.last_seen.elapsed().as_secs() > CLIENT_TTL_S && !self.inflight.values().any(|i| &i.client == *id)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            self.clients.remove(&id);
        }
    }

    fn touch(&mut self, client_id: &str) {
        let entry = self.clients.entry(client_id.to_string()).or_insert(ClientEntry {
            name: client_id.to_string(),
            last_seen: Instant::now(),
            job: None,
            pps: 0.0,
            syns: 0,
            synacks: 0,
            block: String::new(),
            pos: 0,
            total: 0,
            hits: 0,
            keys: 0,
        });
        entry.last_seen = Instant::now();
    }

    pub fn register_client(&mut self, client_id: &str, name: &str) {
        let entry = self.clients.entry(client_id.to_string()).or_insert(ClientEntry {
            name: name.to_string(),
            last_seen: Instant::now(),
            job: None,
            pps: 0.0,
            syns: 0,
            synacks: 0,
            block: String::new(),
            pos: 0,
            total: 0,
            hits: 0,
            keys: 0,
        });
        entry.name = name.to_string();
        entry.last_seen = Instant::now();
    }

    /// Per-client rate share of the aggregate target.
    fn client_rate(&self) -> f64 {
        if self.opts.target_rate <= 0.0 {
            return 0.0;
        }
        let active = self
            .clients
            .values()
            .filter(|c| c.last_seen.elapsed().as_secs() <= CLIENT_TTL_S)
            .count()
            .max(1);
        self.opts.target_rate / active as f64
    }

    // -----------------------------------------------------------------------
    // Accounting
    // -----------------------------------------------------------------------

    pub fn lease_s(&self) -> u64 {
        self.opts.lease_s
    }

    pub fn current_rate(&self) -> f64 {
        self.client_rate()
    }

    pub fn results_dir(&self) -> &std::path::Path {
        self.results.dir()
    }

    pub fn include_safe(&self) -> bool {
        self.opts.include_safe
    }

    pub fn tpc(&self) -> usize {
        self.opts.tpc
    }

    fn is_covered(&self, addr: u32) -> bool {
        self.done.contains(addr)
    }

    pub fn blocks_done(&self) -> u64 {
        self.plan
            .blocks
            .iter()
            .filter(|b| self.done.contains(b.begin))
            .count() as u64
    }

    pub fn blocks_remaining(&self) -> u64 {
        let total = self.plan.blocks_len() as u64;
        total.saturating_sub(self.blocks_done())
    }

    pub fn addresses_done(&self) -> u64 {
        self.done.count()
    }

    pub fn elapsed_s(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    fn refresh_rate(&mut self) {
        let now = Instant::now();
        let (then, syns_then) = self.last_rate_sample;
        let dt = now.duration_since(then).as_secs_f64();
        if dt >= 0.5 {
            let instant = self.stats.syns.saturating_sub(syns_then) as f64 / dt;
            self.rate_pps = if self.rate_pps > 0.0 {
                self.rate_pps * 0.6 + instant * 0.4
            } else {
                instant
            };
            self.last_rate_sample = (now, self.stats.syns);
        }
    }

    fn eta_s(&self) -> u64 {
        let total_probes = self.plan.total_addresses().saturating_mul(self.plan.ports_count());
        if self.rate_pps < 1.0 || total_probes == 0 {
            return 0;
        }
        let done_fraction = if total_probes == 0 {
            1.0
        } else {
            self.addresses_done() as f64 / self.plan.total_addresses().max(1) as f64
        };
        let remaining = total_probes as f64 * (1.0 - done_fraction);
        (remaining / self.rate_pps) as u64
    }

    pub fn status(&mut self) -> StatusResponse {
        self.refresh_rate();
        self.reap();

        let total_addr = self.plan.total_addresses();
        let done_addr = self.addresses_done();
        let blocks_total = self.plan.blocks_len() as u64;
        let blocks_done = self.blocks_done();

        let mut clients: Vec<ClientSnapshot> = self
            .clients
            .iter()
            .map(|(id, c)| ClientSnapshot {
                id: id.clone(),
                name: c.name.clone(),
                job_id: c.job,
                pps: c.pps,
                syns: c.syns,
                synacks: c.synacks,
                idle_s: c.last_seen.elapsed().as_secs(),
                block: c.block.clone(),
                pos: c.pos,
                total: c.total,
                hits: c.hits,
                keys: c.keys,
            })
            .collect();
        clients.sort_by(|a, b| b.pps.partial_cmp(&a.pps).unwrap_or(std::cmp::Ordering::Equal));

        StatusResponse {
            api_version: API_VERSION,
            running: !matches!(self.peek(), Claim::Done),
            ports: self.plan.ports.clone(),
            blocks_total,
            blocks_done,
            blocks_inflight: self.inflight.len() as u64,
            blocks_partial: self.partial.len() as u64,
            blocks_remaining: blocks_total.saturating_sub(blocks_done),
            addresses_total: total_addr,
            addresses_done: done_addr,
            targets: self.plan.targets.to_cidrs(),
            done_cidrs: self.done.to_cidrs(),
            remaining_cidrs: self.remaining_set().to_cidrs(),
            percent: if total_addr == 0 {
                100.0
            } else {
                done_addr as f64 * 100.0 / total_addr as f64
            },
            syns: self.stats.syns,
            synacks: self.stats.synacks,
            hits: self.results.totals().0,
            keys: self.results.totals().1,
            rate_pps: self.rate_pps,
            elapsed_s: self.elapsed_s(),
            eta_s: self.eta_s(),
            clients,
        }
    }

    pub fn coverage(&self) -> CoverageResponse {
        let total_addr = self.plan.total_addresses();
        let done_addr = self.addresses_done();
        CoverageResponse {
            addresses_total: total_addr,
            addresses_done: done_addr,
            percent: if total_addr == 0 {
                100.0
            } else {
                done_addr as f64 * 100.0 / total_addr as f64
            },
            done_cidrs: self.done.to_cidrs(),
            remaining_cidrs: self.remaining_set().to_cidrs(),
            blocks_total: self.plan.blocks_len() as u64,
            blocks_done: self.blocks_done(),
            blocks_partial: self.partial.len() as u64,
            blocks_inflight: self.inflight.len() as u64,
        }
    }

    fn remaining_set(&self) -> RangeSet4 {
        let mut remaining = self.plan.targets.clone();
        remaining.subtract(&self.done);
        remaining
    }

    fn peek(&self) -> Claim {
        if self.next_ptr >= self.order.len() && self.inflight.is_empty() && self.partial.is_empty() {
            Claim::Done
        } else {
            Claim::Waiting
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coord::plan::Plan;
    use crate::coord::set4::RangeSet4;

    fn opts(dir: &std::path::Path) -> Options {
        Options {
            state_path: dir.join("state.json"),
            results_dir: dir.join("results"),
            lease_s: 1,
            include_safe: false,
            tpc: 2,
            target_rate: 10_000.0,
            reset: false,
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zorp-sched-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn plan(cidr: &str, chunk: u64) -> Plan {
        Plan::new("80,443", RangeSet4::from_cidrs(&[cidr]).unwrap(), chunk, 1234)
    }

    fn job_of(claim: Claim) -> JobSpec {
        match claim {
            Claim::Job(j) => *j,
            other => panic!("expected job, got {:?}", other),
        }
    }

    #[test]
    fn claims_cover_every_block_exactly_once() {
        let dir = temp_dir("cover");
        let plan = plan("10.0.0.0/20", 256);
        let mut sched = Scheduler::load_or_create(plan.clone(), opts(&dir)).unwrap();

        let mut seen = Vec::new();
        loop {
            match sched.claim("c1") {
                Claim::Job(j) => {
                    seen.push(j.job_id);
                    sched.complete("c1", j.job_id, j.resume_pos, 0, 0).unwrap();
                }
                Claim::Waiting => panic!("unexpected waiting"),
                Claim::Done => break,
            }
        }
        seen.sort_unstable();
        let expected: Vec<u64> = (0..plan.blocks_len() as u64).collect();
        assert_eq!(seen, expected);
        assert_eq!(sched.addresses_done(), 4096);
        assert_eq!(sched.blocks_remaining(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn completion_and_state_survive_a_restart() {
        let dir = temp_dir("restart");
        let plan = plan("10.0.0.0/20", 256);

        let mut done_len = 0;
        {
            let mut sched = Scheduler::load_or_create(plan.clone(), opts(&dir)).unwrap();
            let j = job_of(sched.claim("c1"));
            done_len = j.end as u64 - j.begin as u64 + 1;
            sched.complete("c1", j.job_id, 0, 0, 0).unwrap();
            // Lease a second block but never finish it.
            let j2 = job_of(sched.claim("c1"));
            sched.progress("c1", j2.job_id, 512, 1000, 12, 0, 0, 0, 0.0, "");
            sched.save().unwrap();
        }

        let mut sched = Scheduler::load_or_create(plan.clone(), opts(&dir)).unwrap();
        assert_eq!(sched.addresses_done(), done_len);
        assert_eq!(sched.partial.len(), 1);

        // The interrupted block comes back first, resuming at its offset.
        let j = job_of(sched.claim("c2"));
        assert_eq!(j.resume_pos, 512);
        assert_eq!(sched.partial.len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_leases_are_reclaimed_with_their_position() {
        let dir = temp_dir("lease");
        let plan = plan("10.0.0.0/20", 256);
        let mut sched = Scheduler::load_or_create(plan, opts(&dir)).unwrap();

        let j = job_of(sched.claim("c1"));
        sched.progress("c1", j.job_id, 300, 10, 1, 0, 0, 0, 0.0, "");
        std::thread::sleep(Duration::from_millis(1200));
        sched.reap();

        let again = job_of(sched.claim("c2"));
        assert_eq!(again.job_id, j.job_id);
        assert_eq!(again.resume_pos, 300);
        // The old client is told to stop.
        let (_rate, cancel) = sched.progress("c1", j.job_id, 400, 20, 2, 0, 0, 0, 0.0, "");
        assert!(cancel);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn state_refuses_a_different_plan() {
        let dir = temp_dir("mismatch");
        let opts_v = opts(&dir);
        {
            let mut sched = Scheduler::load_or_create(plan("10.0.0.0/20", 256), opts_v.clone()).unwrap();
            sched.save().unwrap();
        }
        let err = Scheduler::load_or_create(plan("11.0.0.0/20", 256), opts_v)
            .err()
            .expect("plan mismatch must be rejected");
        assert!(err.contains("different scan plan"), "got: {}", err);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn changed_block_size_keeps_completed_addresses() {
        let dir = temp_dir("chunk");
        let opts_v = opts(&dir);
        let done_addr;
        {
            let plan = plan("10.0.0.0/24", 256);
            let mut sched = Scheduler::load_or_create(plan, opts_v.clone()).unwrap();
            let j = job_of(sched.claim("c1"));
            sched.complete("c1", j.job_id, 0, 0, 0).unwrap();
            done_addr = sched.plan.block(j.job_id).unwrap().len();
            sched.save().unwrap();
        }

        let plan = plan("10.0.0.0/24", 64);
        let sched = Scheduler::load_or_create(plan, opts_v).unwrap();
        assert_eq!(sched.addresses_done(), done_addr);
        assert_eq!(sched.partial.len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rate_is_split_between_active_clients() {
        let dir = temp_dir("rate");
        let plan = plan("10.0.0.0/16", 256);
        let mut sched = Scheduler::load_or_create(plan, opts(&dir)).unwrap();
        sched.register_client("a", "alpha");
        sched.register_client("b", "beta");
        let j = job_of(sched.claim("a"));
        assert!((j.rate - 5000.0).abs() < 1.0, "rate {}", j.rate);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn results_credit_counter_deltas_when_no_progress_arrived() {
        let dir = temp_dir("counters");
        let plan = plan("10.0.0.0/23", 256);
        let mut sched = Scheduler::load_or_create(plan, opts(&dir)).unwrap();
        let j = job_of(sched.claim("a"));
        // No progress call at all: a block that finished immediately.
        sched.submit_results("a", j.job_id, &[], &[], 2000, 40);
        assert_eq!(sched.status().syns, 2000);
        // A second delivery of the same counters must not double count.
        sched.submit_results("a", j.job_id, &[], &[], 2000, 40);
        assert_eq!(sched.status().syns, 2000);
        // A later block on the same client keeps accumulating.
        sched.complete("a", j.job_id, 0, 0, 0).unwrap();
        let j2 = job_of(sched.claim("a"));
        sched.submit_results("a", j2.job_id, &[], &[], 500, 10);
        assert_eq!(sched.status().syns, 2500);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn releasing_a_finished_block_records_it_as_done() {
        let dir = temp_dir("release-done");
        let plan = plan("10.0.0.0/24", 256);
        let mut sched = Scheduler::load_or_create(plan.clone(), opts(&dir)).unwrap();
        let j = job_of(sched.claim("a"));
        let len = j.end as u64 - j.begin as u64 + 1;
        let ports = sched.plan.ports_count();
        sched.release("a", j.job_id, len * ports);
        assert_eq!(sched.addresses_done(), len);
        assert!(sched.partial.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn results_are_deduped_by_the_sink() {
        let dir = temp_dir("results");
        let plan = plan("10.0.0.0/24", 256);
        let mut sched = Scheduler::load_or_create(plan, opts(&dir)).unwrap();
        let hits = vec![(0x0A000001u32, 80u16)];
        let key = KeyRecord {
            confirmed: true,
            ip: "10.0.0.1".into(),
            key: "sk_test".into(),
            provider: "stripe".into(),
            category: "payment".into(),
            timestamp: String::new(),
        };
        assert_eq!(
            sched.submit_results("a", 0, &hits, std::slice::from_ref(&key), 0, 0),
            (1, 1, 0, 0)
        );
        assert_eq!(
            sched.submit_results("a", 0, &hits, std::slice::from_ref(&key), 0, 0),
            (0, 0, 1, 1)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
