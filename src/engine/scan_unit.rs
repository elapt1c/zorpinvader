//! The scan unit: one initialized adapter plus the fetch/verify pipeline, able
//! to scan one block at a time.
//!
//! A block is an aligned address interval plus a port list. Its probe space is
//! `addresses * ports` indices, walked through a BlackRock permutation so the
//! order is random but every index is hit exactly once. That makes progress a
//! single number (`pos`) — which is what makes resuming, leasing and
//! work-stealing well defined: a block is a job, and `pos` is where the job is.
//!
//! This replaces the old global spirograph stride: with blocks, the early-scan
//! spread across the address space comes from the block order (see
//! [`crate::coord::plan::Plan`]), not from striding a global index.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::crypto::blackrock::BlackRock;
use crate::greyhat::{Fetcher, GreyhatScanner, Verifier};
use crate::main_mod::conf::Zorp;
use crate::main_mod::initadapter;
use crate::massip::massip::MassIP;
use crate::massip::rangesv4::RangeList;
use crate::misc::syn_cookie;
use crate::rawsock::adapter::Adapter;
use crate::templ::opts::TemplateOptions;
use crate::templ::pkt::{self, TemplateSet};

use super::hits::HitLog;
use super::keys::KeyTail;

/// Progress snapshot handed to the caller every few hundred milliseconds.
#[derive(Clone, Debug, Default)]
pub struct BlockProgress {
    /// Probes emitted so far within this block (0..total).
    pub pos: u64,
    pub total: u64,
    pub syns: u64,
    pub synacks: u64,
    pub hits: u64,
    pub elapsed_s: f64,
}

/// What a block scan produced.
#[derive(Clone, Debug, Default)]
pub struct BlockOutcome {
    pub pos: u64,
    pub total: u64,
    pub syns: u64,
    pub synacks: u64,
    pub hits: Vec<(u32, u16)>,
    pub keys: Vec<crate::coord::protocol::KeyRecord>,
    /// True if every probe in the block was emitted.
    pub completed: bool,
    /// True if the block was stopped early by a cancel/shutdown request.
    pub cancelled: bool,
}

/// Callback return value: `false` aborts the block (e.g. the controller
/// reassigned it).
pub type ProgressFn<'a> = &'a mut dyn FnMut(&BlockProgress) -> bool;

pub struct ScanEngine {
    adapter: Arc<Adapter>,
    tmplset: Arc<TemplateSet>,
    source_ip: u32,
    source_port: u16,
    entropy: u64,
    seed: u64,
    rounds: u32,
    scanner: Arc<GreyhatScanner>,
    verifier: Arc<Verifier>,
    fetcher: Arc<Fetcher>,
    hits: Arc<HitLog>,
    keys: parking_lot::Mutex<KeyTail>,
}

impl ScanEngine {
    /// Initialize the adapter and the fetch/verify pipeline once. Every block
    /// scanned by this engine reuses them.
    pub fn new(zorp: &Zorp, tpc: usize, include_safe: bool) -> Result<Self, String> {
        let mut targets = MassIP::new();
        for range_str in &zorp.target_ranges {
            let _ = targets.add_target_string(range_str.as_bytes());
        }
        if targets.ipv4.count_addresses() == 0 && targets.ipv6.count_addresses().lo == 0 {
            targets.ipv4.add_range(0, u32::MAX);
        }

        let mut nic_config = zorp.nic[0].clone();
        let init_result = initadapter::initialize_adapter(zorp, &mut nic_config, 0, &targets)?;
        let source_ip = nic_config.src_ipv4_first;
        if source_ip == 0 {
            return Err("no source IP detected. Use --adapter-ip <ip>".to_string());
        }
        let source_port: u16 = if nic_config.src_port_first != 0 {
            nic_config.src_port_first
        } else {
            61234
        };

        let entropy = syn_cookie::get_entropy();
        let tmpl_opts = TemplateOptions::default();
        let data_link = init_result.adapter.link_type.to_raw();
        let tmplset = Arc::new(pkt::template_packet_init(
            init_result.source_mac,
            init_result.router_mac_ipv4,
            init_result.router_mac_ipv6,
            None,
            None,
            data_link,
            entropy,
            &tmpl_opts,
        ));

        let scanner = Arc::new(GreyhatScanner::new(include_safe));
        let verifier = Arc::new(Verifier::new(0));
        let fetcher = Arc::new(Fetcher::new(
            scanner.clone(),
            verifier.clone(),
            Some(tpc),
        ));

        log::info!(
            "[engine] adapter {} ip {} port {} entropy 0x{:016x}",
            init_result.adapter.name,
            crate::coord::set4::format_ip(source_ip),
            source_port,
            entropy
        );

        Ok(ScanEngine {
            adapter: Arc::new(init_result.adapter),
            tmplset,
            source_ip,
            source_port,
            entropy,
            seed: zorp.seed,
            rounds: zorp.blackrock_rounds,
            scanner,
            verifier,
            fetcher,
            hits: Arc::new(HitLog::new()),
            keys: parking_lot::Mutex::new(KeyTail::new(super::keys::DEFAULT_KEYS_FILE)),
        })
    }

    pub fn adapter_name(&self) -> &str {
        &self.adapter.name
    }

    pub fn source_ip(&self) -> u32 {
        self.source_ip
    }

    /// Pipeline components, for the live status display.
    pub fn pipeline(&self) -> (&GreyhatScanner, &Fetcher, &Verifier) {
        (&self.scanner, &self.fetcher, &self.verifier)
    }

    pub fn fetcher_queue_depth(&self) -> usize {
        self.fetcher.queue_depth()
    }

    /// Read keys the verifier appended since the last call.
    pub fn drain_keys(&self) -> Vec<crate::coord::protocol::KeyRecord> {
        self.keys.lock().read_new()
    }

    pub fn key_tail_offset(&self) -> u64 {
        self.keys.lock().offset()
    }

    /// Scan one block. `cancel` is polled continuously; `on_progress` is called
    /// roughly every 400 ms and returning `false` stops the block.
    pub fn scan_block(
        &self,
        job: &crate::coord::scheduler::JobSpec,
        cancel: &AtomicBool,
        on_progress: ProgressFn<'_>,
    ) -> Result<BlockOutcome, String> {
        let ports = parse_ports(&job.ports)?;
        let count_ports = ports.count_addresses().max(1);
        let addresses = job.end as u64 - job.begin as u64 + 1;
        let total = addresses.saturating_mul(count_ports);
        if total == 0 {
            return Err("empty block".to_string());
        }

        let start_pos = job.resume_pos.min(total);
        self.hits.reset(total);

        let ctx = Arc::new(BlockCtx {
            adapter: self.adapter.clone(),
            tmplset: self.tmplset.clone(),
            hits: self.hits.clone(),
            fetcher: self.fetcher.clone(),
            source_ip: self.source_ip,
            source_port: self.source_port,
            entropy: self.entropy,
            seed: self.seed ^ job.job_id.wrapping_mul(0x9E37_79B9_7F4A_7C15),
            rounds: self.rounds,
            begin: job.begin,
            count_ports,
            total,
            ports: Arc::new(ports),
            start_pos,
            rate: if job.rate > 0.0 { job.rate } else { f64::INFINITY },
            stop_tx: AtomicBool::new(false),
            stop_rx: AtomicBool::new(false),
            pos: AtomicU64::new(start_pos),
            syns: AtomicU64::new(0),
            synacks: AtomicU64::new(0),
        });

        let tx_ctx = ctx.clone();
        let tx = std::thread::spawn(move || transmit_loop(tx_ctx));
        let rx_ctx = ctx.clone();
        let rx = std::thread::spawn(move || receive_loop(rx_ctx));

        let started = Instant::now();
        let mut tx_done_at: Option<Instant> = None;
        let mut cancelled = false;
        let mut grace = Duration::from_secs(1);

        loop {
            std::thread::sleep(Duration::from_millis(400));

            let stop = cancel.load(Ordering::SeqCst) || crate::main_mod::globals::is_tx_done();
            if stop {
                cancelled = true;
                ctx.stop_tx.store(true, Ordering::SeqCst);
            }

            if tx.is_finished() && tx_done_at.is_none() {
                tx_done_at = Some(Instant::now());
                let block_elapsed = started.elapsed().as_secs_f64();
                grace = Duration::from_millis(
                    ((block_elapsed * 250.0) as u64).clamp(300, 3_000),
                );
            }

            let progress = BlockProgress {
                pos: ctx.pos.load(Ordering::SeqCst),
                total,
                syns: ctx.syns.load(Ordering::SeqCst),
                synacks: ctx.synacks.load(Ordering::SeqCst),
                hits: self.hits.len() as u64,
                elapsed_s: started.elapsed().as_secs_f64(),
            };

            if !on_progress(&progress) {
                cancelled = true;
                ctx.stop_tx.store(true, Ordering::SeqCst);
            }

            if let Some(done_at) = tx_done_at {
                // Grace period for in-flight SYN-ACKs after the last probe,
                // proportional to how long the block took: a 1-probe block is
                // done in milliseconds, while a long block still gets a full 3s
                // to collect replies.
                if done_at.elapsed() >= grace {
                    break;
                }
            }
            if cancelled && tx.is_finished() {
                break;
            }
        }

        ctx.stop_tx.store(true, Ordering::SeqCst);
        ctx.stop_rx.store(true, Ordering::SeqCst);
        let _ = tx.join();
        let _ = rx.join();

        // Let the HTTP pipeline finish before the block is declared complete,
        // otherwise keys found in the last pages of the block are lost.
        let drain_deadline = Instant::now() + Duration::from_secs(45);
        while self.fetcher.queue_depth() > 0 && Instant::now() < drain_deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
        // Verified keys need a moment to land in the CSV after the queue empties.
        std::thread::sleep(Duration::from_millis(500));

        let pos = ctx.pos.load(Ordering::SeqCst);
        let outcome = BlockOutcome {
            pos,
            total,
            syns: ctx.syns.load(Ordering::SeqCst),
            synacks: ctx.synacks.load(Ordering::SeqCst),
            hits: self.hits.take(),
            keys: self.drain_keys(),
            completed: !cancelled && pos >= total,
            cancelled,
        };

        log::info!(
            "[engine] block {} ({}) pos {}/{} syns {} synacks {} hits {} keys {}",
            job.job_id,
            job.cidr,
            outcome.pos,
            outcome.total,
            outcome.syns,
            outcome.synacks,
            outcome.hits.len(),
            outcome.keys.len()
        );

        Ok(outcome)
    }

    /// Stop the pipeline. Consumes the engine so `Arc::try_unwrap` succeeds.
    pub fn shutdown(self) {
        match Arc::try_unwrap(self.fetcher) {
            Ok(f) => f.shutdown(),
            Err(arc) => drop(arc),
        }
        match Arc::try_unwrap(self.verifier) {
            Ok(v) => v.shutdown(),
            Err(arc) => drop(arc),
        }
    }
}

/// Data shared with the two block threads.
struct BlockCtx {
    adapter: Arc<Adapter>,
    tmplset: Arc<TemplateSet>,
    hits: Arc<HitLog>,
    fetcher: Arc<Fetcher>,
    source_ip: u32,
    source_port: u16,
    entropy: u64,
    seed: u64,
    rounds: u32,
    begin: u32,
    count_ports: u64,
    total: u64,
    ports: Arc<RangeList>,
    start_pos: u64,
    rate: f64,
    stop_tx: AtomicBool,
    stop_rx: AtomicBool,
    pos: AtomicU64,
    syns: AtomicU64,
    synacks: AtomicU64,
}

fn transmit_loop(ctx: Arc<BlockCtx>) {
    let blackrock = BlackRock::init(ctx.total, ctx.seed, ctx.rounds);
    let mut throttler = crate::main_mod::throttle::Throttler::new();
    throttler.start(ctx.rate);

    let mut px = vec![0u8; 2048];
    let mut pos = ctx.start_pos;

    while pos < ctx.total && !ctx.stop_tx.load(Ordering::SeqCst) {
        // Backpressure: do not outrun the HTTP pipeline.
        if ctx.fetcher.queue_depth() > 4096 {
            std::thread::sleep(Duration::from_millis(200));
            continue;
        }

        let batch = throttler
            .next_batch(ctx.syns.load(Ordering::Relaxed))
            .max(1) as u64;
        let end = (pos + batch).min(ctx.total);

        for _ in pos..end {
            let index = blackrock.shuffle(pos);
            let ip_them = ctx.begin + (index / ctx.count_ports) as u32;
            let port_them = ctx.ports.pick(index % ctx.count_ports);

            let cookie = syn_cookie::syn_cookie_ipv4(
                ip_them,
                port_them,
                ctx.source_ip,
                ctx.source_port as u32,
                ctx.entropy,
            );
            let seqno = cookie as u32;

            let len = pkt::template_set_target_ipv4(
                &ctx.tmplset,
                ip_them,
                port_them,
                ctx.source_ip,
                ctx.source_port,
                seqno,
                &mut px,
            );
            if len > 0 {
                let _ = ctx.adapter.send_packet(&px[..len]);
            }
            ctx.syns.fetch_add(1, Ordering::Relaxed);
            pos += 1;
        }

        ctx.pos.store(pos, Ordering::SeqCst);
    }

    ctx.pos.store(pos, Ordering::SeqCst);
}

fn receive_loop(ctx: Arc<BlockCtx>) {
    // Short receive timeout so the stop flag is honoured.
    if let Some(socket) = ctx.adapter.socket() {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 100_000,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
    }

    let mut buf = [0u8; 2048];
    while !ctx.stop_rx.load(Ordering::SeqCst) {
        match ctx.adapter.recv_packet(&mut buf) {
            Ok(recv) => {
                let data = recv.data;
                if let Some((ip_src, port_src, ip_dst, port_dst, ack_seq)) = parse_synack(data) {
                    if ip_dst != ctx.source_ip || port_dst != ctx.source_port {
                        continue;
                    }
                    let cookie_received = ack_seq.wrapping_sub(1);
                    let expected = syn_cookie::syn_cookie_ipv4(
                        ip_src,
                        port_src as u32,
                        ctx.source_ip,
                        ctx.source_port as u32,
                        ctx.entropy,
                    ) as u32;
                    if cookie_received != expected {
                        continue;
                    }

                    ctx.synacks.fetch_add(1, Ordering::Relaxed);
                    ctx.hits.push(ip_src, port_src);
                    ctx.fetcher
                        .submit(&crate::coord::set4::format_ip(ip_src), port_src);
                }
            }
            Err(_) => {
                // Timeout: loop around and re-check the stop flag.
            }
        }
    }
}

/// Parse an Ethernet frame for a TCP SYN-ACK.
fn parse_synack(pkt: &[u8]) -> Option<(u32, u16, u32, u16, u32)> {
    if pkt.len() < 54 {
        return None;
    }
    let ethertype = ((pkt[12] as u16) << 8) | pkt[13] as u16;
    if ethertype != 0x0800 {
        return None;
    }

    let ip_off = 14;
    let version_ihl = pkt[ip_off];
    if (version_ihl >> 4) != 4 {
        return None;
    }
    let ihl = ((version_ihl & 0x0F) as usize) * 4;
    if ihl < 20 || ip_off + ihl + 20 > pkt.len() {
        return None;
    }
    if pkt[ip_off + 9] != 6 {
        return None;
    }

    let ip_src = ((pkt[ip_off + 12] as u32) << 24)
        | ((pkt[ip_off + 13] as u32) << 16)
        | ((pkt[ip_off + 14] as u32) << 8)
        | pkt[ip_off + 15] as u32;
    let ip_dst = ((pkt[ip_off + 16] as u32) << 24)
        | ((pkt[ip_off + 17] as u32) << 16)
        | ((pkt[ip_off + 18] as u32) << 8)
        | pkt[ip_off + 19] as u32;

    let tcp_off = ip_off + ihl;
    let port_src = ((pkt[tcp_off] as u16) << 8) | pkt[tcp_off + 1] as u16;
    let port_dst = ((pkt[tcp_off + 2] as u16) << 8) | pkt[tcp_off + 3] as u16;
    let ack = ((pkt[tcp_off + 8] as u32) << 24)
        | ((pkt[tcp_off + 9] as u32) << 16)
        | ((pkt[tcp_off + 10] as u32) << 8)
        | pkt[tcp_off + 11] as u32;
    let flags = pkt[tcp_off + 13];

    if flags & 0x12 != 0x12 {
        return None;
    }
    Some((ip_src, port_src, ip_dst, port_dst, ack))
}

fn parse_ports(spec: &str) -> Result<RangeList, String> {
    let mut list = RangeList::new();
    let mut is_error = false;
    crate::massip::rangesv4::rangelist_parse_ports(&mut list, spec, Some(&mut is_error), 0);
    if is_error || list.count_addresses() == 0 {
        return Err(format!("invalid port specification: {}", spec));
    }
    list.optimize();
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_specs_are_parsed_and_optimised() {
        let ports = parse_ports("80,443,8000-8002").unwrap();
        assert_eq!(ports.count_addresses(), 5);
        assert_eq!(ports.pick(0), 80);
        assert_eq!(ports.pick(2), 8000);
        assert_eq!(ports.pick(4), 8002);
        assert!(parse_ports("").is_err());
        assert!(parse_ports("not-a-port").is_err());
    }

    #[test]
    fn synack_parser_accepts_a_crafted_packet() {
        let mut frame = [0u8; 54];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45; // IPv4, IHL 5
        frame[23] = 6; // TCP
        frame[26..30].copy_from_slice(&[1, 2, 3, 4]); // src
        frame[30..34].copy_from_slice(&[5, 6, 7, 8]); // dst
        frame[34] = 0x01;
        frame[35] = 0xBB; // src port 443
        frame[36] = 0x30;
        frame[37] = 0x39; // dst port 12345
        frame[47] = 0x12; // SYN|ACK

        let parsed = parse_synack(&frame).unwrap();
        assert_eq!(parsed.0, 0x01020304);
        assert_eq!(parsed.1, 443);
        assert_eq!(parsed.2, 0x05060708);
        assert_eq!(parsed.3, 12345);

        frame[47] = 0x10; // plain ACK is ignored
        assert!(parse_synack(&frame).is_none());
    }
}
