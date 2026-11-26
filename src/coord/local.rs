//! Standalone mode: the scheduler and the engine in one process.
//!
//! This is the default `zorpinvader --rate N` behaviour, and it runs on exactly
//! the same code path a controller uses — the only difference is that the
//! scheduler is called in-process instead of over HTTP. Resume, coverage
//! accounting and results de-duplication therefore behave identically whether the
//! scan ran on one machine or across ten.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::engine::ScanEngine;
use crate::main_mod::conf::{self, Zorp};
use crate::main_mod::globals;
use crate::main_mod::status::Status;

use super::plan::Plan;
use super::scheduler::{Claim, Options, Scheduler};
use super::set4::format_ip;

pub fn run(zorp: Arc<Zorp>) -> i32 {
    let targets = match super::targets::build(&zorp) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ERROR: {}", e);
            return 1;
        }
    };
    let ports = super::targets::ports(&zorp);
    let seed = if zorp.seed != 0 {
        zorp.seed
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    };

    let mut plan = Plan::new(&ports, targets, zorp.job_size, seed);
    plan.restrict_shard(zorp.shard.one, zorp.shard.of);
    let opts = Options {
        state_path: zorp.state_file.clone(),
        results_dir: zorp.results_dir.clone(),
        lease_s: zorp.lease_s,
        include_safe: zorp.include_safe,
        tpc: zorp.tpc,
        target_rate: zorp.max_rate,
        reset: zorp.reset_state,
    };

    let mut scheduler = match Scheduler::load_or_create(plan.clone(), opts) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ERROR: {}", e);
            return 1;
        }
    };

    // The verifier opens found_keys.csv best-effort; a root-owned leftover
    // would silently discard every key, so check it before scanning.
    if let Err(e) = super::results::check_writable(std::path::Path::new(super::results::KEYS_FILE)) {
        eprintln!("ERROR: {}", e);
        return 1;
    }

    print_banner(&plan, &scheduler);

    let engine = match ScanEngine::new(&zorp, zorp.tpc, zorp.include_safe) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("ERROR: {}", e);
            return 1;
        }
    };
    eprintln!(
        "[+] adapter {} source {} → found_keys.csv, {}",
        engine.adapter_name(),
        format_ip(engine.source_ip()),
        scheduler.results_dir().display()
    );

    // Ctrl-C stops the current block; the scheduler keeps the position and the
    // state file is written, so the next run resumes mid-block.
    {
        let _ = ctrlc::set_handler(move || {
            eprintln!("\n[+] stopping after the current block (state will be saved)");
            globals::set_tx_done(true);
        });
    }

    let mut status = Status::new();
    status.start();

    let total_addresses = plan.total_addresses();
    let total_probes = total_addresses.saturating_mul(plan.ports_count());
    let ports_count = plan.ports_count().max(1);
    let start_status = scheduler.status();
    let base_syns = start_status.syns;
    let base_synacks = start_status.synacks;
    let mut last_sample = (Instant::now(), base_syns);
    let mut measured_pps = 0.0f64;

    let mut blocks_scanned = 0u64;

    loop {
        let job = match scheduler.claim("local") {
            Claim::Job(job) => job,
            Claim::Waiting => {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            Claim::Done => break,
        };

        globals::set_tx_done(false);
        let done_before = scheduler.addresses_done();
        let cancel = AtomicBool::new(false);
        let mut last_print = Instant::now();

        let outcome = engine.scan_block(&job, &cancel, &mut |progress| {
            // Keep the scheduler's lease and aggregate counters current, exactly
            // as a remote client's progress reports would.
            scheduler.progress(
                "local",
                job.job_id,
                progress.pos,
                progress.syns,
                progress.synacks,
                progress.total,
                progress.hits,
                0,
                0.0,
                &job.cidr,
            );

            if progress.syns > 0 {
                let (then, syns_then) = last_sample;
                let dt = then.elapsed().as_secs_f64();
                if dt >= 0.5 {
                    let instant = progress.syns.saturating_sub(syns_then) as f64 / dt;
                    measured_pps = if measured_pps > 0.0 {
                        measured_pps * 0.6 + instant * 0.4
                    } else {
                        instant
                    };
                    last_sample = (Instant::now(), progress.syns);
                }
            }

            if last_print.elapsed() >= Duration::from_millis(700) {
                last_print = Instant::now();
                let (scanner, fetcher, verifier) = engine.pipeline();
                let ips_checked =
                    (done_before + progress.pos / ports_count).min(total_addresses);
                status.print(
                    ips_checked,
                    total_addresses,
                    measured_pps,
                    0,
                    base_synacks + progress.synacks,
                    base_syns + progress.syns,
                    0,
                    zorp.output.is_status_ndjson,
                    scanner,
                    fetcher,
                    verifier,
                    progress.pos,
                    total_probes,
                );
            }
            true
        });

        let outcome = match outcome {
            Ok(o) => o,
            Err(e) => {
                eprintln!("\nERROR: block {} failed: {}", job.job_id, e);
                scheduler.release("local", job.job_id, 0);
                break;
            }
        };

        let (accepted_hits, accepted_keys, _dup_hits, _dup_keys) =
            scheduler.submit_results(
                "local",
                job.job_id,
                &outcome.hits,
                &outcome.keys,
                outcome.syns,
                outcome.synacks,
            );

        if outcome.completed {
            if let Err(e) = scheduler.complete("local", job.job_id, outcome.pos, outcome.syns, outcome.synacks) {
                eprintln!("\nERROR: cannot record block {}: {}", job.job_id, e);
            } else {
                blocks_scanned += 1;
            }
        } else {
            scheduler.release("local", job.job_id, outcome.pos);
        }

        eprintln!(
            "[+] block {} {} → {} hits, {} keys (pos {}/{})",
            job.job_id,
            job.cidr,
            accepted_hits,
            accepted_keys,
            outcome.pos,
            outcome.total
        );

        if let Err(e) = scheduler.save() {
            eprintln!("[state] save failed: {}", e);
        }

        if globals::is_tx_done() {
            break;
        }
    }

    let status_snapshot = scheduler.status();
    if let Err(e) = scheduler.save() {
        eprintln!("[state] save failed: {}", e);
    }
    status.finish();

    eprintln!("\nScan {}.", if globals::is_tx_done() { "stopped" } else { "complete" });
    eprintln!(
        "[+] {} SYNs sent, {} SYN-ACKs received, {} open ports, {} keys",
        status_snapshot.syns, status_snapshot.synacks, status_snapshot.hits, status_snapshot.keys
    );
    eprintln!(
        "[+] coverage {:.2}% ({} of {} addresses), {} blocks scanned, state in {}",
        status_snapshot.percent,
        status_snapshot.addresses_done,
        status_snapshot.addresses_total,
        blocks_scanned,
        zorp.state_file.display()
    );
    if status_snapshot.percent < 100.0 {
        // Nothing to remember: the progress file is the state, and running the
        // same command again picks it up.
        eprintln!("[+] run the same command again to resume");
    }
    eprintln!("[+] results in {}", scheduler.results_dir().display());

    engine.shutdown();
    0
}

fn print_banner(plan: &Plan, scheduler: &Scheduler) {
    let coverage = scheduler.coverage();
    eprintln!("ZorpInvader {} — standalone", conf::VERSION);
    eprintln!(
        "  targets   {} address(es) in {} CIDR(s)",
        plan.total_addresses(),
        plan.targets.to_cidrs().len()
    );
    eprintln!("  ports     {} ({} per host)", plan.ports, plan.ports_count());
    eprintln!(
        "  blocks    {} of {} addresses",
        plan.blocks_len(),
        plan.chunk
    );
    if coverage.addresses_done > 0 {
        eprintln!(
            "  resuming  {:.2}% covered, {} blocks done, {} partial",
            coverage.percent, coverage.blocks_done, coverage.blocks_partial
        );
    }
    eprintln!();
}
