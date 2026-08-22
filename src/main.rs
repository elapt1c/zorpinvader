#![allow(dead_code, unused_imports, unused_variables, unused_mut, unused_assignments)]

mod app;

use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crossbeam_queue::ArrayQueue;
use parking_lot::Condvar;

use zorpinvader::crypto::blackrock::BlackRock;
use zorpinvader::greyhat::{Fetcher, GreyhatScanner, Verifier};
use zorpinvader::main_mod::conf::{self, Operation, Zorp};
use zorpinvader::main_mod::dedup::DedupTable;
use zorpinvader::main_mod::globals;
use zorpinvader::main_mod::initadapter::{self, AdapterInitResult};
use zorpinvader::main_mod::status::Status;
use zorpinvader::main_mod::throttle::Throttler;
use zorpinvader::massip::addr::{IpAddress, MacAddress};
use zorpinvader::misc::syn_cookie;
use zorpinvader::pixie::timer;
use zorpinvader::rawsock::adapter::Adapter;
use zorpinvader::templ::opts::TemplateOptions;
use zorpinvader::templ::pkt::{self, TemplateSet};

/// Per-NIC thread pair parameters.
struct ThreadPair {
    zorp: Arc<Zorp>,
    nic_index: usize,
    adapter: Arc<Adapter>,
    tmplset: Arc<TemplateSet>,
    source_ip: u32,
    source_port: u16,
    entropy: u64,
    done_transmitting: AtomicBool,
    done_receiving: AtomicBool,
    my_index: AtomicU64,
    pass_pos: AtomicU64,
    throttler: parking_lot::Mutex<Throttler>,
    total_synacks: AtomicU64,
    total_tcbs: AtomicU64,
    total_syns: AtomicU64,
    fetcher: Arc<Fetcher>,
}

/// Parse a CIDR string like "10.0.0.0/8" into (begin, end) u32 range.
fn parse_cidr(s: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip_parts: Vec<u32> = parts[0].split('.').filter_map(|p| p.parse().ok()).collect();
    if ip_parts.len() != 4 {
        return None;
    }
    let prefix_len: u32 = parts[1].parse().ok()?;
    if prefix_len > 32 {
        return None;
    }
    let ip = (ip_parts[0] << 24) | (ip_parts[1] << 16) | (ip_parts[2] << 8) | ip_parts[3];
    let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
    let begin = ip & mask;
    let end = begin | (!mask);
    Some((begin, end))
}

/// Format a u32 IPv4 address as a dotted-quad string.
fn ipv4_to_string(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

fn transmit_thread(parms: Arc<ThreadPair>) {
    let zorp = &parms.zorp;
    let seed = zorp.seed;
    let nic_count = zorp.nic_count() as u64;

    log::info!("[+] starting transmit thread #{}", parms.nic_index);

    parms.total_syns.store(0, Ordering::SeqCst);

    let mut throttler = Throttler::new();
    let effective_rate = if zorp.max_rate <= 0.0 {
        f64::INFINITY
    } else {
        zorp.max_rate / nic_count as f64
    };
    throttler.start(effective_rate);

    let mut targets = zorpinvader::massip::massip::MassIP::new();
    for range_str in &zorp.target_ranges {
        let _ = targets.add_target_string(range_str.as_bytes());
    }
    if !zorp.ports.is_empty() {
        for port_str in zorp.ports.split(',') {
            let _ = targets.add_port_string(port_str.trim(), 0);
        }
    }

    // Apply exclude ranges
    if !zorp.exclude_ranges.is_empty() {
        let mut excludes = zorpinvader::massip::rangesv4::RangeList::new();
        for excl in &zorp.exclude_ranges {
            if let Some((begin, end)) = parse_cidr(excl) {
                excludes.add_range(begin, end);
            }
        }
        targets.ipv4.exclude(&excludes);
    }

    targets.optimize();

    let count_ipv4 = targets.ipv4.count_addresses();
    let count_ipv6 = targets.ipv6.count_addresses().lo;
    let count_ports = targets.ports.count_addresses() as u64;

    let ip_me = parms.source_ip;
    let port_me = parms.source_port;
    let entropy = parms.entropy;
    let adapter = &parms.adapter;
    let tmplset = &parms.tmplset;
    let mut px = [0u8; 2048];

    // Compute stride for spirograph-style coverage.
    // Stride = range/64 ensures we sweep the full IPv4 space in 64 big steps,
    // then spiral back to fill in the gaps. Must be odd (coprime with powers of 2).
    let base_range = count_ipv4 * count_ports + count_ipv6 * count_ports;
    let mut stride = if zorp.stride > 0 {
        zorp.stride
    } else {
        (base_range / 64).max(1)
    };
    if stride % 2 == 0 {
        stride |= 1; // ensure odd for coprimality
    }

    // Each NIC/shard starts at a different offset so they don't overlap.
    let shard_start = (zorp.shard.one as u64 - 1) * nic_count + parms.nic_index as u64;
    let step = stride * nic_count * zorp.shard.of as u64;

    // Resume: decode saved position into (pass, current).
    // The saved index encodes both the pass number and the current position.
    // pass = saved_index / base_range, current = saved_index % base_range.
    let mut pass: u64 = if zorp.resume.index > 0 {
        zorp.resume.index / base_range
    } else {
        0
    };
    let mut current: u64 = if zorp.resume.index > 0 {
        zorp.resume.index % base_range
    } else {
        shard_start
    };

    let mut last_save = std::time::Instant::now();

    log::info!("[+] transmit thread #{}: stride={}, start_pass={}", parms.nic_index, stride, pass);

    'infinite: loop {
        let range = base_range;
        let range_ipv6 = count_ipv6 * count_ports;
        let blackrock = BlackRock::init(range, seed, zorp.blackrock_rounds);

        // Outer loop: one pass per offset. Each pass sweeps ~range/step indices.
        // After stride passes, every index has been visited exactly once.
        while pass < stride {
            // Start this pass at the offset for this pass
            let pass_start = pass + shard_start;
            if pass_start >= stride {
                break; // all passes complete
            }
            current = pass_start;

            // Inner loop: stride through the index space
            while current < range {
                // Throttle SYN scan if fetcher queue is backing up
                let qdepth = parms.fetcher.queue_depth();
                if qdepth > 4096 {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }

                let syns_sent = parms.total_syns.load(Ordering::Relaxed);
                let batch_size = throttler.next_batch(syns_sent);
                let mut remaining = batch_size;

                while remaining > 0 && current < range {
                    let xx = blackrock.shuffle(current);

                    if xx < range_ipv6 {
                        // Skip IPv6 for now
                    } else {
                        let xx = xx - range_ipv6;
                        let ip_them = targets.ipv4.pick(xx % count_ipv4);
                        let port_them = targets.ports.pick(xx / count_ipv4);

                        let cookie = syn_cookie::syn_cookie_ipv4(
                            ip_them, port_them, ip_me, port_me as u32, entropy,
                        );
                        let seqno = cookie as u32;

                        let len = pkt::template_set_target_ipv4(
                            tmplset, ip_them, port_them, ip_me, port_me, seqno, &mut px,
                        );

                        if len > 0 {
                            let _ = adapter.send_packet(&px[..len]);
                        }

                        parms.total_syns.fetch_add(1, Ordering::SeqCst);
                    }

                    remaining -= 1;

                    // Advance by stride (spirograph step)
                    current += step;
                }

                // Encode progress as (pass * range + current) for save/resume
                let progress = pass * range + current.min(range - 1);
                parms.my_index.store(progress, Ordering::SeqCst);
                parms.pass_pos.store(current % range, Ordering::SeqCst);

                // Periodic save every 60 seconds
                if last_save.elapsed() >= Duration::from_secs(60) {
                    if let Err(e) = zorp.save_state(progress) {
                        log::warn!("[save] failed: {}", e);
                    } else {
                        log::info!("[save] progress saved (pass={}, index={})", pass, progress);
                    }
                    last_save = std::time::Instant::now();
                }

                if globals::is_tx_done() {
                    break;
                }
            }

            // This pass is done — advance to next offset
            pass += 1;
            log::info!("[+] pass {}/{} complete", pass, stride);

            if globals::is_tx_done() {
                break;
            }
        }

        if zorp.is_infinite && !globals::is_tx_done() {
            pass = 0; // restart spirograph from beginning
            continue 'infinite;
        }
        break;
    }

    // Final save on completion
    let progress = pass * base_range + current.min(base_range.saturating_sub(1));
    let _ = zorp.save_state(progress);
    log::info!("[save] final state saved (pass={}, progress={})", pass, progress);

    log::info!("[+] transmit thread #{} complete", parms.nic_index);

    // Wait for receive thread to finish collecting responses
    while !globals::is_rx_done() {
        std::thread::sleep(Duration::from_millis(1));
    }

    parms.done_transmitting.store(true, Ordering::SeqCst);
    log::info!("[+] exiting transmit thread #{}", parms.nic_index);
}

/// Parse an incoming Ethernet frame for a SYN-ACK response.
///
/// Returns `Some((ip_src, port_src, ip_dst, port_dst, ack_seq))` if the
/// packet is an IPv4 TCP SYN-ACK. Returns `None` otherwise.
fn parse_synack(pkt: &[u8]) -> Option<(u32, u16, u32, u16, u32)> {
    // Need at least Ethernet (14) + IPv4 (20) + TCP (20) = 54 bytes
    if pkt.len() < 54 {
        return None;
    }

    // Ethernet: check EtherType = 0x0800 (IPv4)
    let ethertype = ((pkt[12] as u16) << 8) | pkt[13] as u16;
    if ethertype != 0x0800 {
        return None;
    }

    let ip_off = 14;

    // IPv4: check version and IHL
    let version_ihl = pkt[ip_off];
    if (version_ihl >> 4) != 4 {
        return None;
    }
    let ihl = ((version_ihl & 0x0F) as usize) * 4;
    if ihl < 20 || ip_off + ihl + 20 > pkt.len() {
        return None;
    }

    // Check protocol = TCP (6)
    let protocol = pkt[ip_off + 9];
    if protocol != 6 {
        return None;
    }

    // Extract IPs (from the response: src = remote, dst = us)
    let ip_src = ((pkt[ip_off + 12] as u32) << 24)
        | ((pkt[ip_off + 13] as u32) << 16)
        | ((pkt[ip_off + 14] as u32) << 8)
        | pkt[ip_off + 15] as u32;
    let ip_dst = ((pkt[ip_off + 16] as u32) << 24)
        | ((pkt[ip_off + 17] as u32) << 16)
        | ((pkt[ip_off + 18] as u32) << 8)
        | pkt[ip_off + 19] as u32;

    let tcp_off = ip_off + ihl;

    // TCP: extract ports, flags, seq, ack
    let port_src = ((pkt[tcp_off] as u16) << 8) | pkt[tcp_off + 1] as u16;
    let port_dst = ((pkt[tcp_off + 2] as u16) << 8) | pkt[tcp_off + 3] as u16;
    let seq = ((pkt[tcp_off + 4] as u32) << 24)
        | ((pkt[tcp_off + 5] as u32) << 16)
        | ((pkt[tcp_off + 6] as u32) << 8)
        | pkt[tcp_off + 7] as u32;
    let ack = ((pkt[tcp_off + 8] as u32) << 24)
        | ((pkt[tcp_off + 9] as u32) << 16)
        | ((pkt[tcp_off + 10] as u32) << 8)
        | pkt[tcp_off + 11] as u32;
    let flags = pkt[tcp_off + 13];

    // Check for SYN-ACK (SYN=1, ACK=1)
    if flags & 0x12 != 0x12 {
        return None;
    }

    Some((ip_src, port_src, ip_dst, port_dst, ack))
}

fn receive_thread(parms: Arc<ThreadPair>) {
    log::info!("[+] starting receive thread #{}", parms.nic_index);

    let dedup = DedupTable::new();
    let adapter = &parms.adapter;
    let ip_me = parms.source_ip;
    let port_me = parms.source_port;
    let entropy = parms.entropy;
    let fetcher = &parms.fetcher;

    // Set receive timeout so we can check shutdown flag periodically
    {
        let fd = adapter.socket().map(|s| s.as_raw_fd()).unwrap_or(-1);
        if fd >= 0 {
            let tv = libc::timeval {
                tv_sec: 0,
                tv_usec: 100_000, // 100ms
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
    }

    let mut buf = [0u8; 2048];
    let mut _dedup = dedup;

    // Wait for responses: continue until tx_done + grace period
    let mut tx_done_since = Option::<std::time::Instant>::None;

    loop {
        if globals::is_rx_done() {
            break;
        }

        // Try to receive a packet
        match adapter.recv_packet(&mut buf) {
            Ok(recv) => {
                let data = recv.data;

                // Parse for SYN-ACK
                if let Some((ip_src, port_src, ip_dst, port_dst, ack_seq)) = parse_synack(data) {
                    // Verify: ip_dst should be us, port_dst should be our source port
                    if ip_dst != ip_me || port_dst != port_me {
                        continue;
                    }

                    // The SYN cookie is ack_seq - 1 (server echoes seq+1)
                    let cookie_received = ack_seq.wrapping_sub(1);

                    // Recompute expected cookie
                    let expected = syn_cookie::syn_cookie_ipv4(
                        ip_src, port_src as u32, ip_me, port_me as u32, entropy,
                    ) as u32;

                    if cookie_received != expected {
                        continue; // Invalid cookie — not our response
                    }

                    parms.total_synacks.fetch_add(1, Ordering::SeqCst);

                    let ip_str = ipv4_to_string(ip_src);
                    log::debug!("[recv] SYN-ACK from {}:{}", ip_str, port_src);

                    // Submit open port to the HTTP fetcher for API key scanning
                    fetcher.submit(&ip_str, port_src);
                }
            }
            Err(_) => {
                // Timeout or error — check if we should stop
                if globals::is_tx_done() {
                    match tx_done_since {
                        None => {
                            // Start grace period to catch late responses
                            tx_done_since = Some(std::time::Instant::now());
                        }
                        Some(since) => {
                            // Wait up to 10 seconds after transmit is done
                            if since.elapsed() > Duration::from_secs(10) {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    log::info!("[+] exiting receive thread #{}", parms.nic_index);
    parms.done_receiving.store(true, Ordering::SeqCst);
}

fn control_c_handler() {
    ctrlc::set_handler(move || {
        static PRESSED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let count = PRESSED.fetch_add(1, Ordering::SeqCst);
        if count == 0 {
            eprintln!("waiting several seconds to exit...");
            globals::set_tx_done(true);
        } else if globals::is_rx_done() {
            std::process::exit(1);
        } else {
            globals::set_rx_done(true);
        }
    })
    .expect("Error setting Ctrl-C handler");
}

fn main_scan(zorp: Arc<Zorp>) -> i32 {
    let mut targets = zorpinvader::massip::massip::MassIP::new();
    for range_str in &zorp.target_ranges {
        let _ = targets.add_target_string(range_str.as_bytes());
    }
    if !zorp.ports.is_empty() {
        for port_str in zorp.ports.split(',') {
            let _ = targets.add_port_string(port_str.trim(), 0);
        }
    }

    // Default: scan entire IPv4 space when no targets specified
    if targets.ipv4.count_addresses() == 0 && targets.ipv6.count_addresses().lo == 0 {
        eprintln!("No targets specified, defaulting to 0.0.0.0/0");
        targets.ipv4.add_range(0x00000000, 0xFFFFFFFF);
    }

    // Apply exclude ranges (from defaults or --exclude flags)
    if !zorp.exclude_ranges.is_empty() {
        let mut excludes = zorpinvader::massip::rangesv4::RangeList::new();
        for excl in &zorp.exclude_ranges {
            if let Some((begin, end)) = parse_cidr(excl) {
                excludes.add_range(begin, end);
            }
        }
        targets.ipv4.exclude(&excludes);
    }

    // Default ports: common HTTP/API ports
    if targets.ports.count_addresses() == 0 {
        eprintln!("No ports specified, defaulting to common HTTP ports");
        for port in [80u32, 8080, 8443, 8000, 3000, 5000, 8888] {
            let _ = targets.ports.add_range(port, port);
        }
    }

    targets.optimize();

    let count_ips = targets.ipv4.count_addresses() + targets.ipv6.count_addresses().lo;
    if count_ips == 0 {
        log::error!("FAIL: target IP address list empty");
        return 1;
    }
    let count_ports = targets.ports.count_addresses() as u64;
    if count_ports == 0 {
        log::error!("FAIL: no ports were specified");
        return 1;
    }
    let range = count_ips * count_ports + zorp.retries as u64 * count_ips * count_ports;

    control_c_handler();

    // --- Initialize network adapter ---
    let mut nic_config = zorp.nic[0].clone();
    let init_result = match initadapter::initialize_adapter(&zorp, &mut nic_config, 0, &targets) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ERROR: adapter init failed: {}", e);
            return 1;
        }
    };

    let adapter = Arc::new(init_result.adapter);
    let source_mac = init_result.source_mac;
    let router_mac_ipv4 = init_result.router_mac_ipv4;
    let source_ip = nic_config.src_ipv4_first;

    if source_ip == 0 {
        eprintln!("ERROR: no source IP detected. Use --adapter-ip <ip>");
        return 1;
    }

    let source_port: u16 = 61234;

    let entropy = syn_cookie::get_entropy();
    let tmpl_opts = TemplateOptions::default();
    let data_link = adapter.link_type.to_raw();
    let tmplset = Arc::new(pkt::template_packet_init(
        source_mac,
        router_mac_ipv4,
        init_result.router_mac_ipv6,
        None,
        None,
        data_link,
        entropy,
        &tmpl_opts,
    ));

    eprintln!("[+] adapter: {} (ip={}, mac={})",
        adapter.name,
        ipv4_to_string(source_ip),
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            source_mac.addr[0], source_mac.addr[1], source_mac.addr[2],
            source_mac.addr[3], source_mac.addr[4], source_mac.addr[5]));
    eprintln!("[+] source port: {}, entropy: 0x{:016x}", source_port, entropy);

    // Compute and display stride
    let stride_display = if zorp.stride > 0 {
        zorp.stride
    } else {
        let s = (range / 64).max(1);
        if s % 2 == 0 { s | 1 } else { s }
    };
    eprintln!("[+] stride: {} (spirograph coverage, ~{:.0} passes to complete)",
        stride_display, range as f64 / stride_display as f64);
    if zorp.resume.index > 0 {
        eprintln!("[+] resuming from index {}", zorp.resume.index);
    }

    // --- Build the greyhat API key scanning pipeline ---
    let scanner = Arc::new(GreyhatScanner::new(zorp.include_safe));
    let verifier = Arc::new(Verifier::new(0));
    let fetcher = Arc::new(Fetcher::new(
        scanner.clone(),
        verifier.clone(),
        Some(zorp.tpc),
    ));

    let total_patterns = zorpinvader::greyhat::greyhat::KEY_PATTERNS.len();
    let safe_count = zorpinvader::greyhat::greyhat::KEY_PATTERNS.iter().filter(|p| p.safe).count();
    let active_patterns = if zorp.include_safe { total_patterns } else { total_patterns - safe_count };
    eprintln!("[+] API key scanner: {} patterns active ({} safe excluded), results → found_keys.csv{}",
        active_patterns, safe_count,
        if zorp.include_safe { " (--include-safe)" } else { "" });

    // --- Create thread pair ---
    let parms = Arc::new(ThreadPair {
        zorp: zorp.clone(),
        nic_index: 0,
        adapter: adapter.clone(),
        tmplset: tmplset.clone(),
        source_ip,
        source_port,
        entropy,
        done_transmitting: AtomicBool::new(false),
        done_receiving: AtomicBool::new(false),
        my_index: AtomicU64::new(zorp.resume.index),
        pass_pos: AtomicU64::new(0),
        throttler: parking_lot::Mutex::new(Throttler::new()),
        total_synacks: AtomicU64::new(0),
        total_tcbs: AtomicU64::new(0),
        total_syns: AtomicU64::new(0),
        fetcher: fetcher.clone(),
    });

    {
        let now_t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let time_str = chrono::DateTime::from_timestamp(now_t as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S GMT").to_string())
            .unwrap_or_default();
        eprintln!("Starting ZorpInvader {} at {}", conf::VERSION, time_str);
        eprintln!("Initiating SYN Stealth Scan");
        eprintln!(
            "Scanning {} hosts [{} port{}/host]",
            count_ips, count_ports,
            if count_ports == 1 { "" } else { "s" }
        );
    }

    // --- Spawn transmit and receive threads ---
    let p = parms.clone();
    let xmit_handle = std::thread::spawn(move || transmit_thread(p));
    let p = parms.clone();
    let recv_handle = std::thread::spawn(move || receive_thread(p));

    std::thread::sleep(Duration::from_millis(100));

    let mut status = Status::new();
    status.is_infinite = zorp.is_infinite;
    status.start();

    // --- Status monitoring loop ---
    // Recompute stride for progress decoding (must match transmit thread).
    let mut stride = if zorp.stride > 0 { zorp.stride } else { (range / 64).max(1) };
    if stride % 2 == 0 { stride |= 1; }

    let mut last_syns: u64 = 0;
    let mut last_time = std::time::Instant::now();

    while zorp.output.is_status_updates {
        let idx = parms.my_index.load(Ordering::SeqCst);
        let total_synacks = parms.total_synacks.load(Ordering::SeqCst);
        let total_syns = parms.total_syns.load(Ordering::SeqCst);

        // Calculate actual send rate
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(last_time).as_secs_f64();
        let actual_rate = if elapsed > 0.0 {
            (total_syns.saturating_sub(last_syns)) as f64 / elapsed
        } else {
            0.0
        };
        last_syns = total_syns;
        last_time = now;

        // idx encodes (pass * range + current_position).
        // Scan is complete when all stride passes are done.
        let current_pass = if range > 0 { idx / range } else { 0 };
        if current_pass >= stride && total_syns > 0 && !zorp.is_infinite {
            globals::set_tx_done(true);
        }

        // Pass position from dedicated atomic (avoids clamping artifacts)
        let pass_pos = parms.pass_pos.load(Ordering::SeqCst);

        let ips_checked = if count_ports > 0 { total_syns / count_ports } else { total_syns };
        status.print(
            ips_checked, count_ips, actual_rate, 0, total_synacks, total_syns, 0,
            zorp.output.is_status_ndjson,
            &scanner, &fetcher, &verifier,
            pass_pos, range,
        );

        // --- Shutdown: keep status updating while threads exit and pipeline drains ---
        if globals::is_tx_done() {
            globals::set_rx_done(true);

            // Join scan threads (they exit quickly once rx_done is set)
            let _ = xmit_handle.join();
            let _ = recv_handle.join();

            // Drain fetcher: brief pause for in-flight HTTP requests
            let pending = fetcher.queue_depth();
            if pending > 0 {
                eprint!("\x1b[18;1H\x1b[2K\x1b[33m[+] draining pipeline ({} pending)...\x1b[0m\n", pending);
            }
            std::thread::sleep(Duration::from_millis(1500));

            // Shutdown fetcher workers
            match Arc::try_unwrap(fetcher) {
                Ok(f) => f.shutdown(),
                Err(arc) => { drop(arc); }
            }
            // Brief pause for verifier to process remaining candidates
            std::thread::sleep(Duration::from_millis(500));

            // Shutdown verifier workers
            match Arc::try_unwrap(verifier) {
                Ok(v) => v.shutdown(),
                Err(arc) => { drop(arc); }
            }

            // Move cursor below TUI area so final output doesn't interleave with prompt
            eprint!("\x1b[19;1H");

            let total_synacks = parms.total_synacks.load(Ordering::SeqCst);
            let total_syns = parms.total_syns.load(Ordering::SeqCst);
            eprintln!("\nScan Complete.");
            eprintln!("[+] {} SYNs sent, {} SYN-ACKs received", total_syns, total_synacks);
            eprintln!("[+] results in found_keys.csv");
            return 0;
        }

        std::thread::sleep(Duration::from_millis(750));
    }

    // Fallback for --no-status mode: join threads and clean up without TUI
    if globals::is_tx_done() {
        globals::set_rx_done(true);
    }
    let _ = xmit_handle.join();
    let _ = recv_handle.join();

    match Arc::try_unwrap(fetcher) {
        Ok(f) => f.shutdown(),
        Err(arc) => { drop(arc); }
    }
    match Arc::try_unwrap(verifier) {
        Ok(v) => v.shutdown(),
        Err(arc) => { drop(arc); }
    }

    let total_synacks = parms.total_synacks.load(Ordering::SeqCst);
    let total_syns = parms.total_syns.load(Ordering::SeqCst);
    eprintln!("\nScan Complete.");
    eprintln!("[+] {} SYNs sent, {} SYN-ACKs received", total_syns, total_synacks);
    eprintln!("[+] results in found_keys.csv");
    0
}

fn selftest() -> i32 {
    let mut failures = 0;
    failures += if zorpinvader::main_mod::dedup::DedupTable::selftest() { 0 } else { 1 };
    failures += zorpinvader::data::smack::Smack::selftest();
    failures += zorpinvader::data::rte_ring::rte_ring_selftest();
    failures += app::selftest();
    if failures != 0 {
        eprintln!("regression test: failed :( ");
        1
    } else {
        eprintln!("regression test: success!");
        0
    }
}

fn main() {
    env_logger::init();

    let _usec_start = timer::gettime();
    globals::update_global_now();

    let args: Vec<String> = std::env::args().collect();

    let mut zorp = match Zorp::from_args(&args) {
        Ok(z) => z,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    // Apply defaults so the transmit thread has targets even when
    // no --range/--ports are specified on the command line.
    if zorp.op == Operation::Scan || zorp.op == Operation::Default {
        if zorp.target_ranges.is_empty() {
            zorp.target_ranges.push("0.0.0.0/0".to_string());
            // Default excludes: RFC1918, CGNAT, link-local, loopback, multicast, reserved
            zorp.exclude_ranges.push("10.0.0.0/8".to_string());
            zorp.exclude_ranges.push("172.16.0.0/12".to_string());
            zorp.exclude_ranges.push("192.168.0.0/16".to_string());
            zorp.exclude_ranges.push("100.64.0.0/10".to_string());
            zorp.exclude_ranges.push("169.254.0.0/16".to_string());
            zorp.exclude_ranges.push("127.0.0.0/8".to_string());
            zorp.exclude_ranges.push("224.0.0.0/4".to_string());
            zorp.exclude_ranges.push("240.0.0.0/4".to_string());
        }
        if zorp.ports.is_empty() {
            zorp.ports = "80,8080,8443,8000,3000,5000,8888".to_string();
        }
    }

    // Load saved scan state if --resume was passed
    if zorp.auto_resume {
        if zorp.load_state() {
            // State loaded successfully
        } else {
            eprintln!("[!] --resume: no paused.conf found, starting fresh");
        }
    }

    let zorp = Arc::new(zorp);

    match zorp.op {
        Operation::Default | Operation::Scan => {
            std::process::exit(main_scan(zorp));
        }
        Operation::ListAdapters => {
            println!("Network adapters:");
            println!("  (use --adapter <name> to specify)");
        }
        Operation::Selftest => {
            std::process::exit(selftest());
        }
        Operation::Benchmark => {
            println!("=== benchmarking ({}-bits) ===\n", std::mem::size_of::<usize>() * 8);
            println!("benchmark not yet implemented");
        }
        Operation::Echo | Operation::EchoAll => {
            println!("echo not yet implemented");
        }
        Operation::EchoCidr => {
            println!("echo-cidr not yet implemented");
        }
        Operation::ListScan => {
            log::info!("List scan mode");
        }
        Operation::ReadScan => {
            log::info!("Read scan mode");
        }
        Operation::ReadRange => {
            log::info!("Read range mode");
        }
        Operation::DebugInterface => {
            log::info!("Debug interface mode");
        }
    }
}
