//! List scan mode: output a randomized list of all target IPs.
//!
//! This module implements the "listscan" operation, which iterates over all
//! IP/port combinations in the target set using the BlackRock format-preserving
//! cipher to produce a pseudo-random permutation. The output can be piped to
//! other tools or saved to a file.

use std::io::{self, Write};

use crate::crypto::BlackRock;
use crate::massip::addr::IpAddress;
use crate::massip::massip::MassIP;

use super::conf::Zorp;

/// Run the list scan: print every IP/port combination in pseudo-random order.
///
/// This is the Rust equivalent of the C `main_listscan()` function.
///
/// # Arguments
///
/// * `zorp` - The master configuration (provides seed, shard, resume, retries, etc.)
/// * `targets` - The target IP/port set (must already be optimized).
/// * `out` - The writer to print results to (typically stdout).
pub fn main_listscan(
    zorp: &Zorp,
    targets: &mut MassIP,
    out: &mut dyn Write,
) -> io::Result<()> {
    // If no ports were configured, add a pseudo-port so the algorithm works.
    if !targets.has_target_ports() {
        targets.ports.add_range(80, 80);
    }
    targets.optimize();

    // Total number of IP/port combinations.
    let range_total = targets.range().lo;

    let increment = if zorp.shard.of > 0 {
        zorp.shard.of as u64
    } else {
        1
    };

    let mut seed = zorp.seed;

    // Outer loop for infinite mode (re-seed and repeat).
    loop {
        let blackrock = BlackRock::init(range_total, seed, zorp.blackrock_rounds);

        let start = zorp.resume.index + (zorp.shard.one.saturating_sub(1)) as u64;
        let mut end = range_total;

        if zorp.resume.count > 0 && end > start + zorp.resume.count {
            end = start + zorp.resume.count;
        }
        end += (zorp.retries as f64 * zorp.max_rate) as u64;

        let mut i = start;
        while i < end {
            let shuffled = blackrock.shuffle(i);
            let (addr, port) = targets.pick(shuffled);

            if zorp.is_test_csv {
                // CSV test output: last two bytes of IPv4 address.
                if let IpAddress::V4(ipv4) = addr {
                    writeln!(out, "{},{}", (ipv4 >> 8) & 0xFF, ipv4 & 0xFF)?;
                }
            } else if targets.count_ports == 1 {
                // Normal case: just print the IP address.
                writeln!(out, "{}", addr)?;
            } else {
                // Multiple ports: print IP:port.
                match addr {
                    IpAddress::V6(_) => {
                        writeln!(out, "[{}]:{}", addr, port)?;
                    }
                    IpAddress::V4(_) => {
                        writeln!(out, "{}:{}", addr, port)?;
                    }
                }
            }

            i += increment;
        }

        if !zorp.is_infinite {
            break;
        }
        seed += 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::main_mod::conf::Zorp;
    use crate::massip::massip::MassIP;

    fn make_test_targets() -> MassIP {
        let mut targets = MassIP::new();
        // Add a /24 network: 192.0.2.0 - 192.0.2.255 (256 addresses)
        targets.ipv4.add_range(0xC000_0200, 0xC000_02FF);
        targets.ports.add_range(80, 80);
        targets.optimize();
        targets
    }

    #[test]
    fn test_listscan_produces_output() {
        let zorp = Zorp {
            shard: super::super::conf::ShardConfig { one: 1, of: 1 },
            seed: 42,
            ..Zorp::default()
        };
        let mut targets = make_test_targets();
        let mut buf = Vec::new();

        main_listscan(&zorp, &mut targets, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();

        // Should produce 256 lines (one per IP in /24)
        assert_eq!(lines.len(), 256);

        // Each line should be an IP address
        for line in &lines {
            assert!(
                line.contains('.'),
                "expected IPv4 address, got: {}",
                line
            );
        }
    }

    #[test]
    fn test_listscan_with_shards() {
        // Shard 1 of 2 should produce roughly half the output
        let zorp = Zorp {
            shard: super::super::conf::ShardConfig { one: 1, of: 2 },
            seed: 42,
            ..Zorp::default()
        };
        let mut targets = make_test_targets();
        let mut buf = Vec::new();

        main_listscan(&zorp, &mut targets, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();

        assert_eq!(lines.len(), 128); // 256 / 2
    }

    #[test]
    fn test_listscan_csv_mode() {
        let zorp = Zorp {
            is_test_csv: true,
            seed: 42,
            ..Zorp::default()
        };
        let mut targets = make_test_targets();
        let mut buf = Vec::new();

        main_listscan(&zorp, &mut targets, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // CSV output should have comma-separated values
        for line in output.lines() {
            assert!(line.contains(','), "expected CSV, got: {}", line);
        }
    }

    #[test]
    fn test_listscan_multiple_ports() {
        let mut targets = MassIP::new();
        targets.ipv4.add_range(0xC000_0201, 0xC000_0201); // single IP
        targets.ports.add_range(80, 82); // 3 ports
        targets.optimize();

        let zorp = Zorp {
            seed: 42,
            ..Zorp::default()
        };
        let mut buf = Vec::new();

        main_listscan(&zorp, &mut targets, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();

        // 1 IP * 3 ports = 3 lines
        assert_eq!(lines.len(), 3);

        // Each line should contain IP:port
        for line in &lines {
            assert!(line.contains(':'), "expected IP:port, got: {}", line);
        }
    }
}
