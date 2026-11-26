#![allow(dead_code, unused_imports, unused_variables, unused_mut, unused_assignments)]

mod app;

use std::sync::Arc;

use zorpinvader::coord::{client, local, server};
use zorpinvader::main_mod::conf::{self, Mode, Operation, Zorp};
use zorpinvader::main_mod::globals;
use zorpinvader::pixie::timer;

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

    // Controller mode owns the target set; a client is told what to scan and must
    // not invent ranges of its own.
    if zorp.op == Operation::Scan || zorp.op == Operation::Default {
        if zorp.mode != Mode::Client {
            if zorp.target_ranges.is_empty() {
                zorp.target_ranges.push("0.0.0.0/0".to_string());
                // Default excludes: RFC1918, CGNAT, link-local, loopback, multicast, reserved
                for excluded in [
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "100.64.0.0/10",
                    "169.254.0.0/16",
                    "127.0.0.0/8",
                    "224.0.0.0/4",
                    "240.0.0.0/4",
                ] {
                    zorp.exclude_ranges.push(excluded.to_string());
                }
            }
        }
        if zorp.ports.trim().is_empty() {
            zorp.ports = "80,8080,8443,8000,3000,5000,8888".to_string();
        }
    }

    let zorp = Arc::new(zorp);

    match zorp.op {
        Operation::Default | Operation::Scan => {
            let code = match zorp.mode {
                Mode::Server => server::run(zorp.clone()),
                Mode::Client => client::run(zorp.clone()),
                Mode::Local => local::run(zorp.clone()),
            };
            std::process::exit(code);
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
