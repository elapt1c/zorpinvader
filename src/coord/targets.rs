//! Collect the target set and ports for a scan plan from the parsed config.

use crate::main_mod::conf::Zorp;
use crate::massip::massip::MassIP;

use super::set4::RangeSet4;

pub const DEFAULT_PORTS: &str = "80,8080,8443,8000,3000,5000,8888";

/// Resolve `--range` / `--exclude` / `--ports` into an exact address set.
///
/// Parsing goes through [`MassIP`] so the accepted syntax is identical to the
/// rest of the scanner (CIDR, ranges, comma lists). The result is then copied
/// into a [`RangeSet4`], which is what the coverage model needs.
pub fn build(zorp: &Zorp) -> Result<RangeSet4, String> {
    let mut targets = MassIP::new();
    for range_str in &zorp.target_ranges {
        targets
            .add_target_string(range_str.as_bytes())
            .map_err(|_| format!("invalid target range: {}", range_str))?;
    }

    if targets.ipv4.count_addresses() == 0 && targets.ipv6.count_addresses().lo == 0 {
        targets.ipv4.add_range(0, u32::MAX);
    }
    if targets.ipv6.count_addresses().lo > 0 {
        return Err(
            "IPv6 targets are not supported by block scheduling; specify IPv4 ranges only"
                .to_string(),
        );
    }

    if !zorp.exclude_ranges.is_empty() {
        let mut excludes = MassIP::new();
        for excl in &zorp.exclude_ranges {
            excludes
                .add_target_string(excl.as_bytes())
                .map_err(|_| format!("invalid exclude range: {}", excl))?;
        }
        targets.ipv4.exclude(&excludes.ipv4);
    }

    targets.ipv4.sort();
    let set = RangeSet4::from_intervals(targets.ipv4.list.iter().map(|r| (r.begin, r.end)));
    if set.is_empty() {
        return Err("target address set is empty after excludes".to_string());
    }
    Ok(set)
}

/// The ports a plan scans, defaulting to the usual HTTP/API set.
pub fn ports(zorp: &Zorp) -> String {
    if zorp.ports.trim().is_empty() {
        DEFAULT_PORTS.to_string()
    } else {
        zorp.ports.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(args: &[&str]) -> Zorp {
        let mut argv: Vec<String> = vec!["zorpinvader".to_string()];
        argv.extend(args.iter().map(|s| s.to_string()));
        Zorp::from_args(&argv).unwrap()
    }

    #[test]
    fn builds_targets_and_applies_excludes() {
        let zorp = config(&["--range", "10.0.0.0/8", "--exclude", "10.0.0.0/16"]);
        let set = build(&zorp).unwrap();
        assert_eq!(set.count(), (1u64 << 24) - (1u64 << 16));
        assert!(!set.contains(0x0A000001));
        assert!(set.contains(0x0A010001));
    }

    #[test]
    fn defaults_to_the_whole_space_when_no_ranges_given() {
        let zorp = config(&["--ports", "80"]);
        let set = build(&zorp).unwrap();
        assert_eq!(set.count(), 1u64 << 32);
        assert_eq!(ports(&zorp), "80");
    }

    #[test]
    fn default_ports_are_applied() {
        let zorp = config(&["--range", "10.0.0.0/8"]);
        assert_eq!(ports(&zorp), DEFAULT_PORTS);
    }
}
