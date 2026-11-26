//! Configuration parsing for ZorpInvader.
//!
//! This module handles command-line argument parsing (using clap) and
//! configuration file reading. The `Zorp` struct is the master configuration
//! that holds all scanner settings.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use log::{debug, error, info, warn};

use crate::massip::addr::{Ipv4Address, Ipv6Address, MacAddress, IpAddress};
use crate::rawsock::adapter::{Adapter, LinkType};

/// Version string for ZorpInvader.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum number of network interfaces.
pub const MAX_NICS: usize = 8;

/// Default scan rate in packets per second.
pub const DEFAULT_RATE: f64 = 100.0;

/// Default TCP connection timeout in seconds.
pub const DEFAULT_CONNECTION_TIMEOUT: u32 = 30;

/// Default minimum packet size.
pub const DEFAULT_MIN_PACKET_SIZE: u32 = 60;

/// The operation to perform (scan, selftest, list adapters, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Operation {
    #[default]
    Default = 0,
    ListAdapters = 1,
    Selftest = 2,
    Scan = 3,
    DebugInterface = 4,
    ListScan = 5,
    ReadScan = 6,
    ReadRange = 7,
    Benchmark = 8,
    Echo = 9,
    EchoAll = 10,
    EchoCidr = 11,
}

/// Output format for scan results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Default = 0x0000,
    Interactive = 0x0001,
    List = 0x0002,
    Binary = 0x0004,
    Xml = 0x0008,
    Json = 0x0010,
    Ndjson = 0x0011,
    Nmap = 0x0020,
    ScriptKiddie = 0x0040,
    Grepable = 0x0080,
    Redis = 0x0100,
    Unicornscan = 0x0200,
    None = 0x0400,
    Certs = 0x0800,
    Hostonly = 0x1000,
}

impl OutputFormat {
    /// Parse an output format from a string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "interactive" => Some(OutputFormat::Interactive),
            "list" => Some(OutputFormat::List),
            "binary" => Some(OutputFormat::Binary),
            "xml" => Some(OutputFormat::Xml),
            "json" => Some(OutputFormat::Json),
            "ndjson" => Some(OutputFormat::Ndjson),
            "grepable" | "greppable" => Some(OutputFormat::Grepable),
            "redis" => Some(OutputFormat::Redis),
            "unicornscan" => Some(OutputFormat::Unicornscan),
            "none" => Some(OutputFormat::None),
            "certs" => Some(OutputFormat::Certs),
            "hostonly" => Some(OutputFormat::Hostonly),
            _ => None,
        }
    }
}

/// How this process participates in the scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Scheduler and scanner in one process (default).
    #[default]
    Local,
    /// Controller: plans blocks, allocates work, aggregates results. Never scans.
    Server,
    /// Worker: claims blocks from a controller and scans them.
    Client,
}

/// Scan type configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanType {
    pub tcp: bool,
    pub udp: bool,
    pub sctp: bool,
    pub ping: bool,
    pub arp: bool,
    pub oproto: bool,
}

/// Network interface configuration.
#[allow(unused)]
pub struct NicConfig {
    /// Interface name (e.g., "eth0")
    pub ifname: String,

    /// Adapter handle (set during initialization)
    pub adapter: Option<Adapter>,

    /// Source IPv4 address range
    pub src_ipv4_first: Ipv4Address,
    pub src_ipv4_last: Ipv4Address,
    pub src_ipv4_range: u32,

    /// Source IPv6 address range
    pub src_ipv6_first: Ipv6Address,
    pub src_ipv6_last: Ipv6Address,
    pub src_ipv6_range: u32,

    /// Source port range
    pub src_port_first: u16,
    pub src_port_last: u16,
    pub src_port_range: u32,

    /// Source MAC address
    pub source_mac: MacAddress,
    pub my_mac_count: bool,

    /// Router MAC addresses
    pub router_mac_ipv4: MacAddress,
    pub router_mac_ipv6: MacAddress,
    pub router_ip: Ipv4Address,

    /// Link type
    pub link_type: u32,

    /// VLAN configuration
    pub vlan_id: u32,
    pub is_vlan: bool,

    /// Whether this NIC is usable for the configured targets
    pub is_usable: bool,
}

impl Default for NicConfig {
    fn default() -> Self {
        Self {
            ifname: String::new(),
            adapter: None,
            src_ipv4_first: 0,
            src_ipv4_last: 0,
            src_ipv4_range: 0,
            src_ipv6_first: Ipv6Address::default(),
            src_ipv6_last: Ipv6Address::default(),
            src_ipv6_range: 0,
            src_port_first: 0,
            src_port_last: 0,
            src_port_range: 0,
            source_mac: MacAddress::default(),
            my_mac_count: false,
            router_mac_ipv4: MacAddress::default(),
            router_mac_ipv6: MacAddress::default(),
            router_ip: 0,
            link_type: 0,
            vlan_id: 0,
            is_vlan: false,
            is_usable: false,
        }
    }
}

impl std::fmt::Debug for NicConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NicConfig")
            .field("ifname", &self.ifname)
            .field("adapter", &self.adapter.as_ref().map(|_| "Adapter(...)"))
            .field("src_ipv4_first", &self.src_ipv4_first)
            .field("src_ipv4_last", &self.src_ipv4_last)
            .field("is_usable", &self.is_usable)
            .finish()
    }
}

impl Clone for NicConfig {
    fn clone(&self) -> Self {
        Self {
            ifname: self.ifname.clone(),
            adapter: None, // Adapter is not Clone; caller must re-open
            src_ipv4_first: self.src_ipv4_first,
            src_ipv4_last: self.src_ipv4_last,
            src_ipv4_range: self.src_ipv4_range,
            src_ipv6_first: self.src_ipv6_first,
            src_ipv6_last: self.src_ipv6_last,
            src_ipv6_range: self.src_ipv6_range,
            src_port_first: self.src_port_first,
            src_port_last: self.src_port_last,
            src_port_range: self.src_port_range,
            source_mac: self.source_mac,
            my_mac_count: self.my_mac_count,
            router_mac_ipv4: self.router_mac_ipv4,
            router_mac_ipv6: self.router_mac_ipv6,
            router_ip: self.router_ip,
            link_type: self.link_type,
            vlan_id: self.vlan_id,
            is_vlan: self.is_vlan,
            is_usable: self.is_usable,
        }
    }
}

/// Output configuration.
#[derive(Debug, Clone, Default)]
pub struct OutputConfig {
    /// Output format
    pub format: OutputFormat,

    /// Output filename (empty for stdout)
    pub filename: String,

    /// XSL stylesheet for XML output
    pub stylesheet: String,

    /// Append to output file
    pub is_append: bool,

    /// Output NDJSON status
    pub is_status_ndjson: bool,

    /// Show open ports
    pub is_show_open: bool,

    /// Show closed ports
    pub is_show_closed: bool,

    /// Show host messages
    pub is_show_host: bool,

    /// Show reason for port state
    pub is_reason: bool,

    /// Interactive output alongside file output
    pub is_interactive: bool,

    /// Print status updates
    pub is_status_updates: bool,

    /// Flush output on every result
    pub is_output_flush: bool,

    /// Rotation settings
    pub rotate_timeout: u32,
    pub rotate_offset: u32,
    pub rotate_filesize: u64,
    pub rotate_directory: String,
}

/// HTTP configuration for banner grabbing.
#[derive(Debug, Clone, Default)]
pub struct HttpConfig {
    pub method: String,
    pub url: String,
    pub version: String,
    pub host: String,
    pub user_agent: String,
    pub payload: String,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<String>,
    pub remove_headers: Vec<String>,
}

/// Hello payload for TCP connections.
#[derive(Debug, Clone)]
pub struct TcpHelloPayload {
    /// Base64-encoded payload data
    pub payload_base64: String,

    /// TCP port this payload applies to
    pub port: u16,
}

/// Redis connection configuration.
#[derive(Debug, Clone, Default)]
pub struct RedisConfig {
    pub ip: IpAddress,
    pub password: Option<String>,
    pub port: u16,
}

/// Resume configuration for paused scans.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResumeConfig {
    pub index: u64,
    pub count: u64,
    pub target_ip: u32,
    pub target_port: u16,
}

/// Shard configuration for distributed scanning.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShardConfig {
    /// This shard's index (1-based)
    pub one: u32,

    /// Total number of shards
    pub of: u32,
}

/// The master ZorpInvader configuration structure.
///
/// This holds all settings parsed from command-line arguments
/// and configuration files. Once parsed, this structure is
/// effectively read-only during the scan.
pub struct Zorp {
    /// Operation to perform
    pub op: Operation,

    /// Scan type configuration
    pub scan_type: ScanType,

    /// Top ports count (0 = disabled)
    pub top_ports: u32,

    /// Network interface configurations
    pub nic: Vec<NicConfig>,

    /// Target IP ranges (simplified - actual implementation uses MassIP)
    pub target_ranges: Vec<String>,

    /// Exclude IP ranges
    pub exclude_ranges: Vec<String>,

    /// Target ports (as string specification)
    pub ports: String,

    /// Maximum packet rate
    pub max_rate: f64,

    /// Number of retries
    pub retries: u32,

    /// Feature flags
    pub is_pfring: bool,
    pub is_sendq: bool,
    pub is_banners: bool,
    pub is_banners_rawudp: bool,
    pub is_offline: bool,
    pub is_noreset: bool,
    pub is_gmt: bool,
    pub is_capture_cert: bool,
    pub is_capture_html: bool,
    pub is_capture_heartbleed: bool,
    pub is_capture_ticketbleed: bool,
    pub is_capture_servername: bool,
    pub is_test_csv: bool,
    pub is_infinite: bool,
    pub is_readscan: bool,
    pub is_heartbleed: bool,
    pub is_ticketbleed: bool,
    pub is_poodle_sslv3: bool,
    pub is_hello_ssl: bool,
    pub is_hello_smbv1: bool,
    pub is_hello_http: bool,
    pub is_scripting: bool,

    /// Wait time for responses (0 = default, u32::MAX = forever)
    pub wait: u32,

    /// Resume configuration
    pub resume: ResumeConfig,

    /// Shard configuration
    pub shard: ShardConfig,

    /// Random seed (0 = random)
    pub seed: u64,

    /// Output configuration
    pub output: OutputConfig,

    /// Nmap-compatible options
    pub nmap_data_length: u32,
    pub nmap_ttl: u32,
    pub nmap_badsum: bool,
    pub nmap_packet_trace: bool,
    pub nmap_datadir: String,

    /// PCAP filename for capture
    pub pcap_filename: String,

    /// TCP connection timeout
    pub tcp_connection_timeout: u32,

    /// TCP hello timeout
    pub tcp_hello_timeout: u32,

    /// BPF filter expression
    pub bpf_filter: Option<String>,

    /// HTTP configuration
    pub http: HttpConfig,

    /// TCP hello payloads
    pub tcp_hello_payloads: Vec<TcpHelloPayload>,

    /// Payload file paths
    pub pcap_payloads_filename: Option<String>,
    pub nmap_payloads_filename: Option<String>,
    pub nmap_service_probes_filename: Option<String>,

    /// Redis configuration
    pub redis: RedisConfig,

    /// Minimum packet size
    pub min_packet_size: u32,

    /// BlackRock randomization rounds
    pub blackrock_rounds: u32,

    /// Script filename
    pub script_name: Option<String>,

    /// Vulnerability check name
    pub vuln_name: Option<String>,

    /// Configuration files to read
    pub config_files: Vec<PathBuf>,

    /// Threads per core for fetcher/worker pools
    pub tpc: usize,

    /// Include "safe" key patterns (e.g. Stripe publishable keys) that are
    /// designed to be public/client-side. Disabled by default.
    pub include_safe: bool,

    /// Stride for index iteration — skip this many indices per step to spread
    /// coverage across the full IPv4 space quickly (spirograph pattern).
    /// Computed automatically from range size if not set (default: range/64).
    pub stride: u64,

    /// Resume a previous scan from the state file instead of starting fresh.
    pub auto_resume: bool,

    /// Start over even if a state file exists.
    pub reset_state: bool,

    /// Mode: standalone, controller or client.
    pub mode: Mode,

    /// Controller listen port (`--server <port>`).
    pub server_port: u16,

    /// Controller listen address (default 0.0.0.0, or 127.0.0.1 with --tor).
    pub server_bind: String,

    /// True when --server-bind was given explicitly.
    pub server_bind_set: bool,

    /// Optional shared secret. Without it the controller accepts any worker that
    /// has the address (onion or URL).
    pub token: Option<String>,

    /// Controller base URL (`--client <url>`).
    pub client_url: String,

    /// Human-readable client name; defaults to the hostname.
    pub client_name: Option<String>,

    /// Scan state file (coverage + leases).
    pub state_file: PathBuf,

    /// Where the controller writes open_ports.csv and found_keys.csv.
    pub results_dir: PathBuf,

    /// Addresses per job block; 0 selects automatically.
    pub job_size: u64,

    /// Seconds a block stays leased without a progress report.
    pub lease_s: u64,

    /// Publish the controller on an onion service / force tor for a client.
    pub tor: bool,

    /// Explicit SOCKS endpoint to use instead of starting tor.
    pub tor_socks: Option<String>,

    /// Explicit tor binary.
    pub tor_binary: Option<PathBuf>,

    /// Where tor keeps its DataDirectory (default: next to the progress file).
    pub tor_dir: Option<PathBuf>,

    /// Seconds to wait for tor to bootstrap.
    pub tor_timeout: u64,

    /// Install missing runtime tools (tor, curl) with the distro's package
    /// manager instead of failing.
    pub auto_install: bool,
}

impl Default for Zorp {
    fn default() -> Self {
        Self {
            op: Operation::Default,
            scan_type: ScanType {
                tcp: true,
                ..Default::default()
            },
            top_ports: 0,
            nic: vec![NicConfig::default(); MAX_NICS],
            target_ranges: Vec::new(),
            exclude_ranges: Vec::new(),
            ports: String::new(),
            max_rate: DEFAULT_RATE,
            retries: 0,
            is_pfring: false,
            is_sendq: false,
            is_banners: true,
            is_banners_rawudp: false,
            is_offline: false,
            is_noreset: false,
            is_gmt: false,
            is_capture_cert: true,
            is_capture_html: true,
            is_capture_heartbleed: false,
            is_capture_ticketbleed: false,
            is_capture_servername: true,
            is_test_csv: false,
            is_infinite: false,
            is_readscan: false,
            is_heartbleed: false,
            is_ticketbleed: false,
            is_poodle_sslv3: false,
            is_hello_ssl: false,
            is_hello_smbv1: false,
            is_hello_http: false,
            is_scripting: false,
            wait: 10,
            resume: ResumeConfig::default(),
            shard: ShardConfig { one: 1, of: 1 },
            seed: 0,
            output: OutputConfig::default(),
            nmap_data_length: 0,
            nmap_ttl: 0,
            nmap_badsum: false,
            nmap_packet_trace: false,
            nmap_datadir: String::new(),
            pcap_filename: String::new(),
            tcp_connection_timeout: DEFAULT_CONNECTION_TIMEOUT,
            tcp_hello_timeout: 0,
            bpf_filter: None,
            http: HttpConfig::default(),
            tcp_hello_payloads: Vec::new(),
            pcap_payloads_filename: None,
            nmap_payloads_filename: None,
            nmap_service_probes_filename: None,
            redis: RedisConfig::default(),
            min_packet_size: DEFAULT_MIN_PACKET_SIZE,
            blackrock_rounds: 0,
            script_name: None,
            vuln_name: None,
            config_files: Vec::new(),
            tpc: 16,
            include_safe: false,
            stride: 0,
            auto_resume: false,
            reset_state: false,
            mode: Mode::Local,
            server_port: 0,
            server_bind: "0.0.0.0".to_string(),
            server_bind_set: false,
            token: None,
            client_url: String::new(),
            client_name: None,
            state_file: PathBuf::from("zorpinvader.progress"),
            results_dir: PathBuf::from("."),
            job_size: 0,
            // Single source of truth: the scheduler's own default.
            lease_s: crate::coord::scheduler::DEFAULT_LEASE_S,
            tor: false,
            tor_socks: None,
            tor_binary: None,
            tor_dir: None,
            tor_timeout: 180,
            auto_install: true,
        }
    }
}

impl Zorp {
    /// Create a new Zorp configuration with default values.
    pub fn new() -> Self {
        let mut zorp = Self::default();
        // Match original C defaults for scanning
        zorp.output.is_status_updates = true;
        zorp.output.is_show_open = true;
        zorp.is_capture_cert = true;
        zorp.blackrock_rounds = 14;
        zorp.max_rate = 0.0; // uncapped by default
        zorp.wait = 10;
        zorp.min_packet_size = 60;
        zorp
    }

    /// Parse command-line arguments into a Zorp configuration.
    pub fn from_args(args: &[String]) -> Result<Self, String> {
        let mut zorp = Self::new();

        let mut i = 1; // Skip program name
        while i < args.len() {
            let arg = &args[i];

            if arg.starts_with("--") {
                let name = &arg[2..];

                // Handle --name=value syntax
                let (name, value) = if let Some(eq_pos) = name.find('=') {
                    (&name[..eq_pos], Some(&name[eq_pos + 1..]))
                } else if let Some(colon_pos) = name.find(':') {
                    (&name[..colon_pos], Some(&name[colon_pos + 1..]))
                } else {
                    (name, None)
                };

                // Get value (either from = or next arg)
                let value = match value {
                    Some(v) => v.to_string(),
                    None => {
                        if Self::is_singleton(name) {
                            String::new()
                        } else if i + 1 < args.len() {
                            i += 1;
                            args[i].clone()
                        } else {
                            return Err(format!("{}: missing value", name));
                        }
                    }
                };

                zorp.set_parameter(name, &value)?;
            } else if arg.starts_with('-') && arg.len() > 1 {
                // Single-dash options
                let opt = arg.chars().nth(1).unwrap();
                let rest = if arg.len() > 2 { Some(&arg[2..]) } else { None };

                match opt {
                    'c' => {
                        let filename = rest.map(String::from).unwrap_or_else(|| {
                            i += 1;
                            args[i].clone()
                        });
                        zorp.read_config_file(&filename)?;
                    }
                    'e' => {
                        let iface = rest.map(String::from).unwrap_or_else(|| {
                            i += 1;
                            args[i].clone()
                        });
                        zorp.set_parameter("adapter", &iface)?;
                    }
                    'p' => {
                        let ports = rest.map(String::from).unwrap_or_else(|| {
                            i += 1;
                            args[i].clone()
                        });
                        zorp.ports = ports;
                        if zorp.op == Operation::Default {
                            zorp.op = Operation::Scan;
                        }
                    }
                    'S' => {
                        let ip = rest.map(String::from).unwrap_or_else(|| {
                            i += 1;
                            args[i].clone()
                        });
                        zorp.set_parameter("adapter-ip", &ip)?;
                    }
                    'g' => {
                        let port = rest.map(String::from).unwrap_or_else(|| {
                            i += 1;
                            args[i].clone()
                        });
                        zorp.set_parameter("adapter-port", &port)?;
                    }
                    'v' => {
                        // Verbosity - count 'v's
                        for _ in 1..arg.len() {
                            log::set_max_level(log::LevelFilter::Trace);
                        }
                    }
                    'd' => {
                        // Debug - count 'd's
                        for _ in 1..arg.len() {
                            log::set_max_level(log::LevelFilter::Trace);
                        }
                    }
                    'V' => {
                        Self::print_version();
                        std::process::exit(0);
                    }
                    'h' | '?' => {
                        Self::print_help();
                        std::process::exit(0);
                    }
                    's' => {
                        // Scan type
                        for c in arg.chars().skip(2) {
                            match c {
                                'S' => zorp.scan_type.tcp = true,
                                'U' => zorp.scan_type.udp = true,
                                'Z' => zorp.scan_type.sctp = true,
                                'O' => zorp.scan_type.oproto = true,
                                'L' => zorp.op = Operation::ListScan,
                                'T' => {
                                    // TCP connect - warn and use SYN
                                    warn!("Warning: doing SYN scan (-sS) anyway, ignoring (-sT)");
                                }
                                _ => {
                                    return Err(format!("Unsupported scan type: -s{}", c));
                                }
                            }
                        }
                    }
                    'o' => {
                        // Output format
                        let fmt_char = arg.chars().nth(2).unwrap_or('X');
                        let format = match fmt_char {
                            'B' => OutputFormat::Binary,
                            'D' => OutputFormat::Ndjson,
                            'J' => OutputFormat::Json,
                            'X' => OutputFormat::Xml,
                            'G' => OutputFormat::Grepable,
                            'L' => OutputFormat::List,
                            'U' => OutputFormat::Unicornscan,
                            'H' => OutputFormat::Hostonly,
                            _ => return Err(format!("Unknown output format: -o{}", fmt_char)),
                        };
                        zorp.output.format = format;

                        // Get filename
                        i += 1;
                        if i < args.len() {
                            zorp.output.filename = args[i].clone();
                        }
                    }
                    _ => {
                        return Err(format!("Unknown option: {}", arg));
                    }
                }
            } else if !arg.is_empty() {
                // Bare arguments are treated as IP ranges
                zorp.target_ranges.push(arg.clone());
                if zorp.op == Operation::Default {
                    zorp.op = Operation::Scan;
                }
            }

            i += 1;
        }

        // Default to TCP if no scan type specified
        if !zorp.scan_type.tcp
            && !zorp.scan_type.udp
            && !zorp.scan_type.sctp
            && !zorp.scan_type.ping
            && !zorp.scan_type.arp
            && !zorp.scan_type.oproto
        {
            zorp.scan_type.tcp = true;
        }

        Ok(zorp)
    }

    /// Set a configuration parameter by name.
    pub fn set_parameter(&mut self, name: &str, value: &str) -> Result<(), String> {
        let name_lower = name.to_lowercase();

        match name_lower.as_str() {
            "rate" | "max-rate" => {
                self.max_rate = value
                    .parse::<f64>()
                    .map_err(|_| format!("rate: invalid number: {}", value))?;
                if self.op == Operation::Default {
                    self.op = Operation::Scan;
                }
            }

            "retries" | "retry" | "max-retries" | "max-retry" => {
                self.retries = value
                    .parse::<u32>()
                    .map_err(|_| format!("retries: invalid number: {}", value))?;
                if self.retries >= 1000 {
                    return Err("retries: expected number less than 1000".to_string());
                }
            }

            "adapter" | "if" | "interface" => {
                if !self.nic.is_empty() && self.nic[0].ifname.is_empty() {
                    self.nic[0].ifname = value.to_string();
                }
            }

            "adapter-ip" | "source-ip" | "src-ip" | "spoof-ip" => {
                // Parse IP address/range
                if let Ok(ip) = value.parse::<Ipv4Addr>() {
                    let ip_int = u32::from(ip);
                    if !self.nic.is_empty() {
                        self.nic[0].src_ipv4_first = ip_int;
                        self.nic[0].src_ipv4_last = ip_int;
                        self.nic[0].src_ipv4_range = 1;
                    }
                } else {
                    // Could be a range - simplified handling
                    debug!("adapter-ip range: {}", value);
                }
            }

            "adapter-port" | "source-port" | "src-port" => {
                if let Ok(port) = value.parse::<u16>() {
                    if !self.nic.is_empty() {
                        self.nic[0].src_port_first = port;
                        self.nic[0].src_port_last = port;
                        self.nic[0].src_port_range = 1;
                    }
                }
            }

            "adapter-mac" | "source-mac" | "spoof-mac" | "src-mac" => {
                if let Some(mac) = Self::parse_mac_address(value) {
                    if !self.nic.is_empty() {
                        self.nic[0].source_mac = mac;
                        self.nic[0].my_mac_count = true;
                    }
                } else {
                    return Err(format!("bad MAC address: {}", value));
                }
            }

            "router-mac" | "router" | "dest-mac" | "destination-mac" | "dst-mac" | "target-mac" => {
                if let Some(mac) = Self::parse_mac_address(value) {
                    if !self.nic.is_empty() {
                        self.nic[0].router_mac_ipv4 = mac;
                        self.nic[0].router_mac_ipv6 = mac;
                    }
                } else {
                    return Err(format!("bad MAC address: {}", value));
                }
            }

            "router-ip" => {
                if let Ok(ip) = value.parse::<Ipv4Addr>() {
                    if !self.nic.is_empty() {
                        self.nic[0].router_ip = u32::from(ip);
                    }
                }
            }

            "banners" | "banner" => {
                self.is_banners = Self::parse_boolean(value);
            }

            "nobanners" | "nobanner" => {
                self.is_banners = !Self::parse_boolean(value);
            }

            "offline" | "notransmit" | "nosend" | "dry-run" => {
                self.is_offline = Self::parse_boolean(value);
            }

            "noreset" => {
                self.is_noreset = Self::parse_boolean(value);
            }

            "seed" => {
                if value.eq_ignore_ascii_case("time") {
                    self.seed = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                } else {
                    self.seed = value
                        .parse::<u64>()
                        .map_err(|_| format!("seed: invalid number: {}", value))?;
                }
            }

            "shard" | "shards" => {
                let parts: Vec<&str> = value.split('/').collect();
                if parts.len() == 2 {
                    self.shard.one = parts[0]
                        .parse()
                        .map_err(|_| "shard: invalid format".to_string())?;
                    self.shard.of = parts[1]
                        .parse()
                        .map_err(|_| "shard: invalid format".to_string())?;
                    if self.shard.one < 1 || self.shard.one > self.shard.of {
                        return Err("shard: invalid specification (e.g., 1/4 2/4)".to_string());
                    }
                }
            }

            "output-format" => {
                self.output.format = OutputFormat::from_str(value)
                    .ok_or_else(|| format!("unknown output format: {}", value))?;
            }

            "output-file" | "output-filename" => {
                self.output.filename = value.to_string();
                if matches!(self.output.format, OutputFormat::Default) {
                    self.output.format = OutputFormat::Xml;
                }
            }

            "output-flush" => {
                self.output.is_output_flush = Self::parse_boolean(value);
            }

            "output-append" | "append-output" => {
                self.output.is_append = Self::parse_boolean(value);
            }

            "open" | "open-only" => {
                self.output.is_show_open = true;
                self.output.is_show_closed = false;
                self.output.is_show_host = false;
            }

            "packet-trace" | "trace-packet" => {
                self.nmap_packet_trace = true;
            }

            "pfring" => {
                self.is_pfring = true;
            }

            "sendq" | "sendqueue" => {
                self.is_sendq = true;
            }

            "infinite" => {
                self.is_infinite = true;
            }

            "bpf" => {
                self.bpf_filter = Some(value.to_string());
            }

            "connection-timeout" | "tcp-timeout" => {
                self.tcp_connection_timeout = value
                    .parse()
                    .map_err(|_| format!("timeout: invalid number: {}", value))?;
            }

            "min-packet" | "min-pkt" => {
                self.min_packet_size = value
                    .parse()
                    .map_err(|_| format!("min-packet: invalid number: {}", value))?;
            }

            "blackrock-rounds" => {
                self.blackrock_rounds = value
                    .parse()
                    .map_err(|_| format!("blackrock-rounds: invalid number: {}", value))?;
            }

            "resume-index" => {
                self.resume.index = value
                    .parse()
                    .map_err(|_| format!("resume-index: invalid number: {}", value))?;
            }

            "resume-count" => {
                self.resume.count = value
                    .parse()
                    .map_err(|_| format!("resume-count: invalid number: {}", value))?;
            }

            "selftest" | "self-test" | "regress" => {
                self.op = Operation::Selftest;
            }

            "benchmark" => {
                self.op = Operation::Benchmark;
            }

            "echo" => {
                self.op = Operation::Echo;
            }

            "echo-all" => {
                self.op = Operation::EchoAll;
            }

            "echo-cidr" => {
                self.op = Operation::EchoCidr;
            }

            "iflist" => {
                self.op = Operation::ListAdapters;
            }

            "readrange" | "read-range" | "read-ranges" => {
                self.op = Operation::ReadRange;
            }

            "help" => {
                Self::print_help();
                std::process::exit(0);
            }

            "version" => {
                Self::print_version();
                std::process::exit(0);
            }

            "conf" | "config" => {
                self.read_config_file(value)?;
            }

            "range" | "ranges" | "ip" | "ipv4" | "target-ip" | "destination-ip" => {
                self.target_ranges.push(value.to_string());
                if self.op == Operation::Default {
                    self.op = Operation::Scan;
                }
            }

            "exclude" | "exclude-range" | "exclude-ranges" | "exclude-ip" | "exclude-ipv4" => {
                self.exclude_ranges.push(value.to_string());
            }

            "ports" | "port" | "dst-port" | "dest-port" | "target-port" => {
                self.ports = value.to_string();
                if self.op == Operation::Default {
                    self.op = Operation::Scan;
                }
            }

            "tcp-ports" | "tcp-port" => {
                self.scan_type.tcp = true;
                self.ports = value.to_string();
            }

            "udp-ports" | "udp-port" => {
                self.scan_type.udp = true;
                self.ports = value.to_string();
            }

            "top-ports" => {
                self.top_ports = if value.is_empty() {
                    20
                } else {
                    value.parse().unwrap_or(20)
                };
            }

            "ttl" => {
                self.nmap_ttl = value
                    .parse()
                    .map_err(|_| format!("ttl: invalid number: {}", value))?;
                if self.nmap_ttl >= 256 {
                    return Err("ttl: expected number less than 256".to_string());
                }
            }

            "data-length" => {
                self.nmap_data_length = value
                    .parse()
                    .map_err(|_| format!("data-length: invalid number: {}", value))?;
                if self.nmap_data_length >= 1500 {
                    return Err("data-length: expected number less than 1500".to_string());
                }
            }

            "hello" => {
                match value {
                    "ssl" => self.is_hello_ssl = true,
                    "smbv1" => self.is_hello_smbv1 = true,
                    "http" => self.is_hello_http = true,
                    _ => return Err(format!("unknown hello type: {}", value)),
                }
            }

            "hello-timeout" => {
                self.tcp_hello_timeout = value
                    .parse()
                    .map_err(|_| format!("hello-timeout: invalid number: {}", value))?;
            }

            "capture" => {
                match value {
                    "cert" => self.is_capture_cert = true,
                    "servername" => self.is_capture_servername = true,
                    "html" => self.is_capture_html = true,
                    "heartbleed" => self.is_capture_heartbleed = true,
                    "ticketbleed" => self.is_capture_ticketbleed = true,
                    _ => return Err(format!("unknown capture type: {}", value)),
                }
            }

            "nocapture" | "no-capture" => {
                match value {
                    "cert" => self.is_capture_cert = false,
                    "servername" => self.is_capture_servername = false,
                    "html" => self.is_capture_html = false,
                    "heartbleed" => self.is_capture_heartbleed = false,
                    "ticketbleed" => self.is_capture_ticketbleed = false,
                    _ => return Err(format!("unknown nocapture type: {}", value)),
                }
            }

            "heartbleed" => {
                self.is_heartbleed = true;
                self.is_capture_heartbleed = false;
                self.is_banners = true;
            }

            "ticketbleed" => {
                self.is_ticketbleed = true;
                self.is_capture_ticketbleed = false;
                self.is_banners = true;
            }

            "vuln" => {
                match value {
                    "heartbleed" => {
                        self.is_heartbleed = true;
                        self.is_banners = true;
                    }
                    "ticketbleed" => {
                        self.is_ticketbleed = true;
                        self.is_banners = true;
                    }
                    "poodle" | "sslv3" => {
                        self.is_poodle_sslv3 = true;
                        self.is_banners = true;
                    }
                    _ => {
                        self.vuln_name = Some(value.to_string());
                    }
                }
            }

            "wait" => {
                if value.eq_ignore_ascii_case("forever") {
                    self.wait = u32::MAX;
                } else {
                    self.wait = value
                        .parse()
                        .map_err(|_| format!("wait: invalid number: {}", value))?;
                }
            }

            "tpc" | "threads-per-core" => {
                self.tpc = value
                    .parse()
                    .map_err(|_| format!("tpc: invalid number: {}", value))?;
                self.tpc = self.tpc.clamp(1, 32);
            }

            "include-safe" => {
                self.include_safe = Self::parse_boolean(value);
            }

            "stride" => {
                self.stride = value
                    .parse()
                    .map_err(|_| format!("stride: invalid number: {}", value))?;
            }

            "resume" | "auto-resume" => {
                self.auto_resume = Self::parse_boolean(value);
            }

            "reset" | "fresh" | "no-resume" => {
                self.reset_state = Self::parse_boolean(value);
            }

            "server" | "listen" | "controller" => {
                // Accept `--server 8000` and `--server 0.0.0.0:8000`.
                let (bind, port) = match value.rsplit_once(':') {
                    Some((bind, port)) => (Some(bind.to_string()), port),
                    None => (None, value),
                };
                let port: u16 = port
                    .parse()
                    .map_err(|_| format!("server: invalid port: {}", value))?;
                if port == 0 {
                    return Err("server: port must be greater than 0".to_string());
                }
                if let Some(bind) = bind {
                    self.server_bind = bind;
                    self.server_bind_set = true;
                }
                self.server_port = port;
                self.mode = Mode::Server;
                if self.op == Operation::Default {
                    self.op = Operation::Scan;
                }
            }

            "server-bind" | "bind" => {
                self.server_bind = value.to_string();
                self.server_bind_set = true;
            }

            "token" | "server-token" | "client-token" => {
                self.token = Some(value.to_string());
            }

            "client" | "controller-url" => {
                if value.trim().is_empty() {
                    return Err("client: missing controller URL".to_string());
                }
                self.client_url = value.trim_end_matches('/').to_string();
                self.mode = Mode::Client;
                if self.op == Operation::Default {
                    self.op = Operation::Scan;
                }
            }

            "client-name" | "worker-name" => {
                self.client_name = Some(value.to_string());
            }

            "tor" | "onion" => {
                self.tor = Self::parse_boolean(value);
                // `--tor` on its own is a controller: publishing an onion service
                // is the whole point, and the local port is an implementation
                // detail tor proxies to. A client still wins if it was asked for.
                if self.tor && self.client_url.is_empty() {
                    self.mode = Mode::Server;
                    if self.op == Operation::Default {
                        self.op = Operation::Scan;
                    }
                }
            }

            "tor-socks" | "socks" => {
                self.tor_socks = Some(value.to_string());
            }

            "tor-binary" | "tor-path" => {
                self.tor_binary = Some(PathBuf::from(value));
            }

            "tor-dir" => {
                self.tor_dir = Some(PathBuf::from(value));
            }

            "install" | "auto-install" | "tor-install" => {
                self.auto_install = Self::parse_boolean(value);
            }

            "no-install" => {
                self.auto_install = false;
            }

            "tor-timeout" => {
                self.tor_timeout = value
                    .parse()
                    .map_err(|_| format!("tor-timeout: invalid number: {}", value))?;
                if self.tor_timeout < 10 {
                    return Err("tor-timeout: must be at least 10 seconds".to_string());
                }
            }

            "state" | "state-file" | "checkpoint" => {
                self.state_file = PathBuf::from(value);
            }

            "results-dir" | "output-dir" => {
                self.results_dir = PathBuf::from(value);
            }

            "job-size" | "block-size" | "job" => {
                self.job_size = value
                    .parse()
                    .map_err(|_| format!("job-size: invalid number: {}", value))?;
            }

            "lease" | "lease-seconds" => {
                self.lease_s = value
                    .parse()
                    .map_err(|_| format!("lease: invalid number: {}", value))?;
                if self.lease_s < 10 {
                    return Err("lease: must be at least 10 seconds".to_string());
                }
            }

            // Silently ignore some parameters
            "randomize-hosts" | "send-eth" | "nobacktrace" | "backtrace" => {}

            _ => {
                warn!("Unknown configuration option: {}={}", name, value);
            }
        }

        Ok(())
    }

    /// Read configuration from a file.
    fn read_config_file(&mut self, filename: &str) -> Result<(), String> {
        let file = File::open(filename).map_err(|e| format!("{}: {}", filename, e))?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line.map_err(|e| format!("{}: {}", filename, e))?;
            let line = line.trim().to_string();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            // Parse name=value
            if let Some(eq_pos) = line.find('=') {
                let name = line[..eq_pos].trim();
                let value = line[eq_pos + 1..].trim();
                self.set_parameter(name, value)?;
            }
        }

        self.config_files.push(PathBuf::from(filename));
        Ok(())
    }

    /// Check if a parameter name is a "singleton" (doesn't take a value).
    fn is_singleton(name: &str) -> bool {
        matches!(
            name.to_lowercase().as_str(),
            "echo"
                | "echo-all"
                | "echo-cidr"
                | "selftest"
                | "self-test"
                | "regress"
                | "benchmark"
                | "version"
                | "open"
                | "open-only"
                | "packet-trace"
                | "iflist"
                | "pfring"
                | "sendq"
                | "infinite"
                | "interactive"
                | "nointeractive"
                | "status"
                | "nostatus"
                | "readrange"
                | "read-range"
                | "readscan"
                | "help"
                | "heartbleed"
                | "ticketbleed"
                | "nobanners"
                | "banners"
                | "offline"
                | "noreset"
                | "arpscan"
                | "arp"
                | "ping"
                | "reset"
                | "fresh"
                | "no-resume"
                | "tor"
                | "no-install"
        )
    }

    /// Parse a boolean value from a string.
    fn parse_boolean(s: &str) -> bool {
        if s.is_empty() {
            return true;
        }
        match s.to_lowercase().as_str() {
            "1" | "true" | "yes" | "on" | "enable" | "enabled" => true,
            "0" | "false" | "no" | "off" | "disable" | "disabled" => false,
            _ => true, // Default to true for unknown values
        }
    }

    /// Parse a MAC address from various formats.
    fn parse_mac_address(s: &str) -> Option<MacAddress> {
        let s = s.replace(['-', ':', '.'], "");
        if s.len() != 12 {
            return None;
        }

        let mut addr = [0u8; 6];
        for i in 0..6 {
            addr[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }

        Some(MacAddress { addr })
    }

    /// Print version information.
    pub fn print_version() {
        println!("ZorpInvader version {} (https://github.com/elapt1c/zorpinvader)", VERSION);
        println!(
            "OS: {}  Architecture: {}",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        // Which libc the binary carries decides whether it runs on an arbitrary
        // distribution, so a deployment check can assert on it.
        let libc = if cfg!(target_env = "musl") {
            "musl (static)"
        } else if cfg!(target_env = "gnu") {
            "glibc (dynamic)"
        } else {
            "unknown"
        };
        println!("Libc: {}", libc);
        println!("Kernel features: AF_PACKET raw sockets (needs root or CAP_NET_RAW)");
    }

    /// Print help information.
    pub fn print_help() {
        println!(
            r#"usage: zorpinvader [options]
ZorpInvader is an API key scanner. It scans the Internet for exposed
services and inspects banners/HTTP responses for leaked API keys,
then verifies them against live endpoints.

Quick start:
    zorpinvader --rate 5000

This auto-detects your network interface and begins scanning with
banner capture (and auto-enables HTML body capture, since keys often
live in <script> tags).

By default, ZorpInvader scans 0.0.0.0/0 but excludes RFC1918, CGNAT,
link-local, and loopback ranges. Default ports: 80, 8080, 8443, 8000,
3000, 5000, 8888.

Found keys are written to found_keys.csv with real-time TUI feedback.

Common options:
    --rate <packets/s>   Scan speed (default: uncapped)
    --tpc <n>            Fetcher threads per core (default: 16, max: 32)
    --include-safe       Also detect "safe" keys (Stripe publishable, customer IDs)
    --stride <n>         Index stride for spirograph coverage (default: range/64)
    --resume             Resume the scan recorded in zorp-state.json
    --reset              Ignore an existing state file and start over
    --banners            Enable banner/API key scanning (required)
    --adapter-ip <ip>    Set source IP manually
    --adapter-mac <mac>  Set source MAC manually
    --router-mac <mac>   Set gateway MAC manually
    -c <filename>        Use a config file
    --echo               Print current config and exit

Distributed scanning:
    --server [port]      Run a controller: plan blocks and hand them to clients
                         (with --tor the port is optional: one is picked)
    --server-bind <ip>   Controller listen address (default: 0.0.0.0)
    --token <secret>     Optional shared secret; without it the controller is
                         open to any worker that has the address
    --client <url>       Join a controller (http:// or https://) and scan blocks
    --client-name <name> Client name shown in the controller status (default: hostname)
    --job-size <addrs>   Addresses per block (default: automatic, keeps blocks ≤ 65536)
    --lease <seconds>    Silence before a client is dropped and its block
                         reassigned (default: 30; clients report every 5s)
    --state <file>       Progress file: coverage, leases, onion address, token
                         (default: zorpinvader.progress)
    --results-dir <dir>  Where results are written (default: current directory)

A controller never transmits; clients need the raw-socket privileges. The
controller speaks plain HTTP, so put it behind cloudflared/Caddy/nginx for TLS.

Tor (no ports to open, no external proxy to configure):
    --tor                Publish the controller on an onion service, or force a
                         client to reach the controller through tor
    --tor-socks <h:p>    Use an existing tor SOCKS proxy instead of starting one
    --tor-binary <path>  Explicit tor binary (default: find tor in PATH)
    --tor-dir <dir>      tor DataDirectory (default: next to the progress file)
    --tor-timeout <s>    Bootstrap timeout (default: 180)

A .onion address on --client implies tor; the onion address the controller
publishes is written to the progress file together with a ready-to-run
--client command.

Parameters can be set via command-line or config file. To generate a
config file from current settings:

    zorpinvader --echo > myscan.conf
"#
        );
    }

    /// Get the number of configured NICs.
    pub fn nic_count(&self) -> usize {
        self.nic.iter().filter(|n| !n.ifname.is_empty()).count().max(1)
    }
}

/// Command-line argument structure using clap.
#[derive(Parser, Debug)]
#[command(name = "zorpinvader")]
#[command(version = VERSION)]
#[command(about = "Internet-scale API key scanner")]
pub struct Cli {
    /// Scan rate in packets per second
    #[arg(long, default_value_t = 100.0)]
    pub rate: f64,

    /// Network interface to use
    #[arg(short = 'e', long)]
    pub adapter: Option<String>,

    /// Source IP address
    #[arg(long)]
    pub adapter_ip: Option<String>,

    /// Source MAC address
    #[arg(long)]
    pub adapter_mac: Option<String>,

    /// Router MAC address
    #[arg(long)]
    pub router_mac: Option<String>,

    /// Target ports
    #[arg(short = 'p', long)]
    pub ports: Option<String>,

    /// Target IP ranges
    #[arg(long)]
    pub range: Vec<String>,

    /// Exclude IP ranges
    #[arg(long)]
    pub exclude: Vec<String>,

    /// Configuration file
    #[arg(short = 'c', long)]
    pub config: Option<String>,

    /// Enable banner grabbing
    #[arg(long)]
    pub banners: bool,

    /// Offline mode (no packets sent)
    #[arg(long)]
    pub offline: bool,

    /// Output format
    #[arg(long)]
    pub output_format: Option<String>,

    /// Output filename
    #[arg(long)]
    pub output_file: Option<String>,

    /// Print current config and exit
    #[arg(long)]
    pub echo: bool,

    /// Print help
    #[arg(long)]
    pub help: bool,

    /// Print version
    #[arg(short = 'V', long)]
    pub version: bool,

    /// Verbose output
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Debug output
    #[arg(short = 'd', action = clap::ArgAction::Count)]
    pub debug: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zorp_default() {
        let zorp = Zorp::new();
        // 0 means uncapped: the default rate was removed deliberately.
        assert_eq!(zorp.max_rate, 0.0);
        assert!(zorp.scan_type.tcp);
        assert!(zorp.is_banners);
    }

    #[test]
    fn tor_alone_is_a_controller_without_a_port() {
        let zorp = Zorp::from_args(&[
            "zorpinvader".to_string(),
            "--tor".to_string(),
            "-p".to_string(),
            "80,443".to_string(),
        ])
        .unwrap();
        assert!(zorp.tor);
        assert_eq!(zorp.mode, Mode::Server);
        // 0 means "let the OS pick" and bind to loopback.
        assert_eq!(zorp.server_port, 0);
        assert!(!zorp.server_bind_set);
    }

    #[test]
    fn client_with_tor_stays_a_client() {
        let zorp = Zorp::from_args(&[
            "zorpinvader".to_string(),
            "--client".to_string(),
            "abc.onion".to_string(),
            "--tor".to_string(),
        ])
        .unwrap();
        assert_eq!(zorp.mode, Mode::Client);
        assert!(zorp.tor);
    }

    #[test]
    fn explicit_bind_and_port_are_remembered() {
        let zorp = Zorp::from_args(&[
            "zorpinvader".to_string(),
            "--server".to_string(),
            "0.0.0.0:8000".to_string(),
        ])
        .unwrap();
        assert_eq!(zorp.server_port, 8000);
        assert_eq!(zorp.server_bind, "0.0.0.0");
        assert!(zorp.server_bind_set);
    }

    #[test]
    fn test_parse_boolean() {
        assert!(Zorp::parse_boolean("true"));
        assert!(Zorp::parse_boolean("yes"));
        assert!(Zorp::parse_boolean("1"));
        assert!(Zorp::parse_boolean(""));
        assert!(!Zorp::parse_boolean("false"));
        assert!(!Zorp::parse_boolean("no"));
        assert!(!Zorp::parse_boolean("0"));
    }

    #[test]
    fn test_parse_mac_address() {
        let mac = Zorp::parse_mac_address("00:11:22:33:44:55").unwrap();
        assert_eq!(mac.addr, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let mac = Zorp::parse_mac_address("aa-bb-cc-dd-ee-ff").unwrap();
        assert_eq!(mac.addr, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_from_args_basic() {
        let args = vec![
            "zorpinvader".to_string(),
            "--rate".to_string(),
            "1000".to_string(),
            "--banners".to_string(),
        ];
        let zorp = Zorp::from_args(&args).unwrap();
        assert_eq!(zorp.max_rate, 1000.0);
        assert!(zorp.is_banners);
    }

    #[test]
    fn test_output_format_from_str() {
        assert_eq!(OutputFormat::from_str("xml"), Some(OutputFormat::Xml));
        assert_eq!(OutputFormat::from_str("json"), Some(OutputFormat::Json));
        assert_eq!(OutputFormat::from_str("binary"), Some(OutputFormat::Binary));
        assert_eq!(OutputFormat::from_str("invalid"), None);
    }
}
