//! Banner1 module - protocol parser registration and dispatch.
//!
//! Contains the `Banner1` struct with SMACK patterns for protocol detection,
//! `StreamState` for per-connection state, and `ProtocolParserStream` for
//! protocol parser registration.

use std::collections::HashMap;
use crate::proto::banout::{BannerOutput, BannerBase64};

/// Application protocol identifiers.
///
/// These values are used in output files, so do NOT change existing values.
/// Add new ones at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum AppProtocol {
    None = 0,
    Heur = 1,
    Ssh1 = 2,
    Ssh2 = 3,
    Http = 4,
    Ftp = 5,
    DnsVersionBind = 6,
    Snmp = 7,
    NbtStat = 8,
    Ssl3 = 9,
    Smb = 10,
    Smtp = 11,
    Pop3 = 12,
    Imap4 = 13,
    UdpZeroAccess = 14,
    X509Cert = 15,
    X509CaCert = 16,
    HtmlTitle = 17,
    HtmlFull = 18,
    Ntp = 19,
    Vuln = 20,
    Heartbleed = 21,
    Ticketbleed = 22,
    VncOld = 23,
    Safe = 24,
    Memcached = 25,
    Scripting = 26,
    Versioning = 27,
    Coap = 28,
    Telnet = 29,
    Rdp = 30,
    HttpServer = 31,
    Mc = 32,
    VncRfb = 33,
    VncInfo = 34,
    Isakmp = 35,
    Error = 36,
    EndOfList = 37,
}

impl AppProtocol {
    /// Convert from raw u32 value.
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::None,
            1 => Self::Heur,
            2 => Self::Ssh1,
            3 => Self::Ssh2,
            4 => Self::Http,
            5 => Self::Ftp,
            6 => Self::DnsVersionBind,
            7 => Self::Snmp,
            8 => Self::NbtStat,
            9 => Self::Ssl3,
            10 => Self::Smb,
            11 => Self::Smtp,
            12 => Self::Pop3,
            13 => Self::Imap4,
            14 => Self::UdpZeroAccess,
            15 => Self::X509Cert,
            16 => Self::X509CaCert,
            17 => Self::HtmlTitle,
            18 => Self::HtmlFull,
            19 => Self::Ntp,
            20 => Self::Vuln,
            21 => Self::Heartbleed,
            22 => Self::Ticketbleed,
            23 => Self::VncOld,
            24 => Self::Safe,
            25 => Self::Memcached,
            26 => Self::Scripting,
            27 => Self::Versioning,
            28 => Self::Coap,
            29 => Self::Telnet,
            30 => Self::Rdp,
            31 => Self::HttpServer,
            32 => Self::Mc,
            33 => Self::VncRfb,
            34 => Self::VncInfo,
            35 => Self::Isakmp,
            36 => Self::Error,
            _ => Self::EndOfList,
        }
    }

    /// Convert protocol to human-readable string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "unknown",
            Self::Heur => "heur",
            Self::Ssh1 => "ssh1",
            Self::Ssh2 => "ssh2",
            Self::Http => "http",
            Self::Ftp => "ftp",
            Self::DnsVersionBind => "dns-versionbind",
            Self::Snmp => "snmp",
            Self::NbtStat => "nbtstat",
            Self::Ssl3 => "ssl",
            Self::Smb => "smb",
            Self::Smtp => "smtp",
            Self::Pop3 => "pop3",
            Self::Imap4 => "imap4",
            Self::UdpZeroAccess => "zeroaccess",
            Self::X509Cert => "x509-cert",
            Self::X509CaCert => "x509-cacert",
            Self::HtmlTitle => "html-title",
            Self::HtmlFull => "html-full",
            Self::Ntp => "ntp",
            Self::Vuln => "vuln",
            Self::Heartbleed => "heartbleed",
            Self::Ticketbleed => "ticketbleed",
            Self::VncOld => "vnc-old",
            Self::Safe => "safe",
            Self::Memcached => "memcached",
            Self::Scripting => "scripting",
            Self::Versioning => "versioning",
            Self::Coap => "coap",
            Self::Telnet => "telnet",
            Self::Rdp => "rdp",
            Self::HttpServer => "http-server",
            Self::Mc => "minecraft",
            Self::VncRfb => "vnc-rfb",
            Self::VncInfo => "vnc-info",
            Self::Isakmp => "isakmp",
            Self::Error => "error",
            Self::EndOfList => "end-of-list",
        }
    }
}

/// Flags for protocol parser streams.
#[derive(Debug, Clone, Copy)]
pub enum StreamFlags {
    /// No special flags.
    None = 0,
    /// Send FIN after the static hello is sent.
    Close = 0x01,
    /// Send our hello immediately, don't wait for their hello.
    NoWaitHello = 0x02,
}

/// Pattern matching entry for protocol detection.
#[derive(Debug, Clone)]
pub struct Pattern {
    /// The pattern bytes to match.
    pub pattern: Vec<u8>,
    /// Protocol ID this pattern identifies.
    pub id: AppProtocol,
    /// Whether this pattern is anchored (must match at beginning).
    pub is_anchored: bool,
    /// Extra protocol-specific data (e.g., VNC version).
    pub extra: u32,
}

/// SMACK anchor flags (matching C SMACK_ANCHOR_BEGIN etc.).
pub const SMACK_ANCHOR_BEGIN: u32 = 0x01;
/// SMACK wildcard flag.
pub const SMACK_WILDCARDS: u32 = 0x04;

/// SSL Server Hello state.
#[derive(Debug, Default, Clone)]
pub struct SslServerHello {
    pub state: u32,
    pub remaining: u32,
    pub timestamp: u32,
    pub cipher_suite: u16,
    pub ext_tag: u16,
    pub ext_remaining: u16,
    pub compression_method: u8,
    pub version_major: u8,
    pub version_minor: u8,
}

/// SSL Server Certificate state.
#[derive(Debug, Default, Clone)]
pub struct SslServerCert {
    pub state: u32,
    pub remaining: u32,
    pub sub_remaining: u32,
    // x509 decoder state would go here
}

/// SSL Server Alert state.
#[derive(Debug, Default, Clone)]
pub struct SslServerAlert {
    pub level: u8,
    pub description: u8,
}

/// SSL record-level state.
#[derive(Debug, Default, Clone)]
pub struct SslRecord {
    pub rec_type: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub handshake_state: u32,
    pub handshake_type: u8,
    pub handshake_remaining: u32,
    pub server_hello: SslServerHello,
    pub server_cert: SslServerCert,
    pub server_alert: SslServerAlert,
}

/// VNC pixel format information.
#[derive(Debug, Default, Clone)]
pub struct PixelFormat {
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
    pub bits_per_pixel: u8,
    pub depth: u8,
    pub big_endian_flag: bool,
    pub true_colour_flag: bool,
}

/// VNC protocol state.
#[derive(Debug, Default, Clone)]
pub struct VncState {
    pub sectype: u32,
    pub version: u8,
    pub len: u8,
    pub width: u16,
    pub height: u16,
    pub pixel: PixelFormat,
}

/// FTP protocol state.
#[derive(Debug, Default, Clone)]
pub struct FtpState {
    pub code: u32,
    pub is_last: bool,
}

/// MC (Minecraft) protocol state.
#[derive(Debug, Default, Clone)]
pub struct McState {
    pub ban_mem: Vec<u8>,
    pub total_len: usize,
    pub img_start: usize,
    pub img_end: usize,
    pub bracket_count: i32,
}

/// SMTP protocol state.
#[derive(Debug, Default, Clone)]
pub struct SmtpState {
    pub code: u32,
    pub is_last: bool,
}

/// POP3 protocol state.
#[derive(Debug, Default, Clone)]
pub struct Pop3State {
    pub code: u32,
    pub is_last: bool,
}

/// Memcached protocol state.
#[derive(Debug, Default, Clone)]
pub struct MemcachedState {
    pub match_state: u32,
}

/// SMB negotiation parameters.
#[derive(Debug, Default, Clone)]
pub struct Smb72Negotiate {
    pub dialect_index: u16,
    pub security_mode: u16,
    pub system_time: u64,
    pub session_key: u32,
    pub capabilities: u32,
    pub server_timezone: u16,
    pub challenge_length: u8,
    pub challenge_offset: u8,
}

/// SMB setup parameters.
#[derive(Debug, Default, Clone)]
pub struct Smb73Setup {
    pub blob_length: u16,
    pub blob_offset: u16,
}

/// SMB SMB1 header fields.
#[derive(Debug, Default, Clone)]
pub struct Smb1Header {
    pub command: u8,
    pub status: u32,
    pub flags1: u8,
    pub flags2: u16,
    pub pid: u32,
    pub signature: [u8; 8],
    pub tid: u16,
    pub uid: u16,
    pub mid: u16,
    pub param_length: u16,
    pub param_offset: u16,
    pub byte_count: u16,
    pub byte_offset: u16,
    pub byte_state: u16,
    pub unicode_char: u16,
}

/// SMB SMB2 header fields.
#[derive(Debug, Default, Clone)]
pub struct Smb2Header {
    pub seqno: u32,
    pub header_length: u16,
    pub offset: u16,
    pub state: u16,
    pub opcode: u16,
    pub struct_length: u16,
    pub is_dynamic: bool,
    pub flags: u8,
    pub ntstatus: u32,
    pub number: u32,
    pub blob_offset: u16,
    pub blob_length: u16,
}

/// SMB negotiate v2 parameters.
#[derive(Debug, Default, Clone)]
pub struct SmbNegotiate2 {
    pub current_time: u64,
    pub boot_time: u64,
}

/// SMB protocol state.
#[derive(Debug, Default, Clone)]
pub struct SmbState {
    pub nbt_state: u32,
    pub nbt_type: u8,
    pub nbt_flags: u8,
    pub is_printed_ver: bool,
    pub is_printed_guid: bool,
    pub is_printed_time: bool,
    pub is_printed_boottime: bool,
    pub nbt_length: u32,
    pub nbt_err: u32,
    pub hdr_smb1: Smb1Header,
    pub hdr_smb2: Smb2Header,
    pub parms_negotiate: Smb72Negotiate,
    pub parms_setup: Smb73Setup,
    pub parms_negotiate2: SmbNegotiate2,
}

/// RDP protocol state.
#[derive(Debug, Default, Clone)]
pub struct RdpState {
    pub tpkt_length: u16,
    pub cotp_state: u32,
    pub cotp_dstref: u16,
    pub cotp_srcref: u16,
    pub cotp_len: u8,
    pub cotp_type: u8,
    pub cotp_flags: u8,
    pub cc_state: u32,
    pub cc_result: u32,
    pub cc_type: u8,
    pub cc_flags: u8,
    pub cc_len: u8,
}

/// SSH protocol state.
#[derive(Debug, Default, Clone)]
pub struct SshState {
    pub packet_length: usize,
}

/// Protocol-specific sub-state for a stream connection.
///
/// Replaces the C union with a Rust enum, ensuring only one
/// variant is active at a time.
#[derive(Debug, Clone)]
pub enum ProtocolSubState {
    Ssl(SslRecord),
    Vnc(VncState),
    Ftp(FtpState),
    Smtp(SmtpState),
    Pop3(Pop3State),
    Memcached(MemcachedState),
    Smb(SmbState),
    Rdp(RdpState),
    Mc(McState),
    Ssh(SshState),
}

impl Default for ProtocolSubState {
    fn default() -> Self {
        ProtocolSubState::Ssl(SslRecord::default())
    }
}

/// Per-connection stream state.
///
/// Tracks the state machine for a single TCP connection,
/// including the detected protocol and protocol-specific state.
#[derive(Debug, Clone)]
pub struct StreamState {
    /// State machine state variable.
    pub state: u32,
    /// Remaining bytes to read in current field.
    pub remaining: u32,
    /// Port number for this connection.
    pub port: u16,
    /// Detected application protocol.
    pub app_proto: u16,
    /// Whether we've already sent an SSL hello.
    pub is_sent_sslhello: bool,
    /// Base64 encoding state for streaming base64 output.
    pub base64: BannerBase64,
    /// Protocol-specific sub-state.
    pub sub: ProtocolSubState,
}

impl Default for StreamState {
    fn default() -> Self {
        StreamState {
            state: 0,
            remaining: 0,
            port: 0,
            app_proto: AppProtocol::None as u16,
            is_sent_sslhello: false,
            base64: BannerBase64::new(),
            sub: ProtocolSubState::default(),
        }
    }
}

/// Function signature for banner parser callbacks.
pub type BannerParserFn = fn(
    &Banner1,
    &mut StreamState,
    &[u8],        // px (packet data)
    usize,        // length
    &mut BannerOutput,
);

/// Function signature for parser init callbacks.
pub type ParserInitFn = fn(&mut Banner1);

/// Function signature for parser selftest callbacks.
pub type ParserSelftestFn = fn() -> bool;

/// Function signature for parser cleanup callbacks.
pub type ParserCleanupFn = fn(&mut StreamState);

/// Registration structure for a TCP stream protocol parser
/// (HTTP, SSL, SSH, etc.).
#[derive(Clone)]
pub struct ProtocolParserStream {
    /// Name of this parser (e.g., "http", "ssl").
    pub name: &'static str,
    /// Default port for this protocol.
    pub port: u16,
    /// Hello message to send upon connection.
    pub hello: Vec<u8>,
    /// Flags controlling connection behavior.
    pub flags: StreamFlags,
    /// Selftest function.
    pub selftest: Option<ParserSelftestFn>,
    /// Initialization function.
    pub init: Option<ParserInitFn>,
    /// Main parse function.
    pub parse: Option<BannerParserFn>,
    /// Cleanup function.
    pub cleanup: Option<ParserCleanupFn>,
}

impl std::fmt::Debug for ProtocolParserStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolParserStream")
            .field("name", &self.name)
            .field("port", &self.port)
            .field("hello_len", &self.hello.len())
            .finish()
    }
}

/// The main banner detection system.
///
/// Contains SMACK pattern matchers and registered protocol parsers.
pub struct Banner1 {
    /// Whether to capture HTML content.
    pub is_capture_html: bool,
    /// Whether to capture SSL certificates.
    pub is_capture_cert: bool,
    /// Whether to capture server names.
    pub is_capture_servername: bool,
    /// Whether to capture heartbleed data.
    pub is_capture_heartbleed: bool,
    /// Whether to capture ticketbleed data.
    pub is_capture_ticketbleed: bool,
    /// Whether to attempt heartbleed exploit.
    pub is_heartbleed: bool,
    /// Whether to attempt ticketbleed exploit.
    pub is_ticketbleed: bool,
    /// Whether to check for POODLE (SSLv3).
    pub is_poodle_sslv3: bool,

    /// Per-port TCP parser assignments.
    pub payloads_tcp: HashMap<u16, usize>,

    /// Registered parsers indexed by protocol enum value.
    pub parsers: Vec<Option<BannerParserFn>>,

    /// Pattern list for heuristic protocol detection.
    pub patterns: Vec<Pattern>,
}

impl Banner1 {
    /// Create a new Banner1 instance with default configuration.
    pub fn new() -> Self {
        let mut parsers = Vec::new();
        parsers.resize_with(AppProtocol::EndOfList as usize, || None);

        let mut b = Banner1 {
            is_capture_html: false,
            is_capture_cert: true,
            is_capture_servername: true,
            is_capture_heartbleed: false,
            is_capture_ticketbleed: false,
            is_heartbleed: false,
            is_ticketbleed: false,
            is_poodle_sslv3: false,
            payloads_tcp: HashMap::new(),
            parsers,
            patterns: Vec::new(),
        };

        b.init_patterns();
        b.init_payloads();
        b
    }

    /// Initialize the heuristic protocol detection patterns.
    fn init_patterns(&mut self) {
        self.patterns = vec![
            // SMB patterns
            Pattern { pattern: b"\x00\x00**\xffSMB".to_vec(), id: AppProtocol::Smb, is_anchored: true, extra: 0 },
            Pattern { pattern: b"\x00\x00**\xfeSMB".to_vec(), id: AppProtocol::Smb, is_anchored: true, extra: 0 },
            Pattern { pattern: b"\x82\x00\x00\x00".to_vec(), id: AppProtocol::Smb, is_anchored: true, extra: 0 },
            Pattern { pattern: b"\x83\x00\x00\x01\x80".to_vec(), id: AppProtocol::Smb, is_anchored: true, extra: 0 },
            Pattern { pattern: b"\x83\x00\x00\x01\x81".to_vec(), id: AppProtocol::Smb, is_anchored: true, extra: 0 },
            Pattern { pattern: b"\x83\x00\x00\x01\x82".to_vec(), id: AppProtocol::Smb, is_anchored: true, extra: 0 },
            Pattern { pattern: b"\x83\x00\x00\x01\x83".to_vec(), id: AppProtocol::Smb, is_anchored: true, extra: 0 },
            Pattern { pattern: b"\x83\x00\x00\x01\x8f".to_vec(), id: AppProtocol::Smb, is_anchored: true, extra: 0 },

            // MC pattern
            Pattern { pattern: b"{\x22".to_vec(), id: AppProtocol::Mc, is_anchored: false, extra: 0 },

            // SSH patterns
            Pattern { pattern: b"SSH-1.".to_vec(), id: AppProtocol::Ssh1, is_anchored: true, extra: 0 },
            Pattern { pattern: b"SSH-2.".to_vec(), id: AppProtocol::Ssh2, is_anchored: true, extra: 0 },

            // HTTP
            Pattern { pattern: b"HTTP/1.".to_vec(), id: AppProtocol::Http, is_anchored: true, extra: 0 },

            // FTP
            Pattern { pattern: b"220-".to_vec(), id: AppProtocol::Ftp, is_anchored: true, extra: 0 },
            Pattern { pattern: b"220 ".to_vec(), id: AppProtocol::Ftp, is_anchored: true, extra: 1 },

            // POP3
            Pattern { pattern: b"+OK ".to_vec(), id: AppProtocol::Pop3, is_anchored: true, extra: 0 },

            // IMAP4
            Pattern { pattern: b"* OK ".to_vec(), id: AppProtocol::Imap4, is_anchored: true, extra: 0 },

            // SMTP
            Pattern { pattern: b"521 ".to_vec(), id: AppProtocol::Smtp, is_anchored: true, extra: 0 },

            // SSL/TLS
            Pattern { pattern: vec![0x16, 0x03, 0x00], id: AppProtocol::Ssl3, is_anchored: true, extra: 0 },
            Pattern { pattern: vec![0x16, 0x03, 0x01], id: AppProtocol::Ssl3, is_anchored: true, extra: 0 },
            Pattern { pattern: vec![0x16, 0x03, 0x02], id: AppProtocol::Ssl3, is_anchored: true, extra: 0 },
            Pattern { pattern: vec![0x16, 0x03, 0x03], id: AppProtocol::Ssl3, is_anchored: true, extra: 0 },
            Pattern { pattern: vec![0x15, 0x03, 0x00], id: AppProtocol::Ssl3, is_anchored: true, extra: 0 },
            Pattern { pattern: vec![0x15, 0x03, 0x01], id: AppProtocol::Ssl3, is_anchored: true, extra: 0 },
            Pattern { pattern: vec![0x15, 0x03, 0x02], id: AppProtocol::Ssl3, is_anchored: true, extra: 0 },
            Pattern { pattern: vec![0x15, 0x03, 0x03], id: AppProtocol::Ssl3, is_anchored: true, extra: 0 },

            // VNC RFB patterns
            Pattern { pattern: b"RFB 000.000\n".to_vec(), id: AppProtocol::VncRfb, is_anchored: true, extra: 1 },
            Pattern { pattern: b"RFB 003.003\n".to_vec(), id: AppProtocol::VncRfb, is_anchored: true, extra: 3 },
            Pattern { pattern: b"RFB 003.005\n".to_vec(), id: AppProtocol::VncRfb, is_anchored: true, extra: 3 },
            Pattern { pattern: b"RFB 003.006\n".to_vec(), id: AppProtocol::VncRfb, is_anchored: true, extra: 3 },
            Pattern { pattern: b"RFB 003.007\n".to_vec(), id: AppProtocol::VncRfb, is_anchored: true, extra: 7 },
            Pattern { pattern: b"RFB 003.008\n".to_vec(), id: AppProtocol::VncRfb, is_anchored: true, extra: 8 },
            Pattern { pattern: b"RFB 003.889\n".to_vec(), id: AppProtocol::VncRfb, is_anchored: true, extra: 8 },
            Pattern { pattern: b"RFB 003.009\n".to_vec(), id: AppProtocol::VncRfb, is_anchored: true, extra: 8 },
            Pattern { pattern: b"RFB 004.000\n".to_vec(), id: AppProtocol::VncRfb, is_anchored: true, extra: 8 },
            Pattern { pattern: b"RFB 004.001\n".to_vec(), id: AppProtocol::VncRfb, is_anchored: true, extra: 8 },
            Pattern { pattern: b"RFB 004.002\n".to_vec(), id: AppProtocol::VncRfb, is_anchored: true, extra: 8 },

            // Memcached
            Pattern { pattern: b"STAT pid ".to_vec(), id: AppProtocol::Memcached, is_anchored: true, extra: 0 },

            // Telnet patterns (selection)
            Pattern { pattern: vec![0xFF, 0xFB, 0x01, 0xFF, 0xF0], id: AppProtocol::Telnet, is_anchored: false, extra: 0 },
            Pattern { pattern: vec![0xFF, 0xFB, 0x01, 0xFF, 0xFB], id: AppProtocol::Telnet, is_anchored: false, extra: 0 },
            Pattern { pattern: vec![0xFF, 0xFB, 0x01, 0xFF, 0xFC], id: AppProtocol::Telnet, is_anchored: false, extra: 0 },
            Pattern { pattern: vec![0xFF, 0xFB, 0x01, 0xFF, 0xFD], id: AppProtocol::Telnet, is_anchored: false, extra: 0 },
            Pattern { pattern: vec![0xFF, 0xFB, 0x01, 0xFF, 0xFE], id: AppProtocol::Telnet, is_anchored: false, extra: 0 },
            Pattern { pattern: vec![0xFF, 0xFB, 0x01, 0x1B, 0x5B], id: AppProtocol::Telnet, is_anchored: true, extra: 0 },
            Pattern { pattern: b"login:".to_vec(), id: AppProtocol::Telnet, is_anchored: true, extra: 0 },
            Pattern { pattern: b"password:".to_vec(), id: AppProtocol::Telnet, is_anchored: true, extra: 0 },

            // RDP patterns
            Pattern { pattern: vec![0x03, 0x00, 0x00, 0x13, 0x0E, 0xD0, 0xBE, 0xEF, 0x12, 0x34, 0x00, 0x02], id: AppProtocol::Rdp, is_anchored: true, extra: 0 },
            Pattern { pattern: vec![0x03, 0x00, 0x00, 0x13, 0x0E, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02], id: AppProtocol::Rdp, is_anchored: true, extra: 0 },
        ];
    }

    /// Initialize per-port TCP parser assignments.
    fn init_payloads(&mut self) {
        // HTTP
        self.payloads_tcp.insert(80, 0);
        self.payloads_tcp.insert(8080, 0);
        self.payloads_tcp.insert(8530, 0);

        // SMB
        self.payloads_tcp.insert(139, 1);
        self.payloads_tcp.insert(445, 1);

        // SSL/TLS
        for port in &[443u16, 465, 990, 991, 992, 993, 994, 995,
                       2083, 2087, 2096, 8443, 8531, 9050, 8140,
                       636, 637, 3269, 11712, 5061, 322, 2376, 49955] {
            self.payloads_tcp.insert(*port, 2);
        }

        // Memcached
        self.payloads_tcp.insert(11211, 3);

        // Telnet
        self.payloads_tcp.insert(23, 4);

        // RDP
        self.payloads_tcp.insert(3389, 5);

        // X11
        for port in 6000u16..6020 {
            self.payloads_tcp.insert(port, 6);
        }

        // DNS
        self.payloads_tcp.insert(53, 7);

        // Docker
        self.payloads_tcp.insert(2375, 8);
        self.payloads_tcp.insert(2379, 8);
        self.payloads_tcp.insert(2380, 8);

        // Redis
        self.payloads_tcp.insert(6379, 9);

        // LDAP
        for port in &[256u16, 257, 389, 390, 1702, 3268, 3892, 11711] {
            self.payloads_tcp.insert(*port, 10);
        }

        // SIP
        self.payloads_tcp.insert(5060, 11);

        // RTSP
        self.payloads_tcp.insert(554, 12);

        // Java RMI
        self.payloads_tcp.insert(1098, 13);
        self.payloads_tcp.insert(1099, 13);

        // Kerberos
        self.payloads_tcp.insert(88, 14);

        // MongoDB
        self.payloads_tcp.insert(27017, 15);
        self.payloads_tcp.insert(49153, 15);

        // AFP
        self.payloads_tcp.insert(548, 16);
    }

    /// Parse incoming data for a stream connection.
    ///
    /// Dispatches to the appropriate protocol parser based on the
    /// detected or configured protocol.
    pub fn parse(
        &self,
        stream_state: &mut StreamState,
        px: &[u8],
        length: usize,
        banout: &mut BannerOutput,
    ) -> u16 {
        let app_proto = AppProtocol::from_u32(stream_state.app_proto as u32);

        match app_proto {
            AppProtocol::None | AppProtocol::Heur => {
                // Heuristic protocol detection
                self.parse_heuristic(stream_state, px, length, banout)
            }
            AppProtocol::Ftp => {
                crate::proto::ftp::ftp_parse(self, stream_state, px, length, banout);
                stream_state.app_proto
            }
            AppProtocol::Smtp => {
                crate::proto::smtp::smtp_parse(self, stream_state, px, length, banout);
                stream_state.app_proto
            }
            AppProtocol::Telnet => {
                crate::proto::tcp_telnet::telnet_parse(self, stream_state, px, length, banout);
                stream_state.app_proto
            }
            AppProtocol::Rdp => {
                crate::proto::tcp_rdp::rdp_parse(self, stream_state, px, length, banout);
                stream_state.app_proto
            }
            AppProtocol::Pop3 => {
                crate::proto::pop3::pop3_parse(self, stream_state, px, length, banout);
                stream_state.app_proto
            }
            AppProtocol::Imap4 => {
                crate::proto::imap4::imap4_parse(self, stream_state, px, length, banout);
                stream_state.app_proto
            }
            AppProtocol::Ssh1 | AppProtocol::Ssh2 => {
                crate::proto::ssh::ssh_parse(self, stream_state, px, length, banout);
                stream_state.app_proto
            }
            AppProtocol::Http => {
                crate::proto::http::http_parse(self, stream_state, px, length, banout);
                stream_state.app_proto
            }
            AppProtocol::Ssl3 => {
                crate::proto::ssl::ssl_parse(self, stream_state, px, length, banout);
                stream_state.app_proto
            }
            AppProtocol::Smb => {
                crate::proto::smb::smb_parse(self, stream_state, px, length, banout);
                stream_state.app_proto
            }
            AppProtocol::VncRfb => {
                crate::proto::vnc::vnc_parse(self, stream_state, px, length, banout);
                stream_state.app_proto
            }
            AppProtocol::Memcached => {
                crate::proto::memcached::memcached_tcp_parse(self, stream_state, px, length, banout);
                stream_state.app_proto
            }
            AppProtocol::Mc => {
                crate::proto::mc::mc_parse(self, stream_state, px, length, banout);
                stream_state.app_proto
            }
            AppProtocol::Versioning => {
                crate::proto::versioning::versioning_tcp_parse(self, stream_state, px, length, banout);
                stream_state.app_proto
            }
            _ => {
                stream_state.app_proto
            }
        }
    }

    /// Heuristic protocol detection using pattern matching.
    fn parse_heuristic(
        &self,
        stream_state: &mut StreamState,
        px: &[u8],
        length: usize,
        banout: &mut BannerOutput,
    ) -> u16 {
        // Simple pattern matching against accumulated heuristic data
        // and new data
        let heuristic_data = banout.string(AppProtocol::Heur as u32);

        // Try matching patterns against both existing heuristic data and new data
        let mut matched_proto: Option<(AppProtocol, usize)> = None;

        for (idx, pattern) in self.patterns.iter().enumerate() {
            let data_to_check = if pattern.is_anchored {
                // For anchored patterns, check against accumulated heuristic + new data
                if let Some(existing) = heuristic_data {
                    // Check if existing data already matches
                    if existing.starts_with(&pattern.pattern) {
                        matched_proto = Some((pattern.id, idx));
                        break;
                    }
                }
                // Check if new data starts with pattern
                if px.starts_with(&pattern.pattern) {
                    matched_proto = Some((pattern.id, idx));
                    break;
                }
                // Check combined
                if let Some(existing) = heuristic_data {
                    let combined: Vec<u8> = existing.iter().chain(px.iter()).copied().collect();
                    if combined.starts_with(&pattern.pattern) {
                        matched_proto = Some((pattern.id, idx));
                        break;
                    }
                }
                &[] as &[u8]
            } else {
                // Non-anchored: search anywhere in the data
                if px.windows(pattern.pattern.len()).any(|w| w == pattern.pattern) {
                    matched_proto = Some((pattern.id, idx));
                    break;
                }
                if let Some(existing) = heuristic_data {
                    if existing.windows(pattern.pattern.len()).any(|w| w == pattern.pattern) {
                        matched_proto = Some((pattern.id, idx));
                        break;
                    }
                }
                &[]
            };
            let _ = data_to_check; // suppress unused warning
        }

        if let Some((proto, idx)) = matched_proto {
            // Kludge: FTP pattern with extra==1 might be SMTP on port 25/587
            let mut final_proto = proto;
            if proto == AppProtocol::Ftp && self.patterns[idx].extra == 1 {
                if stream_state.port == 25 || stream_state.port == 587 {
                    final_proto = AppProtocol::Smtp;
                }
            }
            // VNC: store version info
            if proto == AppProtocol::VncRfb {
                if let ProtocolSubState::Vnc(ref mut vnc) = stream_state.sub {
                    vnc.version = self.patterns[idx].extra as u8;
                }
            }

            stream_state.app_proto = final_proto as u16;
            stream_state.state = 0;

            // Re-parse heuristic data if we have any
            if let Some(existing) = banout.string(AppProtocol::Heur as u32) {
                let existing_copy: Vec<u8> = existing.to_vec();
                let existing_len = existing_copy.len();
                if existing_len > 0 {
                    self.parse(stream_state, &existing_copy, existing_len, banout);
                }
            }

            // Parse the current data
            self.parse(stream_state, px, length, banout)
        } else {
            // No match yet; accumulate data for heuristic detection
            banout.append(AppProtocol::Heur as u32, px, length);
            stream_state.app_proto
        }
    }
}

impl Default for Banner1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert protocol enum to string.
pub fn app_to_string(proto: AppProtocol) -> &'static str {
    proto.as_str()
}

/// Convert string to protocol enum.
pub fn string_to_app(s: &str) -> Option<AppProtocol> {
    for i in 0..(AppProtocol::EndOfList as u32) {
        let proto = AppProtocol::from_u32(i);
        if proto.as_str() == s {
            return Some(proto);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_protocol_strings() {
        assert_eq!(AppProtocol::Http.as_str(), "http");
        assert_eq!(AppProtocol::Ssh2.as_str(), "ssh2");
        assert_eq!(AppProtocol::Ssl3.as_str(), "ssl");
    }

    #[test]
    fn test_string_to_app() {
        assert_eq!(string_to_app("http"), Some(AppProtocol::Http));
        assert_eq!(string_to_app("nonexistent"), None);
    }

    #[test]
    fn test_banner1_create() {
        let b = Banner1::new();
        assert!(!b.patterns.is_empty());
        assert!(!b.payloads_tcp.is_empty());
    }
}
