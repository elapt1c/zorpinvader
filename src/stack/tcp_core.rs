//! TCP connection table and state machine.
//!
//! This is the core of the network scanner's custom TCP/IP stack. It manages
//! thousands of concurrent TCP connections (TCP Control Blocks), tracking
//! their state through the TCP state diagram.
//!
//! The state machine is simplified compared to a full TCP implementation:
//! - No receive buffering (out-of-order packets are dropped).
//! - No window scaling or advanced options.
//! - Send and receive are separated into distinct states.
//!
//! Converted from `c-src/stack-tcp-core.h`, `c-src/stack-tcp-core.c`,
//! and `c-src/stack-tcp-api.h`.
//!
//! ```text
//!                              +---------+ ---------\      active OPEN
//!                              |  CLOSED |            \    -----------
//!                              +---------+<---------\   \   create TCB
//!                                |     ^              \   \  snd SYN
//!                   passive OPEN |     |   CLOSE        \   \
//!                   ------------ |     | ----------       \   \
//!                    create TCB  |     | delete TCB         \   \
//!                                V     |                      \   \
//!                              +---------+            CLOSE    |    \
//!                              |  LISTEN |          ---------- |     |
//!                              +---------+          delete TCB |     |
//!                   rcv SYN      |     |     SEND              |     |
//!                  -----------   |     |    -------            |     V
//! +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
//! |         |<-----------------           ------------------>|         |
//! |   SYN   |                    rcv SYN                     |   SYN   |
//! |   RCVD  |<-----------------------------------------------|   SENT  |
//! |         |                    snd ACK                     |         |
//! |         |------------------           -------------------|         |
//! +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
//!   |           --------------   |     |   -----------
//!   |                  x         |     |     snd ACK
//!   |                            V     V
//!   |  CLOSE                   +---------+
//!   | -------                  |  ESTAB  |
//!   | snd FIN                  +---------+
//! ```

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::massip::addr::{IpAddress, Ipv4Address, Ipv6Address};
use super::tcp_app::{AppState, AppEvent, SendFlags, Banner1, ProtocolParserStream, StreamState};
use super::queue::Stack;

// ---------------------------------------------------------------------------
// TCP packet field extraction macros (from raw packet bytes)
// ---------------------------------------------------------------------------

/// Extract the TCP sequence number from raw packet bytes at offset `i`.
#[inline]
pub fn tcp_seqno(px: &[u8], i: usize) -> u32 {
    ((px[i + 4] as u32) << 24)
        | ((px[i + 5] as u32) << 16)
        | ((px[i + 6] as u32) << 8)
        | (px[i + 7] as u32)
}

/// Extract the TCP acknowledgement number from raw packet bytes.
#[inline]
pub fn tcp_ackno(px: &[u8], i: usize) -> u32 {
    ((px[i + 8] as u32) << 24)
        | ((px[i + 9] as u32) << 16)
        | ((px[i + 10] as u32) << 8)
        | (px[i + 11] as u32)
}

/// Extract the TCP flags byte from raw packet bytes.
#[inline]
pub fn tcp_flags(px: &[u8], i: usize) -> u8 {
    px[i + 13]
}

/// Check if the TCP flags indicate a SYN-ACK.
#[inline]
pub fn tcp_is_synack(px: &[u8], i: usize) -> bool {
    (tcp_flags(px, i) & 0x12) == 0x12
}

/// Check if the TCP flags indicate an ACK.
#[inline]
pub fn tcp_is_ack(px: &[u8], i: usize) -> bool {
    (tcp_flags(px, i) & 0x10) == 0x10
}

/// Check if the TCP flags indicate a RST.
#[inline]
pub fn tcp_is_rst(px: &[u8], i: usize) -> bool {
    (tcp_flags(px, i) & 0x04) == 0x04
}

/// Check if the TCP flags indicate a FIN.
#[inline]
pub fn tcp_is_fin(px: &[u8], i: usize) -> bool {
    (tcp_flags(px, i) & 0x01) == 0x01
}

// ---------------------------------------------------------------------------
// TCP state machine states
// ---------------------------------------------------------------------------

/// Internal TCP connection states.
///
/// These differ from the standard TCP states because our scanner splits
/// ESTABLISHED into separate SEND and RECV sub-states, and has custom
/// FIN-WAIT-1 variants for send vs receive contexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// SYN sent, waiting for SYN-ACK. Must be the initial state.
    SynSent,
    /// Established and currently sending data.
    EstablishedSend,
    /// Established and currently receiving data.
    EstablishedRecv,
    /// Received FIN from remote; waiting for app to close.
    CloseWait,
    /// Sent FIN, waiting for final ACK.
    LastAck,
    /// Sent FIN while in SEND state; waiting for ACKs.
    FinWait1Send,
    /// Sent FIN while in RECV state; waiting for ACKs.
    FinWait1Recv,
    /// Our FIN was ACKed; waiting for their FIN.
    FinWait2,
    /// Both sides sent FIN; waiting for final ACK.
    Closing,
    /// Connection fully closed; waiting for 2MSL timeout.
    TimeWait,
}

impl TcpState {
    fn as_str(self) -> &'static str {
        match self {
            TcpState::SynSent => "SYN_SENT",
            TcpState::EstablishedSend => "ESTABLISHED_SEND",
            TcpState::EstablishedRecv => "ESTABLISHED_RECV",
            TcpState::CloseWait => "CLOSE-WAIT",
            TcpState::LastAck => "LAST-ACK",
            TcpState::FinWait1Send => "FIN-WAIT-1-SEND",
            TcpState::FinWait1Recv => "FIN-WAIT-1-RECV",
            TcpState::FinWait2 => "FIN-WAIT-2",
            TcpState::Closing => "CLOSING",
            TcpState::TimeWait => "TIME-WAIT",
        }
    }
}

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// TCP events that drive the state machine
// ---------------------------------------------------------------------------

/// Events that can occur on a TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpWhat {
    /// Timeout expired (retransmit or connection timeout).
    Timeout,
    /// Received SYN-ACK.
    SynAck,
    /// Received RST.
    Rst,
    /// Received FIN.
    Fin,
    /// Received ACK (no data).
    Ack,
    /// Received data payload.
    Data,
    /// Application requested close.
    Close,
}

impl TcpWhat {
    fn as_str(self) -> &'static str {
        match self {
            TcpWhat::Timeout => "TIMEOUT",
            TcpWhat::SynAck => "SYNACK",
            TcpWhat::Rst => "RST",
            TcpWhat::Fin => "FIN",
            TcpWhat::Ack => "ACK",
            TcpWhat::Data => "DATA",
            TcpWhat::Close => "CLOSE",
        }
    }
}

impl std::fmt::Display for TcpWhat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result of processing an incoming TCP event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcbResult {
    /// Connection still alive.
    Okay,
    /// Connection was destroyed during processing.
    Destroyed,
}

// ---------------------------------------------------------------------------
// TCP segment (queued outgoing data)
// ---------------------------------------------------------------------------

/// A queued outgoing TCP segment.
///
/// When the application calls `send()`, the data is split into MSS-sized
/// segments and appended to the TCB's segment list. Segments are removed
/// as they are acknowledged by the remote side.
struct TcpSegment {
    /// Sequence number of the first byte in this segment.
    seqno: u32,
    /// Payload data (may be empty for FIN-only segments).
    data: Vec<u8>,
    /// Whether this segment includes a FIN flag.
    is_fin: bool,
    /// How the data was provided (determines cleanup behavior).
    flags: SendFlags,
}

// ---------------------------------------------------------------------------
// Timeout entry (simplified - delegates to event_timeout module)
// ---------------------------------------------------------------------------

/// Timeout tracking for a TCB.
///
/// Each TCB must always have an active timeout. When the timeout fires,
/// the TCB is processed with a `TcpWhat::Timeout` event.
#[derive(Debug)]
pub struct TcbTimeout {
    /// Absolute tick timestamp when this timeout fires.
    pub expires: u64,
    /// Whether this timeout is currently linked/active.
    pub is_linked: bool,
}

impl TcbTimeout {
    pub fn new() -> Self {
        Self {
            expires: 0,
            is_linked: false,
        }
    }

    pub fn is_unlinked(&self) -> bool {
        !self.is_linked
    }

    pub fn set(&mut self, expires: u64) {
        self.expires = expires;
        self.is_linked = true;
    }

    pub fn unlink(&mut self) {
        self.is_linked = false;
    }
}

// ---------------------------------------------------------------------------
// Banner output
// ---------------------------------------------------------------------------

/// A single banner output entry.
#[derive(Debug)]
pub struct BannerOutput {
    /// Protocol identifier.
    pub protocol: u32,
    /// Banner data bytes.
    pub banner: Vec<u8>,
}

// ---------------------------------------------------------------------------
// TCP Control Block (TCB)
// ---------------------------------------------------------------------------

/// Unique key identifying a TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub ip_me: IpAddress,
    pub ip_them: IpAddress,
    pub port_me: u16,
    pub port_them: u16,
}

/// TCP Control Block — tracks the state of a single TCP connection.
///
/// This is the Rust equivalent of `struct TCP_Control_Block` from the C code.
/// Each active connection in the scanner has exactly one TCB.
pub struct TcpControlBlock {
    // --- Connection identity ---
    /// Our IP address for this connection.
    pub ip_me: IpAddress,
    /// Their IP address.
    pub ip_them: IpAddress,
    /// Our port number.
    pub port_me: u16,
    /// Their port number.
    pub port_them: u16,

    // --- Sequence numbers ---
    /// Next sequence number we will use for transmit.
    pub seqno_me: u32,
    /// Next sequence number we expect to receive.
    pub seqno_them: u32,
    /// Last acknowledged sequence number from them.
    pub ackno_me: u32,
    /// Last acknowledged sequence number from us.
    pub ackno_them: u32,
    /// Initial sequence number (ours).
    pub seqno_me_first: u32,
    /// Initial sequence number (theirs).
    pub seqno_them_first: u32,

    // --- Connection metadata ---
    /// TTL from the initial SYN-ACK packet.
    pub ttl: u8,
    /// Number of SYNs we've sent (for retransmission tracking).
    pub syns_sent: u8,
    /// Maximum Segment Size.
    pub mss: u16,

    // --- State ---
    /// Current TCP state machine state.
    pub tcp_state: TcpState,
    /// Whether this is an IPv6 connection.
    pub is_ipv6: bool,
    /// Whether to use a small TCP window (for heartbleed scanning).
    pub is_small_window: bool,
    /// Whether the remote side has sent a FIN.
    pub is_their_fin: bool,
    /// Whether this TCB is currently active/allocated.
    pub is_active: bool,

    // --- Application state ---
    /// Application-layer state machine state.
    pub app_state: AppState,
    /// Stream parsing state for banner grabbing.
    pub banner1_state: StreamState,
    /// Collected banner output entries.
    pub banners: Vec<BannerOutput>,

    // --- Timeout ---
    /// Timeout tracking for this connection.
    pub timeout: TcbTimeout,

    // --- Segment queue ---
    /// Queued outgoing segments.
    segments: Vec<TcpSegment>,

    // --- Timing ---
    /// Timestamp (seconds since epoch) when this TCB was created.
    pub when_created: u64,

    // --- Protocol stream ---
    /// Protocol parser stream for this connection.
    pub stream: Option<std::sync::Arc<ProtocolParserStream>>,

    /// Packet number counter (for diagnostics).
    pub packet_number: u32,
}

impl TcpControlBlock {
    /// Create a new TCB with the given connection parameters.
    fn new(
        ip_me: IpAddress,
        ip_them: IpAddress,
        port_me: u16,
        port_them: u16,
        seqno_me: u32,
        seqno_them: u32,
        ttl: u8,
        stream: Option<std::sync::Arc<ProtocolParserStream>>,
        secs: u32,
        _usecs: u32,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            ip_me,
            ip_them,
            port_me,
            port_them,
            seqno_me,
            seqno_them,
            ackno_me: seqno_them,
            ackno_them: seqno_me,
            seqno_me_first: seqno_me,
            seqno_them_first: seqno_them,
            ttl,
            syns_sent: 0,
            mss: 1400,
            tcp_state: TcpState::SynSent,
            is_ipv6: ip_me.version() == 6,
            is_small_window: false,
            is_their_fin: false,
            is_active: true,
            app_state: AppState::Connect,
            banner1_state: StreamState {
                port: port_them,
                ..Default::default()
            },
            banners: Vec::new(),
            timeout: TcbTimeout::new(),
            segments: Vec::new(),
            when_created: now,
            stream,
            packet_number: 0,
        }
    }

    /// Get the connection key for this TCB.
    pub fn key(&self) -> ConnectionKey {
        ConnectionKey {
            ip_me: self.ip_me,
            ip_them: self.ip_them,
            port_me: self.port_me,
            port_them: self.port_them,
        }
    }

    /// Change the TCP state (with optional debug logging).
    fn change_state(&mut self, new_state: TcpState) {
        if TCP_DEBUG_ENABLED {
            log::trace!(
                "[{}:{}] {{{}}} -> {{{}}}",
                self.ip_them, self.port_them,
                self.tcp_state, new_state
            );
        }
        self.tcp_state = new_state;
    }

    /// Set a timeout for this TCB.
    pub fn set_timeout(&mut self, secs: u32, usecs: u32) {
        let ticks = ticks_from_tv(secs, usecs);
        self.timeout.set(ticks);
    }

    /// Switch from sending to receiving state.
    pub fn switch_to_recv(&mut self) {
        match self.tcp_state {
            TcpState::EstablishedSend => self.change_state(TcpState::EstablishedRecv),
            TcpState::FinWait1Recv => {} // already in recv variant
            TcpState::FinWait1Send => self.change_state(TcpState::FinWait1Recv),
            _ => {}
        }
    }

    /// Queue data for sending.
    pub fn send(&mut self, data: &[u8], flags: SendFlags) {
        if data.is_empty() && flags != SendFlags::CloseFin {
            return;
        }

        let is_fin = flags == SendFlags::CloseFin;
        let mut remaining = data.len();
        let mut offset = 0;
        let mut seqno = self.seqno_me;

        // Advance past existing segments.
        for seg in &self.segments {
            seqno = seg.seqno.wrapping_add(seg.data.len() as u32);
            if seg.is_fin {
                log::warn!("can't send past a FIN");
                return;
            }
        }

        // Split data into MSS-sized segments.
        while remaining > 0 || (offset == 0 && is_fin) {
            let chunk_len = remaining.min(self.mss as usize);
            let is_last = remaining <= self.mss as usize;

            let seg = TcpSegment {
                seqno,
                data: if chunk_len > 0 {
                    data[offset..offset + chunk_len].to_vec()
                } else {
                    Vec::new()
                },
                is_fin: is_last && is_fin,
                flags,
            };

            seqno = seqno.wrapping_add(chunk_len as u32);
            offset += chunk_len;
            remaining -= chunk_len;

            self.segments.push(seg);

            if remaining == 0 && !is_fin {
                break;
            }
            if remaining == 0 && is_fin && is_last {
                break;
            }
        }
    }

    /// Request a close (sends FIN).
    pub fn close(&mut self) {
        self.send(&[], SendFlags::CloseFin);
    }

    /// Set the SSL hello flag.
    pub fn set_ssl_hello(&mut self, value: bool) {
        self.banner1_state.is_sent_sslhello = value;
    }

    /// Set the small window flag.
    pub fn set_small_window(&mut self, value: bool) {
        self.is_small_window = value;
    }

    /// Flush all collected banners (placeholder).
    pub fn banner_flush(&mut self) {
        // In the full implementation, this would report banners via the
        // output callback. For now, just clear them.
        self.banners.clear();
    }

    /// Parse incoming payload for banner information (placeholder).
    pub fn banner_parse(&mut self, payload: &[u8]) {
        // In the full implementation, this delegates to banner1_parse.
        // For now, just store the raw bytes.
        if !payload.is_empty() {
            self.banners.push(BannerOutput {
                protocol: 0,
                banner: payload.to_vec(),
            });
        }
    }

    /// Check whether the remote side has acknowledged our FIN.
    fn they_have_acked_my_fin(&self) -> bool {
        if let Some(seg) = self.segments.first() {
            if seg.is_fin && seg.data.is_empty() {
                return self.ackno_them >= seg.seqno.wrapping_add(1);
            }
        }
        false
    }

    /// Process an ACK for outstanding segments.
    ///
    /// Returns `true` if the ACK was valid and advanced our state.
    fn acknowledge(&mut self, ackno: u32) -> bool {
        // Duplicate ACK (nothing new acknowledged).
        if ackno == self.seqno_me {
            return false;
        }

        // Reject ACKs from the past (wrapping-safe check).
        if ackno.wrapping_sub(self.seqno_me) > 100_000 {
            return false;
        }

        // Reject ACKs from the future.
        if self.seqno_me.wrapping_sub(ackno) < 100_000 {
            return false;
        }

        // Handle FIN acknowledgement specially.
        if let Some(seg) = self.segments.first() {
            if seg.is_fin && seg.data.is_empty() {
                if seg.seqno.wrapping_add(1) == ackno {
                    self.seqno_me = self.seqno_me.wrapping_add(1);
                    self.ackno_them = self.ackno_them.wrapping_add(1);
                    self.segments.remove(0);
                    return true;
                } else if seg.seqno == ackno {
                    return false;
                }
            }
        }

        // Retire fully-acknowledged segments.
        let mut length = ackno.wrapping_sub(self.seqno_me);
        while let Some(seg) = self.segments.first() {
            if seg.is_fin {
                break;
            }
            if length < seg.data.len() as u32 {
                break;
            }
            length -= seg.data.len() as u32;
            self.seqno_me = self.seqno_me.wrapping_add(seg.data.len() as u32);
            self.ackno_them = self.ackno_them.wrapping_add(seg.data.len() as u32);
            self.segments.remove(0);
            if ackno == self.ackno_them {
                return true;
            }
        }

        // Handle partially-acknowledged segment.
        if let Some(seg) = self.segments.first_mut() {
            if length > 0 && length < seg.data.len() as u32 {
                let length = length as usize;
                self.seqno_me = self.seqno_me.wrapping_add(length as u32);
                self.ackno_them = self.ackno_them.wrapping_add(length as u32);
                seg.data = seg.data[length..].to_vec();
                seg.flags = SendFlags::Copy;
            }
        }

        true
    }
}

// ---------------------------------------------------------------------------
// TCP Connection Table
// ---------------------------------------------------------------------------

/// Whether TCP debug logging is enabled.
static TCP_DEBUG_ENABLED: bool = false;

/// Ticks per second for timeout calculations.
const TICKS_PER_SECOND: u64 = 16_777_216; // 2^24

/// Convert seconds + microseconds to a tick count.
fn ticks_from_tv(secs: u32, usecs: u32) -> u64 {
    (secs as u64) * TICKS_PER_SECOND + (usecs as u64) * TICKS_PER_SECOND / 1_000_000
}

/// Convert seconds to a tick count.
fn ticks_from_secs(secs: u64) -> u64 {
    secs * TICKS_PER_SECOND
}

/// Compute a hash for a connection key.
///
/// Uses a symmetric hash so that incoming and outgoing packets for the
/// same connection hash to the same bucket.
fn tcb_hash(ip_me: IpAddress, port_me: u16, ip_them: IpAddress, port_them: u16, entropy: u64) -> u64 {
    match (ip_me, ip_them) {
        (IpAddress::V4(v4_me), IpAddress::V4(v4_them)) => {
            let ip_xor = v4_me ^ v4_them;
            let port_xor = (port_me as u64) ^ (port_them as u64);
            // Simple hash combining XOR and entropy.
            let h = (ip_xor as u64).wrapping_mul(0x9E3779B97F4A7C15)
                ^ port_xor.wrapping_mul(0x517CC1B727220A95)
                ^ entropy;
            h
        }
        (IpAddress::V6(v6_me), IpAddress::V6(v6_them)) => {
            let hi_xor = v6_me.hi ^ v6_them.hi;
            let lo_xor = v6_me.lo ^ v6_them.lo;
            let port_xor = (port_me as u64) ^ (port_them as u64);
            let h = hi_xor.wrapping_mul(0x9E3779B97F4A7C15)
                ^ lo_xor.wrapping_mul(0x517CC1B727220A95)
                ^ port_xor.wrapping_mul(0xBF58476D1CE4E5B9)
                ^ entropy;
            h
        }
        _ => {
            // Mixed IPv4/IPv6 shouldn't happen, but hash anyway.
            0
        }
    }
}

/// Reason a TCB was destroyed.
#[derive(Debug, Clone, Copy)]
enum DestroyReason {
    Timeout,
    Fin,
    Rst,
    Shutdown,
    StateDone,
}

/// Callback type for reporting banners.
pub type ReportBannerFn = Box<dyn Fn(&IpAddress, u16, u32, u8, &[u8]) + Send + Sync>;

/// The TCP connection table.
///
/// Stores all active TCP Control Blocks, indexed by a symmetric hash
/// of the connection 4-tuple (ip_me, port_me, ip_them, port_them).
///
/// Connections are looked up when incoming packets arrive and created
/// when we receive a SYN-ACK (confirming our SYN-cookie).
pub struct TcpConnectionTable {
    /// Hash map of active connections, keyed by connection key.
    entries: HashMap<ConnectionKey, Box<TcpControlBlock>>,

    /// Maximum number of connections before we start rejecting new ones.
    capacity: usize,

    /// Connection timeout in seconds.
    pub timeout_connection: u32,

    /// Hello timeout in seconds (time to wait for server banner).
    pub timeout_hello: u32,

    /// Current number of active connections.
    pub active_count: u64,

    /// Entropy seed for SYN-cookie generation and hashing.
    pub entropy: u64,

    /// Reference to the network stack (packet buffers, transmit queue).
    pub stack: std::sync::Arc<Stack>,

    /// Banner parsing configuration.
    pub banner1: Banner1,

    /// Callback for reporting discovered banners.
    pub report_banner: Option<ReportBannerFn>,

    /// Protocol parser streams indexed by port number.
    pub payloads: Vec<Option<std::sync::Arc<ProtocolParserStream>>>,

    /// Template packet for formatting responses.
    /// (Opaque handle to the templ-pkt module.)
    pub pkt_template: Option<Box<dyn std::any::Any + Send + Sync>>,

    /// Timeout tracking: maps tick timestamps to lists of connection keys.
    timeout_queue: Vec<(u64, ConnectionKey)>,
}

impl TcpConnectionTable {
    /// Maximum hash table size (16 million entries).
    const MAX_ENTRIES: usize = 1 << 24;
    /// Minimum hash table size.
    const MIN_ENTRIES: usize = 1 << 10;

    /// Create a new TCP connection table.
    ///
    /// `entry_count` is a hint for the expected number of concurrent
    /// connections (rounded up to a power of 2, clamped to [1024, 16M]).
    pub fn new(
        entry_count: usize,
        stack: std::sync::Arc<Stack>,
        connection_timeout: u32,
        entropy: u64,
    ) -> Self {
        // Round up to power of 2.
        let mut size = 1usize;
        while size < entry_count {
            size = size.checked_mul(2).unwrap_or(Self::MAX_ENTRIES);
        }
        size = size.min(Self::MAX_ENTRIES).max(Self::MIN_ENTRIES);

        let timeout = if connection_timeout == 0 { 30 } else { connection_timeout };

        Self {
            entries: HashMap::with_capacity(size),
            capacity: size,
            timeout_connection: timeout,
            timeout_hello: 2,
            active_count: 0,
            entropy,
            stack,
            banner1: Banner1::default(),
            report_banner: None,
            payloads: vec![None; 65536],
            pkt_template: None,
            timeout_queue: Vec::new(),
        }
    }

    /// Set banner capture flags.
    pub fn set_banner_flags(
        &mut self,
        is_capture_cert: bool,
        is_capture_servername: bool,
        is_capture_html: bool,
        is_capture_heartbleed: bool,
        is_capture_ticketbleed: bool,
    ) {
        self.banner1.is_capture_cert = is_capture_cert;
        self.banner1.is_capture_servername = is_capture_servername;
        self.banner1.is_capture_html = is_capture_html;
        self.banner1.is_capture_heartbleed = is_capture_heartbleed;
        self.banner1.is_capture_ticketbleed = is_capture_ticketbleed;
    }

    /// Look up a TCB by connection 4-tuple.
    pub fn lookup_tcb(
        &self,
        ip_me: IpAddress,
        ip_them: IpAddress,
        port_me: u16,
        port_them: u16,
    ) -> Option<&TcpControlBlock> {
        let key = ConnectionKey { ip_me, ip_them, port_me, port_them };
        self.entries.get(&key).map(|b| b.as_ref())
    }

    /// Look up a TCB mutably by connection 4-tuple.
    pub fn lookup_tcb_mut(
        &mut self,
        ip_me: IpAddress,
        ip_them: IpAddress,
        port_me: u16,
        port_them: u16,
    ) -> Option<&mut TcpControlBlock> {
        let key = ConnectionKey { ip_me, ip_them, port_me, port_them };
        self.entries.get_mut(&key).map(|b| b.as_mut())
    }

    /// Create a new TCB (or return existing one if already present).
    ///
    /// Called when we receive a SYN-ACK confirming our SYN-cookie, or
    /// when initiating a new outbound connection.
    pub fn create_tcb(
        &mut self,
        ip_me: IpAddress,
        ip_them: IpAddress,
        port_me: u16,
        port_them: u16,
        seqno_me: u32,
        seqno_them: u32,
        ttl: u8,
        stream: Option<std::sync::Arc<ProtocolParserStream>>,
        secs: u32,
        usecs: u32,
    ) -> Option<&mut TcpControlBlock> {
        let key = ConnectionKey { ip_me, ip_them, port_me, port_them };

        // If already exists, return the existing one.
        if self.entries.contains_key(&key) {
            return self.entries.get_mut(&key).map(|b| b.as_mut());
        }

        // Enforce capacity.
        if self.entries.len() >= self.capacity {
            log::warn!("TCB table full, rejecting new connection");
            return None;
        }

        // If no stream specified, look up by port.
        let stream = stream.or_else(|| {
            self.payloads.get(port_them as usize)
                .and_then(|s| s.clone())
        });

        let mut tcb = TcpControlBlock::new(
            ip_me, ip_them, port_me, port_them,
            seqno_me, seqno_them, ttl, stream, secs, usecs,
        );

        // Set initial timeout.
        tcb.set_timeout(secs + 1, usecs);

        self.active_count += 1;
        self.entries.insert(key, Box::new(tcb));
        self.entries.get_mut(&key).map(|b| b.as_mut())
    }

    /// Destroy a TCB, flushing banners and removing from the table.
    fn destroy_tcb(&mut self, key: ConnectionKey, _reason: DestroyReason) {
        if let Some(mut tcb) = self.entries.remove(&key) {
            // Flush any remaining banners.
            tcb.banner_flush();

            // Mark as inactive.
            tcb.is_active = false;
            tcb.timeout.unlink();

            self.active_count = self.active_count.saturating_sub(1);
        }
    }

    /// Send an RST packet for a connection.
    pub fn send_rst(
        &self,
        ip_me: IpAddress,
        ip_them: IpAddress,
        port_me: u16,
        port_them: u16,
        seqno_them: u32,
        ackno_them: u32,
    ) {
        // Create a temporary TCB just for sending the RST.
        let mut tcb = TcpControlBlock::new(
            ip_me, ip_them, port_me, port_them,
            ackno_them, seqno_them.wrapping_add(1),
            0, None, 0, 0,
        );
        tcb.ackno_me = seqno_them.wrapping_add(1);
        tcb.seqno_them = seqno_them.wrapping_add(1);
        tcb.ackno_them = ackno_them;

        Self::send_packet_for_tcb(&self.stack, &tcb, 0x04 /* RST */, &[]);
    }

    /// Send a TCP packet for a given TCB.
    ///
    /// Formats the packet using the template, optionally applies the
    /// small-window kludge, and queues it for transmission.
    fn send_packet_for_tcb(
        stack: &Stack,
        tcb: &TcpControlBlock,
        tcp_flags: u8,
        payload: &[u8],
    ) {
        let is_syn = tcp_flags == 0x02;

        // Log ACK sends.
        if TCP_DEBUG_ENABLED && (tcp_flags & 0x10) != 0 {
            log::trace!(
                "xmit ACK ackingthem={}",
                tcb.seqno_them.wrapping_sub(tcb.seqno_them_first)
            );
        }

        // Get a packet buffer.
        let mut response = match stack.get_packet_buffer() {
            Some(buf) => buf,
            None => {
                log::error!("packet buffers exhausted");
                return;
            }
        };

        // Format the packet.
        // In the full implementation, this delegates to tcp_create_packet
        // using the template. For now, we format a minimal TCP packet.
        let seqno = if is_syn {
            tcb.seqno_me.wrapping_sub(1)
        } else {
            tcb.seqno_me
        };

        response.length = format_tcp_packet(
            tcb.ip_them, tcb.port_them,
            tcb.ip_me, tcb.port_me,
            seqno, tcb.seqno_them,
            tcp_flags,
            payload,
            &mut response.px,
        );

        // Apply small-window kludge if needed.
        if tcb.is_small_window && response.length >= 16 {
            // Set TCP window to 600.
            response.px[14 + 14] = (600 >> 8) as u8;
            response.px[14 + 15] = (600 & 0xFF) as u8;
        }

        stack.transmit_packet_buffer(response);
    }

    /// Process all timeout events up to the given timestamp.
    pub fn process_timeouts(&mut self, secs: u32, usecs: u32) {
        let timestamp = ticks_from_tv(secs, usecs);

        // Collect timed-out keys first (can't borrow self mutably while iterating).
        let mut timed_out: Vec<ConnectionKey> = Vec::new();

        for (expires, key) in &self.timeout_queue {
            if *expires <= timestamp {
                timed_out.push(*key);
            }
        }
        self.timeout_queue.retain(|(expires, _)| *expires > timestamp);

        for key in timed_out {
            let result = self.process_event(
                key,
                TcpWhat::Timeout,
                &[],
                secs,
                usecs,
                0,
                0,
            );

            // Safety net: if TCB still alive but has no timeout, add one.
            if result != TcbResult::Destroyed {
                if let Some(tcb) = self.entries.get_mut(&key) {
                    if tcb.timeout.is_unlinked() {
                        tcb.set_timeout(secs + 2, usecs);
                    }
                }
            }
        }
    }

    /// Process an incoming TCP event on a specific connection.
    ///
    /// This is the heart of the TCP state machine. It handles timeouts,
    /// incoming packets (SYN-ACK, ACK, DATA, FIN, RST), and application
    /// close requests.
    pub fn process_event(
        &mut self,
        key: ConnectionKey,
        what: TcpWhat,
        payload: &[u8],
        secs: u32,
        usecs: u32,
        seqno_them: u32,
        ackno_them: u32,
    ) -> TcbResult {
        // Filter: reject out-of-order payloads.
        let (filtered_payload, filtered_seqno) = if !payload.is_empty() {
            let tcb = match self.entries.get(&key) {
                Some(t) => t,
                None => return TcbResult::Destroyed,
            };

            let payload_offset = seqno_them.wrapping_sub(tcb.seqno_them) as i32;
            if payload_offset < 0 {
                let offset = (-payload_offset) as usize;
                if offset >= payload.len() {
                    // Entirely old data, discard.
                    return TcbResult::Okay;
                }
                (&payload[offset..], seqno_them.wrapping_add(offset as u32))
            } else if payload_offset > 0 {
                // Out-of-order future fragment, discard.
                return TcbResult::Okay;
            } else {
                (payload, seqno_them)
            }
        } else {
            (payload, seqno_them)
        };

        // Filter: reject out-of-order / duplicate FINs.
        if what == TcpWhat::Fin {
            let tcb = match self.entries.get(&key) {
                Some(t) => t,
                None => return TcbResult::Destroyed,
            };
            if seqno_them == tcb.seqno_them.wrapping_sub(1) {
                // Duplicate FIN — re-ACK it.
                self.send_ack(&key);
                return TcbResult::Okay;
            } else if seqno_them != tcb.seqno_them {
                // Out-of-order FIN — drop.
                return TcbResult::Okay;
            }
        }

        // Get mutable access to the TCB.
        let tcb = match self.entries.get_mut(&key) {
            Some(t) => t,
            None => return TcbResult::Destroyed,
        };

        // Connection timeout check.
        if what == TcpWhat::Timeout {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if tcb.when_created + self.timeout_connection as u64 <= now {
                Self::send_packet_for_tcb(&self.stack, tcb, 0x04 /* RST */, &[]);
                self.destroy_tcb(key, DestroyReason::Timeout);
                return TcbResult::Destroyed;
            }
        }

        // RST always destroys.
        if what == TcpWhat::Rst {
            self.destroy_tcb(key, DestroyReason::Rst);
            return TcbResult::Destroyed;
        }

        // Dispatch based on current TCP state.
        let current_state = tcb.tcp_state;
        match current_state {
            TcpState::SynSent => {
                self.handle_syn_sent(key, what, filtered_payload, secs, usecs, filtered_seqno, ackno_them)
            }
            TcpState::EstablishedSend => {
                self.handle_established_send(key, what, filtered_payload, secs, usecs, filtered_seqno, ackno_them)
            }
            TcpState::EstablishedRecv => {
                self.handle_established_recv(key, what, filtered_payload, secs, usecs, filtered_seqno, ackno_them)
            }
            TcpState::FinWait1Send => {
                self.handle_fin_wait1_send(key, what, filtered_payload, secs, usecs, filtered_seqno, ackno_them)
            }
            TcpState::FinWait1Recv => {
                self.handle_fin_wait1_recv(key, what, filtered_payload, secs, usecs, filtered_seqno, ackno_them)
            }
            TcpState::Closing => {
                self.handle_closing(key, what, secs, usecs, ackno_them)
            }
            TcpState::FinWait2 | TcpState::TimeWait => {
                self.handle_fin_wait2_or_time_wait(key, what, filtered_payload, secs, usecs, filtered_seqno, ackno_them)
            }
            TcpState::CloseWait => {
                self.handle_close_wait(key, what, secs, usecs)
            }
            TcpState::LastAck => {
                self.handle_last_ack(key, what, secs, usecs, ackno_them)
            }
        }
    }

    // --- State handlers ---

    fn handle_syn_sent(
        &mut self,
        key: ConnectionKey,
        what: TcpWhat,
        _payload: &[u8],
        secs: u32,
        usecs: u32,
        seqno_them: u32,
        ackno_them: u32,
    ) -> TcbResult {
        match what {
            TcpWhat::Timeout => {
                if let Some(tcb) = self.entries.get_mut(&key) {
                    tcb.syns_sent += 1;
                    Self::send_packet_for_tcb(&self.stack, tcb, 0x02 /* SYN */, &[]);
                }
                TcbResult::Okay
            }
            TcpWhat::SynAck => {
                if let Some(tcb) = self.entries.get_mut(&key) {
                    tcb.seqno_them = seqno_them;
                    tcb.seqno_them_first = seqno_them.wrapping_sub(1);
                    tcb.seqno_me = ackno_them;
                    tcb.seqno_me_first = ackno_them.wrapping_sub(1);

                    Self::send_packet_for_tcb(&self.stack, tcb, 0x10 /* ACK */, &[]);
                    tcb.change_state(TcpState::EstablishedRecv);

                    // Notify application of connection.
                    tcb.app_state = AppState::ReceiveHello;
                }
                TcbResult::Okay
            }
            _ => {
                log::trace!("SYN_SENT: unhandled event {}", what);
                TcbResult::Okay
            }
        }
    }

    fn handle_established_send(
        &mut self,
        key: ConnectionKey,
        what: TcpWhat,
        payload: &[u8],
        secs: u32,
        usecs: u32,
        seqno_them: u32,
        ackno_them: u32,
    ) -> TcbResult {
        match what {
            TcpWhat::Close => {
                if let Some(tcb) = self.entries.get_mut(&key) {
                    tcb.send(&[], SendFlags::CloseFin);
                    tcb.change_state(TcpState::FinWait1Send);
                }
                TcbResult::Okay
            }
            TcpWhat::Fin => {
                if let Some(tcb) = self.entries.get_mut(&key) {
                    if seqno_them == tcb.seqno_them {
                        tcb.seqno_them = tcb.seqno_them.wrapping_add(1);
                        tcb.ackno_me = tcb.ackno_me.wrapping_add(1);
                        tcb.is_their_fin = true;
                        tcb.change_state(TcpState::FinWait1Send);
                        Self::send_packet_for_tcb(&self.stack, tcb, 0x10 /* ACK */, &[]);
                    } else {
                        Self::send_packet_for_tcb(&self.stack, tcb, 0x10, &[]);
                    }
                }
                TcbResult::Okay
            }
            TcpWhat::Ack => {
                let all_sent;
                if let Some(tcb) = self.entries.get_mut(&key) {
                    tcb.acknowledge(ackno_them);

                    // Check if all data has been sent.
                    all_sent = tcb.segments.is_empty()
                        || tcb.segments.first().map(|s| s.data.is_empty()).unwrap_or(false);

                    if all_sent {
                        tcb.change_state(TcpState::EstablishedRecv);
                        tcb.app_state = AppState::ReceiveNext;
                    }
                }
                TcbResult::Okay
            }
            TcpWhat::Timeout => {
                // Resend the last segment.
                if let Some(tcb) = self.entries.get_mut(&key) {
                    if let Some(seg) = tcb.segments.first() {
                        let data = seg.data.clone();
                        let is_fin = seg.is_fin;
                        let flags = if is_fin { 0x11 } else { 0x18 };
                        Self::send_packet_for_tcb(&self.stack, tcb, flags, &data);
                    }
                }
                TcbResult::Okay
            }
            TcpWhat::Data => {
                // Don't receive data while in send state.
                TcbResult::Okay
            }
            _ => {
                log::trace!("ESTABLISHED_SEND: unhandled event {}", what);
                TcbResult::Okay
            }
        }
    }

    fn handle_established_recv(
        &mut self,
        key: ConnectionKey,
        what: TcpWhat,
        payload: &[u8],
        secs: u32,
        usecs: u32,
        seqno_them: u32,
        ackno_them: u32,
    ) -> TcbResult {
        match what {
            TcpWhat::Close => {
                if let Some(tcb) = self.entries.get_mut(&key) {
                    tcb.send(&[], SendFlags::CloseFin);
                    tcb.change_state(TcpState::FinWait1Recv);
                }
                TcbResult::Okay
            }
            TcpWhat::Fin => {
                if let Some(tcb) = self.entries.get_mut(&key) {
                    if seqno_them == tcb.seqno_them {
                        tcb.seqno_them = tcb.seqno_them.wrapping_add(1);
                        tcb.ackno_me = tcb.ackno_me.wrapping_add(1);
                        tcb.is_their_fin = true;
                        tcb.change_state(TcpState::CloseWait);
                        tcb.app_state = AppState::Close;
                    } else {
                        Self::send_packet_for_tcb(&self.stack, tcb, 0x10, &[]);
                    }
                }
                TcbResult::Okay
            }
            TcpWhat::Ack => {
                if let Some(tcb) = self.entries.get_mut(&key) {
                    tcb.acknowledge(ackno_them);
                }
                TcbResult::Okay
            }
            TcpWhat::Timeout => {
                if let Some(tcb) = self.entries.get_mut(&key) {
                    tcb.app_state = AppState::ReceiveHello;
                }
                TcbResult::Okay
            }
            TcpWhat::Data => {
                if let Some(tcb) = self.entries.get_mut(&key) {
                    let len = payload.len();
                    if len > 0 {
                        tcb.seqno_them = tcb.seqno_them.wrapping_add(len as u32);
                        tcb.ackno_me = tcb.ackno_me.wrapping_add(len as u32);
                        tcb.banner_parse(payload);
                        Self::send_packet_for_tcb(&self.stack, tcb, 0x10 /* ACK */, &[]);
                    }
                }
                TcbResult::Okay
            }
            TcpWhat::SynAck => {
                // Delayed SYN-ACK; ignore silently.
                TcbResult::Okay
            }
            _ => {
                log::trace!("ESTABLISHED_RECV: unhandled event {}", what);
                TcbResult::Okay
            }
        }
    }

    fn handle_fin_wait1_send(
        &mut self,
        key: ConnectionKey,
        what: TcpWhat,
        _payload: &[u8],
        secs: u32,
        usecs: u32,
        seqno_them: u32,
        ackno_them: u32,
    ) -> TcbResult {
        match what {
            TcpWhat::Fin => {
                // Ignore FIN while still sending.
                TcbResult::Okay
            }
            TcpWhat::Ack => {
                let transition;
                if let Some(tcb) = self.entries.get_mut(&key) {
                    tcb.acknowledge(ackno_them);
                    transition = tcb.segments.is_empty()
                        || tcb.segments.first().map(|s| s.data.is_empty()).unwrap_or(false);
                    if transition {
                        tcb.change_state(TcpState::FinWait1Recv);
                        tcb.app_state = AppState::ReceiveNext;
                    }
                }
                TcbResult::Okay
            }
            TcpWhat::Timeout => {
                if let Some(tcb) = self.entries.get_mut(&key) {
                    if let Some(seg) = tcb.segments.first() {
                        let data = seg.data.clone();
                        let is_fin = seg.is_fin;
                        let flags = if is_fin { 0x11 } else { 0x18 };
                        Self::send_packet_for_tcb(&self.stack, tcb, flags, &data);
                    }
                }
                TcbResult::Okay
            }
            _ => TcbResult::Okay,
        }
    }

    fn handle_fin_wait1_recv(
        &mut self,
        key: ConnectionKey,
        what: TcpWhat,
        payload: &[u8],
        secs: u32,
        usecs: u32,
        seqno_them: u32,
        ackno_them: u32,
    ) -> TcbResult {
        match what {
            TcpWhat::Fin => {
                if let Some(tcb) = self.entries.get_mut(&key) {
                    tcb.seqno_them = tcb.seqno_them.wrapping_add(1);
                    tcb.ackno_me = tcb.ackno_me.wrapping_add(1);
                    tcb.is_their_fin = true;
                    tcb.change_state(TcpState::Closing);
                    Self::send_packet_for_tcb(&self.stack, tcb, 0x10, &[]);
                    tcb.app_state = AppState::Close;
                }
                TcbResult::Okay
            }
            TcpWhat::Ack => {
                if let Some(tcb) = self.entries.get_mut(&key) {
                    tcb.acknowledge(ackno_them);
                    if tcb.they_have_acked_my_fin() {
                        tcb.change_state(TcpState::FinWait2);
                        tcb.app_state = AppState::Close;
                    }
                }
                TcbResult::Okay
            }
            TcpWhat::Timeout => {
                if let Some(tcb) = self.entries.get_mut(&key) {
                    if let Some(seg) = tcb.segments.first() {
                        let data = seg.data.clone();
                        let is_fin = seg.is_fin;
                        let flags = if is_fin { 0x11 } else { 0x18 };
                        Self::send_packet_for_tcb(&self.stack, tcb, flags, &data);
                    }
                }
                TcbResult::Okay
            }
            TcpWhat::Data => {
                if let Some(tcb) = self.entries.get_mut(&key) {
                    let len = payload.len();
                    if len > 0 {
                        tcb.seqno_them = tcb.seqno_them.wrapping_add(len as u32);
                        tcb.ackno_me = tcb.ackno_me.wrapping_add(len as u32);
                        tcb.banner_parse(payload);
                        Self::send_packet_for_tcb(&self.stack, tcb, 0x10, &[]);
                    }
                }
                TcbResult::Okay
            }
            _ => TcbResult::Okay,
        }
    }

    fn handle_closing(
        &mut self,
        key: ConnectionKey,
        what: TcpWhat,
        secs: u32,
        usecs: u32,
        ackno_them: u32,
    ) -> TcbResult {
        match what {
            TcpWhat::Timeout => {
                self.destroy_tcb(key, DestroyReason::Timeout);
                TcbResult::Destroyed
            }
            TcpWhat::Ack => {
                let mut destroyed = false;
                if let Some(tcb) = self.entries.get_mut(&key) {
                    tcb.acknowledge(ackno_them);
                    destroyed = tcb.they_have_acked_my_fin();
                }
                if destroyed {
                    self.destroy_tcb(key, DestroyReason::Fin);
                    return TcbResult::Destroyed;
                }
                TcbResult::Okay
            }
            TcpWhat::Fin => {
                // Re-ACK their FIN.
                self.send_ack(&key);
                TcbResult::Okay
            }
            _ => TcbResult::Okay,
        }
    }

    fn handle_fin_wait2_or_time_wait(
        &mut self,
        key: ConnectionKey,
        what: TcpWhat,
        _payload: &[u8],
        secs: u32,
        usecs: u32,
        seqno_them: u32,
        ackno_them: u32,
    ) -> TcbResult {
        let is_time_wait;
        if let Some(tcb) = self.entries.get(&key) {
            is_time_wait = tcb.tcp_state == TcpState::TimeWait;
        } else {
            return TcbResult::Destroyed;
        }

        match what {
            TcpWhat::Timeout => {
                if is_time_wait {
                    self.destroy_tcb(key, DestroyReason::Timeout);
                    return TcbResult::Destroyed;
                }
                TcbResult::Okay
            }
            TcpWhat::Fin => {
                if let Some(tcb) = self.entries.get_mut(&key) {
                    tcb.seqno_them = tcb.seqno_them.wrapping_add(1);
                    tcb.ackno_me = tcb.ackno_me.wrapping_add(1);
                    tcb.change_state(TcpState::TimeWait);
                    tcb.set_timeout(secs + 5, usecs);
                    Self::send_packet_for_tcb(&self.stack, tcb, 0x10, &[]);
                }
                TcbResult::Okay
            }
            _ => TcbResult::Okay,
        }
    }

    fn handle_close_wait(
        &mut self,
        key: ConnectionKey,
        what: TcpWhat,
        secs: u32,
        usecs: u32,
    ) -> TcbResult {
        match what {
            TcpWhat::Close => {
                if let Some(tcb) = self.entries.get_mut(&key) {
                    tcb.send(&[], SendFlags::CloseFin);
                    tcb.change_state(TcpState::LastAck);
                }
                TcbResult::Okay
            }
            TcpWhat::Timeout => {
                // Remind the app we're waiting for close.
                if let Some(tcb) = self.entries.get_mut(&key) {
                    tcb.app_state = AppState::Close;
                }
                TcbResult::Okay
            }
            _ => TcbResult::Okay,
        }
    }

    fn handle_last_ack(
        &mut self,
        key: ConnectionKey,
        what: TcpWhat,
        secs: u32,
        usecs: u32,
        ackno_them: u32,
    ) -> TcbResult {
        match what {
            TcpWhat::Timeout => {
                // Resend.
                if let Some(tcb) = self.entries.get_mut(&key) {
                    if let Some(seg) = tcb.segments.first() {
                        let data = seg.data.clone();
                        let is_fin = seg.is_fin;
                        let flags = if is_fin { 0x11 } else { 0x18 };
                        Self::send_packet_for_tcb(&self.stack, tcb, flags, &data);
                    }
                }
                TcbResult::Okay
            }
            TcpWhat::Ack => {
                let destroy;
                if let Some(tcb) = self.entries.get_mut(&key) {
                    destroy = tcb.acknowledge(ackno_them);
                } else {
                    destroy = false;
                }
                if destroy {
                    self.destroy_tcb(key, DestroyReason::Shutdown);
                    return TcbResult::Destroyed;
                }
                TcbResult::Okay
            }
            _ => TcbResult::Okay,
        }
    }

    // --- Helper methods ---

    /// Send a bare ACK for a connection.
    fn send_ack(&self, key: &ConnectionKey) {
        if let Some(tcb) = self.entries.get(key) {
            Self::send_packet_for_tcb(&self.stack, tcb, 0x10 /* ACK */, &[]);
        }
    }

    /// Gracefully destroy all connections (called at shutdown).
    ///
    /// Flushes all remaining banners before freeing the table.
    pub fn destroy_all(&mut self) {
        let keys: Vec<ConnectionKey> = self.entries.keys().copied().collect();
        for key in keys {
            self.destroy_tcb(key, DestroyReason::Shutdown);
        }
    }

    /// Set a configuration parameter by name.
    pub fn set_parameter(&mut self, name: &str, value: &str) {
        let name_lower = name.to_lowercase().replace('-', "").replace('_', "");
        match name_lower.as_str() {
            "timeout" | "connectiontimeout" => {
                if let Ok(n) = value.parse::<u32>() {
                    self.timeout_connection = n;
                    log::info!("TCP connection-timeout = {}", n);
                }
            }
            "hellotimeout" => {
                if let Ok(n) = value.parse::<u32>() {
                    self.timeout_hello = n;
                    log::info!("TCP hello-timeout = {}", n);
                }
            }
            "heartbleed" => {
                self.banner1.is_heartbleed = true;
            }
            "ticketbleed" => {
                self.banner1.is_ticketbleed = true;
            }
            _ => {
                log::debug!("tcpcon: unknown parameter '{}'", name);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Packet formatting (simplified; full version in templ-pkt module)
// ---------------------------------------------------------------------------

/// Format a TCP packet into the given buffer.
///
/// Returns the number of bytes written. This is a simplified version;
/// the full implementation uses template packets for efficiency.
fn format_tcp_packet(
    ip_them: IpAddress,
    port_them: u16,
    ip_me: IpAddress,
    port_me: u16,
    seqno_me: u32,
    seqno_them: u32,
    tcp_flags: u8,
    payload: &[u8],
    px: &mut [u8],
) -> usize {
    match (ip_them, ip_me) {
        (IpAddress::V4(dst), IpAddress::V4(src)) => {
            format_ipv4_tcp_packet(
                dst, port_them, src, port_me,
                seqno_me, seqno_them, tcp_flags, payload, px,
            )
        }
        (IpAddress::V6(dst), IpAddress::V6(src)) => {
            format_ipv6_tcp_packet(
                dst, port_them, src, port_me,
                seqno_me, seqno_them, tcp_flags, payload, px,
            )
        }
        _ => 0,
    }
}

/// Format an IPv4/TCP packet.
fn format_ipv4_tcp_packet(
    dst_ip: u32,
    dst_port: u16,
    src_ip: u32,
    src_port: u16,
    seqno: u32,
    ackno: u32,
    tcp_flags: u8,
    payload: &[u8],
    px: &mut [u8],
) -> usize {
    let tcp_header_len: usize = 20;
    let ip_header_len: usize = 20;
    let eth_header_len: usize = 14;
    let tcp_len = tcp_header_len + payload.len();
    let ip_len = ip_header_len + tcp_len;
    let total = eth_header_len + ip_len;

    if total > px.len() {
        return 0;
    }

    // Ethernet header (placeholder MACs - filled by template).
    px[0..6].copy_from_slice(&[0; 6]); // dst MAC
    px[6..12].copy_from_slice(&[0; 6]); // src MAC
    px[12] = 0x08; px[13] = 0x00; // EtherType = IPv4

    // IPv4 header.
    let ip = eth_header_len;
    px[ip] = 0x45; // version=4, ihl=5
    px[ip + 1] = 0; // DSCP/ECN
    px[ip + 2] = (ip_len >> 8) as u8;
    px[ip + 3] = (ip_len & 0xFF) as u8;
    px[ip + 4] = 0; px[ip + 5] = 0; // ID
    px[ip + 6] = 0x40; px[ip + 7] = 0; // flags=DF
    px[ip + 8] = 64; // TTL
    px[ip + 9] = 6; // protocol = TCP
    px[ip + 10] = 0; px[ip + 11] = 0; // checksum (filled later)
    px[ip + 12] = (src_ip >> 24) as u8;
    px[ip + 13] = (src_ip >> 16) as u8;
    px[ip + 14] = (src_ip >> 8) as u8;
    px[ip + 15] = (src_ip) as u8;
    px[ip + 16] = (dst_ip >> 24) as u8;
    px[ip + 17] = (dst_ip >> 16) as u8;
    px[ip + 18] = (dst_ip >> 8) as u8;
    px[ip + 19] = (dst_ip) as u8;

    // IPv4 header checksum.
    let mut sum: u32 = 0;
    for i in (0..20).step_by(2) {
        sum += ((px[ip + i] as u32) << 8) | (px[ip + i + 1] as u32);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let xsum = !(sum as u16);
    px[ip + 10] = (xsum >> 8) as u8;
    px[ip + 11] = (xsum & 0xFF) as u8;

    // TCP header.
    let tcp = eth_header_len + ip_header_len;
    px[tcp] = (src_port >> 8) as u8;
    px[tcp + 1] = (src_port & 0xFF) as u8;
    px[tcp + 2] = (dst_port >> 8) as u8;
    px[tcp + 3] = (dst_port & 0xFF) as u8;
    px[tcp + 4] = (seqno >> 24) as u8;
    px[tcp + 5] = (seqno >> 16) as u8;
    px[tcp + 6] = (seqno >> 8) as u8;
    px[tcp + 7] = (seqno) as u8;
    px[tcp + 8] = (ackno >> 24) as u8;
    px[tcp + 9] = (ackno >> 16) as u8;
    px[tcp + 10] = (ackno >> 8) as u8;
    px[tcp + 11] = (ackno) as u8;
    px[tcp + 12] = 0x50; // data offset = 5 (20 bytes)
    px[tcp + 13] = tcp_flags;
    px[tcp + 14] = 0x40; px[tcp + 15] = 0x00; // window = 16384
    px[tcp + 16] = 0; px[tcp + 17] = 0; // checksum (placeholder)
    px[tcp + 18] = 0; px[tcp + 19] = 0; // urgent pointer

    // Payload.
    if !payload.is_empty() {
        px[tcp + 20..tcp + 20 + payload.len()].copy_from_slice(payload);
    }

    total
}

/// Format an IPv6/TCP packet.
fn format_ipv6_tcp_packet(
    dst_ip: Ipv6Address,
    dst_port: u16,
    src_ip: Ipv6Address,
    src_port: u16,
    seqno: u32,
    ackno: u32,
    tcp_flags: u8,
    payload: &[u8],
    px: &mut [u8],
) -> usize {
    let tcp_header_len: usize = 20;
    let ipv6_header_len: usize = 40;
    let eth_header_len: usize = 14;
    let tcp_len = tcp_header_len + payload.len();
    let total = eth_header_len + ipv6_header_len + tcp_len;

    if total > px.len() {
        return 0;
    }

    // Ethernet header.
    px[0..6].copy_from_slice(&[0; 6]); // dst MAC
    px[6..12].copy_from_slice(&[0; 6]); // src MAC
    px[12] = 0x86; px[13] = 0xDD; // EtherType = IPv6

    // IPv6 header.
    let ip = eth_header_len;
    px[ip] = 0x60; // version = 6
    px[ip + 1] = 0; px[ip + 2] = 0; px[ip + 3] = 0; // traffic class + flow label
    px[ip + 4] = (tcp_len >> 8) as u8;
    px[ip + 5] = (tcp_len & 0xFF) as u8;
    px[ip + 6] = 6; // next header = TCP
    px[ip + 7] = 64; // hop limit

    let src_bytes = src_ip.to_bytes();
    px[ip + 8..ip + 24].copy_from_slice(&src_bytes);
    let dst_bytes = dst_ip.to_bytes();
    px[ip + 24..ip + 40].copy_from_slice(&dst_bytes);

    // TCP header.
    let tcp = eth_header_len + ipv6_header_len;
    px[tcp] = (src_port >> 8) as u8;
    px[tcp + 1] = (src_port & 0xFF) as u8;
    px[tcp + 2] = (dst_port >> 8) as u8;
    px[tcp + 3] = (dst_port & 0xFF) as u8;
    px[tcp + 4] = (seqno >> 24) as u8;
    px[tcp + 5] = (seqno >> 16) as u8;
    px[tcp + 6] = (seqno >> 8) as u8;
    px[tcp + 7] = (seqno) as u8;
    px[tcp + 8] = (ackno >> 24) as u8;
    px[tcp + 9] = (ackno >> 16) as u8;
    px[tcp + 10] = (ackno >> 8) as u8;
    px[tcp + 11] = (ackno) as u8;
    px[tcp + 12] = 0x50;
    px[tcp + 13] = tcp_flags;
    px[tcp + 14] = 0x40; px[tcp + 15] = 0x00;
    px[tcp + 16] = 0; px[tcp + 17] = 0;
    px[tcp + 18] = 0; px[tcp + 19] = 0;

    // Payload.
    if !payload.is_empty() {
        px[tcp + 20..tcp + 20 + payload.len()].copy_from_slice(payload);
    }

    total
}

// ---------------------------------------------------------------------------
// Standalone RST sending (no TCB needed)
// ---------------------------------------------------------------------------

/// Send a RST packet without requiring a TCP connection table.
///
/// This is used when we receive a packet for a connection we don't
/// have a TCB for (e.g., a stale connection that was already destroyed).
pub fn tcp_send_rst(
    stack: &Stack,
    ip_them: IpAddress,
    ip_me: IpAddress,
    port_them: u16,
    port_me: u16,
    seqno_them: u32,
    seqno_me: u32,
) {
    let mut response = match stack.get_packet_buffer() {
        Some(buf) => buf,
        None => {
            log::error!("packet buffers exhausted for RST");
            return;
        }
    };

    response.length = format_tcp_packet(
        ip_them, port_them,
        ip_me, port_me,
        seqno_me, seqno_them,
        0x04, // RST
        &[],
        &mut response.px,
    );

    stack.transmit_packet_buffer(response);
}
