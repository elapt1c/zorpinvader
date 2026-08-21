//! TCP application layer — banner grabbing and protocol dispatch.
//!
//! This module sits above the TCP state machine and implements the
//! scanning "application" logic:
//!
//! - Wait for a server "hello" banner (SSH, FTP, SMTP, etc.).
//! - Send a probe (HTTP request, TLS ClientHello, etc.).
//! - Parse the response for banner information.
//! - Optionally reconnect with a different protocol handler.
//!
//! Converted from `c-src/stack-tcp-app.h` and `c-src/stack-tcp-app.c`.

use super::tcp_core::{TcpConnectionTable, TcpControlBlock};

/// Events delivered to the application layer by the TCP state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEvent {
    /// Connection established (received SYN-ACK).
    Connected,
    /// No data received within the timeout period.
    RecvTimeout,
    /// Incoming payload data from the remote side.
    RecvPayload,
    /// Our data is being sent (notification before transmit).
    Sending,
    /// All our data has been acknowledged.
    SendSent,
    /// Remote side sent a FIN (connection closing).
    Close,
}

/// Application-level state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    /// Just connected; waiting to decide what to do.
    Connect,
    /// Waiting for the server's initial "hello" banner.
    ReceiveHello,
    /// Receiving data (after initial hello or post-send response).
    ReceiveNext,
    /// About to send the first probe.
    SendFirst,
    /// Waiting for acknowledgement of sent data.
    SendNext,
    /// Connection is closing.
    Close,
}

impl AppState {
    /// Convert from a raw `u32` (for compatibility with C code using integer states).
    pub fn from_raw(val: u32) -> Self {
        match val {
            0 => AppState::Connect,
            1 => AppState::ReceiveHello,
            2 => AppState::ReceiveNext,
            3 => AppState::SendFirst,
            4 => AppState::SendNext,
            5 => AppState::Close,
            _ => AppState::Connect,
        }
    }

    /// Convert to a raw `u32`.
    pub fn to_raw(self) -> u32 {
        match self {
            AppState::Connect => 0,
            AppState::ReceiveHello => 1,
            AppState::ReceiveNext => 2,
            AppState::SendFirst => 3,
            AppState::SendNext => 4,
            AppState::Close => 5,
        }
    }
}

impl std::fmt::Display for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppState::Connect => write!(f, "connect"),
            AppState::ReceiveHello => write!(f, "wait-for-hello"),
            AppState::ReceiveNext => write!(f, "receive"),
            AppState::SendFirst => write!(f, "send-first"),
            AppState::SendNext => write!(f, "send"),
            AppState::Close => write!(f, "close"),
        }
    }
}

impl std::fmt::Display for AppEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppEvent::Connected => write!(f, "connected"),
            AppEvent::RecvTimeout => write!(f, "timeout"),
            AppEvent::RecvPayload => write!(f, "payload"),
            AppEvent::Sending => write!(f, "sending"),
            AppEvent::SendSent => write!(f, "sent"),
            AppEvent::Close => write!(f, "close"),
        }
    }
}

/// Flags controlling how the application sends data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendFlags {
    /// Static data that the send function can just reference.
    Static,
    /// The send function must copy the data.
    Copy,
    /// The buffer was just allocated; the send function can adopt it.
    Adopt,
    /// Send a FIN after the data (half-close).
    CloseFin,
}

/// Socket error codes returned by TCP API functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketError {
    /// No error.
    None,
    /// Bad socket descriptor.
    BadFileDescriptor,
}

impl SocketError {
    pub fn is_ok(self) -> bool {
        self == SocketError::None
    }
}

/// Handle to a TCP connection, passed to application-layer callbacks.
///
/// This is the Rust equivalent of `stack_handle_t` from the C code.
/// It bundles references to the connection table and the specific TCB
/// being operated on, along with the current timestamp.
pub struct StackHandle<'a> {
    pub tcpcon: &'a TcpConnectionTable,
    pub tcb: &'a mut TcpControlBlock,
    pub secs: u32,
    pub usecs: u32,
}

/// Process an application-level event.
///
/// This is the main dispatch function that drives the banner-grabbing
/// state machine. It is called by the TCP layer whenever a significant
/// event occurs (connection established, data received, timeout, etc.).
///
/// The function implements a simple state machine:
///
/// ```text
/// Connect ──(connected)──► ReceiveHello ──(timeout)──► SendFirst
///                              │                           │
///                         (payload)                    (send done)
///                              ▼                           ▼
///                         ReceiveNext ◄──────────── SendNext
///                              │
///                          (close)
///                              ▼
///                           Close
/// ```
pub fn application_event(
    handle: &mut StackHandle<'_>,
    state: AppState,
    event: AppEvent,
    _stream: Option<&ProtocolParserStream>,
    _banner1: Option<&Banner1>,
    payload: &[u8],
) -> AppState {
    let mut current_state = state;

    // The C code uses goto for state transitions; we use a loop instead.
    loop {
        match current_state {
            AppState::Connect => {
                match event {
                    AppEvent::Connected => {
                        // If there are multiple protocol handlers for this port,
                        // try the next one via reconnect.
                        // (Reconnect logic deferred to when full stream support exists.)

                        // By default, wait for the "hello timeout" period.
                        // If the protocol has SF__nowait_hello, skip to sending.
                        if let Some(stream) = _stream {
                            if stream.flags.contains(StreamFlags::NO_WAIT_HELLO) {
                                current_state = AppState::SendFirst;
                                continue;
                            }
                        }

                        // Set a 2-second timeout and switch to receiving.
                        handle.tcb.set_timeout(handle.secs + 2, handle.usecs);
                        handle.tcb.switch_to_recv();
                        handle.tcb.app_state = AppState::ReceiveHello;
                        return AppState::ReceiveHello;
                    }
                    _ => {
                        log::error!(
                            "TCP.app: unhandled event: state={} event={}",
                            current_state, event
                        );
                        return current_state;
                    }
                }
            }

            AppState::ReceiveHello => {
                match event {
                    AppEvent::RecvTimeout => {
                        // No response from server; switch to sending our probe.
                        if _stream.is_some() {
                            current_state = AppState::SendFirst;
                            continue;
                        }
                        return current_state;
                    }
                    AppEvent::RecvPayload => {
                        // Got data from server; keep receiving.
                        handle.tcb.app_state = AppState::ReceiveNext;
                        current_state = AppState::ReceiveNext;
                        continue;
                    }
                    AppEvent::Close => {
                        handle.tcb.banner_flush();
                        handle.tcb.close();
                        return current_state;
                    }
                    _ => {
                        log::error!(
                            "TCP.app: unhandled event: state={} event={}",
                            current_state, event
                        );
                        return current_state;
                    }
                }
            }

            AppState::ReceiveNext => {
                match event {
                    AppEvent::RecvPayload => {
                        // Parse the incoming data for banner information.
                        handle.tcb.banner_parse(payload);
                        return current_state;
                    }
                    AppEvent::Close => {
                        // Remote side sent FIN; flush banners and close.
                        handle.tcb.banner_flush();
                        handle.tcb.close();
                        return current_state;
                    }
                    AppEvent::RecvTimeout => {
                        return current_state;
                    }
                    AppEvent::Sending => {
                        // A higher-level protocol started sending while receiving.
                        handle.tcb.app_state = AppState::SendNext;
                        return AppState::SendNext;
                    }
                    AppEvent::SendSent => {
                        return current_state;
                    }
                    _ => {
                        log::error!(
                            "TCP.app: unhandled event: state={} event={}",
                            current_state, event
                        );
                        return current_state;
                    }
                }
            }

            AppState::SendFirst => {
                // This state is entered internally (not from an external event).
                // Send the protocol's hello/probe message.
                if let Some(stream) = _stream {
                    // Check for SSL-specific handling.
                    if stream.is_ssl() {
                        handle.tcb.set_ssl_hello(true);
                    }

                    // Check for heartbleed scanning.
                    if let Some(banner1) = _banner1 {
                        if banner1.is_heartbleed {
                            handle.tcb.set_small_window(true);
                        }
                    }

                    // Send the probe data.
                    if let Some(ref transmit_fn) = stream.transmit_hello {
                        // Custom transmit callback.
                        transmit_fn(handle);
                    } else if !stream.hello.is_empty() {
                        // Static hello template.
                        handle.tcb.send(&stream.hello, SendFlags::Static);

                        // Optionally close after sending.
                        if stream.flags.contains(StreamFlags::CLOSE) {
                            handle.tcb.close();
                        }
                    }
                }

                handle.tcb.app_state = AppState::SendNext;
                return AppState::SendNext;
            }

            AppState::SendNext => {
                match event {
                    AppEvent::SendSent => {
                        // All data acknowledged; switch to receiving.
                        handle.tcb.switch_to_recv();
                        handle.tcb.app_state = AppState::ReceiveNext;
                        return AppState::ReceiveNext;
                    }
                    AppEvent::Sending => {
                        return current_state;
                    }
                    _ => {
                        log::error!(
                            "TCP.app: unhandled event: state={} event={}",
                            current_state, event
                        );
                        return current_state;
                    }
                }
            }

            AppState::Close => {
                return current_state;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Placeholder types for protocol streams and banner1.
// These will be replaced by full implementations from crate::proto::banner1
// when that module is completed.
// ---------------------------------------------------------------------------

/// Bitflags for protocol stream behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFlags(u32);

impl StreamFlags {
    pub const NONE: Self = Self(0);
    /// Don't wait for a server hello before sending.
    pub const NO_WAIT_HELLO: Self = Self(1 << 0);
    /// Close the connection after sending the hello.
    pub const CLOSE: Self = Self(1 << 1);
    /// Indicates this is an SSL stream.
    pub const IS_SSL: Self = Self(1 << 2);

    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// Protocol parser stream configuration.
///
/// Describes how to interact with a particular protocol (what bytes to
/// send, whether to wait for a hello, etc.).
pub struct ProtocolParserStream {
    /// Protocol name (e.g., "http", "ssl", "ssh").
    pub name: String,
    /// Hello/probe bytes to send to the server.
    pub hello: Vec<u8>,
    /// Stream behavior flags.
    pub flags: StreamFlags,
    /// Optional custom transmit function.
    pub transmit_hello: Option<Box<dyn Fn(&mut StackHandle<'_>)>>,
    /// Next protocol handler to try on reconnect (for multi-protocol ports).
    pub next: Option<Box<ProtocolParserStream>>,
}

impl ProtocolParserStream {
    /// Check if this is an SSL/TLS stream.
    pub fn is_ssl(&self) -> bool {
        self.name == "ssl" || self.flags.contains(StreamFlags::IS_SSL)
    }
}

/// Banner parsing state (placeholder).
///
/// Will be replaced by `crate::proto::banner1::Banner1` when that module
/// is fully implemented.
pub struct Banner1 {
    /// Whether heartbleed scanning is enabled.
    pub is_heartbleed: bool,
    /// Whether ticketbleed scanning is enabled.
    pub is_ticketbleed: bool,
    /// Whether POODLE/SSLv3 scanning is enabled.
    pub is_poodle_sslv3: bool,
    /// Whether to capture X.509 certificates.
    pub is_capture_cert: bool,
    /// Whether to capture the server name (SNI).
    pub is_capture_servername: bool,
    /// Whether to capture HTML titles.
    pub is_capture_html: bool,
    /// Whether to capture heartbleed results.
    pub is_capture_heartbleed: bool,
    /// Whether to capture ticketbleed results.
    pub is_capture_ticketbleed: bool,
}

impl Default for Banner1 {
    fn default() -> Self {
        Self {
            is_heartbleed: false,
            is_ticketbleed: false,
            is_poodle_sslv3: false,
            is_capture_cert: false,
            is_capture_servername: false,
            is_capture_html: false,
            is_capture_heartbleed: false,
            is_capture_ticketbleed: false,
        }
    }
}

/// Per-connection stream parsing state.
#[derive(Debug, Default)]
pub struct StreamState {
    /// Port number this state is tracking.
    pub port: u16,
    /// Application-layer protocol identifier.
    pub app_proto: u32,
    /// Whether an SSL hello has been sent.
    pub is_sent_sslhello: bool,
}
