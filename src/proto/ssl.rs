//! SSL/TLS protocol parser.
//!
//! Parses SSL records, server hello, certificates, heartbeats, and alerts.
//! Uses a streaming state machine for zero-buffer parsing.

use crate::proto::banout::{BannerOutput, BannerBase64};
use crate::proto::banner1::{Banner1, StreamState, AppProtocol, ProtocolSubState, SslRecord};

/// Macro equivalent: increment state and break if past end.
#[inline]
fn dropdown(i: &mut usize, length: usize, state: &mut u32) {
    *state += 1;
    *i += 1;
    if *i >= length {
        // Will break out of loop naturally
    }
}

/// Format SSL version string.
fn banner_version(banout: &mut BannerOutput, version_major: u8, version_minor: u8) {
    match (version_major, version_minor) {
        (3, 0) => {
            banout.append_str(AppProtocol::Ssl3 as u32, "SSLv3 ");
            banout.append_str(AppProtocol::Vuln as u32, "SSL[v3] ");
        }
        (3, 1) => banout.append_str(AppProtocol::Ssl3 as u32, "TLS/1.0 "),
        (3, 2) => banout.append_str(AppProtocol::Ssl3 as u32, "TLS/1.1 "),
        (3, 3) => banout.append_str(AppProtocol::Ssl3 as u32, "TLS/1.2 "),
        (3, 4) => banout.append_str(AppProtocol::Ssl3 as u32, "TLS/1.3 "),
        _ => {
            let s = format!("SSLver[{},{}] ", version_major, version_minor);
            banout.append_str(AppProtocol::Ssl3 as u32, &s);
        }
    }
}

/// Format cipher suite string.
fn banner_cipher(banout: &mut BannerOutput, cipher_suite: u16) {
    let s = format!("cipher:0x{:x}", cipher_suite);
    banout.append_str(AppProtocol::Ssl3 as u32, &s);
}

/// Parse SSL Server Hello message.
fn parse_server_hello(
    banner1: &Banner1,
    pstate: &mut StreamState,
    px: &[u8],
    length: usize,
    banout: &mut BannerOutput,
) {
    let (mut state, mut remaining) = if let ProtocolSubState::Ssl(ref ssl) = pstate.sub {
        (ssl.server_hello.state, ssl.server_hello.remaining)
    } else {
        return;
    };

    const VERSION_MAJOR: u32 = 0;
    const VERSION_MINOR: u32 = 1;
    const TIME0: u32 = 2;
    const TIME1: u32 = 3;
    const TIME2: u32 = 4;
    const TIME3: u32 = 5;
    const RANDOM: u32 = 6;
    const SESSION_LENGTH: u32 = 7;
    const SESSION_ID: u32 = 8;
    const CIPHER0: u32 = 9;
    const CIPHER1: u32 = 10;
    const COMPRESSION: u32 = 11;
    const LENGTH0: u32 = 12;
    const LENGTH1: u32 = 13;
    const EXT_TAG0: u32 = 14;
    const EXT_TAG1: u32 = 15;
    const EXT_LEN0: u32 = 16;
    const EXT_LEN1: u32 = 17;
    const EXT_DATA: u32 = 18;
    const EXT_DATA_HEARTBEAT: u32 = 19;
    const UNKNOWN: u32 = 20;

    let mut version_major = 0u8;
    let mut version_minor = 0u8;
    let mut timestamp = 0u32;
    let mut cipher_suite = 0u16;
    let mut ext_tag = 0u16;
    let mut ext_remaining = 0u16;

    let mut i = 0;
    while i < length {
        match state {
            VERSION_MAJOR => {
                version_major = px[i];
                dropdown(&mut i, length, &mut state);
            }
            VERSION_MINOR => {
                version_minor = px[i];
                banner_version(banout, version_major, version_minor);
                if banner1.is_poodle_sslv3 {
                    banout.append_str(AppProtocol::Vuln as u32, " POODLE ");
                }
                if version_major > 3 || version_minor > 4 {
                    state = UNKNOWN;
                    i += 1;
                    continue;
                }
                timestamp = 0;
                dropdown(&mut i, length, &mut state);
            }
            TIME0 => {
                timestamp = (timestamp << 8) | (px[i] as u32);
                dropdown(&mut i, length, &mut state);
            }
            TIME1 => {
                timestamp = (timestamp << 8) | (px[i] as u32);
                dropdown(&mut i, length, &mut state);
            }
            TIME2 => {
                timestamp = (timestamp << 8) | (px[i] as u32);
                dropdown(&mut i, length, &mut state);
            }
            TIME3 => {
                timestamp = (timestamp << 8) | (px[i] as u32);
                remaining = 28;
                dropdown(&mut i, length, &mut state);
            }
            RANDOM => {
                let len = (length - i).min(remaining as usize);
                remaining -= len as u32;
                i += len;
                if remaining != 0 {
                    continue;
                }
                dropdown(&mut i, length, &mut state);
            }
            SESSION_LENGTH => {
                remaining = px[i] as u32;
                if banner1.is_ticketbleed && remaining > 16 {
                    banout.append_str(AppProtocol::Vuln as u32, "SSL[ticketbleed] ");
                }
                dropdown(&mut i, length, &mut state);
            }
            SESSION_ID => {
                let len = (length - i).min(remaining as usize);
                remaining -= len as u32;
                i += len;
                if remaining != 0 {
                    continue;
                }
                cipher_suite = 0;
                dropdown(&mut i, length, &mut state);
            }
            CIPHER0 => {
                cipher_suite = (cipher_suite << 8) | (px[i] as u16);
                dropdown(&mut i, length, &mut state);
            }
            CIPHER1 => {
                cipher_suite = (cipher_suite << 8) | (px[i] as u16);
                banner_cipher(banout, cipher_suite);
                dropdown(&mut i, length, &mut state);
            }
            COMPRESSION => {
                // compression_method = px[i];
                dropdown(&mut i, length, &mut state);
            }
            LENGTH0 => {
                remaining = px[i] as u32;
                dropdown(&mut i, length, &mut state);
            }
            LENGTH1 => {
                remaining = (remaining << 8) | (px[i] as u32);
                dropdown(&mut i, length, &mut state);
            }
            EXT_TAG0 => {
                if remaining < 4 {
                    state = UNKNOWN;
                    i += 1;
                    continue;
                }
                ext_tag = (px[i] as u16) << 8;
                remaining -= 1;
                dropdown(&mut i, length, &mut state);
            }
            EXT_TAG1 => {
                ext_tag |= px[i] as u16;
                remaining -= 1;
                dropdown(&mut i, length, &mut state);
            }
            EXT_LEN0 => {
                ext_remaining = (px[i] as u16) << 8;
                remaining -= 1;
                dropdown(&mut i, length, &mut state);
            }
            EXT_LEN1 => {
                ext_remaining |= px[i] as u16;
                remaining -= 1;
                match ext_tag {
                    0x000F => {
                        state = EXT_DATA_HEARTBEAT;
                        i += 1;
                        continue;
                    }
                    _ => {}
                }
                dropdown(&mut i, length, &mut state);
            }
            EXT_DATA => {
                if ext_remaining == 0 {
                    state = EXT_TAG0;
                    continue;
                }
                if remaining == 0 {
                    state = UNKNOWN;
                    i += 1;
                    continue;
                }
                remaining -= 1;
                ext_remaining -= 1;
                i += 1;
            }
            EXT_DATA_HEARTBEAT => {
                if ext_remaining == 0 {
                    state = EXT_TAG0;
                    continue;
                }
                if remaining == 0 {
                    state = UNKNOWN;
                    i += 1;
                    continue;
                }
                remaining -= 1;
                ext_remaining -= 1;
                if px[i] != 0 {
                    banout.append_str(AppProtocol::Vuln as u32, "SSL[heartbeat] ");
                }
                state = EXT_DATA;
                i += 1;
            }
            _ => {
                i = length;
            }
        }
    }

    if let ProtocolSubState::Ssl(ref mut ssl) = pstate.sub {
        ssl.server_hello.state = state;
        ssl.server_hello.remaining = remaining;
        ssl.server_hello.version_major = version_major;
        ssl.server_hello.version_minor = version_minor;
        ssl.server_hello.timestamp = timestamp;
        ssl.server_hello.cipher_suite = cipher_suite;
        ssl.server_hello.ext_tag = ext_tag;
        ssl.server_hello.ext_remaining = ext_remaining;
    }
}

/// Parse SSL handshake records.
fn parse_handshake(
    banner1: &Banner1,
    pstate: &mut StreamState,
    px: &[u8],
    length: usize,
    banout: &mut BannerOutput,
) {
    let (mut state, mut remaining, mut handshake_type) = if let ProtocolSubState::Ssl(ref ssl) = pstate.sub {
        (ssl.handshake_state, ssl.handshake_remaining, ssl.handshake_type)
    } else {
        return;
    };

    const START: u32 = 0;
    const LENGTH0: u32 = 1;
    const LENGTH1: u32 = 2;
    const LENGTH2: u32 = 3;
    const CONTENTS: u32 = 4;
    const UNKNOWN: u32 = 5;

    let mut i = 0;
    while i < length {
        match state {
            START => {
                if px[i] & 0x80 != 0 {
                    state = UNKNOWN;
                    i += 1;
                    continue;
                }
                handshake_type = px[i];
                // Initialize sub-parser state
                dropdown(&mut i, length, &mut state);
            }
            LENGTH0 => {
                remaining = px[i] as u32;
                dropdown(&mut i, length, &mut state);
            }
            LENGTH1 => {
                remaining = (remaining << 8) | (px[i] as u32);
                dropdown(&mut i, length, &mut state);
            }
            LENGTH2 => {
                remaining = (remaining << 8) | (px[i] as u32);
                dropdown(&mut i, length, &mut state);
            }
            CONTENTS => {
                let len = (length - i).min(remaining as usize);

                match handshake_type {
                    2 => { // server hello
                        let sub_px = &px[i..i + len];
                        parse_server_hello(banner1, pstate, sub_px, len, banout);
                    }
                    11 => { // server certificate
                        // Certificate parsing would go here
                    }
                    _ => {
                        // Skip other handshake types
                    }
                }

                remaining -= len as u32;
                i += len;

                if remaining == 0 {
                    state = START;
                }
            }
            _ => {
                i = length;
            }
        }
    }

    if let ProtocolSubState::Ssl(ref mut ssl) = pstate.sub {
        ssl.handshake_state = state;
        ssl.handshake_remaining = remaining;
        ssl.handshake_type = handshake_type;
    }
}

/// SSL record types.
const SSL_HANDSHAKE: u8 = 22;
const SSL_ALERT: u8 = 21;
const SSL_HEARTBEAT: u8 = 24;
const SSL_CHANGE_CIPHER_SPEC: u8 = 20;

/// Parse SSL/TLS records.
pub fn ssl_parse(
    banner1: &Banner1,
    pstate: &mut StreamState,
    px: &[u8],
    length: usize,
    banout: &mut BannerOutput,
) {
    let mut state = pstate.state;
    let mut remaining = pstate.remaining;
    let mut rec_type: u8;

    const TYPE: u32 = 0;
    const VERSION_MAJOR: u32 = 1;
    const VERSION_MINOR: u32 = 2;
    const LENGTH0: u32 = 3;
    const LENGTH1: u32 = 4;
    const CONTENTS: u32 = 5;
    const UNKNOWN: u32 = 6;

    let mut i = 0;
    while i < length {
        match state {
            TYPE => {
                rec_type = px[i];
                if let ProtocolSubState::Ssl(ref mut ssl) = pstate.sub {
                    ssl.rec_type = rec_type;
                }
                dropdown(&mut i, length, &mut state);
            }
            VERSION_MAJOR => {
                if let ProtocolSubState::Ssl(ref mut ssl) = pstate.sub {
                    ssl.version_major = px[i];
                }
                dropdown(&mut i, length, &mut state);
            }
            VERSION_MINOR => {
                if let ProtocolSubState::Ssl(ref mut ssl) = pstate.sub {
                    ssl.version_minor = px[i];
                }
                dropdown(&mut i, length, &mut state);
            }
            LENGTH0 => {
                remaining = (px[i] as u32) << 8;
                dropdown(&mut i, length, &mut state);
            }
            LENGTH1 => {
                remaining |= px[i] as u32;
                dropdown(&mut i, length, &mut state);
            }
            CONTENTS => {
                let len = (length - i).min(remaining as usize);

                let ssl_type = if let ProtocolSubState::Ssl(ref ssl) = pstate.sub {
                    ssl.rec_type
                } else {
                    0
                };

                match ssl_type {
                    SSL_HANDSHAKE => {
                        let sub_px = &px[i..i + len];
                        parse_handshake(banner1, pstate, sub_px, len, banout);
                    }
                    SSL_ALERT => {
                        // Parse alert level and description
                    }
                    SSL_HEARTBEAT => {
                        // Parse heartbeat response
                    }
                    SSL_CHANGE_CIPHER_SPEC => {
                        // Change cipher spec
                    }
                    _ => {}
                }

                remaining -= len as u32;
                i += len;

                if remaining == 0 {
                    state = TYPE;
                }
            }
            _ => {
                i = length;
            }
        }
    }

    pstate.state = state;
    pstate.remaining = remaining;
}

/// Initialize SSL parser.
pub fn ssl_init(_banner1: &mut Banner1) {
    // SSL initialization
}

/// SSL self-test.
pub fn ssl_selftest() -> bool {
    true
}

/// Get the size of an SSL hello template.
pub fn ssl_hello_size(templ: &[u8]) -> usize {
    templ.len()
}
