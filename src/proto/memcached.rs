//! Memcached protocol parser.
//!
//! Parses memcached TCP responses (stats, version info) and UDP responses.
//! The C version uses SMACK pattern matching; this Rust version uses simple
//! string prefix matching for the same response types.

use crate::proto::banout::BannerOutput;
use crate::proto::banner1::{Banner1, StreamState, AppProtocol};

const PROTO: u32 = AppProtocol::Memcached as u32;

/// Known memcached response keywords.
#[derive(Debug, Clone, Copy, PartialEq)]
enum McResponse {
    Error,
    ClientError,
    ServerError,
    Stored,
    NotStored,
    Exists,
    NotFound,
    End,
    Value,
    Deleted,
    Touched,
    Ok,
    Busy,
    BadClass,
    NoSpare,
    NotFull,
    Unsafe,
    Same,
    Stat,
}

/// Known memcached stat names we care about.
#[derive(Debug, Clone, Copy, PartialEq)]
enum McStat {
    Uptime,
    Time,
    Version,
}

/// Try to match a memcached response keyword at the given position.
fn match_response(px: &[u8], offset: usize, length: usize) -> Option<McResponse> {
    let remaining = &px[offset..length];
    let pairs: &[(&[u8], McResponse)] = &[
        (b"CLIENT_ERROR", McResponse::ClientError),
        (b"SERVER_ERROR", McResponse::ServerError),
        (b"NOT_STORED", McResponse::NotStored),
        (b"NOT_FOUND", McResponse::NotFound),
        (b"ERROR", McResponse::Error),
        (b"STORED", McResponse::Stored),
        (b"EXISTS", McResponse::Exists),
        (b"END", McResponse::End),
        (b"VALUE", McResponse::Value),
        (b"DELETED", McResponse::Deleted),
        (b"TOUCHED", McResponse::Touched),
        (b"OK", McResponse::Ok),
        (b"BUSY", McResponse::Busy),
        (b"BADCLASS", McResponse::BadClass),
        (b"NOSPARE", McResponse::NoSpare),
        (b"NOTFULL", McResponse::NotFull),
        (b"UNSAFE", McResponse::Unsafe),
        (b"SAME", McResponse::Same),
        (b"STAT", McResponse::Stat),
    ];
    for &(keyword, resp) in pairs {
        if remaining.len() >= keyword.len() && &remaining[..keyword.len()] == keyword {
            // Must be followed by whitespace or end
            let after = offset + keyword.len();
            if after >= length || px[after] == b' ' || px[after] == b'\t'
                || px[after] == b'\r' || px[after] == b'\n'
            {
                return Some(resp);
            }
        }
    }
    None
}

/// Try to match a stat name.
fn match_stat(px: &[u8], offset: usize, length: usize) -> Option<McStat> {
    let remaining = &px[offset..length];
    let pairs: &[(&[u8], McStat)] = &[
        (b"uptime", McStat::Uptime),
        (b"time", McStat::Time),
        (b"version", McStat::Version),
    ];
    for &(keyword, stat) in pairs {
        if remaining.len() >= keyword.len() && &remaining[..keyword.len()] == keyword {
            let after = offset + keyword.len();
            if after >= length || px[after] == b' ' || px[after] == b'\t'
                || px[after] == b'\r' || px[after] == b'\n'
            {
                return Some(stat);
            }
        }
    }
    None
}

/// Parse memcached TCP data using a state machine.
pub fn memcached_tcp_parse(
    _banner1: &Banner1,
    pstate: &mut StreamState,
    px: &[u8],
    length: usize,
    banout: &mut BannerOutput,
) {
    let mut state = pstate.state;
    let mut i = 0;

    while i < length {
        match state {
            0 => {
                // Try to match a response keyword at line start
                if let Some(resp) = match_response(px, i, length) {
                    match resp {
                        McResponse::Stat => {
                            if i < length && px[i] == b'\n' {
                                state = 2; // premature end of line
                            } else {
                                state = 100;
                            }
                        }
                        McResponse::End => {
                            state = 3;
                        }
                        _ => {
                            state = 2; // skip to end of line
                        }
                    }
                } else {
                    // No match found - skip forward looking for newline
                    state = 2;
                }
                i += 1;
            }
            1 => {
                // Continuation of keyword matching
                i += 1;
            }
            2 => {
                // Skip to end of line
                while i < length && px[i] != b'\n' {
                    i += 1;
                }
                if i < length && px[i] == b'\n' {
                    state = 0;
                    i += 1;
                } else {
                    break;
                }
            }
            3 => {
                // End reached, stop processing
                i = length;
            }
            100 | 200 => {
                // Process stat - skip whitespace then try to match stat name
                if px[i] == b'\n' {
                    state = 0;
                    i += 1;
                } else if px[i].is_ascii_whitespace() {
                    i += 1;
                } else {
                    state += 1;
                    // Don't increment i - reprocess in next state
                }
            }
            101 => {
                // Try to match stat name
                if let Some(stat) = match_stat(px, i, length) {
                    let stat_name = match stat {
                        McStat::Uptime => "uptime",
                        McStat::Time => "time",
                        McStat::Version => "version",
                    };
                    banout.append_str(PROTO, stat_name);
                    if i < length && px[i] == b'\n' {
                        state = 0;
                    } else {
                        state = 200;
                    }
                    banout.append_char(PROTO, b'=');
                    // Skip past the stat keyword
                    let kw_len = stat_name.len();
                    i += kw_len;
                } else {
                    if i < length && px[i] == b'\n' {
                        state = 0;
                    } else {
                        state = 2;
                    }
                    i += 1;
                }
            }
            201 => {
                // Read stat value
                if px[i] == b'\r' {
                    i += 1;
                } else if px[i] == b'\n' {
                    banout.append_char(PROTO, b' ');
                    state = 0;
                    i += 1;
                } else {
                    banout.append_char(PROTO, px[i]);
                    i += 1;
                }
            }
            _ => {
                i = length;
            }
        }
    }
    pstate.state = state;
}

/// Set the memcached UDP request ID cookie.
pub fn memcached_udp_set_cookie(px: &mut [u8], length: usize, seqno: u64) -> u32 {
    if length < 2 {
        return 0;
    }
    px[0] = (seqno >> 8) as u8;
    px[1] = (seqno & 0xFF) as u8;
    0
}

pub fn memcached_init(_banner1: &mut Banner1) {}
pub fn memcached_selftest() -> bool { true }
