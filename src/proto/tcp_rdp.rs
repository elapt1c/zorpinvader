//! RDP (Remote Desktop Protocol) parser via TPKT/COTP.
//!
//! Parses RDP connection negotiation through the TPKT (RFC 1006) and
//! COTP (ISO 8073) transport layers, detecting NLA (Network Level
//! Authentication) support in the server's response.
//!
//! ```text
//! TPKT: version(1) reserved(1) length(2)
//! COTP: length(1) pdu_type(1) dst_ref(2) src_ref(2) flags(1)
//! CC:   type(1) flags(1) length(1) reserved(1) result(4)
//! ```

use crate::proto::banout::BannerOutput;
use crate::proto::banner1::{Banner1, StreamState, AppProtocol, ProtocolSubState};

const PROTO_RDP: u32 = AppProtocol::Rdp as u32;
const PROTO_HEUR: u32 = AppProtocol::Heur as u32;

// CC (Connection Confirm) sub-parser states
const CC_TYPE: u32 = 0;
const CC_FLAGS: u32 = 1;
const CC_LENGTH: u32 = 2;
const CC_RESERVED: u32 = 3;
const CC_RESULT0: u32 = 4;
const CC_RESULT1: u32 = 5;
const CC_RESULT2: u32 = 6;
const CC_RESULT3: u32 = 7;
const CC_EXTRA: u32 = 8;
const CC_UNKNOWN: u32 = 9;

// COTP sub-parser states
const COTP_LENGTH: u32 = 0;
const COTP_PDU_TYPE: u32 = 1;
const COTP_DSTREF0: u32 = 2;
const COTP_DSTREF1: u32 = 3;
const COTP_SRCREF0: u32 = 4;
const COTP_SRCREF1: u32 = 5;
const COTP_FLAGS: u32 = 6;
const COTP_CONTENT: u32 = 7;
const COTP_UNKNOWN: u32 = 8;

// TPKT top-level states
const TPKT_START: u32 = 0;
const TPKT_RESERVED: u32 = 1;
const TPKT_LENGTH0: u32 = 2;
const TPKT_LENGTH1: u32 = 3;
const TPKT_CONTENT: u32 = 4;
const TPKT_UNKNOWN: u32 = 5;

/// Parse the CC (RDP Negotiation Response) sub-layer.
fn cc_parse(
    banout: &mut BannerOutput,
    cc_state: &mut u32,
    cc_type: &mut u8,
    _cc_flags: &mut u8,
    cc_len: &mut u8,
    cc_result: &mut u32,
    px: &[u8],
    length: usize,
) -> usize {
    let mut offset = 0;
    let mut state = *cc_state;

    while offset < length {
        let c = px[offset];
        match state {
            CC_TYPE => {
                *cc_type = c;
                state = CC_FLAGS;
                offset += 1;
            }
            CC_FLAGS => {
                *_cc_flags = c;
                state = CC_LENGTH;
                offset += 1;
            }
            CC_LENGTH => {
                *cc_len = c;
                if *cc_len < 4 {
                    state = CC_UNKNOWN;
                } else {
                    *cc_len -= 4;
                    state = CC_RESERVED;
                }
                offset += 1;
            }
            CC_RESERVED => {
                match *cc_type {
                    2 | 3 => {
                        state = CC_RESULT0;
                        *cc_result = 0;
                    }
                    _ => state = CC_EXTRA,
                }
                offset += 1;
            }
            CC_RESULT0 | CC_RESULT1 | CC_RESULT2 | CC_RESULT3 => {
                if *cc_len == 0 {
                    state = CC_EXTRA;
                } else {
                    *cc_len -= 1;
                    *cc_result = (*cc_result >> 8) | ((c as u32) << 24);
                    state += 1;
                    if state == CC_EXTRA {
                        match *cc_type {
                            2 => {
                                if *cc_result & 2 != 0 {
                                    banout.append_str(PROTO_RDP, " NLA-supported");
                                } else {
                                    banout.append_str(PROTO_RDP, " NLA-unused");
                                }
                            }
                            3 => {
                                if *cc_result == 5 {
                                    banout.append_str(PROTO_RDP, " NLA-unsupported");
                                } else {
                                    banout.append_str(PROTO_RDP, " failure");
                                }
                            }
                            _ => {
                                banout.append_str(PROTO_RDP, " unknown");
                            }
                        }
                    }
                }
                offset += 1;
            }
            CC_EXTRA => {
                offset = length;
            }
            CC_UNKNOWN => {
                banout.append(PROTO_HEUR, px, length);
                offset = length;
            }
            _ => {
                offset = length;
            }
        }
    }

    *cc_state = state;
    offset
}

/// Parse the COTP transport layer.
fn cotp_parse(
    banout: &mut BannerOutput,
    cotp_state: &mut u32,
    cotp_type: &mut u8,
    cotp_len: &mut u8,
    cotp_dstref: &mut u16,
    _cotp_srcref: &mut u16,
    cotp_flags: &mut u8,
    cc_state: &mut u32,
    cc_type: &mut u8,
    cc_flags: &mut u8,
    cc_len: &mut u8,
    cc_result: &mut u32,
    px: &[u8],
    length: usize,
) -> usize {
    let mut offset = 0;
    let mut state = *cotp_state;

    while offset < length {
        let c = px[offset];
        match state {
            COTP_LENGTH => {
                *cotp_len = c;
                if *cotp_len < 6 {
                    state = COTP_UNKNOWN;
                } else {
                    *cotp_len -= 6;
                    state = COTP_PDU_TYPE;
                }
                offset += 1;
            }
            COTP_PDU_TYPE => {
                *cotp_type = c;
                *_cotp_srcref = 0;
                *cotp_dstref = 0;
                state = COTP_DSTREF0;
                offset += 1;
            }
            COTP_DSTREF0 | COTP_DSTREF1 => {
                *cotp_dstref = (*cotp_dstref << 8) | (c as u16);
                state += 1;
                offset += 1;
            }
            COTP_SRCREF0 | COTP_SRCREF1 => {
                // Note: C code has a bug - writes to dstref instead of srcref
                *cotp_dstref = (*cotp_dstref << 8) | (c as u16);
                state += 1;
                offset += 1;
            }
            COTP_FLAGS => {
                *cotp_flags = c;
                *cc_state = 0;
                state = COTP_CONTENT;
                offset += 1;
            }
            COTP_CONTENT => {
                match *cotp_type {
                    0xd0 => {
                        // Connect Confirm
                        let mut inner_len = *cotp_len as usize;
                        if inner_len >= length - offset {
                            inner_len = length - offset;
                        }

                        let bytes_parsed = cc_parse(
                            banout, cc_state, cc_type, cc_flags, cc_len, cc_result,
                            &px[offset..], inner_len,
                        );

                        if bytes_parsed == 0 {
                            offset = length;
                            break;
                        }
                        offset += bytes_parsed;
                        *cotp_len -= bytes_parsed as u8;

                        if *cotp_len != 0 {
                            state = COTP_CONTENT;
                        } else {
                            state = COTP_UNKNOWN;
                        }
                    }
                    _ => {
                        banout.append_str(PROTO_RDP, " COTPPDU=unknown");
                        offset = length;
                    }
                }
            }
            COTP_UNKNOWN => {
                banout.append(PROTO_HEUR, px, length);
                offset = length;
            }
            _ => {
                offset = length;
            }
        }
    }

    *cotp_state = state;
    offset
}

/// Parse RDP data through TPKT → COTP → CC layers.
pub fn rdp_parse(
    _banner1: &Banner1,
    pstate: &mut StreamState,
    px: &[u8],
    length: usize,
    banout: &mut BannerOutput,
) {
    let mut state = pstate.state & 0x00FF_FFFF;

    let (mut tpkt_length, mut cotp_state, mut cotp_type, mut cotp_len,
         mut cotp_dstref, mut cotp_srcref, mut cotp_flags,
         mut cc_state, mut cc_type, mut cc_flags, mut cc_len, mut cc_result) =
        if let ProtocolSubState::Rdp(ref rdp) = pstate.sub {
            (rdp.tpkt_length, rdp.cotp_state, rdp.cotp_type, rdp.cotp_len,
             rdp.cotp_dstref, rdp.cotp_srcref, rdp.cotp_flags,
             rdp.cc_state, rdp.cc_type, rdp.cc_flags, rdp.cc_len, rdp.cc_result)
        } else {
            (0u16, 0u32, 0u8, 0u8, 0u16, 0u16, 0u8, 0u32, 0u8, 0u8, 0u8, 0u32)
        };

    let mut offset = 0;
    while offset < length {
        let c = px[offset];
        match state & 0xF {
            TPKT_START => {
                if c != 3 {
                    state = TPKT_UNKNOWN;
                    // Don't increment - reprocess
                } else {
                    tpkt_length = 0;
                    cotp_state = 0;
                    state = TPKT_RESERVED;
                    offset += 1;
                }
            }
            TPKT_RESERVED => {
                state = TPKT_LENGTH0;
                offset += 1;
            }
            TPKT_LENGTH0 => {
                // High byte of length (ignored in C - bug or intentional)
                state = TPKT_LENGTH1;
                offset += 1;
            }
            TPKT_LENGTH1 => {
                tpkt_length = (tpkt_length << 8) | (c as u16);
                if tpkt_length < 4 {
                    state = TPKT_UNKNOWN;
                } else if tpkt_length == 4 {
                    state = TPKT_START;
                } else {
                    tpkt_length -= 4;
                    state = TPKT_CONTENT;
                }
                offset += 1;
            }
            TPKT_CONTENT => {
                let mut inner_len = tpkt_length as usize;
                if inner_len >= length - offset {
                    inner_len = length - offset;
                }

                let bytes_parsed = cotp_parse(
                    banout, &mut cotp_state, &mut cotp_type, &mut cotp_len,
                    &mut cotp_dstref, &mut cotp_srcref, &mut cotp_flags,
                    &mut cc_state, &mut cc_type, &mut cc_flags, &mut cc_len,
                    &mut cc_result,
                    &px[offset..], inner_len,
                );

                if bytes_parsed == 0 {
                    offset = length; // consumed by outer while loop check
                    break;
                }
                offset += bytes_parsed;
                tpkt_length -= bytes_parsed as u16;

                if tpkt_length != 0 {
                    state = TPKT_CONTENT;
                } else {
                    state = TPKT_START;
                }
            }
            TPKT_UNKNOWN => {
                banout.append(PROTO_HEUR, px, length);
                offset = length;
            }
            _ => {
                offset += 1;
            }
        }
    }

    pstate.state = state;

    // Save state back
    if let ProtocolSubState::Rdp(ref mut rdp) = pstate.sub {
        rdp.tpkt_length = tpkt_length;
        rdp.cotp_state = cotp_state;
        rdp.cotp_type = cotp_type;
        rdp.cotp_len = cotp_len;
        rdp.cotp_dstref = cotp_dstref;
        rdp.cotp_srcref = cotp_srcref;
        rdp.cotp_flags = cotp_flags;
        rdp.cc_state = cc_state;
        rdp.cc_type = cc_type;
        rdp.cc_flags = cc_flags;
        rdp.cc_len = cc_len;
        rdp.cc_result = cc_result;
    }
}

/// Self-test helper.
fn rdp_selftest_item(input: &[u8], expect: &str) -> bool {
    let banner1 = Banner1::default();
    let mut pstate = StreamState::default();
    let mut banout = BannerOutput::new();

    rdp_parse(&banner1, &mut pstate, input, input.len(), &mut banout);

    banout.is_contains(PROTO_RDP, expect)
}

/// Self-test for the RDP parser.
pub fn rdp_selftest() -> bool {
    // Test 1: NLA supported
    let test1: &[u8] = b"\x03\x00\x00\x13\
\x0e\xd0\x00\x00\x12\x34\x00\x02\x0f\x08\x00\x02\x00\x00\x00";

    // Test 2: NLA unsupported
    let test2: &[u8] = b"\x03\x00\x00\x13\
\x0e\xd0\x00\x00\x12\x34\x00\x03\x00\x08\x00\x05\x00\x00\x00";

    let mut result = 0;
    if !rdp_selftest_item(test1, "NLA-sup") {
        result += 1;
    }
    if !rdp_selftest_item(test2, "NLA-unsup") {
        result += 1;
    }
    result == 0
}

pub fn rdp_init(_banner1: &mut Banner1) {}
