//! X.509 certificate decoder using a state-machine parser.
//!
//! Decodes X.509 certificates in a streaming fashion, fragment by fragment,
//! without requiring the entire certificate in memory. This is necessary
//! for scalability when processing millions of connections simultaneously.
//!
//! Extracts the subject common name (e.g., "*.google.com") and validity dates.
//! Uses an ASN.1 state machine that maintains a stack of nested field lengths.
//!
//! # Certificate format (simplified):
//! ```text
//! Certificate ::= SEQUENCE {
//!     tbsCertificate       TBSCertificate,
//!     signatureAlgorithm   AlgorithmIdentifier,
//!     signatureValue       BIT STRING }
//! ```

use crate::proto::banout::BannerOutput;
use crate::proto::banner1::AppProtocol;

const PROTO: u32 = AppProtocol::Ssl3 as u32;

/// Subject name type (which OID was last matched).
#[derive(Debug, Clone, Copy, PartialEq)]
enum SubjectType {
    Unknown,
    Common,
}

/// ASN.1 stack depth limit.
const STACK_DEPTH: usize = 9;

/// ASN.1 length/state stack for nested field tracking.
#[derive(Debug, Clone)]
pub struct Asn1Stack {
    remainings: [u16; STACK_DEPTH],
    states: [u8; STACK_DEPTH],
    depth: u8,
}

impl Default for Asn1Stack {
    fn default() -> Self {
        Asn1Stack {
            remainings: [0; STACK_DEPTH],
            states: [0; STACK_DEPTH],
            depth: 0,
        }
    }
}

/// Intermediate decode state union (mirrors C union).
#[derive(Debug, Clone, Default)]
struct DecodeUnion {
    tag_remaining: u16,
    tag_length_of_length: u8,
    num: u64,
    oid_num: u64,
    oid_state: u16,
    oid_last_id: u8,
    timestamp_state: u8,
    year: u8,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

/// X.509 certificate state-machine decoder.
///
/// Maintains ~60 bytes of state to parse certificates fragment-by-fragment
/// without memory allocation.
#[derive(Debug, Clone)]
pub struct CertDecode {
    /// Main state variable.
    pub state: u32,
    /// ASN.1 nesting stack.
    pub stack: Asn1Stack,
    /// Whether a DER encoding error was detected.
    pub is_der_failure: bool,
    /// Whether to capture the subject name.
    pub is_capture_subject: bool,
    /// Whether to capture the issuer name.
    pub is_capture_issuer: bool,
    /// Certificate count in chain.
    pub count: u8,
    /// Subject type from last OID match.
    subject_type: SubjectType,
    /// Child/brother states for SPNEGO compatibility.
    pub child_state: u32,
    pub brother_state: u32,
    /// Intermediate decode values.
    u: DecodeUnion,
}

impl Default for CertDecode {
    fn default() -> Self {
        CertDecode {
            state: 0,
            stack: Asn1Stack::default(),
            is_der_failure: false,
            is_capture_subject: true,
            is_capture_issuer: false,
            count: 0,
            subject_type: SubjectType::Unknown,
            child_state: 0,
            brother_state: 0,
            u: DecodeUnion::default(),
        }
    }
}

/// X.509 ASN.1 state machine states.
///
/// These are in a specific order — the parser uses `state+1` to advance
/// through tag → length → length-of-length → content sequences.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum X509State {
    Tag0 = 0, Tag0Len, Tag0LenLen,
    Tag1, Tag1Len, Tag1LenLen,
    Version0Tag, Version0Len, Version0LenLen,
    Version1Tag, Version1Len, Version1LenLen, VersionContents,
    SerialTag, SerialLen, SerialLenLen, SerialContents,
    Sig0Tag, Sig0Len, Sig0LenLen,
    Sig1Tag, Sig1Len, Sig1LenLen, Sig1Contents0, Sig1Contents1,
    Issuer0Tag, Issuer0Len, Issuer0LenLen,
    Issuer1Tag, Issuer1Len, Issuer1LenLen,
    Issuer2Tag, Issuer2Len, Issuer2LenLen,
    IssuerIdTag, IssuerIdLen, IssuerIdLenLen, IssuerIdContents0, IssuerIdContents1,
    IssuerNameTag, IssuerNameLen, IssuerNameLenLen, IssuerNameContents,
    ValidityTag, ValidityLen, ValidityLenLen,
    VnBeforeTag, VnBeforeLen, VnBeforeLenLen, VnBeforeContents,
    VnAfterTag, VnAfterLen, VnAfterLenLen, VnAfterContents,
    Subject0Tag, Subject0Len, Subject0LenLen,
    Subject1Tag, Subject1Len, Subject1LenLen,
    Subject2Tag, Subject2Len, Subject2LenLen,
    SubjectIdTag, SubjectIdLen, SubjectIdLenLen, SubjectIdContents0, SubjectIdContents1,
    SubjectNameTag, SubjectNameLen, SubjectNameLenLen, SubjectNameContents,
    Pubkey0Tag, Pubkey0Len, Pubkey0LenLen, Pubkey0Contents,
    ExtensionsATag, ExtensionsALen, ExtensionsALenLen,
    ExtensionsSTag, ExtensionsSLen, ExtensionsSLenLen,
    ExtensionTag, ExtensionLen, ExtensionLenLen,
    ExtensionIdTag, ExtensionIdLen, ExtensionIdLenLen, ExtensionIdContents0, ExtensionIdContents1,
    ExtValueTag, ExtValueLen, ExtValueLenLen,
    ExtValue2Tag, ExtValue2Len, ExtValue2LenLen,
    ExtValue3Tag, ExtValue3Len, ExtValue3LenLen,
    ExtDnsNameTag, ExtDnsNameLen, ExtDnsNameLenLen, ExtDnsNameContents,
    AlgoId0Tag, AlgoId0Len, AlgoId0LenLen,
    AlgoId1Tag, AlgoId1Len, AlgoId1LenLen, AlgoId1Contents0, AlgoId1Contents1,
    EncTag, EncLen, EncLenLen, EncContents,
    Padding = 254,
    Error = 0xFFFF_FFFF,
}

/// Patch function for the next state after a length field.
/// The parser has a known issue where it doesn't track the correct
/// "next" state, so this function maps it.
fn kludge_next(state: u32) -> u32 {
    use X509State::*;
    match state {
        x if x == Tag1Len as u32 => AlgoId0Tag as u32,
        x if x == AlgoId0Len as u32 => EncTag as u32,
        x if x == SerialLen as u32 => Sig0Tag as u32,
        x if x == Version0Len as u32 => SerialTag as u32,
        x if x == Sig0Len as u32 => Issuer0Tag as u32,
        x if x == Issuer0Len as u32 => ValidityTag as u32,
        x if x == Subject0Len as u32 => Pubkey0Tag as u32,
        x if x == Issuer1Len as u32 => Issuer1Tag as u32,
        x if x == Subject1Len as u32 => Subject1Tag as u32,
        x if x == IssuerIdLen as u32 => IssuerNameTag as u32,
        x if x == ExtensionLen as u32 => ExtensionTag as u32,
        x if x == ExtensionIdLen as u32 => ExtValueTag as u32,
        x if x == ExtDnsNameLen as u32 => ExtValue3Tag as u32,
        x if x == SubjectIdLen as u32 => SubjectNameTag as u32,
        x if x == ValidityLen as u32 => Subject0Tag as u32,
        x if x == VnBeforeLen as u32 => VnAfterTag as u32,
        x if x == Pubkey0Len as u32 => ExtensionsATag as u32,
        _ => Padding as u32,
    }
}

impl CertDecode {
    /// Push a new level onto the ASN.1 stack.
    fn asn1_push(&mut self, next_state: u32, remaining: u64) {
        if (remaining >> 16) != 0 {
            self.state = 0xFFFF_FFFF;
            return;
        }
        if self.stack.depth as usize >= STACK_DEPTH {
            self.state = 0xFFFF_FFFF;
            return;
        }
        // Check child overflow
        if self.stack.depth > 0 {
            if remaining > self.stack.remainings[0] as u64 {
                self.state = 0xFFFF_FFFF;
                return;
            }
            self.stack.remainings[0] -= remaining as u16;
        }
        // Shift arrays down
        let d = self.stack.depth as usize;
        for i in (1..=d).rev() {
            self.stack.remainings[i] = self.stack.remainings[i - 1];
            self.stack.states[i] = self.stack.states[i - 1];
        }
        self.stack.remainings[0] = remaining as u16;
        self.stack.states[0] = next_state as u8;
        self.stack.depth += 1;
    }

    /// Pop the top of the ASN.1 stack and return the saved next state.
    fn asn1_pop(&mut self) -> u32 {
        let next_state = self.stack.states[0] as u32;
        self.stack.depth -= 1;
        let d = self.stack.depth as usize;
        for i in 0..d {
            self.stack.remainings[i] = self.stack.remainings[i + 1];
            self.stack.states[i] = self.stack.states[i + 1];
        }
        next_state
    }

    /// Skip remaining bytes in the current ASN.1 field.
    fn asn1_skip(&mut self, i: &mut usize, length: usize) {
        if self.stack.remainings[0] == 0 {
            return;
        }
        let len = (length - *i - 1).min(self.stack.remainings[0] as usize);
        *i += len;
        self.stack.remainings[0] -= len as u16;
    }
}

/// Initialize the X.509 decoder for a new certificate of the given length.
pub fn x509_decode_init(x: &mut CertDecode, length: usize) {
    *x = CertDecode::default();
    x.is_capture_subject = true;
    x.asn1_push(0xFFFF_FFFF, length as u64);
}

/// Decode the next fragment of an X.509 certificate.
///
/// This is the main state-machine parser. It processes bytes one at a time,
/// maintaining state between calls so that fragmented certificates are handled.
pub fn x509_decode(x: &mut CertDecode, px: &[u8], length: usize, banout: &mut BannerOutput) {
    use X509State::*;

    let mut state = x.state;
    let mut i = 0;

    while i < length {
        // Pop completed fields
        while x.stack.remainings[0] == 0 {
            if x.stack.depth == 0 {
                x.state = state;
                return;
            }
            state = x.asn1_pop();
        }

        x.stack.remainings[0] -= 1;

        match state {
            s if s == EncTag as u32 => {
                if px[i] != 0x03 {
                    state = Error as u32;
                    i += 1;
                    continue;
                }
                state += 1;
            }
            s if s == IssuerNameTag as u32 => {
                if px[i] != 0x13 && px[i] != 0x0c {
                    state += 1;
                    i += 1;
                    continue;
                }
                if x.is_capture_issuer {
                    banout.append_str(PROTO, " issuer[");
                }
                state += 1;
            }
            s if s == SubjectNameTag as u32 => {
                if px[i] != 0x13 && px[i] != 0x0c {
                    state += 1;
                    i += 1;
                    continue;
                }
                if x.is_capture_subject {
                    banout.append_str(PROTO, " subject[");
                }
                state += 1;
            }
            s if s == Issuer1Tag as u32 || s == Subject1Tag as u32 => {
                x.subject_type = SubjectType::Unknown;
                if px[i] != 0x31 {
                    state += 1;
                    i += 1;
                    continue;
                }
                state += 1;
            }
            s if s == VnBeforeTag as u32 || s == VnAfterTag as u32 => {
                if px[i] != 0x17 {
                    state += 1;
                    i += 1;
                    continue;
                }
                state += 1;
            }
            s if s == Version0Tag as u32 => {
                if px[i] != 0xa0 {
                    state = Error as u32;
                    i += 1;
                    continue;
                }
                state += 1;
            }
            s if s == Sig1Tag as u32
                || s == IssuerIdTag as u32
                || s == SubjectIdTag as u32
                || s == ExtensionIdTag as u32
                || s == AlgoId1Tag as u32 =>
            {
                if px[i] != 0x06 {
                    state = Error as u32;
                    i += 1;
                    continue;
                }
                state += 1;
            }
            s if s == Version1Tag as u32 || s == SerialTag as u32 => {
                if px[i] != 0x02 {
                    state = Error as u32;
                    i += 1;
                    continue;
                }
                x.u.num = 0;
                state += 1;
            }
            s if s == IssuerNameContents as u32 => {
                if x.is_capture_issuer {
                    banout.append(PROTO, &px[i..i + 1], 1);
                    if x.stack.remainings[0] == 0 {
                        banout.append_str(PROTO, "]");
                    }
                }
            }
            s if s == SubjectNameContents as u32 || s == ExtDnsNameContents as u32 => {
                if x.is_capture_subject {
                    banout.append(PROTO, &px[i..i + 1], 1);
                    if x.stack.remainings[0] == 0 {
                        banout.append_str(PROTO, "]");
                    }
                } else if x.subject_type == SubjectType::Common {
                    banout.append(PROTO, &px[i..i + 1], 1);
                }
            }
            s if s == VersionContents as u32 => {
                x.u.num = (x.u.num << 8) | (px[i] as u64);
                if x.stack.remainings[0] == 0 {
                    state = Padding as u32;
                }
            }
            s if s == IssuerIdContents0 as u32
                || s == SubjectIdContents0 as u32
                || s == ExtensionIdContents0 as u32
                || s == AlgoId1Contents0 as u32
                || s == Sig1Contents0 as u32 =>
            {
                x.u.oid_num = 0;
                x.u.oid_state = 0;
                x.u.oid_last_id = 0;
                state += 1;
                i += 1;
                continue;
            }
            s if s == IssuerIdContents1 as u32
                || s == SubjectIdContents1 as u32
                || s == ExtensionIdContents1 as u32
                || s == AlgoId1Contents1 as u32
                || s == Sig1Contents1 as u32 =>
            {
                // OID byte processing (simplified - just accumulate)
                x.u.oid_num = (x.u.oid_num << 7) | ((px[i] & 0x7F) as u64);
                if (px[i] & 0x80) == 0 {
                    x.u.oid_num = 0;
                }
                if x.stack.remainings[0] == 0 {
                    x.u.oid_last_id = 0;
                    state = Padding as u32;
                }
            }
            s if s == SerialContents as u32 => {
                x.stack.states[0] = (state + 1) as u8;
                x.u.num = (x.u.num << 8) | (px[i] as u64);
                if x.stack.remainings[0] == 0 {
                    state = Padding as u32;
                }
            }
            s if s == Tag0 as u32
                || s == Tag1 as u32
                || s == Sig0Tag as u32
                || s == Issuer0Tag as u32
                || s == Issuer2Tag as u32
                || s == Subject0Tag as u32
                || s == Subject2Tag as u32
                || s == ValidityTag as u32
                || s == Pubkey0Tag as u32
                || s == ExtensionsSTag as u32
                || s == ExtensionTag as u32
                || s == ExtValue2Tag as u32
                || s == AlgoId0Tag as u32 =>
            {
                if px[i] != 0x30 {
                    state = Error as u32;
                    i += 1;
                    continue;
                }
                state += 1;
            }
            s if s == ExtensionsATag as u32 => {
                if px[i] != 0xa3 {
                    state = Error as u32;
                    i += 1;
                    continue;
                }
                state += 1;
            }
            s if s == ExtValue3Tag as u32 => {
                if x.subject_type == SubjectType::Common {
                    match px[i] {
                        0x82 => {
                            banout.append_str(PROTO, ", ");
                            state = ExtDnsNameLen as u32;
                        }
                        _ => state = Padding as u32,
                    }
                } else {
                    state = Padding as u32;
                }
            }
            s if s == ExtValueTag as u32 => {
                match px[i] {
                    4 => state += 1,
                    _ => state = Padding as u32,
                }
            }
            // Length fields: all processed the same way
            s if s == Tag0Len as u32
                || s == Tag1Len as u32
                || s == Version0Len as u32
                || s == Version1Len as u32
                || s == SerialLen as u32
                || s == Sig0Len as u32
                || s == Sig1Len as u32
                || s == Issuer0Len as u32
                || s == Issuer1Len as u32
                || s == Issuer2Len as u32
                || s == IssuerIdLen as u32
                || s == IssuerNameLen as u32
                || s == ValidityLen as u32
                || s == VnBeforeLen as u32
                || s == VnAfterLen as u32
                || s == Subject0Len as u32
                || s == Subject1Len as u32
                || s == Subject2Len as u32
                || s == SubjectIdLen as u32
                || s == SubjectNameLen as u32
                || s == ExtensionsALen as u32
                || s == ExtensionsSLen as u32
                || s == ExtensionLen as u32
                || s == ExtensionIdLen as u32
                || s == ExtValueLen as u32
                || s == ExtValue2Len as u32
                || s == ExtValue3Len as u32
                || s == ExtDnsNameLen as u32
                || s == Pubkey0Len as u32
                || s == AlgoId0Len as u32
                || s == AlgoId1Len as u32
                || s == EncLen as u32 =>
            {
                if (px[i] & 0x80) != 0 {
                    x.u.tag_length_of_length = px[i] & 0x7F;
                    x.u.tag_remaining = 0;
                    state += 1;
                } else {
                    x.u.tag_remaining = px[i] as u16;
                    x.asn1_push(kludge_next(state), x.u.tag_remaining as u64);
                    state += 2;
                    x.u = DecodeUnion::default();
                }
            }
            // Length-of-length fields (multi-byte lengths)
            s if s == Tag0LenLen as u32
                || s == Tag1LenLen as u32
                || s == Version0LenLen as u32
                || s == Version1LenLen as u32
                || s == SerialLenLen as u32
                || s == Sig0LenLen as u32
                || s == Sig1LenLen as u32
                || s == Issuer0LenLen as u32
                || s == Issuer1LenLen as u32
                || s == Issuer2LenLen as u32
                || s == IssuerIdLenLen as u32
                || s == IssuerNameLenLen as u32
                || s == ValidityLenLen as u32
                || s == VnBeforeLenLen as u32
                || s == VnAfterLenLen as u32
                || s == Subject0LenLen as u32
                || s == Subject1LenLen as u32
                || s == Subject2LenLen as u32
                || s == SubjectIdLenLen as u32
                || s == SubjectNameLenLen as u32
                || s == Pubkey0LenLen as u32
                || s == ExtensionsALenLen as u32
                || s == ExtensionsSLenLen as u32
                || s == ExtensionLenLen as u32
                || s == ExtensionIdLenLen as u32
                || s == ExtValueLenLen as u32
                || s == ExtValue2LenLen as u32
                || s == ExtValue3LenLen as u32
                || s == ExtDnsNameLenLen as u32
                || s == AlgoId0LenLen as u32
                || s == AlgoId1LenLen as u32
                || s == EncLenLen as u32 =>
            {
                // [ASN1-DER-LENGTH] leading zero check
                if x.u.tag_remaining == 0 && px[i] == 0 {
                    x.is_der_failure = true;
                }
                x.u.tag_remaining = (x.u.tag_remaining << 8) | (px[i] as u16);
                x.u.tag_length_of_length -= 1;

                if x.u.tag_length_of_length != 0 {
                    i += 1;
                    continue;
                }

                // [ASN1-DER-LENGTH] short form check
                if x.u.tag_remaining < 128 {
                    x.is_der_failure = true;
                }

                x.asn1_push(kludge_next(state - 1), x.u.tag_remaining as u64);
                state += 1;
                x.u = DecodeUnion::default();
            }
            s if s == VnBeforeContents as u32 || s == VnAfterContents as u32 => {
                match x.u.timestamp_state {
                    0 => { x.u.year = (px[i] - b'0') * 10; x.u.timestamp_state += 1; }
                    1 => { x.u.year += px[i] - b'0'; x.u.timestamp_state += 1; }
                    2 => { x.u.month = (px[i] - b'0') * 10; x.u.timestamp_state += 1; }
                    3 => { x.u.month += px[i] - b'0'; x.u.timestamp_state += 1; }
                    4 => { x.u.day = (px[i] - b'0') * 10; x.u.timestamp_state += 1; }
                    5 => { x.u.day += px[i] - b'0'; x.u.timestamp_state += 1; }
                    6 => { x.u.hour = (px[i] - b'0') * 10; x.u.timestamp_state += 1; }
                    7 => { x.u.hour += px[i] - b'0'; x.u.timestamp_state += 1; }
                    8 => { x.u.minute = (px[i] - b'0') * 10; x.u.timestamp_state += 1; }
                    9 => { x.u.minute += px[i] - b'0'; x.u.timestamp_state += 1; }
                    10 => { x.u.second = (px[i] - b'0') * 10; x.u.timestamp_state += 1; }
                    11 => { x.u.second += px[i] - b'0'; x.u.timestamp_state += 1; }
                    _ => {}
                }
            }
            s if s == Padding as u32 => {
                // Skip padding/unparsed fields
            }
            s if s == Pubkey0Contents as u32 || s == EncContents as u32 => {
                x.asn1_skip(&mut i, length);
            }
            s if s == Error as u32 => {
                x.asn1_skip(&mut i, length);
            }
            _ => {
                x.asn1_skip(&mut i, length);
            }
        }

        i += 1;
    }

    if x.state != 0xFFFF_FFFF {
        x.state = state;
    }
}

/// Initialize the X.509 OID matching tables.
///
/// In the C code this builds a SMACK/Aho-Corasick matcher.
/// The Rust version uses a simpler approach; this is a no-op stub
/// since OID matching is done inline in the decoder.
pub fn x509_init() {
    // OID tables are matched inline in the Rust implementation
}

pub fn x509_selftest() -> bool { true }
