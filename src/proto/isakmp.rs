//! ISAKMP (Internet Security Association and Key Management Protocol) parser.
//!
//! Parses IKEv1 (ISAKMP) handshake responses from UDP port 500.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                          Initiator Cookie                     |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                          Responder Cookie                     |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |  Next Payload | MjVer | MnVer | Exchange Type |    Flags      |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                          Message ID                           |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                            Length                             |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::proto::banout::BannerOutput;
use crate::proto::banner1::AppProtocol;

const PROTO: u32 = AppProtocol::Isakmp as u32;

/// An extract-buffer for reading sequential bytes from a packet.
struct Ebuf<'a> {
    buf: &'a [u8],
    offset: usize,
    max: usize,
}

impl<'a> Ebuf<'a> {
    fn new(buf: &'a [u8], max: usize) -> Self {
        Ebuf { buf, offset: 0, max }
    }

    fn next_byte(&mut self) -> u8 {
        if self.offset < self.max && self.offset < self.buf.len() {
            let b = self.buf[self.offset];
            self.offset += 1;
            b
        } else {
            0
        }
    }

    fn next_short16(&mut self) -> u32 {
        let hi = self.next_byte() as u32;
        let lo = self.next_byte() as u32;
        (hi << 8) | lo
    }

    fn next_int32(&mut self) -> u32 {
        let b0 = self.next_byte() as u32;
        let b1 = self.next_byte() as u32;
        let b2 = self.next_byte() as u32;
        let b3 = self.next_byte() as u32;
        (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }

    fn next_long64(&mut self) -> u64 {
        let mut val = 0u64;
        for _ in 0..8 {
            val = (val << 8) | (self.next_byte() as u64);
        }
        val
    }
}

/// Parsed payload header.
struct Payload {
    next: u8,
    #[allow(dead_code)]
    reserved: u8,
    length: usize,
    ebuf_offset: usize,
    ebuf_max: usize,
}

fn get_payload(ebuf: &Ebuf) -> Payload {
    let start = ebuf.offset;
    let next = if ebuf.offset < ebuf.max && ebuf.offset < ebuf.buf.len() {
        ebuf.buf[ebuf.offset]
    } else { 0 };
    let reserved = if ebuf.offset + 1 < ebuf.max && ebuf.offset + 1 < ebuf.buf.len() {
        ebuf.buf[ebuf.offset + 1]
    } else { 0 };
    let length_hi = if ebuf.offset + 2 < ebuf.max && ebuf.offset + 2 < ebuf.buf.len() {
        ebuf.buf[ebuf.offset + 2] as usize
    } else { 0 };
    let length_lo = if ebuf.offset + 3 < ebuf.max && ebuf.offset + 3 < ebuf.buf.len() {
        ebuf.buf[ebuf.offset + 3] as usize
    } else { 0 };
    let length = (length_hi << 8) | length_lo;

    let inner_max = if length >= 4 {
        (start + 4 + length - 4).min(ebuf.max)
    } else {
        start + 4
    };

    Payload {
        next,
        reserved,
        length,
        ebuf_offset: start + 4,
        ebuf_max: inner_max,
    }
}

fn parse_transform(banout: &mut BannerOutput, ebuf: &mut Ebuf) {
    let _transform_num = ebuf.next_byte();
    let transform_id = ebuf.next_byte();

    match transform_id {
        1 => {
            banout.append_str(PROTO, "trans=IKE ");
            ebuf.next_short16(); // reserved
            while ebuf.offset < ebuf.max {
                let x = ebuf.next_short16();
                let val = ebuf.next_short16();
                if (x & 0x8000) == 0 {
                    return;
                }
                match x & 0x7FFF {
                    1 => match val {
                        5 => banout.append_str(PROTO, "3DES-CBC "),
                        7 => banout.append_str(PROTO, "AES-CBC "),
                        _ => { let s = format!("encrypt=0x{:x} ", val); banout.append_str(PROTO, &s); }
                    },
                    2 => match val {
                        2 => banout.append_str(PROTO, "SHA "),
                        _ => { let s = format!("hash=0x{:x} ", val); banout.append_str(PROTO, &s); }
                    },
                    3 => match val {
                        1 | 5 => banout.append_str(PROTO, "PSK "),
                        _ => { let s = format!("auth=0x{:x} ", val); banout.append_str(PROTO, &s); }
                    },
                    4 | 11 | 12 => {} // group, life type, life duration
                    14 => { let s = format!("key={}bits ", val); banout.append_str(PROTO, &s); }
                    _ => {
                        let s = format!("val=0x{:04x}{:04x} ", x & 0x7FFF, val);
                        banout.append_str(PROTO, &s);
                    }
                }
            }
        }
        _ => {
            let s = format!("trans={} ", transform_id);
            banout.append_str(PROTO, &s);
        }
    }
}

fn parse_transforms(banout: &mut BannerOutput, ebuf: &mut Ebuf, _next_payload: u8) {
    while ebuf.offset + 4 <= ebuf.max {
        let payload = get_payload(ebuf);
        let mut inner = Ebuf {
            buf: ebuf.buf,
            offset: payload.ebuf_offset,
            max: payload.ebuf_max,
        };
        parse_transform(banout, &mut inner);
        ebuf.offset += payload.length;
        if payload.next == 0 {
            break;
        }
    }
}

fn parse_proposal(banout: &mut BannerOutput, ebuf: &mut Ebuf) {
    let proposal_num = ebuf.next_byte();
    let s = format!("{} ", proposal_num);
    banout.append_str(PROTO, &s);

    let proto_id = ebuf.next_byte();
    match proto_id {
        1 => banout.append_str(PROTO, "id=ISAKMP "),
        _ => { let s = format!("id={} ", proto_id); banout.append_str(PROTO, &s); }
    }
    ebuf.next_byte(); // spi size
    ebuf.next_byte(); // proposal transforms

    parse_transforms(banout, ebuf, 0);
}

fn parse_proposals(banout: &mut BannerOutput, ebuf: &mut Ebuf, _next_payload: u8) {
    while ebuf.offset + 4 <= ebuf.max {
        let payload = get_payload(ebuf);
        let mut inner = Ebuf {
            buf: ebuf.buf,
            offset: payload.ebuf_offset,
            max: payload.ebuf_max,
        };
        parse_proposal(banout, &mut inner);
        ebuf.offset += payload.length;
        if payload.next == 0 {
            break;
        }
    }
}

fn payload_security_association(banout: &mut BannerOutput, ebuf: &mut Ebuf) {
    let doi = ebuf.next_int32();
    let bitmap = ebuf.next_int32();
    match doi {
        0 => banout.append_str(PROTO, "DOI=generic "),
        1 => {
            banout.append_str(PROTO, "DOI=ipsec ");
            if bitmap & 0x01 != 0 {
                banout.append_str(PROTO, "IDENTITY ");
            }
            if bitmap & 0x02 != 0 {
                banout.append_str(PROTO, "SECRECY ");
            }
            if bitmap & 0x04 != 0 {
                banout.append_str(PROTO, "INTEGRITY ");
            }
            parse_proposals(banout, ebuf, 0);
        }
        _ => { let s = format!("DOI={} ", doi); banout.append_str(PROTO, &s); }
    }
}

fn payload_vendor_id(banout: &mut BannerOutput, ebuf: &Ebuf) {
    let length = ebuf.max.saturating_sub(ebuf.offset);
    let data = if ebuf.offset + length <= ebuf.buf.len() {
        &ebuf.buf[ebuf.offset..ebuf.offset + length]
    } else {
        return;
    };

    let vendors: &[(usize, &[u8], &str)] = &[
        (16, b"\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f", "RFC-39947-NAT"),
        (16, b"\x12\xf5\xf2\x8c\x45\x71\x68\xa9\x70\x2d\x9f\xe2\x74\xcc\x01\x00", "CISCO-UNITY"),
        (16, b"\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00", "RFC3706-DPD"),
        (8, b"\x09\x00\x26\x89\xdf\xd6\xb7\x12", "XAUTH"),
    ];

    for &(vlen, vdata, vname) in vendors {
        if length == vlen && data == vdata {
            banout.append_str(PROTO, "{");
            banout.append_str(PROTO, vname);
            banout.append_str(PROTO, "} ");
            break;
        }
    }
}

/// Parse an ISAKMP response and produce banner output.
///
/// Returns `true` if valid ISAKMP was parsed.
pub fn isakmp_parse_response(banout: &mut BannerOutput, px: &[u8], length: usize) -> bool {
    if length < 28 || px.len() < length {
        return false;
    }

    let mut ebuf = Ebuf::new(px, length);

    // Skip cookies (8 bytes each)
    ebuf.next_long64();
    ebuf.next_long64();

    // Parse header
    let next_payload = ebuf.next_byte();
    let version = ebuf.next_byte();
    let exchange_type = ebuf.next_byte();
    let flags = ebuf.next_byte();
    ebuf.next_int32(); // message ID
    let my_length = ebuf.next_int32() as usize;
    if ebuf.max >= my_length {
        ebuf.max = my_length;
    }

    let s = format!("v{}.{} ", (version >> 4) & 0xF, version & 0xF);
    banout.append_str(PROTO, &s);
    match exchange_type {
        2 => banout.append_str(PROTO, "xchg=id-prot "),
        _ => { let s = format!("xchg={} ", exchange_type); banout.append_str(PROTO, &s); }
    }

    if flags & 1 != 0 {
        banout.append_str(PROTO, "ENCRYPTED ");
        return true;
    }

    // Payload names
    let payload_names: &[&str] = &[
        "[0]", "[SEC-ASSOC]", "[2]", "[3]",
        "[KEY-XCHG]", "[5]", "[6]", "[7]",
        "[8]", "[9]", "[NONCE]", "[11]",
        "[12]", "", /*vendor-id*/ "[14]", "[15]",
        "[16]", "[17]", "[18]", "[19]",
        "[NAT-D]", "[21]", "[22]", "[23]",
        "[24]", "[25]", "[26]", "[27]",
        "[28]", "[29]", "[30]", "[31]",
    ];

    let mut next = next_payload;
    while next != 0 && ebuf.offset + 4 <= ebuf.max {
        let payload = get_payload(&ebuf);

        // Print payload name
        let idx = next as usize;
        if idx < payload_names.len() {
            banout.append_str(PROTO, payload_names[idx]);
        } else {
            let s = format!("[{}] ", next);
            banout.append_str(PROTO, &s);
        }

        // Handle specific payload types
        let inner_buf = ebuf.buf;
        match next {
            1 => {
                let mut inner = Ebuf {
                    buf: inner_buf,
                    offset: payload.ebuf_offset,
                    max: payload.ebuf_max,
                };
                payload_security_association(banout, &mut inner);
            }
            13 => {
                let inner = Ebuf {
                    buf: inner_buf,
                    offset: payload.ebuf_offset,
                    max: payload.ebuf_max,
                };
                payload_vendor_id(banout, &inner);
            }
            _ => {}
        }

        ebuf.offset += payload.length;
        next = payload.next;
    }

    true
}

/// Set the ISAKMP initiator cookie in an outgoing packet.
pub fn isakmp_set_cookie(px: &mut [u8], length: usize, seqno: u64) -> u32 {
    if length < 8 {
        return 0;
    }
    for i in 0..8 {
        px[i] = (seqno >> (56 - 8 * i)) as u8;
    }
    0
}

/// Helper to test a sample packet against expected output prefix.
fn test_sample(sample: &[u8], expected: &str) -> bool {
    let mut banout = BannerOutput::new();
    let is_valid = isakmp_parse_response(&mut banout, sample, sample.len());
    if !is_valid {
        return false;
    }
    // Check if banner starts with expected string
    if let Some(banner_bytes) = banout.string(PROTO) {
        let banner = String::from_utf8_lossy(banner_bytes);
        banner.starts_with(expected)
    } else {
        false
    }
}

/// Self-test for the ISAKMP parser.
pub fn proto_isakmp_selftest() -> bool {
    let sample1: &[u8] = b"\x00\x00\x00\x00\xc1\x18\
\x84\xda\xbe\x3d\xc6\x8e\xea\xf2\xda\xac\x01\x10\x02\x00\x00\x00\
\x00\x00\x00\x00\x00\x50\x00\x00\x00\x34\x00\x00\x00\x01\x00\x00\
\x00\x01\x00\x00\x00\x28\x01\x01\x00\x01\x00\x00\x00\x20\x01\x01\
\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x04\x00\x02\x80\x03\
\x00\x01\x80\x0b\x00\x01\x80\x0c\x00\x01";

    let sample2: &[u8] = b"\xe4\x7a\x59\x1f\xd0\x57\
\x58\x7f\xa0\x0b\x8e\xf0\x90\x2b\xb8\xec\x01\x10\x02\x00\x00\x00\
\x00\x00\x00\x00\x00\x6c\x0d\x00\x00\x3c\x00\x00\x00\x01\x00\x00\
\x00\x01\x00\x00\x00\x30\x01\x01\x00\x01\x00\x00\x00\x28\x01\x01\
\x00\x00\x80\x01\x00\x07\x80\x0e\x00\x80\x80\x02\x00\x02\x80\x04\
\x00\x02\x80\x03\x00\x01\x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x01\
\x51\x80\x00\x00\x00\x14\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\
\x28\xf2\x0e\x95\x45\x2f";

    let sample4: &[u8] = b"\xe4\x7a\x59\x1f\xd0\x57\x58\x7f\xa0\x0b\x8e\xf0\x90\x2b\xb8\xec\
\x05\x10\x02\x01\x00\x00\x00\x00\x00\x00\x00\x4c\xb0\x32\xaa\xa6\
\x2a\x70\x71\x8e\xf2\xf0\x99\xcd\xd8\xbf\x6e\xb9\x04\x42\xed\x9d\
\x72\x6d\xaa\x6b\x6d\xad\x62\x40\x26\xf5\xfb\xb1\x73\xd9\xf7\x75\
\x71\xc2\x32\xa5\x6a\xcf\xe1\x2c\x74\x03\xe9\x53";

    if !test_sample(sample1, "v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec IDENTITY 1 id=ISAKMP trans=IKE 3DES-CBC SHA PSK") {
        return false;
    }

    if !test_sample(sample2, "v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec IDENTITY 1 id=ISAKMP trans=IKE AES-CBC key=128bits SHA PSK") {
        return false;
    }

    if !test_sample(sample4, "v1.0 xchg=id-prot ENCRYPTED") {
        return false;
    }

    true
}
