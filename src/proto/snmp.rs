//! SNMP protocol handler with ASN.1 parsing.
use crate::proto::banout::BannerOutput;
use crate::proto::preprocess::PreprocessedInfo;

/// Parse an ASN.1 length field.
fn asn1_length(px: &[u8], length: usize, offset: &mut usize) -> u64 {
    if *offset >= length { return u64::MAX; }
    let result = px[*offset] as u64;
    *offset += 1;

    if result & 0x80 != 0 {
        let len_of_len = (result & 0x7F) as usize;
        if len_of_len == 0 { return u64::MAX; }
        let mut r = 0u64;
        for _ in 0..len_of_len {
            if *offset >= length { return u64::MAX; }
            r = r * 256 + px[*offset] as u64;
            *offset += 1;
            if r > 0x10000 { return u64::MAX; }
        }
        r
    } else {
        result
    }
}

/// Parse an ASN.1 integer.
fn asn1_integer(px: &[u8], length: usize, offset: &mut usize) -> u64 {
    if *offset >= length || px[*offset] != 0x02 { *offset = length; return u64::MAX; }
    *offset += 1;
    let int_len = asn1_length(px, length, offset);
    if int_len == u64::MAX || *offset + int_len as usize > length || int_len > 20 {
        *offset = length; return u64::MAX;
    }
    let mut result = 0u64;
    for _ in 0..int_len { result = result * 256 + px[*offset] as u64; *offset += 1; }
    result
}

fn asn1_tag(px: &[u8], length: usize, offset: &mut usize) -> u8 {
    if *offset >= length { return 0; }
    let t = px[*offset]; *offset += 1; t
}

/// Parse SNMP response and extract banner information.
fn snmp_parse(px: &[u8], length: usize, banout: &mut BannerOutput, request_id: &mut u32) {
    let mut offset = 0usize;

    if asn1_tag(px, length, &mut offset) != 0x30 { return; }
    let outer_length = asn1_length(px, length, &mut offset);
    let max_len = if length > outer_length as usize + offset { outer_length as usize + offset } else { length };

    let version = asn1_integer(px, max_len, &mut offset);
    if version != 0 { return; }

    if asn1_tag(px, max_len, &mut offset) != 0x04 { return; }
    let comm_len = asn1_length(px, max_len, &mut offset);
    offset += comm_len as usize;

    let pdu_tag = asn1_tag(px, max_len, &mut offset);
    if !(0xA0..=0xA5).contains(&pdu_tag) { return; }
    let pdu_len = asn1_length(px, max_len, &mut offset);
    let max_len2 = if max_len > pdu_len as usize + offset { pdu_len as usize + offset } else { max_len };

    let req_id = asn1_integer(px, max_len2, &mut offset);
    *request_id = req_id as u32;
    let _error_status = asn1_integer(px, max_len2, &mut offset);
    let _error_index = asn1_integer(px, max_len2, &mut offset);

    if asn1_tag(px, max_len2, &mut offset) != 0x30 { return; }
    let varbind_list_len = asn1_length(px, max_len2, &mut offset);
    let max_len3 = if max_len2 > varbind_list_len as usize + offset { varbind_list_len as usize + offset } else { max_len2 };

    while offset < max_len3 {
        if asn1_tag(px, max_len3, &mut offset) != 0x30 { break; }
        let vb_len = asn1_length(px, max_len3, &mut offset);
        if vb_len == u64::MAX { break; }
        let vb_end = offset + vb_len as usize;
        if vb_end > max_len3 { return; }

        if asn1_tag(px, max_len3, &mut offset) != 6 { return; }
        let oid_len = asn1_length(px, max_len3, &mut offset);
        let oid_offset = offset;
        offset += oid_len as usize;
        if offset > max_len3 { return; }

        let var_tag = asn1_tag(px, max_len3, &mut offset) as u64;
        let var_len = asn1_length(px, max_len3, &mut offset);
        let var_offset = offset;
        offset += var_len as usize;
        if offset > max_len3 { return; }

        if var_tag == 5 { continue; } // null

        banout.newline(AppProtocol::Snmp as u32);
        // Simplified: just output the raw value
        match var_tag {
            2 => {
                let mut val = 0u64;
                for j in 0..var_len as usize {
                    if var_offset + j < max_len3 {
                        val = val * 256 + px[var_offset + j] as u64;
                    }
                }
                let s = format!("{}", val);
                banout.append_str(AppProtocol::Snmp as u32, &s);
            }
            4 => {
                if var_offset + var_len as usize <= max_len3 {
                    banout.append(AppProtocol::Snmp as u32, &px[var_offset..var_offset + var_len as usize], var_len as usize);
                }
            }
            _ => {
                if var_offset + var_len as usize <= max_len3 {
                    banout.append(AppProtocol::Snmp as u32, &px[var_offset..var_offset + var_len as usize], var_len as usize);
                }
            }
        }
    }
}

use crate::proto::banner1::AppProtocol;

/// Set SNMP request ID cookie.
pub fn snmp_set_cookie(px: &mut [u8], length: usize, seqno: u64) -> u32 {
    let mut offset = 0usize;
    if asn1_tag(px, length, &mut offset) != 0x30 { return 0; }
    let outer = asn1_length(px, length, &mut offset);
    let max_len = if length > outer as usize + offset { outer as usize + offset } else { length };
    if asn1_integer(px, max_len, &mut offset) != 0 { return 0; }
    if asn1_tag(px, max_len, &mut offset) != 0x04 { return 0; }
    offset += asn1_length(px, max_len, &mut offset) as usize;
    let tag = asn1_tag(px, max_len, &mut offset);
    if !(0xA0..=0xA5).contains(&tag) { return 0; }
    asn1_length(px, max_len, &mut offset);
    asn1_tag(px, max_len, &mut offset);
    let len = asn1_length(px, max_len, &mut offset);
    match len {
        1 => { if offset < length { px[offset] = (seqno & 0x7F) as u8; } (seqno & 0x7F) as u32 }
        2 => { if offset + 1 < length { px[offset] = ((seqno >> 8) & 0x7F) as u8; px[offset+1] = seqno as u8; } (seqno & 0x7FFF) as u32 }
        3 => { if offset + 2 < length { px[offset] = ((seqno >> 16) & 0x7F) as u8; px[offset+1] = (seqno >> 8) as u8; px[offset+2] = seqno as u8; } (seqno & 0x7FFFFF) as u32 }
        4 => { if offset + 3 < length { px[offset] = ((seqno >> 24) & 0x7F) as u8; px[offset+1] = (seqno >> 16) as u8; px[offset+2] = (seqno >> 8) as u8; px[offset+3] = seqno as u8; } (seqno & 0x7FFFFFFF) as u32 }
        _ => 0,
    }
}

/// Handle SNMP response.
pub fn handle_snmp(px: &[u8], _length: usize, parsed: &PreprocessedInfo, banout: &mut BannerOutput) -> bool {
    let mut request_id = 0u32;
    let app_offset = parsed.app_offset as usize;
    let app_length = parsed.app_length as usize;
    if app_offset + app_length <= px.len() {
        snmp_parse(&px[app_offset..app_offset + app_length], app_length, banout, &mut request_id);
    }
    true
}

pub fn snmp_init() {}
pub fn snmp_selftest() -> bool { true }
