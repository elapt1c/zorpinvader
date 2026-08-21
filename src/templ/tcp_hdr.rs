//! TCP header template construction with options.
//!
//! This module edits an existing TCP packet template, adding, removing,
//! and modifying TCP options (MSS, window scale, SACK, timestamps, etc.).
//!
//! TCP header layout (RFC 793):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |          Source Port          |       Destination Port        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Sequence Number                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Acknowledgment Number                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Data |           |U|A|P|R|S|F|                               |
//! | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
//! |       |           |G|K|H|T|N|N|                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           Checksum            |         Urgent Pointer        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Options                    |    Padding    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use super::opts::{AddRemove, TemplateOptions};

// TCP option kind constants
const OPT_EOL: u8 = 0x00;
const OPT_NOP: u8 = 0x01;
const OPT_MSS: u8 = 0x02;
const OPT_WSCALE: u8 = 0x03;
const OPT_SACKOK: u8 = 0x04;
const OPT_SACK: u8 = 0x05;
const OPT_TIMESTAMP: u8 = 0x08;

/// Maximum TCP header length (15 * 4 = 60 bytes).
const MAX_TCP_HDR_LEN: usize = 60;

/// Information about a found TCP option.
#[derive(Debug)]
struct TcpOpt {
    kind: u8,
    /// Offset to the option data (past kind and length bytes).
    data_offset: usize,
    /// Length of the option data (not including kind and length bytes).
    data_length: usize,
}

/// Location of the TCP header within a packet buffer.
#[derive(Debug, Clone)]
struct TcpHdr {
    /// Offset to the start of the TCP header.
    begin: usize,
    /// Offset to the end of the TCP header (start of payload).
    max: usize,
    /// Offset to the IP header.
    ip_offset: usize,
    /// IP version (4 or 6).
    ip_version: u8,
}

// -----------------------------------------------------------------------
// Minimal packet parsing (just enough for TCP header location)
// -----------------------------------------------------------------------

/// Find the TCP header in an Ethernet-framed packet.
///
/// Supports Ethernet + IPv4/IPv6 with possible 802.1Q VLAN tagging.
/// Returns `None` if the packet doesn't contain a valid TCP header.
fn find_tcp_header(buf: &[u8]) -> Option<TcpHdr> {
    if buf.len() < 14 {
        return None;
    }

    let mut offset = 0usize;

    // Parse Ethernet header
    let mut ethertype = (buf[12] as u16) << 8 | (buf[13] as u16);
    offset = 14;

    // Handle 802.1Q VLAN tag
    if ethertype == 0x8100 {
        if buf.len() < 18 {
            return None;
        }
        ethertype = (buf[16] as u16) << 8 | (buf[17] as u16);
        offset = 18;
    }

    let ip_offset = offset;

    match ethertype {
        0x0800 => {
            // IPv4
            if buf.len() < ip_offset + 20 {
                return None;
            }
            let ip_version = (buf[ip_offset] >> 4) & 0x0F;
            if ip_version != 4 {
                return None;
            }
            let ip_hdr_len = ((buf[ip_offset] & 0x0F) as usize) * 4;
            let ip_protocol = buf[ip_offset + 9];

            if ip_protocol != 6 {
                // Not TCP
                return None;
            }

            let tcp_offset = ip_offset + ip_hdr_len;
            if buf.len() < tcp_offset + 20 {
                return None;
            }

            let tcp_hdr_len = tcp_header_length(buf, tcp_offset);
            let tcp_max = tcp_offset + tcp_hdr_len;

            if tcp_max > buf.len() {
                return None;
            }

            Some(TcpHdr {
                begin: tcp_offset,
                max: tcp_max,
                ip_offset,
                ip_version: 4,
            })
        }
        0x86DD => {
            // IPv6
            if buf.len() < ip_offset + 40 {
                return None;
            }
            let ip_version = (buf[ip_offset] >> 4) & 0x0F;
            if ip_version != 6 {
                return None;
            }
            let next_header = buf[ip_offset + 6];

            if next_header != 6 {
                // Not TCP (simplified: doesn't handle extension headers)
                return None;
            }

            let tcp_offset = ip_offset + 40;
            if buf.len() < tcp_offset + 20 {
                return None;
            }

            let tcp_hdr_len = tcp_header_length(buf, tcp_offset);
            let tcp_max = tcp_offset + tcp_hdr_len;

            if tcp_max > buf.len() {
                return None;
            }

            Some(TcpHdr {
                begin: tcp_offset,
                max: tcp_max,
                ip_offset,
                ip_version: 6,
            })
        }
        _ => None,
    }
}

/// Get the TCP header length from the data offset field.
fn tcp_header_length(buf: &[u8], offset: usize) -> usize {
    if offset + 12 >= buf.len() {
        return 20;
    }
    ((buf[offset + 12] >> 4) as usize) * 4
}

/// Get the start of the options field (20 bytes into TCP header).
fn opt_begin(hdr: &TcpHdr) -> usize {
    hdr.begin + 20
}

/// Advance to the next option in the options list.
fn opt_next(buf: &[u8], hdr: &TcpHdr, offset: usize) -> usize {
    if offset >= hdr.max {
        return hdr.max;
    }
    let kind = buf[offset];
    if kind == OPT_EOL {
        return hdr.max;
    } else if kind == OPT_NOP {
        return offset + 1;
    } else if offset + 1 >= hdr.max {
        return hdr.max;
    } else {
        let len = buf[offset + 1] as usize;
        if len < 2 || offset + len > hdr.max {
            return hdr.max; // corrupt
        }
        offset + len
    }
}

/// Search the options list for a specific kind.
///
/// Returns the option if found, along with any leading NOP count.
fn find_opt(buf: &[u8], hdr: &TcpHdr, kind: u8) -> (usize, u32) {
    let mut nop_count: u32 = 0;
    let mut offset = opt_begin(hdr);

    while offset < hdr.max {
        let k = buf[offset];

        if k == OPT_EOL {
            break;
        }

        if k == kind {
            return (offset, nop_count);
        }

        if k == OPT_NOP {
            nop_count += 1;
        } else {
            nop_count = 0;
        }

        offset = opt_next(buf, hdr, offset);
    }

    (offset, nop_count)
}

/// Find a TCP option and return its data.
fn tcp_find_opt(buf: &[u8], kind: u8) -> Option<TcpOpt> {
    let hdr = find_tcp_header(buf)?;
    let (offset, _) = find_opt(buf, &hdr, kind);

    if offset >= hdr.max || buf[offset] != kind {
        return None;
    }

    if offset + 1 >= hdr.max {
        return None;
    }

    let total_len = buf[offset + 1] as usize;
    if total_len < 2 {
        return None;
    }

    let data_length = total_len - 2;
    if offset + 2 + data_length > hdr.max {
        return None;
    }

    Some(TcpOpt {
        kind,
        data_offset: offset + 2,
        data_length,
    })
}

// -----------------------------------------------------------------------
// Length adjustment
// -----------------------------------------------------------------------

/// Adjust the IP total length and TCP header length fields after
/// adding or removing options.
///
/// `adjustment` must be a multiple of 4.
fn adjust_length(buf: &mut [u8], adjustment: i32, hdr: &TcpHdr) {
    if adjustment % 4 != 0 {
        log::error!("tcp_hdr: adjustment not aligned to 4 bytes");
        return;
    }

    // Adjust IP header length field
    match hdr.ip_version {
        4 => {
            let ip_off = hdr.ip_offset;
            let total_length =
                ((buf[ip_off + 2] as u32) << 8 | buf[ip_off + 3] as u32) as i32;
            let new_length = (total_length + adjustment) as u32;
            buf[ip_off + 2] = (new_length >> 8) as u8;
            buf[ip_off + 3] = (new_length & 0xFF) as u8;
        }
        6 => {
            let ip_off = hdr.ip_offset;
            let payload_length =
                ((buf[ip_off + 4] as u32) << 8 | buf[ip_off + 5] as u32) as i32;
            let new_length = (payload_length + adjustment) as u32;
            buf[ip_off + 4] = (new_length >> 8) as u8;
            buf[ip_off + 5] = (new_length & 0xFF) as u8;
        }
        _ => {}
    }

    // Adjust TCP data offset field
    let tcp_off = hdr.begin + 12;
    let old_hdr_len = ((buf[tcp_off] >> 4) as usize) * 4;
    let new_hdr_len = (old_hdr_len as i32 + adjustment) as usize;
    buf[tcp_off] = (buf[tcp_off] & 0x0F) | (((new_hdr_len / 4) as u8) << 4);
}

// -----------------------------------------------------------------------
// Padding management
// -----------------------------------------------------------------------

/// Add padding bytes (zeroes) at the specified offset in the buffer.
fn add_padding(buf: &mut Vec<u8>, offset: usize, pad_count: usize) {
    let old_len = buf.len();
    buf.resize(old_len + pad_count, 0);

    // Move payload after the new padding
    if offset + pad_count < buf.len() {
        buf.copy_within(offset..old_len, offset + pad_count);
    }

    // Zero the padding
    for i in 0..pad_count {
        buf[offset + i] = 0;
    }
}

/// Normalize padding at the end of the options list.
///
/// Removes excess padding bytes (more than 3 trailing zero bytes)
/// and converts trailing NOPs to EOL bytes.
fn normalize_padding(buf: &mut Vec<u8>) -> bool {
    let hdr = match find_tcp_header(buf) {
        Some(h) => h,
        None => return false,
    };

    // Find the end of options (EOL marker or end of header)
    let (eol_offset, nop_count) = find_opt(buf, &hdr, 0xFF); // 0xFF forces search to end

    if eol_offset >= hdr.max && nop_count == 0 {
        return true; // nothing to normalize
    }

    // Include trailing NOPs in the removal range
    let start = eol_offset - nop_count as usize;
    let remove_count_raw = hdr.max - start;

    // Must be aligned to 4-byte boundary
    let remove_count = remove_count_raw - (remove_count_raw % 4);

    if remove_count == 0 {
        return false; // normal case: nothing to remove
    }

    // Remove the excess padding
    let payload_start = hdr.max;
    let payload_end = buf.len();
    let payload_len = payload_end - payload_start;

    if payload_len > 0 {
        buf.copy_within(payload_start..payload_end, payload_start - remove_count);
    }

    let new_max = hdr.max - remove_count;
    let new_len = buf.len() - remove_count;

    // Zero out remaining padding
    for i in start..new_max {
        if i < new_len {
            buf[i] = 0;
        }
    }

    buf.truncate(new_len);

    // Fix IP and TCP length fields
    let mut hdr_fixed = hdr.clone();
    hdr_fixed.max = new_max;
    adjust_length(buf, -(remove_count as i32), &hdr_fixed);

    true
}

// -----------------------------------------------------------------------
// Option insertion/removal
// -----------------------------------------------------------------------

/// Insert or replace a field in the buffer, adjusting size as needed.
///
/// Returns the size adjustment (positive = grew, negative = shrank).
fn insert_field(
    buf: &mut Vec<u8>,
    begin: usize,
    end: usize,
    new_data: &[u8],
) -> i32 {
    let old_len = end - begin;
    let new_len = new_data.len();
    let adjust = new_len as i32 - old_len as i32;

    if adjust > 0 {
        // Growing: extend buffer and shift payload right
        let payload_end = buf.len();
        buf.resize(payload_end + adjust as usize, 0);
        if end < payload_end {
            buf.copy_within(end..payload_end, end + adjust as usize);
        }
    } else if adjust < 0 {
        // Shrinking: shift payload left, then truncate
        let payload_end = buf.len();
        if end < payload_end {
            buf.copy_within(end..payload_end, begin + new_len);
        }
        buf.truncate((payload_end as i32 + adjust) as usize);
    }

    // Copy new data into position
    buf[begin..begin + new_len].copy_from_slice(new_data);

    adjust
}

/// Remove all padding (NOPs) to make room, compacting options backward.
///
/// Returns the offset where a new option should be inserted (at the end
/// of the compacted options list).
fn squeeze_padding(buf: &mut Vec<u8>, hdr: &mut TcpHdr, in_kind: u8) -> usize {
    let mut offset = opt_begin(hdr);
    let mut nop_count: usize = 0;

    while offset < hdr.max {
        let kind = buf[offset];

        if kind == OPT_NOP {
            nop_count += 1;
            offset += 1;
            continue;
        }

        if kind == OPT_EOL {
            // Zero out from current position back over NOPs
            let start = offset - nop_count;
            for i in start..hdr.max {
                buf[i] = 0;
            }
            return start;
        }

        if kind == in_kind {
            // Convert matching option to NOPs
            let len = buf[offset + 1] as usize;
            for i in offset..offset + len {
                buf[i] = OPT_NOP;
            }
            nop_count += 1;
            offset += len;
            continue;
        }

        if nop_count == 0 {
            offset = opt_next(buf, hdr, offset);
            continue;
        }

        // Move this option backward over the NOPs
        let len = buf[offset + 1] as usize;
        let new_offset = offset - nop_count;
        buf.copy_within(offset..offset + len, new_offset);

        // Fill the vacated space with NOPs
        for i in (new_offset + len)..(new_offset + len + nop_count) {
            if i < buf.len() {
                buf[i] = OPT_NOP;
            }
        }

        offset = new_offset + len;
        nop_count = 0;
    }

    // If we reach here, all trailing bytes were NOPs
    let start = offset - nop_count;
    for i in start..hdr.max {
        if i < buf.len() {
            buf[i] = 0;
        }
    }
    start
}

/// Add or replace a TCP option in the packet buffer.
///
/// The option is identified by `kind`. The `data` is the option payload
/// (not including the kind and length bytes). Maximum data length is 38 bytes.
pub fn tcp_add_opt(buf: &mut Vec<u8>, kind: u8, data: &[u8]) -> bool {
    if data.len() > 38 {
        log::error!("tcp_add_opt: option data too large ({})", data.len());
        return false;
    }

    let hdr = match find_tcp_header(buf) {
        Some(h) => h,
        None => return false,
    };

    let (found_offset, nop_count) = find_opt(buf, &hdr, kind);

    // Build the new option field: [kind, length, data...]
    let new_length = 2 + data.len();
    let mut new_field = vec![kind, new_length as u8];
    new_field.extend_from_slice(data);

    // Determine old field boundaries
    let old_begin;
    let old_end;

    if found_offset >= hdr.max {
        // Option not found, insert at end
        old_begin = hdr.max;
        old_end = hdr.max;
    } else if buf[found_offset] == OPT_EOL {
        // Insert before padding
        old_begin = found_offset;
        old_end = hdr.max;
    } else if buf[found_offset] == kind {
        // Replace existing option
        old_begin = found_offset;
        let len = buf[found_offset + 1] as usize;
        old_end = found_offset + len;
    } else {
        return false;
    }

    // Try to absorb neighboring NOPs to make room
    let mut adj_begin = old_begin;
    let mut adj_end = old_end;

    while (adj_end - adj_begin) < new_length {
        if adj_begin > opt_begin(&hdr) && buf[adj_begin - 1] == OPT_NOP {
            adj_begin -= 1;
        } else if adj_end < hdr.max && buf[adj_end] == OPT_NOP {
            adj_end += 1;
        } else {
            break;
        }
    }

    // Try absorbing trailing EOL padding
    if (adj_end - adj_begin) < new_length && adj_end < hdr.max && buf[adj_end] == OPT_EOL {
        // Zero out remaining padding
        for i in adj_end..hdr.max {
            buf[i] = 0;
        }
        while (adj_end - adj_begin) < new_length && adj_end < hdr.max {
            adj_end += 1;
        }
    }

    // Check if header has room
    if adj_end - adj_begin < new_length {
        // Try squeezing out all padding
        let mut hdr_mut = hdr.clone();
        let squeeze_offset = squeeze_padding(buf, &mut hdr_mut, kind);

        // Re-parse after squeeze
        let hdr2 = match find_tcp_header(buf) {
            Some(h) => h,
            None => return false,
        };

        let old_begin2 = squeeze_offset;
        let old_end2 = hdr2.max;

        let adjust = insert_field(buf, old_begin2, old_end2, &new_field);
        let mut new_hdr = hdr2.clone();
        new_hdr.max = (new_hdr.max as i32 + adjust) as usize;

        // Handle 4-byte alignment padding
        if adjust % 4 != 0 {
            let pad = if adjust > 0 {
                4 - (adjust % 4) as usize
            } else {
                (-(adjust % 4)) as usize
            };
            add_padding(buf, new_hdr.max, pad);
            new_hdr.max += pad;
            let total_adjust = adjust + pad as i32;
            adjust_length(buf, total_adjust, &hdr2);
        } else {
            adjust_length(buf, adjust, &hdr2);
        }

        normalize_padding(buf);
        return true;
    }

    // Insert the field
    let adjust = insert_field(buf, adj_begin, adj_end, &new_field);

    if adjust != 0 {
        let mut new_hdr = hdr.clone();
        new_hdr.max = (new_hdr.max as i32 + adjust) as usize;

        // 4-byte alignment
        if adjust % 4 != 0 {
            let pad = if adjust > 0 {
                4 - (adjust % 4) as usize
            } else {
                (-(adjust % 4)) as usize
            };
            add_padding(buf, new_hdr.max, pad);
            new_hdr.max += pad;
            let total_adjust = adjust + pad as i32;
            adjust_length(buf, total_adjust, &hdr);
        } else {
            adjust_length(buf, adjust, &hdr);
        }

        normalize_padding(buf);
    }

    true
}

/// Remove a TCP option by kind.
///
/// Returns true on success (including when the option wasn't found).
pub fn tcp_remove_opt(buf: &mut Vec<u8>, kind: u8) -> bool {
    let hdr = match find_tcp_header(buf) {
        Some(h) => h,
        None => return false,
    };

    let (offset, nop_count) = find_opt(buf, &hdr, kind);

    // Not found?
    if offset + 2 > hdr.max || buf[offset] != kind {
        return true; // not an error
    }

    let opt_len = buf[offset + 1] as usize;
    if offset + opt_len > hdr.max {
        return false;
    }

    // Calculate total removal including adjacent NOPs
    let mut remove_start = offset - nop_count as usize;
    let mut remove_end = offset + opt_len;

    // Include trailing NOPs
    while remove_end < hdr.max && buf[remove_end] == OPT_NOP {
        remove_end += 1;
    }

    let remove_length = remove_end - remove_start;

    // Remove bytes: shift payload left
    let payload_start = hdr.max;
    let payload_end = buf.len();

    if payload_start < payload_end {
        buf.copy_within(payload_start..payload_end, payload_start - remove_length);
    }

    buf.truncate(buf.len() - remove_length);

    let new_max = hdr.max - remove_length;

    // May need to add back alignment padding
    if remove_length % 4 != 0 {
        let pad_needed = remove_length % 4;
        add_padding(buf, new_max, pad_needed);
        let effective_remove = remove_length - pad_needed;
        let mut hdr_adj = hdr.clone();
        hdr_adj.max = new_max + pad_needed;
        adjust_length(buf, -(effective_remove as i32), &hdr);
    } else {
        let mut hdr_adj = hdr.clone();
        hdr_adj.max = new_max;
        adjust_length(buf, -(remove_length as i32), &hdr);
    }

    normalize_padding(buf);

    true
}

// -----------------------------------------------------------------------
// Option getters
// -----------------------------------------------------------------------

/// Get the MSS (Maximum Segment Size) value from the TCP options.
///
/// Returns `None` if the option is not found.
pub fn tcp_get_mss(buf: &[u8]) -> Option<u16> {
    let opt = tcp_find_opt(buf, OPT_MSS)?;
    if opt.data_length != 2 {
        return None;
    }
    Some(((buf[opt.data_offset] as u16) << 8) | buf[opt.data_offset + 1] as u16)
}

/// Get the window scale value from the TCP options.
///
/// Returns `None` if the option is not found.
pub fn tcp_get_wscale(buf: &[u8]) -> Option<u8> {
    let opt = tcp_find_opt(buf, OPT_WSCALE)?;
    if opt.data_length != 1 {
        return None;
    }
    Some(buf[opt.data_offset])
}

/// Check if SACK-permitted is set in the TCP options.
pub fn tcp_get_sackperm(buf: &[u8]) -> bool {
    tcp_find_opt(buf, OPT_SACKOK).is_some()
}

// -----------------------------------------------------------------------
// Apply template options
// -----------------------------------------------------------------------

/// Apply all configured template options to a TCP packet buffer.
///
/// This is called during configuration to modify the TCP header template
/// based on command-line options like --tcp-mss, --tcp-sackperm,
/// --tcp-wscale, --tcp-ts.
pub fn templ_tcp_apply_options(buf: &mut Vec<u8>, opts: &TemplateOptions) {
    // --tcp-mss <num>
    match opts.tcp.is_mss {
        AddRemove::Remove => {
            tcp_remove_opt(buf, OPT_MSS);
        }
        AddRemove::Add => {
            let mss = opts.tcp.mss;
            let data = [(mss >> 8) as u8, (mss & 0xFF) as u8];
            tcp_add_opt(buf, OPT_MSS, &data);
        }
        AddRemove::Default => {}
    }

    // --tcp-sackok
    match opts.tcp.is_sackok {
        AddRemove::Remove => {
            tcp_remove_opt(buf, OPT_SACKOK);
        }
        AddRemove::Add => {
            tcp_add_opt(buf, OPT_SACKOK, &[]);
        }
        AddRemove::Default => {}
    }

    // --tcp-wscale <num>
    match opts.tcp.is_wscale {
        AddRemove::Remove => {
            tcp_remove_opt(buf, OPT_WSCALE);
        }
        AddRemove::Add => {
            tcp_add_opt(buf, OPT_WSCALE, &[opts.tcp.wscale as u8]);
        }
        AddRemove::Default => {}
    }

    // --tcp-ts <num>
    match opts.tcp.is_tsecho {
        AddRemove::Remove => {
            tcp_remove_opt(buf, OPT_TIMESTAMP);
        }
        AddRemove::Add => {
            let ts = opts.tcp.tsecho;
            let data = [
                (ts >> 24) as u8,
                (ts >> 16) as u8,
                (ts >> 8) as u8,
                ts as u8,
                0, 0, 0, 0, // TSecr = 0
            ];
            tcp_add_opt(buf, OPT_TIMESTAMP, &data);
        }
        AddRemove::Default => {}
    }
}

// -----------------------------------------------------------------------
// Self-tests
// -----------------------------------------------------------------------

/// Default test packet template with TCP options and "DeadBeef" payload.
fn test_template() -> Vec<u8> {
    let mut pkt = Vec::new();

    // Ethernet header (14 bytes)
    pkt.extend_from_slice(b"\x00\x01\x02\x03\x04\x05"); // dst MAC
    pkt.extend_from_slice(b"\x06\x07\x08\x09\x0a\x0b"); // src MAC
    pkt.extend_from_slice(b"\x08\x00"); // IPv4

    // IPv4 header (20 bytes)
    pkt.push(0x45); // version=4, IHL=5
    pkt.push(0x00); // TOS
    pkt.extend_from_slice(b"\x00\x48"); // total length = 72
    pkt.extend_from_slice(b"\x00\x00"); // identification
    pkt.extend_from_slice(b"\x00\x00"); // flags + fragment
    pkt.push(0xFF); // TTL
    pkt.push(0x06); // protocol = TCP
    pkt.extend_from_slice(b"\xFF\xFF"); // checksum (placeholder)
    pkt.extend_from_slice(b"\x00\x00\x00\x00"); // src IP
    pkt.extend_from_slice(b"\x00\x00\x00\x00"); // dst IP

    // TCP header (20 bytes + options)
    pkt.extend_from_slice(b"\x00\x00"); // src port
    pkt.extend_from_slice(b"\x00\x00"); // dst port
    pkt.extend_from_slice(b"\x00\x00\x00\x00"); // seqno
    pkt.extend_from_slice(b"\x00\x00\x00\x00"); // ackno
    pkt.push(0xB0); // data offset = 44 bytes (11 * 4)
    pkt.push(0x02); // SYN
    pkt.extend_from_slice(b"\x04\x01"); // window = 1025
    pkt.extend_from_slice(b"\xFF\xFF"); // checksum
    pkt.extend_from_slice(b"\x00\x00"); // urgent pointer

    // TCP options (24 bytes)
    pkt.extend_from_slice(b"\x02\x04\x05\xb4"); // MSS = 1460
    pkt.extend_from_slice(b"\x01\x03\x03\x06"); // NOP + WScale = 6
    pkt.extend_from_slice(b"\x01\x01\x08\x0a\x1d\xe9\xb2\x98\x00\x00\x00\x00"); // NOP NOP + Timestamp
    pkt.extend_from_slice(b"\x04\x02\x00\x00"); // SACK-OK + padding

    // Payload
    pkt.extend_from_slice(b"DeadBeef");

    pkt
}

/// Validate that the packet structure is consistent.
fn consistency_check(buf: &[u8], expected_payload: &[u8]) -> bool {
    let hdr = match find_tcp_header(buf) {
        Some(h) => h,
        None => {
            log::error!("consistency_check: TCP header not found");
            return false;
        }
    };

    // Check IP total length for IPv4
    if hdr.ip_version == 4 {
        let ip_total =
            ((buf[hdr.ip_offset + 2] as usize) << 8) | buf[hdr.ip_offset + 3] as usize;
        let expected = 14 + ip_total; // ethernet + IP total
        if expected != buf.len() {
            log::error!(
                "consistency_check: IP length mismatch: {} vs {}",
                expected,
                buf.len()
            );
            return false;
        }
    }

    // Validate TCP options are well-formed
    let mut offset = opt_begin(&hdr);
    while offset < hdr.max {
        let kind = buf[offset];
        if kind == OPT_EOL {
            break;
        }
        if kind == OPT_NOP {
            offset += 1;
            continue;
        }
        if offset + 1 >= hdr.max {
            log::error!("consistency_check: truncated option at {}", offset);
            return false;
        }
        let len = buf[offset + 1] as usize;
        if len < 2 || offset + len > hdr.max {
            log::error!("consistency_check: bad option length at {}", offset);
            return false;
        }
        offset += len;
    }

    // Check payload
    let payload = &buf[hdr.max..];
    if payload != expected_payload {
        log::error!(
            "consistency_check: payload mismatch: {:?} vs {:?}",
            payload,
            expected_payload
        );
        return false;
    }

    true
}

/// Replace the options field in a test packet (used for self-test pre-conditions).
fn replace_options(buf: &mut Vec<u8>, new_options: &[u8]) -> bool {
    let hdr = match find_tcp_header(buf) {
        Some(h) => h,
        None => return false,
    };

    let opt_start = opt_begin(&hdr);
    let old_length = hdr.max - opt_start;

    // Pad to 4-byte boundary
    let mut padded = new_options.to_vec();
    while padded.len() % 4 != 0 {
        padded.push(0);
    }

    let new_length = padded.len();
    let adjust = new_length as i32 - old_length as i32;

    if adjust > 0 {
        let old_len = buf.len();
        buf.resize(old_len + adjust as usize, 0);
        if hdr.max < old_len {
            buf.copy_within(hdr.max..old_len, hdr.max + adjust as usize);
        }
    } else if adjust < 0 {
        let old_len = buf.len();
        if hdr.max < old_len {
            buf.copy_within(hdr.max..old_len, (hdr.max as i32 + adjust) as usize);
        }
        buf.truncate((old_len as i32 + adjust) as usize);
    }

    buf[opt_start..opt_start + new_length].copy_from_slice(&padded);

    // Fix length fields
    let mut hdr2 = hdr.clone();
    hdr2.max = opt_start + new_length;
    adjust_length(buf, adjust, &hdr);

    true
}

/// A self-test case.
struct TestCase {
    pre_options: &'static [u8],
    opcode: TestOpcode,
    test_data: &'static [u8],
    post_options: &'static [u8],
}

#[derive(Debug)]
enum TestOpcode {
    Padding,
    Add,
    Remove,
}

/// Self-test cases exercising add, remove, and padding normalization.
static TESTS: &[TestCase] = &[
    // Remove non-existent option (no change)
    TestCase {
        pre_options: b"\x03\x03\x03\x00",
        opcode: TestOpcode::Remove,
        test_data: b"\x08",
        post_options: b"\x03\x03\x03\x00",
    },
    // Remove timestamp option and normalize padding
    TestCase {
        pre_options: b"\x03\x03\x03\x01\x01\x01\x08\x0a\x1d\xe9\xb2\x98\x00\x00\x00\x00",
        opcode: TestOpcode::Remove,
        test_data: b"\x08",
        post_options: b"\x03\x03\x03\x00",
    },
    // Add a 2-byte option to empty options
    TestCase {
        pre_options: b"",
        opcode: TestOpcode::Add,
        test_data: b"\x04\x02",
        post_options: b"\x04\x02\x00\x00",
    },
    // Add a 3-byte option to empty options
    TestCase {
        pre_options: b"",
        opcode: TestOpcode::Add,
        test_data: b"\x03\x03\x03",
        post_options: b"\x03\x03\x03\x00",
    },
    // Add a 4-byte option to empty options
    TestCase {
        pre_options: b"",
        opcode: TestOpcode::Add,
        test_data: b"\x02\x04\x05\x06",
        post_options: b"\x02\x04\x05\x06",
    },
    // Replace a 4-byte option
    TestCase {
        pre_options: b"\x02\x04\x01\x01",
        opcode: TestOpcode::Add,
        test_data: b"\x02\x04\x05\x06",
        post_options: b"\x02\x04\x05\x06",
    },
    // Replace a 3-byte option
    TestCase {
        pre_options: b"\x03\x03\x02",
        opcode: TestOpcode::Add,
        test_data: b"\x03\x03\x03",
        post_options: b"\x03\x03\x03\x00",
    },
    // Replace a 2-byte option
    TestCase {
        pre_options: b"\x04\x02",
        opcode: TestOpcode::Add,
        test_data: b"\x04\x02",
        post_options: b"\x04\x02\x00\x00",
    },
    // Empty options: padding normalization is a no-op
    TestCase {
        pre_options: b"",
        opcode: TestOpcode::Padding,
        test_data: b"",
        post_options: b"",
    },
    // Single EOL: should be removed
    TestCase {
        pre_options: b"\x00",
        opcode: TestOpcode::Padding,
        test_data: b"",
        post_options: b"",
    },
    // 8 bytes of EOL: should all be removed
    TestCase {
        pre_options: b"\x00\x00\x00\x00\x00\x00\x00\x00",
        opcode: TestOpcode::Padding,
        test_data: b"",
        post_options: b"",
    },
    // NOPs followed by EOL: all should be removed
    TestCase {
        pre_options: b"\x01\x01\x00\x00\x00\x00\x00\x00",
        opcode: TestOpcode::Padding,
        test_data: b"",
        post_options: b"",
    },
    // Trailing NOPs should become EOLs
    TestCase {
        pre_options: b"\x03\x03\x03\x01\x00\x00\x00\x00",
        opcode: TestOpcode::Padding,
        test_data: b"",
        post_options: b"\x03\x03\x03\x00",
    },
    // Only trailing NOPs: should be normalized
    TestCase {
        pre_options: b"\x03\x03\x03\x01\x01\x01\x01\x01",
        opcode: TestOpcode::Padding,
        test_data: b"",
        post_options: b"\x03\x03\x03\x00",
    },
];

/// Run all self-tests. Returns true if all pass.
pub fn selftest() -> bool {
    // Run table-driven tests
    for (i, test) in TESTS.iter().enumerate() {
        let mut buf = test_template();

        if !replace_options(&mut buf, test.pre_options) {
            log::error!("selftest #{}: failed to set pre-condition", i);
            return false;
        }

        if !consistency_check(&buf, b"DeadBeef") {
            log::error!("selftest #{}: pre-condition inconsistent", i);
            return false;
        }

        match test.opcode {
            TestOpcode::Padding => {
                normalize_padding(&mut buf);
            }
            TestOpcode::Add => {
                let kind = test.test_data[0];
                let total_len = test.test_data[1] as usize;
                let data = &test.test_data[2..total_len];
                if !tcp_add_opt(&mut buf, kind, data) {
                    log::error!("selftest #{}: tcp_add_opt failed", i);
                    return false;
                }
            }
            TestOpcode::Remove => {
                let kind = test.test_data[0];
                if !tcp_remove_opt(&mut buf, kind) {
                    log::error!("selftest #{}: tcp_remove_opt failed", i);
                    return false;
                }
            }
        }

        if !consistency_check(&buf, b"DeadBeef") {
            log::error!("selftest #{}: post-condition inconsistent", i);
            return false;
        }

        // Verify options match expected
        let hdr = match find_tcp_header(&buf) {
            Some(h) => h,
            None => {
                log::error!("selftest #{}: can't find TCP header post-test", i);
                return false;
            }
        };

        let opt_start = opt_begin(&hdr);
        let opt_end = hdr.max;
        let actual = &buf[opt_start..opt_end];

        if actual != test.post_options {
            log::error!(
                "selftest #{}: options mismatch\n  expected: {:02x?}\n  actual:   {:02x?}",
                i,
                test.post_options,
                actual
            );
            return false;
        }
    }

    // Additional functional tests
    let mut buf = test_template();

    // Check initial values
    if tcp_get_mss(&buf) != Some(1460) {
        log::error!("selftest: initial MSS should be 1460");
        return false;
    }
    if tcp_get_wscale(&buf) != Some(6) {
        log::error!("selftest: initial wscale should be 6");
        return false;
    }
    if !tcp_get_sackperm(&buf) {
        log::error!("selftest: initial sackperm should be present");
        return false;
    }

    // Change MSS
    tcp_add_opt(&mut buf, OPT_MSS, &[(0x12u8), (0x34u8)]);
    if tcp_get_mss(&buf) != Some(0x1234) {
        log::error!("selftest: MSS should be 0x1234 after change");
        return false;
    }
    if !consistency_check(&buf, b"DeadBeef") {
        log::error!("selftest: inconsistent after MSS change");
        return false;
    }

    // Remove wscale
    tcp_remove_opt(&mut buf, OPT_WSCALE);
    if tcp_get_mss(&buf) != Some(0x1234) {
        log::error!("selftest: MSS should still be 0x1234 after wscale removal");
        return false;
    }
    if tcp_get_wscale(&buf).is_some() {
        log::error!("selftest: wscale should be gone");
        return false;
    }
    if !consistency_check(&buf, b"DeadBeef") {
        log::error!("selftest: inconsistent after wscale removal");
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selftest() {
        assert!(selftest(), "TCP header selftest failed");
    }

    #[test]
    fn test_find_header() {
        let buf = test_template();
        let hdr = find_tcp_header(&buf).expect("should find TCP header");
        assert_eq!(hdr.begin, 34); // 14 (eth) + 20 (ip)
        assert_eq!(hdr.ip_version, 4);
        assert_eq!(hdr.max - hdr.begin, 44); // TCP header with 24 bytes of options
    }

    #[test]
    fn test_get_mss() {
        let buf = test_template();
        assert_eq!(tcp_get_mss(&buf), Some(1460));
    }

    #[test]
    fn test_get_wscale() {
        let buf = test_template();
        assert_eq!(tcp_get_wscale(&buf), Some(6));
    }

    #[test]
    fn test_sackperm() {
        let buf = test_template();
        assert!(tcp_get_sackperm(&buf));
    }

    #[test]
    fn test_add_remove_mss() {
        let mut buf = test_template();
        tcp_add_opt(&mut buf, OPT_MSS, &[0x05, 0x78]); // MSS = 1400
        assert_eq!(tcp_get_mss(&buf), Some(1400));

        tcp_remove_opt(&mut buf, OPT_MSS);
        assert_eq!(tcp_get_mss(&buf), None);
    }

    #[test]
    fn test_apply_options_mss_add() {
        let mut buf = test_template();
        // First remove MSS
        tcp_remove_opt(&mut buf, OPT_MSS);
        assert_eq!(tcp_get_mss(&buf), None);

        // Then apply option to add it back
        let mut opts = TemplateOptions::default();
        opts.tcp.is_mss = AddRemove::Add;
        opts.tcp.mss = 1380;
        templ_tcp_apply_options(&mut buf, &opts);
        assert_eq!(tcp_get_mss(&buf), Some(1380));
    }

    #[test]
    fn test_apply_options_wscale_remove() {
        let mut buf = test_template();
        assert!(tcp_get_wscale(&buf).is_some());

        let mut opts = TemplateOptions::default();
        opts.tcp.is_wscale = AddRemove::Remove;
        templ_tcp_apply_options(&mut buf, &opts);
        assert!(tcp_get_wscale(&buf).is_none());
    }
}
