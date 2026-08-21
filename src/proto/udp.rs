//! UDP protocol dispatcher.
use crate::proto::preprocess::PreprocessedInfo;
use crate::proto::banout::BannerOutput;

/// Default UDP parse: report first 64 bytes as banner.
pub fn default_udp_parse(px: &[u8], length: usize, _parsed: &PreprocessedInfo) -> Vec<u8> {
    let len = length.min(64);
    px[..len].to_vec()
}

/// Handle incoming UDP response, dispatching to protocol-specific parsers.
pub fn handle_udp(px: &[u8], length: usize, parsed: &PreprocessedInfo, banout: &mut BannerOutput) {
    let port_them = parsed.port_src;

    match port_them {
        53 => { crate::proto::dns::handle_dns(px, length, parsed, banout); }
        123 => { crate::proto::ntp::ntp_handle_response(px, length, parsed, banout); }
        137 => {
            if let Some((name, _)) = crate::proto::netbios::handle_nbtstat(px, length, parsed.app_offset as usize, parsed.app_length as usize) {
                banout.append_str(0, &String::from_utf8_lossy(&name));
            }
        }
        161 => { crate::proto::snmp::handle_snmp(px, length, parsed, banout); }
        500 => { crate::proto::isakmp::isakmp_parse_response(banout, px, length); }
        5683 => { crate::proto::coap::coap_parse(px, length, banout); }
        11211 => { let _ = (px, length, parsed, banout); /* memcached UDP not yet implemented */ }
        16464 | 16465 | 16470 | 16471 => { crate::proto::zeroaccess::handle_zeroaccess(banout, px, parsed.app_offset as usize, parsed.app_length as usize); }
        _ => { let _ = default_udp_parse(&px[parsed.app_offset as usize..], parsed.app_length as usize, parsed); }
    }
}
