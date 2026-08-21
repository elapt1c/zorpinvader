//! UDP payload database for probe packets.
//!
//! Manages a collection of payloads to send when probing UDP services.
//! Each payload is associated with a destination port number and includes
//! the raw bytes, a pre-computed partial checksum, an optional source port,
//! and an optional cookie-setting function.
//!
//! Payloads can come from:
//! - Hard-coded defaults (for well-known services like DNS, SNMP, etc.)
//! - nmap-payloads files
//! - libpcap capture files

use super::nmap_payloads;

/// Type for a function that sets a "cookie" (transaction ID, sequence number,
/// etc.) in a UDP payload before transmission.
///
/// The function receives:
/// - A mutable reference to the payload bytes
/// - The sequence number / cookie value
pub type SetCookie = fn(&mut [u8], u64);

// -----------------------------------------------------------------------
// Protocol-specific cookie-setting functions.
// These should eventually live in their respective proto modules.
// -----------------------------------------------------------------------

/// Set a 4-byte cookie at offset 0 (used for DNS transaction ID and
/// similar RPC-style protocols).
pub fn dns_set_cookie(px: &mut [u8], seqno: u64) {
    if px.len() >= 2 {
        px[0] = (seqno >> 8) as u8;
        px[1] = (seqno & 0xFF) as u8;
    }
}

/// Set a 4-byte cookie for SNMP (at offset 15 inside the BER-encoded
/// request-id field).
pub fn snmp_set_cookie(px: &mut [u8], seqno: u64) {
    // SNMPv2c GET request: the request-id is at offset 15..19
    // within the typical BER-encoded SNMP message.
    if px.len() >= 19 {
        px[15] = (seqno >> 24) as u8;
        px[16] = (seqno >> 16) as u8;
        px[17] = (seqno >> 8) as u8;
        px[18] = (seqno & 0xFF) as u8;
    }
}

/// Set a 4-byte cookie for NTP (private mode request at offset 4).
pub fn ntp_set_cookie(px: &mut [u8], seqno: u64) {
    if px.len() >= 8 {
        px[4] = (seqno >> 24) as u8;
        px[5] = (seqno >> 16) as u8;
        px[6] = (seqno >> 8) as u8;
        px[7] = (seqno & 0xFF) as u8;
    }
}

/// Set a 2-byte cookie for CoAP (message ID at offset 2).
pub fn coap_udp_set_cookie(px: &mut [u8], seqno: u64) {
    if px.len() >= 4 {
        px[2] = (seqno >> 8) as u8;
        px[3] = (seqno & 0xFF) as u8;
    }
}

/// Set a cookie for memcached (request ID at offset 0).
pub fn memcached_udp_set_cookie(px: &mut [u8], seqno: u64) {
    if px.len() >= 2 {
        px[0] = (seqno >> 8) as u8;
        px[1] = (seqno & 0xFF) as u8;
    }
}

/// Set an 8-byte cookie for ISAKMP (initiator cookie at offset 0).
pub fn isakmp_set_cookie(px: &mut [u8], seqno: u64) {
    if px.len() >= 8 {
        px[0] = (seqno >> 56) as u8;
        px[1] = (seqno >> 48) as u8;
        px[2] = (seqno >> 40) as u8;
        px[3] = (seqno >> 32) as u8;
        px[4] = (seqno >> 24) as u8;
        px[5] = (seqno >> 16) as u8;
        px[6] = (seqno >> 8) as u8;
        px[7] = (seqno & 0xFF) as u8;
    }
}

// -----------------------------------------------------------------------
// Internal types
// -----------------------------------------------------------------------

/// A single UDP payload entry.
#[derive(Clone)]
struct PayloadItem {
    port: u16,
    source_port: u32,
    data: Vec<u8>,
    xsum: u32,
    set_cookie: Option<SetCookie>,
}

/// Database of UDP payloads, indexed by destination port.
pub struct PayloadsUdp {
    items: Vec<PayloadItem>,
}

/// Result of looking up a payload by port number.
pub struct PayloadLookup<'a> {
    pub data: &'a [u8],
    pub source_port: u32,
    pub xsum: u32,
    pub set_cookie: Option<SetCookie>,
}

// -----------------------------------------------------------------------
// Checksum helper
// -----------------------------------------------------------------------

/// Compute a partial checksum over a byte buffer.
///
/// This sums all 16-bit words (big-endian) and folds carries.
/// Used to pre-compute the payload contribution to the UDP checksum,
/// so only the variable fields (IP addresses, ports) need updating
/// at transmit time.
fn partial_checksum(px: &[u8]) -> u32 {
    let mut xsum: u64 = 0;
    let len = px.len();
    let mut i = 0;

    while i + 1 < len {
        xsum += ((px[i] as u64) << 8) | (px[i + 1] as u64);
        i += 2;
    }

    // Handle odd trailing byte
    if len & 1 != 0 {
        xsum += (px[len - 1] as u64) << 8;
    }

    // Fold carries
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);
    xsum = (xsum & 0xFFFF) + (xsum >> 16);

    xsum as u32
}

// -----------------------------------------------------------------------
// Hard-coded default payloads
// -----------------------------------------------------------------------

/// A static default payload definition.
struct DefaultPayload {
    port: u16,
    source_port: u32,
    data: &'static [u8],
    set_cookie: Option<SetCookie>,
}

/// Hard-coded UDP payloads for well-known services.
static DEFAULT_UDP_PAYLOADS: &[DefaultPayload] = &[
    // Echo protocol
    DefaultPayload {
        port: 7,
        source_port: 65536,
        data: b"zorp-test 0x00000000",
        set_cookie: None,
    },
    // QOTD (amplifier)
    DefaultPayload {
        port: 17,
        source_port: 65536,
        data: b"zorp-test\x00\x00",
        set_cookie: None,
    },
    // Chargen (amplifier)
    DefaultPayload {
        port: 19,
        source_port: 65536,
        data: b"zorp-test\x00\x00",
        set_cookie: None,
    },
    // DNS
    DefaultPayload {
        port: 53,
        source_port: 65536,
        data: b"\x50\xb6\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
        set_cookie: Some(dns_set_cookie),
    },
    // TFTP
    DefaultPayload {
        port: 69,
        source_port: 65536,
        data: b"\x00\x01zorp-test\x00netascii\x00",
        set_cookie: None,
    },
    // Portmapper
    DefaultPayload {
        port: 111,
        source_port: 65536,
        data: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        set_cookie: Some(dns_set_cookie),
    },
    // NTP
    DefaultPayload {
        port: 123,
        source_port: 65536,
        data: b"\x17\x00\x03\x2a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        set_cookie: Some(ntp_set_cookie),
    },
    // NetBIOS name service
    DefaultPayload {
        port: 137,
        source_port: 65536,
        data: b"\xab\x12\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
        set_cookie: Some(dns_set_cookie),
    },
    // SNMP
    DefaultPayload {
        port: 161,
        source_port: 65536,
        data: b"\x30\x39\x02\x01\x00\x04\x06public\xa0\x2c\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x1e\x30\x0d\x06\x09\x2b\x06\x01\x80\x02\x01\x01\x01\x00\x05\x00\x30\x0d\x06\x09\x2b\x06\x01\x80\x02\x01\x01\x05\x00\x05\x00",
        set_cookie: Some(snmp_set_cookie),
    },
    // DTLS (port 443)
    DefaultPayload {
        port: 443,
        source_port: 65536,
        data: b"\x16\xfe\xff\x00\x00\x00\x00\x00\x07\x00\x66\x01\x00\x00\x5a\x00\x00\x00\x00\x00\x00\x5a\xfe\xfd\x1d\xb1\xe3\x52\x2e\x89\x94\xb7\x15\x33\x2f\x30\xff\xff\xcf\x76\x27\x77\xab\x04\xe4\x86\x6f\x21\x18\x0e\xf8\xdd\x70\xcc\xab\x9e\x00\x00\x00\x04\xc0\x30\x00\xff\x01\x00\x00\x2c\x00\x0b\x00\x04\x03\x00\x01\x02\x00\x0a\x00\x0c\x00\x0a\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18\x00\x23\x00\x00\x00\x16\x00\x00\x00\x17\x00\x00\x00\x0d\x00\x04\x00\x02\x05\x01",
        set_cookie: None,
    },
    // ISAKMP
    DefaultPayload {
        port: 500,
        source_port: 500,
        data: b"\x00\x11\x22\x33\x44\x55\x66\x77\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x01\x60\x00\x00\x01\x44\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x01\x38\x01\x01\x00\x0d\x03\x00\x00\x20\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0b\x00\x01\x80\x0c\x00\x01\x03\x00\x00\x20\x00\x01\x00\x00\x80\x01\x00\x01\x80\x02\x00\x01\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0b\x00\x01\x80\x0c\x00\x01\x03\x00\x00\x20\x00\x01\x00\x00\x80\x01\x00\x07\x80\x02\x00\x04\x80\x03\x00\x01\x80\x04\x00\x0e\x80\x0b\x00\x01\x80\x0c\x00\x01\x03\x00\x00\x14\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x02\x03\x00\x00\x14\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x03\x03\x00\x00\x14\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x04\x03\x00\x00\x14\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x08\x03\x00\x00\x14\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfa\xdd\x03\x00\x00\x14\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfa\xdf\x03\x00\x00\x14\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfd\xe9\x03\x00\x00\x14\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfd\xeb\x03\x00\x00\x14\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfd\xed\x03\x00\x00\x14\x00\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfd\xef\x00\x00\x00\x08\x00\x01\x00\x00",
        set_cookie: Some(isakmp_set_cookie),
    },
    // RIP
    DefaultPayload {
        port: 520,
        source_port: 65536,
        data: b"\x01\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10",
        set_cookie: None,
    },
    // RADIUS (old auth port)
    DefaultPayload {
        port: 1645,
        source_port: 65536,
        data: b"\x01\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        set_cookie: None,
    },
    // RADIUS (acct port)
    DefaultPayload {
        port: 1646,
        source_port: 65536,
        data: b"\x04\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        set_cookie: None,
    },
    // L2TP
    DefaultPayload {
        port: 1701,
        source_port: 65536,
        data: b"\xc8\x02\x00\x3c\x00\x00\x00\x00\x00\x00\x00\x00\x80\x08\x00\x00\x00\x00\x00\x01\x80\x08\x00\x00\x00\x02\x01\x00\x80\x0e\x00\x00\x00\x07zorp1\x80\x0a\x00\x00\x00\x03\x00\x00\x00\x03\x80\x08\x00\x00\x00\x09\x00\x00",
        set_cookie: None,
    },
    // RADIUS (standard auth port)
    DefaultPayload {
        port: 1812,
        source_port: 65536,
        data: b"\x01\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        set_cookie: None,
    },
    // RADIUS (standard acct port)
    DefaultPayload {
        port: 1813,
        source_port: 65536,
        data: b"\x04\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        set_cookie: None,
    },
    // UPnP SSDP
    DefaultPayload {
        port: 1900,
        source_port: 65536,
        data: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\nUSER-AGENT: unix/1.0 UPnP/1.1 zorp/1.x\r\n",
        set_cookie: None,
    },
    // NFS
    DefaultPayload {
        port: 2049,
        source_port: 65536,
        data: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa3\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        set_cookie: Some(dns_set_cookie),
    },
    // SIP
    DefaultPayload {
        port: 5060,
        source_port: 65536,
        data: b"OPTIONS sip:carol@chicago.com SIP/2.0\r\nVia: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKhjhs8ass877\r\nMax-Forwards: 70\r\nTo: <sip:carol@chicago.com>\r\nFrom: Alice <sip:alice@atlanta.com>;tag=1928301774\r\nCall-ID: a84b4c76e66710\r\nCSeq: 63104 OPTIONS\r\nContact: <sip:alice@pc33.atlanta.com>\r\nAccept: application/sdp\r\nContent-Length: 0\r\n",
        set_cookie: None,
    },
    // CoAP
    DefaultPayload {
        port: 5683,
        source_port: 65536,
        data: b"\x40\x01\x01\xce\xbb\x2e\x77\x65\x6c\x6c\x2d\x6b\x6e\x6f\x77\x6e\x04\x63\x6f\x72\x65",
        set_cookie: Some(coap_udp_set_cookie),
    },
    // Memcached
    DefaultPayload {
        port: 11211,
        source_port: 65536,
        data: b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n",
        set_cookie: Some(memcached_udp_set_cookie),
    },
    // Quake 3 (amplifier)
    DefaultPayload {
        port: 27960,
        source_port: 65536,
        data: b"\xFF\xFF\xFF\xFF\x67\x65\x74\x73\x74\x61\x74\x75\x73\x10",
        set_cookie: None,
    },
];

/// Hard-coded Oproto (other IP protocol) payloads.
static DEFAULT_OPROTO_PAYLOADS: &[DefaultPayload] = &[
    // Protocol 47 (GRE) - echo-like
    DefaultPayload {
        port: 47,
        source_port: 65536,
        data: b"\x00\x00\x00\x00",
        set_cookie: None,
    },
];

// -----------------------------------------------------------------------
// PayloadsUdp implementation
// -----------------------------------------------------------------------

impl PayloadsUdp {
    /// Create a new empty payload database.
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Create a new database pre-populated with hard-coded default UDP payloads.
    pub fn with_defaults() -> Self {
        let mut db = Self::new();
        for def in DEFAULT_UDP_PAYLOADS {
            db.add(def.port, def.data, def.source_port, def.set_cookie);
        }
        db
    }

    /// Create a new database pre-populated with hard-coded Oproto payloads.
    pub fn with_oproto_defaults() -> Self {
        let mut db = Self::new();
        for def in DEFAULT_OPROTO_PAYLOADS {
            db.add(def.port, def.data, def.source_port, def.set_cookie);
        }
        db
    }

    /// Add a payload for a single port.
    ///
    /// If a payload already exists for this port, it is replaced.
    /// Items are kept sorted by port number for efficient lookup.
    pub fn add(
        &mut self,
        port: u16,
        data: &[u8],
        source_port: u32,
        set_cookie: Option<SetCookie>,
    ) {
        let item = PayloadItem {
            port,
            source_port,
            data: data.to_vec(),
            xsum: partial_checksum(data),
            set_cookie,
        };

        // Binary search for insertion point (items are sorted by port)
        match self.items.binary_search_by_key(&port, |it| it.port) {
            Ok(idx) => {
                // Replace existing entry
                self.items[idx] = item;
            }
            Err(idx) => {
                self.items.insert(idx, item);
            }
        }
    }

    /// Add a payload for multiple ports.
    pub fn add_for_ports(
        &mut self,
        ports: &[u16],
        data: &[u8],
        source_port: u32,
        set_cookie: Option<SetCookie>,
    ) {
        for &port in ports {
            self.add(port, data, source_port, set_cookie);
        }
    }

    /// Load payloads from an nmap-payloads formatted reader.
    pub fn load_nmap_payloads<R: std::io::BufRead>(
        &mut self,
        reader: &mut R,
        filename: &str,
    ) {
        let entries = nmap_payloads::read_nmap_payloads(reader, filename);
        for entry in entries {
            let source_port = if entry.source_port >= 0x10000 {
                0x10000
            } else {
                entry.source_port
            };
            self.add_for_ports(&entry.ports, &entry.data, source_port, None);
        }
    }

    /// Look up the payload for a given destination port.
    ///
    /// Returns `None` if no payload is registered for this port.
    pub fn lookup(&self, port: u16) -> Option<PayloadLookup<'_>> {
        self.items
            .binary_search_by_key(&port, |it| it.port)
            .ok()
            .map(|idx| {
                let item = &self.items[idx];
                PayloadLookup {
                    data: &item.data,
                    source_port: item.source_port,
                    xsum: item.xsum,
                    set_cookie: item.set_cookie,
                }
            })
    }

    /// Remove all payloads that are not in the given set of ports.
    ///
    /// This is called after configuration to trim the database down
    /// to only the ports being scanned, making lookups faster.
    pub fn trim_to_ports<F>(&mut self, is_port_scanned: F)
    where
        F: Fn(u16) -> bool,
    {
        self.items.retain(|item| is_port_scanned(item.port));
    }

    /// Return the number of payloads in the database.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Return true if the database has no payloads.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Return the raw data bytes and length for a given port.
    /// Used by the template packet builder to fill in UDP payloads.
    pub fn get_payload_data(&self, port: u16) -> Option<(&[u8], u32, Option<SetCookie>)> {
        self.lookup(port)
            .map(|l| (l.data, l.source_port, l.set_cookie))
    }
}

impl Default for PayloadsUdp {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partial_checksum_even() {
        let data = [0x00, 0x01, 0x00, 0x02];
        let xsum = partial_checksum(&data);
        // 0x0001 + 0x0002 = 0x0003
        assert_eq!(xsum, 3);
    }

    #[test]
    fn test_partial_checksum_odd() {
        let data = [0x01, 0x02, 0x03];
        let xsum = partial_checksum(&data);
        // 0x0102 + 0x0300 = 0x0402
        assert_eq!(xsum, 0x0402);
    }

    #[test]
    fn test_add_and_lookup() {
        let mut db = PayloadsUdp::new();
        db.add(53, b"\x01\x02\x03", 65536, None);
        db.add(161, b"\x04\x05\x06", 65536, None);

        let result = db.lookup(53).unwrap();
        assert_eq!(result.data, b"\x01\x02\x03");
        assert_eq!(result.source_port, 65536);

        let result2 = db.lookup(161).unwrap();
        assert_eq!(result2.data, b"\x04\x05\x06");

        assert!(db.lookup(80).is_none());
    }

    #[test]
    fn test_replace_existing() {
        let mut db = PayloadsUdp::new();
        db.add(53, b"\x01\x02", 65536, None);
        db.add(53, b"\x03\x04\x05", 65536, None);

        assert_eq!(db.len(), 1);
        let result = db.lookup(53).unwrap();
        assert_eq!(result.data, b"\x03\x04\x05");
    }

    #[test]
    fn test_trim() {
        let mut db = PayloadsUdp::new();
        db.add(53, b"\x01", 65536, None);
        db.add(161, b"\x02", 65536, None);
        db.add(5060, b"\x03", 65536, None);

        db.trim_to_ports(|port| port == 53 || port == 5060);

        assert_eq!(db.len(), 2);
        assert!(db.lookup(53).is_some());
        assert!(db.lookup(161).is_none());
        assert!(db.lookup(5060).is_some());
    }

    #[test]
    fn test_defaults_not_empty() {
        let db = PayloadsUdp::with_defaults();
        assert!(!db.is_empty());
        assert!(db.lookup(53).is_some());
        assert!(db.lookup(161).is_some());
        assert!(db.lookup(1900).is_some());
    }

    #[test]
    fn test_dns_cookie() {
        let mut data = vec![0xFF, 0xFF, 0x00, 0x00];
        dns_set_cookie(&mut data, 0x1234);
        assert_eq!(data[0], 0x12);
        assert_eq!(data[1], 0x34);
    }

    #[test]
    fn test_coap_cookie() {
        let mut data = vec![0x40, 0x01, 0x00, 0x00, 0xBB];
        coap_udp_set_cookie(&mut data, 0xABCD);
        assert_eq!(data[2], 0xAB);
        assert_eq!(data[3], 0xCD);
    }
}
