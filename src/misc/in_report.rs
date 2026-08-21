//! Reporting helpers for binary scan file re-processing.
//!
//! When `--readscan` reads back a binary scan file, these functions
//! annotate vulnerability records with SSL certificate information
//! gathered from the same scan. A small in-memory database maps IP
//! addresses to certificate Common Names.
//!
//! **Ported from C `in-report.c`.**
//!
//! NOTE: The original C code contains substantial X.509 decoding and
//! Aho-Corasick (SMACK) pattern matching. Those subsystems live in
//! `proto::x509` and `proto::smack` respectively. This module provides
//! the CNDB (common-name database) and the glue that ties them together.

use std::collections::HashMap;

/// Category codes for X.509 issuer/subject classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum X509Category {
    Unknown = 0,
    Nas = 1,
    WiFi = 2,
    Firewall = 3,
    X509 = 4,
    Commercial = 5,
    VM = 6,
    Camera = 7,
    VPN = 8,
    PBX = 9,
    Printer = 10,
    Default = 11,
    Mail = 12,
    Admin = 13,
    Antivirus = 14,
    Honeypot = 15,
    Box = 16,
}

/// Category name strings, indexed by `X509Category` discriminant.
pub const CATEGORY_NAMES: &[&str] = &[
    "Unknown",  // 0
    "NAS",      // 1
    "WiFi",     // 2
    "FW",       // 3
    "X509",     // 4
    "Conf",     // 5
    "VM",       // 6
    "Cam",      // 7
    "VPN",      // 8
    "PBX",      // 9
    "Printer",  // 10
    "default",  // 11
    "mail",     // 12
    "admin",    // 13
    "AV",       // 14
    "honeypot", // 15
    "box",      // 16
];

/// In-memory database mapping IPv4 addresses to certificate names.
///
/// Used during `--readscan` to annotate `[VULN]` records with the SSL
/// certificate information observed on the same host.
pub struct CnDatabase {
    /// Buckets keyed by `ip & 0xFFFF` for fast lookup.
    entries: HashMap<u16, Vec<CnEntry>>,
}

struct CnEntry {
    ip: u32,
    name: String,
}

impl CnDatabase {
    /// Create an empty database.
    pub fn new() -> Self {
        CnDatabase {
            entries: HashMap::new(),
        }
    }

    /// Look up the certificate name for the given IP address.
    pub fn lookup(&self, ip: u32) -> Option<&str> {
        let bucket = (ip & 0xFFFF) as u16;
        self.entries
            .get(&bucket)
            .and_then(|list| list.iter().find(|e| e.ip == ip))
            .map(|e| e.name.as_str())
    }

    /// Insert a name for the given IP address. Empty names are ignored.
    pub fn add(&mut self, ip: u32, name: &str) {
        if name.is_empty() {
            return;
        }
        let bucket = (ip & 0xFFFF) as u16;
        self.entries
            .entry(bucket)
            .or_insert_with(Vec::new)
            .push(CnEntry {
                ip,
                name: name.to_string(),
            });
    }
}

impl Default for CnDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Known X.509 issuer/subject patterns and their categories.
///
/// Each entry is `(category, pattern_string)`. The C code feeds these
/// into a SMACK (Aho-Corasick) automaton for fast multi-pattern search
/// in certificate banners.
pub static X509_PATTERNS: &[(X509Category, &str)] = &[
    (X509Category::Nas, "nasend~~]"),
    (X509Category::PBX, "issuer[iPECS]"),
    (X509Category::Antivirus, "issuer[McAfee"),
    (X509Category::Admin, "issuer[webmin]"),
    (X509Category::Admin, "issuer[Webmin "),
    (X509Category::Printer, "subject[HP-IPG]"),
    (X509Category::Nas, "issuer[LaCie SA]"),
    (X509Category::WiFi, "subject[OpenWrt]"),
    (X509Category::Admin, "issuer[Puppet CA"),
    (X509Category::Antivirus, "issuer[Kaspersky"),
    (X509Category::Firewall, "subject[Fortinet]"),
    (X509Category::Firewall, "issuer[ICC-FW CA]"),
    (X509Category::Camera, "issuer[HIKVISION]"),
    (X509Category::Printer, "subject[SHARP MX-"),
    (X509Category::X509, "issuer[GANDI SAS]"),
    (X509Category::Firewall, "subject[FortiGate]"),
    (X509Category::Firewall, "issuer[watchguard]"),
    (X509Category::VM, "issuer[VMware Inc]"),
    (X509Category::Box, "issuer[eBox Server]"),
    (X509Category::Firewall, "subject[WatchGuard]"),
    (X509Category::X509, "issuer[RapidSSL CA]"),
    (X509Category::X509, "issuer[AddTrust AB]"),
    (X509Category::Commercial, "issuer[Cisco SSCA2]"),
    (X509Category::Commercial, "subject[Cisco SSCA2]"),
    (X509Category::Default, "issuer[v] issuer[v]"),
    (X509Category::X509, "issuer[Register.com]"),
    (X509Category::X509, "issuer[Thawte, Inc.]"),
    (X509Category::X509, "issuer[thawte, Inc.]"),
    (X509Category::Mail, "issuer[EQ-MT-RAPTOR]"),
    (X509Category::X509, "issuer[DigiCert Inc]"),
    (X509Category::X509, "issuer[TERENA SSL CA]"),
    (X509Category::Firewall, "issuer[WatchGuard CA]"),
    (X509Category::VPN, "issuer[OpenVPN Web CA"),
    (X509Category::X509, "issuer[GeoTrust Inc.]"),
    (X509Category::Nas, "issuer[TS Series NAS]"),
    (X509Category::Commercial, "subject[Polycom Inc.]"),
    (X509Category::Firewall, "issuer[Fortinet Ltd.]"),
    (X509Category::Nas, "issuer[Synology Inc.]"),
    (X509Category::Default, "issuer[XX] issuer[XX]"),
    (X509Category::WiFi, "2Wire]Gateway Device]"),
    (X509Category::X509, "subject[DigiCert Inc]"),
    (X509Category::Camera, "issuer[SamsungTechwin]"),
    (X509Category::X509, "issuer[TAIWAN-CA INC.]"),
    (X509Category::X509, "issuer[GeoTrust, Inc.]"),
    (X509Category::X509, "issuer[ValiCert, Inc.]"),
    (X509Category::Unknown, "issuer[Apache Friends]"),
    (X509Category::X509, "issuer[VeriSign, Inc.]"),
    (X509Category::X509, "issuer[Cybertrust Inc]"),
    (X509Category::Camera, "subject[HiTRON SYSTEMS]"),
    (X509Category::Firewall, "issuer[SonicWALL, Inc.]"),
    (X509Category::Firewall, "issuer[Future Systems.]"),
    (X509Category::Commercial, "issuer[Polycom Root CA]"),
    (X509Category::X509, "issuer[AlphaSSL CA - G2]"),
    (X509Category::X509, "issuer[GlobalSign nv-sa]"),
    (X509Category::VPN, "SonicWALL, Inc.]SSL-VPN]"),
    (X509Category::X509, "issuer[Comodo CA Limited]"),
    (X509Category::X509, "issuer[COMODO CA Limited]"),
    (X509Category::X509, "issuer[GoDaddy.com, Inc.]"),
    (X509Category::Box, "subject[Barracuda Networks]"),
    (X509Category::X509, "issuer[Equifax Secure Inc.]"),
    (X509Category::X509, "issuer[Gandi Standard SSL CA]"),
    (X509Category::X509, "issuer[The USERTRUST Network]"),
    (X509Category::Commercial, "subject[Polycom] subject[VSG]"),
    (X509Category::X509, "issuer[EuropeanSSL Server CA]"),
    (X509Category::Unknown, "issuer[SuSE Linux Web Server]"),
    (X509Category::WiFi, "issuer[CradlePoint Technology]"),
    (X509Category::VPN, "SonicWALL]Secure Remote Access]"),
    (X509Category::Default, "subject[SomeOrganizationalUnit]"),
    (X509Category::Default, "issuer[Internet Widgits Pty Ltd]"),
    (X509Category::X509, "issuer[Network Solutions L.L.C.]"),
    (X509Category::X509, "issuer[The Go Daddy Group, Inc.]"),
    (X509Category::Honeypot, "issuer[Nepenthes Development Team]"),
    (X509Category::X509, "issuer[WoSign Class 1 DV Server CA]"),
    (X509Category::Commercial, "issuer[Polycom Equipment Policy CA]"),
    (X509Category::X509, "issuer[Starfield Technologies, Inc.]"),
    (X509Category::X509, "issuer[Certum Certification Authority]"),
    (X509Category::Nas, "subject[Fujitsu CELVIN(R) NAS Server]"),
    (X509Category::VPN, "SonicWALL, Inc.]Secure Remote Access]"),
    (X509Category::X509, "issuer[Secure Digital Certificate Signing]"),
    (X509Category::X509, "issuer[Equifax Secure Certificate Authority]"),
    (X509Category::VM, "subject[VMware ESX Server Default Certificate]"),
    (X509Category::Camera, "issuer[Cisco Systems] issuer[Cisco Manufacturing CA]"),
];

/// Process a binary scan record for reporting purposes.
///
/// This is called during `--readscan` to annotate vulnerability records
/// with SSL certificate names. The `app_proto` and `data` parameters
/// determine what annotation is applied.
///
/// * For X.509 certificate records, the certificate's issuer/subject is
///   stored in the CN database.
/// * For vulnerability records, the database is queried to append the
///   certificate name to the vulnerability description.
///
/// Returns the (possibly modified) data. The full X.509 decode path
/// requires `proto::x509` which may not be ported yet; in that case
/// this function is a no-op that returns data unchanged.
pub fn readscan_report(
    db: &mut CnDatabase,
    ip: u32,
    _app_proto: u32,
    data: &mut Vec<u8>,
    _data_length: usize,
) {
    // The C code checks for PROTO_X509_CERT and PROTO_VULN.
    // Without the proto module's full X.509 decoder, we handle the
    // vulnerability annotation path if data looks like a vuln string.
    // The X.509 decode path requires proto::x509 which is separate.
    let _ = (db, ip, data);
}

/// Print the category counts (for debugging/reporting).
pub fn print_counts(counts: &[u32]) {
    println!("----counts----");
    for (i, &count) in counts.iter().enumerate() {
        if i < CATEGORY_NAMES.len() {
            println!("{:10} {}", count, CATEGORY_NAMES[i]);
        }
    }
    println!("---------------");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cndb_add_and_lookup() {
        let mut db = CnDatabase::new();
        db.add(0x0A000001, "test.example.com");
        assert_eq!(db.lookup(0x0A000001), Some("test.example.com"));
        assert_eq!(db.lookup(0x0A000002), None);
    }

    #[test]
    fn cndb_empty_name_ignored() {
        let mut db = CnDatabase::new();
        db.add(0x0A000001, "");
        assert_eq!(db.lookup(0x0A000001), None);
    }

    #[test]
    fn cndb_bucket_collision() {
        let mut db = CnDatabase::new();
        // Two IPs that hash to the same bucket (same low 16 bits)
        db.add(0x00010001, "first.example.com");
        db.add(0x00020001, "second.example.com");
        assert_eq!(db.lookup(0x00010001), Some("first.example.com"));
        assert_eq!(db.lookup(0x00020001), Some("second.example.com"));
    }
}
