#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ApplicationProtocol {
    None = 0,
    Heur = 1,
    Ssh1 = 2,
    Ssh2 = 3,
    Http = 4,
    Ftp = 5,
    DnsVersionBind = 6,
    Snmp = 7,
    NbtStat = 8,
    Ssl3 = 9,
    Smb = 10,
    Smtp = 11,
    Pop3 = 12,
    Imap4 = 13,
    UdpZeroAccess = 14,
    X509Cert = 15,
    X509CaCert = 16,
    HtmlTitle = 17,
    HtmlFull = 18,
    Ntp = 19,
    Vuln = 20,
    Heartbleed = 21,
    Ticketbleed = 22,
    VncOld = 23,
    Safe = 24,
    Memcached = 25,
    Scripting = 26,
    Versioning = 27,
    Coap = 28,
    Telnet = 29,
    Rdp = 30,
    HttpServer = 31,
    Mc = 32,
    VncRfb = 33,
    VncInfo = 34,
    Isakmp = 35,
    Error = 36,
}

impl ApplicationProtocol {
    pub const END_OF_LIST: u32 = 37;

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None | Self::Heur => "unknown",
            Self::Ssh1 | Self::Ssh2 => "ssh",
            Self::Http => "http",
            Self::Ftp => "ftp",
            Self::DnsVersionBind => "dns-ver",
            Self::Snmp => "snmp",
            Self::NbtStat => "nbtstat",
            Self::Ssl3 => "ssl",
            Self::Smb => "smb",
            Self::Smtp => "smtp",
            Self::Pop3 => "pop",
            Self::Imap4 => "imap",
            Self::UdpZeroAccess => "zeroaccess",
            Self::X509Cert => "X509",
            Self::X509CaCert => "X509CA",
            Self::HtmlTitle => "title",
            Self::HtmlFull => "html",
            Self::Ntp => "ntp",
            Self::Vuln => "vuln",
            Self::Heartbleed => "heartbleed",
            Self::Ticketbleed => "ticketbleed",
            Self::VncOld | Self::VncRfb => "vnc",
            Self::Safe => "safe",
            Self::Memcached => "memcached",
            Self::Scripting => "scripting",
            Self::Versioning => "versioning",
            Self::Coap => "coap",
            Self::Telnet => "telnet",
            Self::Rdp => "rdp",
            Self::HttpServer => "http.server",
            Self::Mc => "minecraft",
            Self::VncInfo => "vnc-info",
            Self::Isakmp => "isakmp",
            Self::Error => "error",
        }
    }
}

impl std::fmt::Display for ApplicationProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub fn from_string(s: &str) -> ApplicationProtocol {
    match s {
        "ssh1" => ApplicationProtocol::Ssh1,
        "ssh2" | "ssh" => ApplicationProtocol::Ssh2,
        "http" => ApplicationProtocol::Http,
        "ftp" => ApplicationProtocol::Ftp,
        "dns-ver" => ApplicationProtocol::DnsVersionBind,
        "snmp" => ApplicationProtocol::Snmp,
        "nbtstat" => ApplicationProtocol::NbtStat,
        "ssl" => ApplicationProtocol::Ssl3,
        "smtp" => ApplicationProtocol::Smtp,
        "smb" => ApplicationProtocol::Smb,
        "pop" => ApplicationProtocol::Pop3,
        "imap" => ApplicationProtocol::Imap4,
        "x509" => ApplicationProtocol::X509Cert,
        "x509ca" => ApplicationProtocol::X509CaCert,
        "zeroaccess" => ApplicationProtocol::UdpZeroAccess,
        "title" => ApplicationProtocol::HtmlTitle,
        "html" => ApplicationProtocol::HtmlFull,
        "ntp" => ApplicationProtocol::Ntp,
        "vuln" => ApplicationProtocol::Vuln,
        "heartbleed" => ApplicationProtocol::Heartbleed,
        "ticketbleed" => ApplicationProtocol::Ticketbleed,
        "vnc-old" => ApplicationProtocol::VncOld,
        "safe" => ApplicationProtocol::Safe,
        "memcached" => ApplicationProtocol::Memcached,
        "scripting" => ApplicationProtocol::Scripting,
        "versioning" => ApplicationProtocol::Versioning,
        "coap" => ApplicationProtocol::Coap,
        "telnet" => ApplicationProtocol::Telnet,
        "rdp" => ApplicationProtocol::Rdp,
        "http.server" => ApplicationProtocol::HttpServer,
        "minecraft" => ApplicationProtocol::Mc,
        "vnc" => ApplicationProtocol::VncRfb,
        "vnc-info" => ApplicationProtocol::VncInfo,
        "isakmp" => ApplicationProtocol::Isakmp,
        _ => ApplicationProtocol::None,
    }
}

pub fn selftest() -> i32 {
    let tests: &[(ApplicationProtocol, u32)] = &[
        (ApplicationProtocol::Snmp, 7),
        (ApplicationProtocol::X509Cert, 15),
        (ApplicationProtocol::HttpServer, 31),
    ];

    for &(proto, expected) in tests {
        if proto as u32 != expected {
            eprintln!(
                "[-] app selftest: expected={}, found={}",
                expected,
                proto as u32
            );
            return 1;
        }
    }
    0
}
