//! TCP, UDP, and IP-protocol service name lookup.
//!
//! Provides port-to-service-name mapping using a built-in table of common
//! services. This avoids platform-specific dependencies on `/etc/services`
//! or `getservbyport()`.
//!
//! Ported from C `out-tcp-services.c`.

use std::collections::HashMap;
use std::sync::OnceLock;

/// Lazily-initialized TCP service name table.
fn tcp_services() -> &'static HashMap<u32, &'static str> {
    static TABLE: OnceLock<HashMap<u32, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut m = HashMap::new();
        // IANA-assigned well-known ports.
        let entries: &[(u32, &str)] = &[
            (1, "tcpmux"),
            (5, "rje"),
            (7, "echo"),
            (9, "discard"),
            (11, "systat"),
            (13, "daytime"),
            (17, "qotd"),
            (18, "msp"),
            (19, "chargen"),
            (20, "ftp-data"),
            (21, "ftp"),
            (22, "ssh"),
            (23, "telnet"),
            (25, "smtp"),
            (27, "nsw-fe"),
            (29, "msg-icp"),
            (31, "msg-auth"),
            (33, "dsp"),
            (37, "time"),
            (38, "rap"),
            (39, "rlp"),
            (42, "nameserver"),
            (43, "nicname"),
            (49, "tacacs"),
            (50, "re-mail-ck"),
            (53, "domain"),
            (57, "priv-term"),
            (67, "dhcps"),
            (68, "dhcpc"),
            (69, "tftp"),
            (70, "gopher"),
            (71, "netrjs-1"),
            (72, "netrjs-2"),
            (73, "netrjs-3"),
            (74, "netrjs-4"),
            (79, "finger"),
            (80, "http"),
            (81, "hosts2-ns"),
            (82, "xfer"),
            (83, "mit-ml-dev"),
            (84, "ctf"),
            (85, "mit-ml-dev"),
            (88, "kerberos"),
            (90, "dnsix"),
            (95, "supdup"),
            (98, "tacnews"),
            (99, "metagram"),
            (101, "hostname"),
            (102, "iso-tsap"),
            (105, "csnet-ns"),
            (107, "rtelnet"),
            (109, "pop2"),
            (110, "pop3"),
            (111, "sunrpc"),
            (113, "auth"),
            (115, "sftp"),
            (117, "uucp-path"),
            (119, "nntp"),
            (123, "ntp"),
            (129, "pwdgen"),
            (133, "statsrv"),
            (135, "msrpc"),
            (136, "profile"),
            (137, "netbios-ns"),
            (138, "netbios-dgm"),
            (139, "netbios-ssn"),
            (143, "imap"),
            (144, "uma"),
            (150, "sql-net"),
            (156, "sqlsrv"),
            (161, "snmp"),
            (162, "snmptrap"),
            (163, "cmip-man"),
            (164, "cmip-agent"),
            (174, "mailq"),
            (175, "vmnet"),
            (177, "xdmcp"),
            (179, "bgp"),
            (194, "irc"),
            (199, "smux"),
            (210, "z39.50"),
            (213, "ipx"),
            (220, "imap3"),
            (245, "link"),
            (264, "bgmp"),
            (280, "http-mgmt"),
            (347, "fatserv"),
            (363, "rsvp_tunnel"),
            (369, "rpc2portmap"),
            (389, "ldap"),
            (406, "prm-nm"),
            (407, "prm-nm"),
            (427, "svrloc"),
            (434, "mobileip-agent"),
            (443, "https"),
            (444, "snpp"),
            (445, "microsoft-ds"),
            (464, "kpasswd"),
            (465, "smtps"),
            (468, "photuris"),
            (487, "saft"),
            (488, "gss-http"),
            (497, "retrospect"),
            (500, "isakmp"),
            (512, "exec"),
            (513, "login"),
            (514, "shell"),
            (515, "printer"),
            (517, "talk"),
            (518, "ntalk"),
            (520, "efs"),
            (521, "ripng"),
            (525, "timed"),
            (526, "tempo"),
            (530, "courier"),
            (531, "conference"),
            (532, "netnews"),
            (533, "netwall"),
            (540, "uucp"),
            (543, "klogin"),
            (544, "kshell"),
            (546, "dhcpv6-client"),
            (547, "dhcpv6-server"),
            (548, "afp"),
            (550, "new-rwho"),
            (554, "rtsp"),
            (556, "remotefs"),
            (560, "rmonitor"),
            (561, "monitor"),
            (563, "nntps"),
            (587, "submission"),
            (591, "filemaker"),
            (593, "http-rpc-epmap"),
            (623, "asf-rmcp"),
            (625, "dec_dlm"),
            (626, "apple-imap-admin"),
            (631, "ipp"),
            (636, "ldaps"),
            (646, "ldp"),
            (647, "dhcp-failover"),
            (648, "rrp"),
            (654, "apex-mesh"),
            (665, "sun-dr"),
            (674, "acap"),
            (691, "ms-exchange"),
            (694, "heartbeat"),
            (698, "olsr"),
            (706, "silc"),
            (749, "kerberos-adm"),
            (750, "kerberos-iv"),
            (751, "pump"),
            (754, "krb5_prop"),
            (760, "krbupdate"),
            (782, "conserver"),
            (783, "spamd"),
            (800, "mdbs_daemon"),
            (808, "ccproxy-http"),
            (829, "certificate-mgmt"),
            (843, "syam-smc"),
            (847, "dhcp-failover2"),
            (848, "gdoi"),
            (860, "iscsi"),
            (873, "rsync"),
            (888, "cddbp"),
            (900, "omginitialrefs"),
            (902, "vmware-auth"),
            (953, "rndc"),
            (989, "ftps-data"),
            (990, "ftps"),
            (991, "nas"),
            (992, "telnets"),
            (993, "imaps"),
            (994, "ircs"),
            (995, "pop3s"),
            (999, "applix"),
            (1023, "netvenuechat"),
            (1024, "kdm"),
            (1025, "NFS-or-IIS"),
            (1026, "LSA-or-nterm"),
            (1027, "IIS"),
            (1028, "unknown"),
            (1029, "ms-lsa"),
            (1030, "BMC_onekey"),
            (1080, "socks"),
            (1099, "rmiactivation"),
            (1194, "openvpn"),
            (1214, "kazaa"),
            (1234, "vlc"),
            (1241, "nessus"),
            (1248, "hermes"),
            (1293, "ipsec-nat-t"),
            (1311, "dell-eql"),
            (1352, "lotusnotes"),
            (1433, "ms-sql-s"),
            (1434, "ms-sql-m"),
            (1500, "fujitsu-dtc"),
            (1503, "ms-lsa"),
            (1512, "wins"),
            (1521, "oracle"),
            (1527, "tlisrv"),
            (1580, "tn-tl-r1"),
            (1588, "vqp"),
            (1645, "radius"),
            (1646, "radius-acct"),
            (1701, "l2f"),
            (1718, "h323gatedisc"),
            (1719, "h323gatestat"),
            (1720, "h323hostcall"),
            (1723, "pptp"),
            (1741, "cisco-net-mgmt"),
            (1755, "ms-streaming"),
            (1812, "radius"),
            (1813, "radius-acct"),
            (1863, "msnp"),
            (1900, "ssdp"),
            (1935, "rtmp"),
            (1985, "hsrp"),
            (1998, "cisco-serial"),
            (1999, "cisco-tcp-ident"),
            (2000, "cisco-sccp"),
            (2049, "nfs"),
            (2082, "cpanel"),
            (2083, "cpanel-ssl"),
            (2086, "whm"),
            (2087, "whm-ssl"),
            (2095, "webmail"),
            (2096, "webmail-ssl"),
            (2100, "oracle-xdb"),
            (2222, "EtherNetIP-1"),
            (2375, "docker"),
            (2376, "docker-ssl"),
            (2401, "cvspserver"),
            (2483, "oracle-tns"),
            (2484, "oracle-tns-ssl"),
            (2593, "runsql"),
            (2598, "ica"),
            (2717, "pn-requester"),
            (2869, "icslap"),
            (3000, "ppp"),
            (3005, "geniuslm"),
            (3052, "apc-3052"),
            (3128, "squid-http"),
            (3260, "iscsi-target"),
            (3268, "msft-gc"),
            (3269, "msft-gc-ssl"),
            (3306, "mysql"),
            (3333, "dec-notes"),
            (3389, "ms-wbt-server"),
            (3689, "daap"),
            (3690, "svn"),
            (4000, "remoteanything"),
            (4045, "nfs-lockd"),
            (4333, "msql"),
            (4443, "pharos"),
            (4444, "krb524"),
            (4567, "tram"),
            (4662, "kar2ouche"),
            (4711, "pi"),
            (4713, "pulseaudio"),
            (4848, "appserv-http"),
            (4899, "radmin-port"),
            (5000, "upnp"),
            (5001, "commplex-link"),
            (5003, "fmpro-v6"),
            (5050, "mmcc"),
            (5060, "sip"),
            (5061, "sip-tls"),
            (5062, "sip-sigtran"),
            (5190, "aol"),
            (5222, "xmpp-client"),
            (5223, "xmpp-client-ssl"),
            (5269, "xmpp-server"),
            (5298, "presence"),
            (5353, "mdns"),
            (5357, "wsdapi"),
            (5432, "postgresql"),
            (5500, "fcp-addr-srvr1"),
            (5550, "cbus"),
            (5554, "sgi-eventmond"),
            (5555, "sgi-esphttp"),
            (5601, "a3-SDUun"),
            (5631, "pcanywheredata"),
            (5632, "pcanywherestat"),
            (5666, "nrpe"),
            (5667, "nsca"),
            (5672, "amqp"),
            (5678, "ms-sideshow"),
            (5800, "vnc-http"),
            (5900, "vnc"),
            (5901, "vnc-1"),
            (5938, "teamviewer"),
            (5985, "wsman"),
            (5986, "wsmans"),
            (6000, "x11"),
            (6001, "x11:1"),
            (6050, "arcserve"),
            (6112, "npmp-gui"),
            (6129, "dameware"),
            (6346, "gnutella"),
            (6379, "redis"),
            (6389, "clariion-evr"),
            (6514, "syslog-tls"),
            (6588, "analogx"),
            (6665, "ircu"),
            (6666, "ircd"),
            (6667, "irc"),
            (6668, "irc"),
            (6669, "irc"),
            (6697, "ircs-u"),
            (6881, "bittorrent-tracker"),
            (6969, "acmsoda"),
            (6970, "acmsoda"),
            (7000, "afs3-fileserver"),
            (7001, "afs3-callback"),
            (7002, "afs3-prserver"),
            (7007, "afs3-bos"),
            (7070, "realserver"),
            (7200, "fonix"),
            (7443, "oracle-as-https"),
            (7777, "cbt"),
            (7778, "interwise"),
            (8000, "http-alt"),
            (8008, "http"),
            (8009, "ajp13"),
            (8021, "ftp-proxy"),
            (8080, "http-proxy"),
            (8081, "blackice-icecap"),
            (8083, "us-cli"),
            (8084, "us-srv"),
            (8088, "radan-http"),
            (8090, "http-wmap"),
            (8180, "pro-ed"),
            (8222, "vmware-fdm"),
            (8443, "https-alt"),
            (8500, "fmtp"),
            (8808, "sun-answerbook"),
            (8834, "nessus-xmlrpc"),
            (8880, "cddbp-alt"),
            (8888, "sun-answerbook"),
            (8994, "mono"),
            (9000, "cslistener"),
            (9001, "etlservicemgr"),
            (9002, "dynamid"),
            (9042, "cassandra"),
            (9090, "zeus-admin"),
            (9100, "jetdirect"),
            (9101, "peerwire"),
            (9102, "s102"),
            (9160, "cassandra-cql"),
            (9200, "elasticsearch"),
            (9300, "ideafarm-door"),
            (9418, "git"),
            (9999, "abyss"),
            (10000, "snet-sensor-mgmt"),
            (10001, "scp-config"),
            (10443, "swdtp-service"),
            (11211, "memcached"),
            (11371, "hkp"),
            (15672, "rabbitmq-mgmt"),
            (20000, "dnp"),
            (25565, "minecraft"),
            (27017, "mongodb"),
            (27018, "mongodb"),
            (27019, "mongodb"),
            (28017, "mongodb-web"),
            (32768, "filenet-tms"),
            (32769, "filenet-rpc"),
            (32770, "filenet-nch"),
            (32771, "filenet-pc"),
            (49152, "go-advance"),
            (49153, "go-advance"),
            (49154, "go-advance"),
            (49155, "go-advance"),
            (49156, "go-advance"),
            (49157, "go-advance"),
            (50000, "iiimsf"),
            (50030, "smpnameres"),
            (61616, "patrol"),
        ];
        for &(port, name) in entries {
            m.insert(port, name);
        }
        m
    })
}

/// Lazily-initialized UDP service name table.
fn udp_services() -> &'static HashMap<u32, &'static str> {
    static TABLE: OnceLock<HashMap<u32, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut m = HashMap::new();
        let entries: &[(u32, &str)] = &[
            (7, "echo"),
            (9, "discard"),
            (11, "systat"),
            (13, "daytime"),
            (17, "qotd"),
            (19, "chargen"),
            (37, "time"),
            (42, "nameserver"),
            (49, "tacacs"),
            (53, "domain"),
            (67, "dhcps"),
            (68, "dhcpc"),
            (69, "tftp"),
            (88, "kerberos"),
            (111, "sunrpc"),
            (123, "ntp"),
            (135, "msrpc"),
            (137, "netbios-ns"),
            (138, "netbios-dgm"),
            (161, "snmp"),
            (162, "snmptrap"),
            (177, "xdmcp"),
            (347, "fatserv"),
            (389, "ldap"),
            (427, "svrloc"),
            (443, "https"),
            (445, "microsoft-ds"),
            (464, "kpasswd"),
            (500, "isakmp"),
            (514, "syslog"),
            (520, "route"),
            (521, "ripng"),
            (524, "ncp"),
            (525, "timed"),
            (546, "dhcpv6-client"),
            (547, "dhcpv6-server"),
            (548, "afp"),
            (554, "rtsp"),
            (560, "rmonitor"),
            (561, "monitor"),
            (593, "http-rpc-epmap"),
            (623, "asf-rmcp"),
            (626, "apple-imap-admin"),
            (631, "ipp"),
            (694, "heartbeat"),
            (698, "olsr"),
            (751, "pump"),
            (829, "certificate-mgmt"),
            (848, "gdoi"),
            (902, "vmware-auth"),
            (996, "xtreelic"),
            (1025, "unknown"),
            (1026, "unknown"),
            (1027, "unknown"),
            (1028, "unknown"),
            (1029, "ms-lsa"),
            (1194, "openvpn"),
            (1434, "ms-sql-m"),
            (1645, "radius"),
            (1646, "radius-acct"),
            (1701, "l2f"),
            (1718, "h323gatedisc"),
            (1719, "h323gatestat"),
            (1812, "radius"),
            (1813, "radius-acct"),
            (1900, "ssdp"),
            (1985, "hsrp"),
            (2049, "nfs"),
            (2222, "EtherNetIP-1"),
            (3260, "iscsi-target"),
            (3456, "vat"),
            (3478, "stun"),
            (4000, "remoteanything"),
            (4500, "ipsec-nat-t"),
            (5000, "upnp"),
            (5050, "mmcc"),
            (5060, "sip"),
            (5353, "mdns"),
            (5355, "llmnr"),
            (5683, "coap"),
            (5684, "coaps"),
            (6343, "sflow"),
            (7777, "cbt"),
            (8000, "http-alt"),
            (9100, "jetdirect"),
            (10000, "snet-sensor-mgmt"),
            (11211, "memcached"),
            (20000, "dnp"),
            (49152, "go-advance"),
            (49153, "go-advance"),
            (49154, "go-advance"),
            (49155, "go-advance"),
            (49156, "go-advance"),
            (49157, "go-advance"),
        ];
        for &(port, name) in entries {
            m.insert(port, name);
        }
        m
    })
}

/// Lazily-initialized IP protocol number table.
fn oproto_services() -> &'static HashMap<u32, &'static str> {
    static TABLE: OnceLock<HashMap<u32, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut m = HashMap::new();
        let entries: &[(u32, &str)] = &[
            (0, "hopopt"),
            (1, "icmp"),
            (2, "igmp"),
            (3, "ggp"),
            (4, "ipv4"),
            (5, "st"),
            (6, "tcp"),
            (7, "cbt"),
            (8, "egp"),
            (9, "igp"),
            (12, "pup"),
            (17, "udp"),
            (20, "hmp"),
            (27, "rdp"),
            (29, "iso-tp4"),
            (33, "dccp"),
            (36, "idrp"),
            (37, "idrp"),
            (41, "ipv6"),
            (43, "ipv6-route"),
            (44, "ipv6-frag"),
            (45, "idrp"),
            (46, "rsvp"),
            (47, "gre"),
            (50, "esp"),
            (51, "ah"),
            (58, "ipv6-icmp"),
            (59, "ipv6-nonxt"),
            (60, "ipv6-opts"),
            (73, "rspf"),
            (81, "vmtp"),
            (88, "eigrp"),
            (89, "ospf"),
            (94, "ipip"),
            (97, "etherip"),
            (98, "encap"),
            (103, "pim"),
            (108, "ipcomp"),
            (112, "vrrp"),
            (115, "l2tp"),
            (124, "isis"),
            (132, "sctp"),
            (133, "fc"),
            (136, "udplite"),
            (137, "mpls-in-ip"),
            (138, "manet"),
            (139, "hip"),
            (140, "shim6"),
            (141, "wesp"),
            (142, "rohc"),
        ];
        for &(proto, name) in entries {
            m.insert(proto, name);
        }
        m
    })
}

/// Look up the service name for a TCP port number.
pub fn tcp_service_name(port: u32) -> &'static str {
    tcp_services()
        .get(&port)
        .copied()
        .unwrap_or("unknown")
}

/// Look up the service name for a UDP port number.
pub fn udp_service_name(port: u32) -> &'static str {
    udp_services()
        .get(&port)
        .copied()
        .unwrap_or("unknown")
}

/// Look up the protocol name for an IP protocol number.
pub fn oproto_service_name(protocol_number: u32) -> &'static str {
    oproto_services()
        .get(&protocol_number)
        .copied()
        .unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_well_known_ports() {
        assert_eq!(tcp_service_name(22), "ssh");
        assert_eq!(tcp_service_name(80), "http");
        assert_eq!(tcp_service_name(443), "https");
        assert_eq!(tcp_service_name(21), "ftp");
        assert_eq!(tcp_service_name(25), "smtp");
        assert_eq!(tcp_service_name(53), "domain");
        assert_eq!(tcp_service_name(110), "pop3");
        assert_eq!(tcp_service_name(143), "imap");
        assert_eq!(tcp_service_name(993), "imaps");
        assert_eq!(tcp_service_name(995), "pop3s");
        assert_eq!(tcp_service_name(3306), "mysql");
        assert_eq!(tcp_service_name(3389), "ms-wbt-server");
        assert_eq!(tcp_service_name(5432), "postgresql");
        assert_eq!(tcp_service_name(6379), "redis");
        assert_eq!(tcp_service_name(8080), "http-proxy");
        assert_eq!(tcp_service_name(27017), "mongodb");
    }

    #[test]
    fn test_tcp_unknown_port() {
        assert_eq!(tcp_service_name(65535), "unknown");
    }

    #[test]
    fn test_udp_well_known_ports() {
        assert_eq!(udp_service_name(53), "domain");
        assert_eq!(udp_service_name(67), "dhcps");
        assert_eq!(udp_service_name(69), "tftp");
        assert_eq!(udp_service_name(123), "ntp");
        assert_eq!(udp_service_name(161), "snmp");
        assert_eq!(udp_service_name(514), "syslog");
        assert_eq!(udp_service_name(1194), "openvpn");
    }

    #[test]
    fn test_udp_unknown_port() {
        assert_eq!(udp_service_name(65535), "unknown");
    }

    #[test]
    fn test_oproto_well_known() {
        assert_eq!(oproto_service_name(1), "icmp");
        assert_eq!(oproto_service_name(6), "tcp");
        assert_eq!(oproto_service_name(17), "udp");
        assert_eq!(oproto_service_name(47), "gre");
        assert_eq!(oproto_service_name(50), "esp");
        assert_eq!(oproto_service_name(132), "sctp");
    }

    #[test]
    fn test_oproto_unknown() {
        assert_eq!(oproto_service_name(255), "unknown");
    }

    #[test]
    fn test_idempotent_lookups() {
        // Multiple lookups should return the same result.
        assert_eq!(tcp_service_name(80), tcp_service_name(80));
        assert_eq!(udp_service_name(53), udp_service_name(53));
        assert_eq!(oproto_service_name(6), oproto_service_name(6));
    }
}
