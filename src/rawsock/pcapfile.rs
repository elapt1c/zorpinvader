//! Pcap file reader/writer.
//!
//! Implements the libpcap file format directly (no libpcap dependency) so
//! that we can read/write capture files even when libpcap isn't installed.
//! Handles corrupt files by scanning forward to find the next valid packet.
//!
//! File format reference:
//! ```text
//! Global header (24 bytes):
//!   4 bytes  magic number (0xa1b2c3d4 BE or 0xd4c3b2a1 LE)
//!   2 bytes  major version (2)
//!   2 bytes  minor version (4)
//!   4 bytes  timezone offset (unused, 0)
//!   4 bytes  sigfigs (unused, 0)
//!   4 bytes  snaplen
//!   4 bytes  link-layer type
//!
//! Per-packet record (16-byte header + data):
//!   4 bytes  timestamp seconds
//!   4 bytes  timestamp microseconds
//!   4 bytes  captured length
//!   4 bytes  original length
//!   N bytes  packet data (N = captured length)
//! ```

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Magic numbers identifying pcap byte order.
const MAGIC_BIG_ENDIAN: u32 = 0xa1b2_c3d4;
const MAGIC_LITTLE_ENDIAN: u32 = 0xd4c3_b2a1;

/// Standard pcap version 2.4.
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;

/// Default snap length written to new files.
const DEFAULT_SNAPLEN: u32 = 0xFFFF;

/// Maximum packet size we will accept as valid.
const MAX_PACKET_SIZE: u32 = 160_000;

/// Maximum captured size we read into a single buffer.
const MAX_READ_SIZE: u32 = 16_384;

/// Byte order of the pcap file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ByteOrder {
    BigEndian,
    LittleEndian,
    Unknown,
}

impl ByteOrder {
    fn read_u16(self, buf: &[u8]) -> u16 {
        match self {
            Self::BigEndian => u16::from_be_bytes([buf[0], buf[1]]),
            Self::LittleEndian => u16::from_le_bytes([buf[0], buf[1]]),
            Self::Unknown => 0,
        }
    }

    fn read_u32(self, buf: &[u8]) -> u32 {
        match self {
            Self::BigEndian => u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            Self::LittleEndian => u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            Self::Unknown => 0,
        }
    }

    fn write_u32_le(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    fn write_u16_le(v: u16) -> [u8; 2] {
        v.to_le_bytes()
    }
}

/// Link-layer type constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PcapLinkType {
    Ethernet = 1,
    Wifi = 105,
    LinuxSll = 113,
    RawIp = 101,
}

impl PcapLinkType {
    pub fn from_raw(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Ethernet),
            105 => Some(Self::Wifi),
            113 => Some(Self::LinuxSll),
            101 => Some(Self::RawIp),
            _ => None,
        }
    }

    pub fn to_raw(self) -> u32 {
        self as u32
    }
}

/// An open pcap file for reading or writing.
pub struct PcapFile {
    fp: File,
    path: PathBuf,
    byte_order: ByteOrder,
    linktype: u32,
    frame_number: u64,
    file_size: u64,
    bytes_read: u64,
    start_sec: u32,
    start_usec: u32,
    end_sec: u32,
    end_usec: u32,
    is_file_header_written: bool,
}

/// A single pcap packet record.
#[derive(Debug)]
pub struct PcapRecord {
    pub secs: u32,
    pub usecs: u32,
    pub original_length: u32,
    pub captured_length: u32,
    pub data: Vec<u8>,
}

impl PcapFile {
    // -----------------------------------------------------------------------
    // Reading
    // -----------------------------------------------------------------------

    /// Open a pcap file for reading.
    pub fn open_read(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let mut fp = File::open(path)?;
        let file_size = fs::metadata(path)?.len();

        // Read the 24-byte global header.
        let mut hdr = [0u8; 24];
        fp.read_exact(&mut hdr)?;

        // Determine byte order from magic number.
        let magic = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let byte_order = match magic {
            MAGIC_BIG_ENDIAN => ByteOrder::BigEndian,
            MAGIC_LITTLE_ENDIAN => ByteOrder::LittleEndian,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: unknown pcap magic number 0x{:08x}", path.display(), magic),
                ));
            }
        };

        // Validate version.
        let major = byte_order.read_u16(&hdr[4..]);
        let minor = byte_order.read_u16(&hdr[6..]);
        if major != PCAP_VERSION_MAJOR || minor != PCAP_VERSION_MINOR {
            log::warn!(
                "{}: unexpected pcap version {}.{}",
                path.display(),
                major,
                minor
            );
        }

        // Link-layer type.
        let linktype = byte_order.read_u32(&hdr[20..]);

        Ok(Self {
            fp,
            path: path.to_path_buf(),
            byte_order,
            linktype,
            frame_number: 0,
            file_size,
            bytes_read: 24,
            start_sec: 0,
            start_usec: 0,
            end_sec: 0,
            end_usec: 0,
            is_file_header_written: true,
        })
    }

    /// Read the next packet record from the file.
    ///
    /// Returns `Ok(None)` at end of file.
    pub fn read_frame(&mut self, buf: &mut Vec<u8>) -> io::Result<Option<PcapRecord>> {
        loop {
            // Read 16-byte per-packet header.
            let mut pkt_hdr = [0u8; 16];
            match self.fp.read_exact(&mut pkt_hdr) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e),
            }
            self.bytes_read += 16;

            let secs = self.byte_order.read_u32(&pkt_hdr[0..]);
            let usecs = self.byte_order.read_u32(&pkt_hdr[4..]);
            let cap_len = self.byte_order.read_u32(&pkt_hdr[8..]);
            let orig_len = self.byte_order.read_u32(&pkt_hdr[12..]);

            // Validate fields.
            let is_corrupt = usecs > 1_000_100
                || cap_len > MAX_READ_SIZE
                || orig_len < cap_len
                || orig_len < 8
                || orig_len > MAX_PACKET_SIZE;

            if is_corrupt {
                log::warn!(
                    "{}: corrupt record at frame #{}, scanning forward",
                    self.path.display(),
                    self.frame_number
                );
                self.scan_forward_for_valid()?;
                // Recurse: the file pointer now points at a good record.
                return self.read_frame(buf);
            }

            // Read packet data.
            buf.resize(cap_len as usize, 0);
            match self.fp.read_exact(buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e),
            }
            self.bytes_read += cap_len as u64;

            // Track timestamps.
            if self.frame_number == 0 {
                self.start_sec = secs;
                self.start_usec = usecs;
            }
            self.end_sec = secs;
            self.end_usec = usecs;
            self.frame_number += 1;

            return Ok(Some(PcapRecord {
                secs,
                usecs,
                original_length: orig_len,
                captured_length: cap_len,
                data: buf.clone(),
            }));
        }
    }

    /// Scan forward through the file looking for a valid packet header after
    /// corruption was detected.
    fn scan_forward_for_valid(&mut self) -> io::Result<()> {
        let mut chunk = vec![0u8; 16_384];
        loop {
            let pos = self.fp.stream_position()?;
            let n = self.fp.read(&mut chunk)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "no valid packet found after corruption",
                ));
            }
            self.bytes_read += n as u64;

            // Scan byte-by-byte for a plausible header.
            for i in 0..n.saturating_sub(16) {
                if smells_like_valid_header(&chunk[i..], self.byte_order) {
                    let target = pos + i as u64;
                    self.fp.seek(SeekFrom::Start(target))?;
                    log::info!(
                        "{}: valid-looking header found at offset 0x{:x}",
                        self.path.display(),
                        target
                    );
                    return Ok(());
                }
            }
        }
    }

    /// Return the link-layer type.
    pub fn linktype(&self) -> u32 {
        self.linktype
    }

    /// Approximate percentage of the file read so far (0–100).
    pub fn percent_done(&self) -> u32 {
        if self.file_size == 0 {
            return 100;
        }
        (self.bytes_read * 100 / self.file_size) as u32
    }

    /// Return the bytes read so far.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Return the first and last timestamps seen (as seconds since epoch).
    pub fn timestamps(&self) -> (u32, u32) {
        (self.start_sec, self.end_sec)
    }

    /// Return total frames read so far.
    pub fn frame_count(&self) -> u64 {
        self.frame_number
    }

    // -----------------------------------------------------------------------
    // Writing
    // -----------------------------------------------------------------------

    /// Create a new pcap file for writing with the given link-layer type.
    pub fn open_write(path: impl AsRef<Path>, linktype: PcapLinkType) -> io::Result<Self> {
        let path = path.as_ref();
        let mut fp = File::create(path)?;

        write_global_header(&mut fp, linktype.to_raw())?;

        Ok(Self {
            fp,
            path: path.to_path_buf(),
            byte_order: ByteOrder::LittleEndian,
            linktype: linktype.to_raw(),
            frame_number: 0,
            file_size: 0,
            bytes_read: 0,
            start_sec: 0,
            start_usec: 0,
            end_sec: 0,
            end_usec: 0,
            is_file_header_written: true,
        })
    }

    /// Open a pcap file for appending. If the file doesn't exist, a new one
    /// is created.
    pub fn open_append(path: impl AsRef<Path>, linktype: PcapLinkType) -> io::Result<Self> {
        let path = path.as_ref();

        // Try to open existing file for append.
        if path.exists() {
            let mut fp = OpenOptions::new().read(true).append(true).open(path)?;

            // Read header to discover byte order and link type.
            let mut hdr = [0u8; 24];
            fp.seek(SeekFrom::Start(0))?;
            fp.read_exact(&mut hdr)?;
            fp.seek(SeekFrom::End(0))?;

            let magic = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
            let byte_order = match magic {
                MAGIC_BIG_ENDIAN => ByteOrder::BigEndian,
                MAGIC_LITTLE_ENDIAN => ByteOrder::LittleEndian,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unknown pcap magic",
                    ));
                }
            };
            let file_linktype = byte_order.read_u32(&hdr[20..]);

            if file_linktype != linktype.to_raw() {
                log::warn!(
                    "link-type mismatch: file has {}, requested {}",
                    file_linktype,
                    linktype.to_raw()
                );
            }

            Ok(Self {
                fp,
                path: path.to_path_buf(),
                byte_order,
                linktype: file_linktype,
                frame_number: 0,
                file_size: 0,
                bytes_read: 0,
                start_sec: 0,
                start_usec: 0,
                end_sec: 0,
                end_usec: 0,
                is_file_header_written: true,
            })
        } else {
            Self::open_write(path, linktype)
        }
    }

    /// Write a single frame to the file.
    pub fn write_frame(
        &mut self,
        data: &[u8],
        original_length: u32,
        secs: u32,
        usecs: u32,
    ) -> io::Result<()> {
        let cap_len = data.len() as u32;
        let mut hdr = [0u8; 16];
        hdr[0..4].copy_from_slice(&ByteOrder::write_u32_le(secs));
        hdr[4..8].copy_from_slice(&ByteOrder::write_u32_le(usecs));
        hdr[8..12].copy_from_slice(&ByteOrder::write_u32_le(cap_len));
        hdr[12..16].copy_from_slice(&ByteOrder::write_u32_le(original_length));
        self.fp.write_all(&hdr)?;
        self.fp.write_all(data)?;
        self.frame_number += 1;
        Ok(())
    }

    /// Flush buffered data to disk.
    pub fn flush(&mut self) -> io::Result<()> {
        self.fp.flush()
    }

    /// Return the file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Write the 24-byte pcap global header in little-endian byte order.
fn write_global_header(fp: &mut File, linktype: u32) -> io::Result<()> {
    let mut hdr = [0u8; 24];
    // Magic (little-endian: 0xd4c3b2a1)
    hdr[0..4].copy_from_slice(&MAGIC_LITTLE_ENDIAN.to_le_bytes());
    // Version 2.4
    hdr[4..6].copy_from_slice(&ByteOrder::write_u16_le(PCAP_VERSION_MAJOR));
    hdr[6..8].copy_from_slice(&ByteOrder::write_u16_le(PCAP_VERSION_MINOR));
    // Timezone offset = 0 (bytes 8..12)
    // Sigfigs = 0 (bytes 12..16)
    // Snap length
    hdr[16..20].copy_from_slice(&ByteOrder::write_u32_le(DEFAULT_SNAPLEN));
    // Link type
    hdr[20..24].copy_from_slice(&ByteOrder::write_u32_le(linktype));

    fp.write_all(&hdr)
}

/// Quick heuristic: does this 16-byte blob look like a valid pcap packet header?
fn smells_like_valid_header(buf: &[u8], byte_order: ByteOrder) -> bool {
    if buf.len() < 16 {
        return false;
    }

    let secs = byte_order.read_u32(&buf[0..]);
    let usecs = byte_order.read_u32(&buf[4..]);
    let cap_len = byte_order.read_u32(&buf[8..]);
    let orig_len = byte_order.read_u32(&buf[12..]);

    // Timestamps should be in a plausible range (1990–2030).
    if secs > 0x5000_0000 || secs < 0x2600_0000 {
        return false;
    }
    if usecs > 1_000_000 {
        return false;
    }
    // Packet sizes should be sane.
    if cap_len > 10_000 || cap_len < 16 {
        return false;
    }
    if orig_len < cap_len || orig_len > 10_000 {
        return false;
    }

    // If there's enough data, peek at the *next* header for back-to-back validity.
    if buf.len() >= 16 + cap_len as usize + 16 {
        let next = &buf[16 + cap_len as usize..];
        let s2 = byte_order.read_u32(&next[0..]);
        let u2 = byte_order.read_u32(&next[4..]);
        let c2 = byte_order.read_u32(&next[8..]);
        let o2 = byte_order.read_u32(&next[12..]);

        if s2 > 0x5000_0000 || s2 < 0x2600_0000 {
            return false;
        }
        if u2 > 1_000_000 || c2 > 10_000 || c2 < 16 || o2 < c2 || o2 > 10_000 {
            return false;
        }
        return true;
    }

    // Single-header fallback: check Ethernet/IP heuristic.
    // Look for ethertype 0x0800 (IPv4) at offset 12–13, then IPv4 version 4 at offset 14.
    if buf.len() >= 15 && buf[12] == 0x08 && buf[13] == 0x00 && (buf[14] >> 4) == 4 {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trip_write_read() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_pcapfile_roundtrip.pcap");

        // Write a small file.
        {
            let mut pf = PcapFile::open_write(&path, PcapLinkType::Ethernet).unwrap();
            let pkt = vec![0xAA; 64];
            pf.write_frame(&pkt, 64, 1_700_000_000, 12345).unwrap();
            pf.write_frame(&pkt, 64, 1_700_000_001, 67890).unwrap();
            pf.flush().unwrap();
        }

        // Read it back.
        {
            let mut pf = PcapFile::open_read(&path).unwrap();
            assert_eq!(pf.linktype(), PcapLinkType::Ethernet as u32);

            let mut buf = Vec::new();
            let r1 = pf.read_frame(&mut buf).unwrap().unwrap();
            assert_eq!(r1.captured_length, 64);
            assert_eq!(r1.secs, 1_700_000_000);
            assert_eq!(r1.data.len(), 64);

            let r2 = pf.read_frame(&mut buf).unwrap().unwrap();
            assert_eq!(r2.secs, 1_700_000_001);

            assert!(pf.read_frame(&mut buf).unwrap().is_none());
            assert_eq!(pf.frame_count(), 2);
        }

        let _ = fs::remove_file(&path);
    }
}
