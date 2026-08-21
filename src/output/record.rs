//! Output record type identifiers for the binary output format.
//!
//! Ported from C `out-record.h`.

/// Record type tags written into binary output files.
///
/// Discriminant values **must not change** — they are part of the on-disk
/// binary format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OutputRecordType {
    OutOpen = 1,
    OutClosed = 2,
    OutBanner1 = 5,
    OutOpen2 = 6,
    OutClosed2 = 7,
    OutArp2 = 8,
    OutBanner9 = 9,
    OutOpen6 = 10,
    OutClosed6 = 11,
    OutArp6 = 12,
    OutBanner6 = 13,
}

impl OutputRecordType {
    /// Convert from raw byte value read from a binary file.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::OutOpen),
            2 => Some(Self::OutClosed),
            5 => Some(Self::OutBanner1),
            6 => Some(Self::OutOpen2),
            7 => Some(Self::OutClosed2),
            8 => Some(Self::OutArp2),
            9 => Some(Self::OutBanner9),
            10 => Some(Self::OutOpen6),
            11 => Some(Self::OutClosed6),
            12 => Some(Self::OutArp6),
            13 => Some(Self::OutBanner6),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discriminant_values() {
        assert_eq!(OutputRecordType::OutOpen as u8, 1);
        assert_eq!(OutputRecordType::OutClosed as u8, 2);
        assert_eq!(OutputRecordType::OutBanner1 as u8, 5);
        assert_eq!(OutputRecordType::OutOpen2 as u8, 6);
        assert_eq!(OutputRecordType::OutClosed2 as u8, 7);
        assert_eq!(OutputRecordType::OutArp2 as u8, 8);
        assert_eq!(OutputRecordType::OutBanner9 as u8, 9);
        assert_eq!(OutputRecordType::OutOpen6 as u8, 10);
        assert_eq!(OutputRecordType::OutClosed6 as u8, 11);
        assert_eq!(OutputRecordType::OutArp6 as u8, 12);
        assert_eq!(OutputRecordType::OutBanner6 as u8, 13);
    }

    #[test]
    fn test_from_u8() {
        assert_eq!(OutputRecordType::from_u8(1), Some(OutputRecordType::OutOpen));
        assert_eq!(OutputRecordType::from_u8(9), Some(OutputRecordType::OutBanner9));
        assert_eq!(OutputRecordType::from_u8(0), None);
        assert_eq!(OutputRecordType::from_u8(255), None);
    }
}
