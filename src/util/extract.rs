//! Byte extraction from network packets with endian support.
//!
//! Provides a buffer reader that extracts integers in both big-endian
//! (network byte order) and little-endian formats.

/// Endianness for byte extraction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    /// Big-endian (network byte order)
    Big,
    /// Little-endian
    Little,
}

/// A buffer reader for extracting bytes and integers from network packets.
///
/// Tracks the current read position and provides bounds-checked extraction.
pub struct ExtractBuffer<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> ExtractBuffer<'a> {
    /// Create a new ExtractBuffer from a byte slice.
    ///
    /// # Arguments
    /// * `buf` - The byte slice to read from
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    /// Get the current read offset.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Get the remaining bytes available to read.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.offset)
    }

    /// Get the total length of the buffer.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Reset the read offset to the beginning.
    pub fn reset(&mut self) {
        self.offset = 0;
    }

    /// Set the read offset to a specific position.
    ///
    /// # Arguments
    /// * `offset` - The new offset position
    ///
    /// # Returns
    /// Ok(()) if the offset is valid, Err if out of bounds
    pub fn set_offset(&mut self, offset: usize) -> Result<(), &'static str> {
        if offset > self.buf.len() {
            return Err("offset out of bounds");
        }
        self.offset = offset;
        Ok(())
    }

    /// Extract the next byte from the buffer.
    ///
    /// # Returns
    /// Ok(byte) if successful, Err if at end of buffer
    pub fn next_byte(&mut self) -> Result<u8, &'static str> {
        if self.offset + 1 > self.buf.len() {
            return Err("buffer underflow");
        }

        let byte = self.buf[self.offset];
        self.offset += 1;
        Ok(byte)
    }

    /// Extract the next 16-bit integer from the buffer.
    ///
    /// # Arguments
    /// * `endian` - The endianness to use for interpretation
    ///
    /// # Returns
    /// Ok(u16) if successful, Err if insufficient bytes remain
    pub fn next_u16(&mut self, endian: Endian) -> Result<u16, &'static str> {
        if self.offset + 2 > self.buf.len() {
            return Err("buffer underflow");
        }

        let result = match endian {
            Endian::Big => {
                ((self.buf[self.offset] as u16) << 8) | (self.buf[self.offset + 1] as u16)
            }
            Endian::Little => {
                ((self.buf[self.offset + 1] as u16) << 8) | (self.buf[self.offset] as u16)
            }
        };

        self.offset += 2;
        Ok(result)
    }

    /// Extract the next 32-bit integer from the buffer.
    ///
    /// # Arguments
    /// * `endian` - The endianness to use for interpretation
    ///
    /// # Returns
    /// Ok(u32) if successful, Err if insufficient bytes remain
    pub fn next_u32(&mut self, endian: Endian) -> Result<u32, &'static str> {
        if self.offset + 4 > self.buf.len() {
            return Err("buffer underflow");
        }

        let result = match endian {
            Endian::Big => {
                ((self.buf[self.offset] as u32) << 24)
                    | ((self.buf[self.offset + 1] as u32) << 16)
                    | ((self.buf[self.offset + 2] as u32) << 8)
                    | (self.buf[self.offset + 3] as u32)
            }
            Endian::Little => {
                ((self.buf[self.offset + 3] as u32) << 24)
                    | ((self.buf[self.offset + 2] as u32) << 16)
                    | ((self.buf[self.offset + 1] as u32) << 8)
                    | (self.buf[self.offset] as u32)
            }
        };

        self.offset += 4;
        Ok(result)
    }

    /// Extract the next 64-bit integer from the buffer.
    ///
    /// # Arguments
    /// * `endian` - The endianness to use for interpretation
    ///
    /// # Returns
    /// Ok(u64) if successful, Err if insufficient bytes remain
    pub fn next_u64(&mut self, endian: Endian) -> Result<u64, &'static str> {
        if self.offset + 8 > self.buf.len() {
            return Err("buffer underflow");
        }

        let result = match endian {
            Endian::Big => {
                let hi = ((self.buf[self.offset] as u64) << 24)
                    | ((self.buf[self.offset + 1] as u64) << 16)
                    | ((self.buf[self.offset + 2] as u64) << 8)
                    | (self.buf[self.offset + 3] as u64);
                let lo = ((self.buf[self.offset + 4] as u64) << 24)
                    | ((self.buf[self.offset + 5] as u64) << 16)
                    | ((self.buf[self.offset + 6] as u64) << 8)
                    | (self.buf[self.offset + 7] as u64);
                (hi << 32) | lo
            }
            Endian::Little => {
                let lo = ((self.buf[self.offset + 3] as u64) << 24)
                    | ((self.buf[self.offset + 2] as u64) << 16)
                    | ((self.buf[self.offset + 1] as u64) << 8)
                    | (self.buf[self.offset] as u64);
                let hi = ((self.buf[self.offset + 7] as u64) << 24)
                    | ((self.buf[self.offset + 6] as u64) << 16)
                    | ((self.buf[self.offset + 5] as u64) << 8)
                    | (self.buf[self.offset + 4] as u64);
                (hi << 32) | lo
            }
        };

        self.offset += 8;
        Ok(result)
    }

    /// Extract a slice of bytes from the buffer.
    ///
    /// # Arguments
    /// * `len` - Number of bytes to extract
    ///
    /// # Returns
    /// Ok(&[u8]) if successful, Err if insufficient bytes remain
    pub fn next_bytes(&mut self, len: usize) -> Result<&'a [u8], &'static str> {
        if self.offset + len > self.buf.len() {
            return Err("buffer underflow");
        }

        let slice = &self.buf[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_byte() {
        let buf = [0x12, 0x34, 0x56];
        let mut ebuf = ExtractBuffer::new(&buf);

        assert_eq!(ebuf.next_byte().unwrap(), 0x12);
        assert_eq!(ebuf.next_byte().unwrap(), 0x34);
        assert_eq!(ebuf.next_byte().unwrap(), 0x56);
        assert!(ebuf.next_byte().is_err());
    }

    #[test]
    fn test_extract_u16_big_endian() {
        let buf = [0x12, 0x34, 0x56, 0x78];
        let mut ebuf = ExtractBuffer::new(&buf);

        assert_eq!(ebuf.next_u16(Endian::Big).unwrap(), 0x1234);
        assert_eq!(ebuf.next_u16(Endian::Big).unwrap(), 0x5678);
        assert!(ebuf.next_u16(Endian::Big).is_err());
    }

    #[test]
    fn test_extract_u16_little_endian() {
        let buf = [0x34, 0x12, 0x78, 0x56];
        let mut ebuf = ExtractBuffer::new(&buf);

        assert_eq!(ebuf.next_u16(Endian::Little).unwrap(), 0x1234);
        assert_eq!(ebuf.next_u16(Endian::Little).unwrap(), 0x5678);
    }

    #[test]
    fn test_extract_u32_big_endian() {
        let buf = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let mut ebuf = ExtractBuffer::new(&buf);

        assert_eq!(ebuf.next_u32(Endian::Big).unwrap(), 0x12345678);
        assert_eq!(ebuf.next_u32(Endian::Big).unwrap(), 0x9ABCDEF0);
    }

    #[test]
    fn test_extract_u32_little_endian() {
        let buf = [0x78, 0x56, 0x34, 0x12, 0xF0, 0xDE, 0xBC, 0x9A];
        let mut ebuf = ExtractBuffer::new(&buf);

        assert_eq!(ebuf.next_u32(Endian::Little).unwrap(), 0x12345678);
        assert_eq!(ebuf.next_u32(Endian::Little).unwrap(), 0x9ABCDEF0);
    }

    #[test]
    fn test_extract_u64_big_endian() {
        let buf = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let mut ebuf = ExtractBuffer::new(&buf);

        assert_eq!(ebuf.next_u64(Endian::Big).unwrap(), 0x123456789ABCDEF0);
    }

    #[test]
    fn test_extract_u64_little_endian() {
        let buf = [0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12];
        let mut ebuf = ExtractBuffer::new(&buf);

        assert_eq!(ebuf.next_u64(Endian::Little).unwrap(), 0x123456789ABCDEF0);
    }

    #[test]
    fn test_extract_bytes() {
        let buf = [0x12, 0x34, 0x56, 0x78];
        let mut ebuf = ExtractBuffer::new(&buf);

        let slice = ebuf.next_bytes(2).unwrap();
        assert_eq!(slice, &[0x12, 0x34]);

        let slice = ebuf.next_bytes(2).unwrap();
        assert_eq!(slice, &[0x56, 0x78]);

        assert!(ebuf.next_bytes(1).is_err());
    }

    #[test]
    fn test_offset_and_remaining() {
        let buf = [0u8; 10];
        let mut ebuf = ExtractBuffer::new(&buf);

        assert_eq!(ebuf.offset(), 0);
        assert_eq!(ebuf.remaining(), 10);

        ebuf.next_byte().unwrap();
        assert_eq!(ebuf.offset(), 1);
        assert_eq!(ebuf.remaining(), 9);

        ebuf.set_offset(5).unwrap();
        assert_eq!(ebuf.offset(), 5);
        assert_eq!(ebuf.remaining(), 5);

        ebuf.reset();
        assert_eq!(ebuf.offset(), 0);
        assert_eq!(ebuf.remaining(), 10);
    }
}
