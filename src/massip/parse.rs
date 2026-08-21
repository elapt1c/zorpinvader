/// massip-parse
///
/// This module parses IPv4 and IPv6 addresses.
///
/// It's not a typical parser. It's optimized around parsing large
/// files containing millions of addresses and ranges using a
/// "state-machine parser".

use super::addr::{Ipv4Address, Ipv6Address};
use super::rangesv4::Range;
use super::rangesv6::Range6;
use super::massip::MassIP;

/// Result of parsing a range
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeParseResult {
    BadAddress = 0,
    Ipv4Address = 4,
    Ipv6Address = 6,
}

/// Internal parser state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum ParserState {
    LineStart = 0,
    AddrStart,
    Comment,
    Number0,
    Number1,
    Number2,
    Number3,
    NumberErr,
    Second0,
    Second1,
    Second2,
    Second3,
    SecondErr,
    Ipv4CidrNum,
    UniDash1,
    UniDash2,
    Ipv6Begin,
    Ipv6Colon,
    Ipv6Cidr,
    Ipv6CidrNum,
    Ipv6Next,
    Ipv6End,
    Error,
}

/// Result from the internal parser step function
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParserResult {
    StillWorking = 0,
    FoundError,
    FoundIpv4,
    FoundIpv6,
}

/// The parser state structure
struct MassipParser {
    line_number: u64,
    char_number: u64,
    state: ParserState,
    tmp: u32,
    digit_count: u8,
    addr: u32,
    begin: u32,
    end: u32,
    ipv6: Ipv6ParserState,
}

struct Ipv6ParserState {
    begin: Ipv6Address,
    end: Ipv6Address,
    tmp: [u16; 8],
    index: u8,
    ellision_index: u8,
    is_bracket: bool,
    is_second: bool,
}

impl MassipParser {
    fn new() -> Self {
        MassipParser {
            line_number: 1,
            char_number: 0,
            state: ParserState::LineStart,
            tmp: 0,
            digit_count: 0,
            addr: 0,
            begin: 0,
            end: 0,
            ipv6: Ipv6ParserState {
                begin: Ipv6Address { hi: 0, lo: 0 },
                end: Ipv6Address { hi: 0, lo: 0 },
                tmp: [0; 8],
                index: 0,
                ellision_index: 8,
                is_bracket: false,
                is_second: false,
            },
        }
    }

    fn init_next_address(&mut self, is_second: bool) {
        self.tmp = 0;
        self.ipv6.ellision_index = 8;
        self.ipv6.index = 0;
        self.ipv6.is_bracket = false;
        self.digit_count = 0;
        self.ipv6.is_second = is_second;
    }

    fn finish_ipv6(&mut self) -> Result<(), ()> {
        let index = self.ipv6.index as usize;
        let ellision = self.ipv6.ellision_index as usize;

        // We must have seen 8 numbers, or an ellision
        if index < 8 && ellision >= 8 {
            return Err(());
        }

        // Handle ellision
        let count_after_ellision = index - ellision;
        let dest_start = 8 - count_after_ellision;
        // Copy elements after ellision to the end
        for i in (0..count_after_ellision).rev() {
            self.ipv6.tmp[dest_start + i] = self.ipv6.tmp[ellision + i];
        }
        // Zero out the gap
        for i in ellision..(8 - count_after_ellision) {
            self.ipv6.tmp[i] = 0;
        }

        // Copy over to begin/end
        let a = Ipv6Address {
            hi: (self.ipv6.tmp[0] as u64) << 48
                | (self.ipv6.tmp[1] as u64) << 32
                | (self.ipv6.tmp[2] as u64) << 16
                | (self.ipv6.tmp[3] as u64),
            lo: (self.ipv6.tmp[4] as u64) << 48
                | (self.ipv6.tmp[5] as u64) << 32
                | (self.ipv6.tmp[6] as u64) << 16
                | (self.ipv6.tmp[7] as u64),
        };

        if self.ipv6.is_second {
            self.ipv6.end = a;
        } else {
            self.ipv6.begin = a;
            // Set this here in case there is no 'end' address
            self.ipv6.end = a;
        }

        // Reset the parser to start parsing the next address
        self.init_next_address(true);

        Ok(())
    }

    fn get_ipv6(&self) -> (Ipv6Address, Ipv6Address) {
        (self.ipv6.begin, self.ipv6.end)
    }

    /// Convert a decimal number being parsed as if it were hex (for IPv6 detection)
    fn switch_to_ipv6(&mut self) {
        let num = self.tmp;
        let result = ((num / 1000) % 10) * 16 * 16 * 16
            + ((num / 100) % 10) * 16 * 16
            + ((num / 10) % 10) * 16
            + (num % 10);
        self.tmp = result;
    }

    /// The main state machine parser function.
    /// Processes bytes from the buffer and returns the result.
    fn next(
        &mut self,
        buf: &[u8],
        offset: &mut usize,
        length: usize,
        r_begin: &mut u32,
        r_end: &mut u32,
    ) -> ParserResult {
        let mut i = *offset;
        let mut state = self.state;
        let mut result = ParserResult::StillWorking;
        let mut limit = length;

        while i < limit {
            let c = buf[i];
            i += 1;
            self.char_number += 1;

            match state {
                ParserState::LineStart | ParserState::AddrStart => {
                    self.init_next_address(false);
                    match c {
                        b' ' | b'\t' | b'\r' => continue,
                        b'\n' => {
                            self.line_number += 1;
                            self.char_number = 0;
                            continue;
                        }
                        b'#' | b';' | b'/' | b'-' => {
                            state = ParserState::Comment;
                            continue;
                        }
                        b'0'..=b'9' => {
                            self.tmp = (c - b'0') as u32;
                            self.digit_count = 1;
                            state = ParserState::Number0;
                        }
                        b'a'..=b'f' => {
                            self.tmp = (c - b'a' + 10) as u32;
                            self.digit_count = 1;
                            state = ParserState::Ipv6Begin;
                        }
                        b'A'..=b'F' => {
                            self.tmp = (c - b'A' + 10) as u32;
                            self.digit_count = 1;
                            state = ParserState::Ipv6Begin;
                        }
                        b':' => {
                            self.ipv6.tmp[self.ipv6.index as usize] = 0;
                            self.ipv6.index += 1;
                            state = ParserState::Ipv6Colon;
                        }
                        b'[' => {
                            self.ipv6.is_bracket = true;
                            state = ParserState::Ipv6Begin;
                        }
                        _ => {
                            state = ParserState::Error;
                            limit = i;
                        }
                    }
                }

                ParserState::Ipv6Cidr => {
                    self.digit_count = 0;
                    self.tmp = 0;
                    match c {
                        b'0'..=b'9' => {
                            self.tmp = (c - b'0') as u32;
                            self.digit_count = 1;
                            state = ParserState::Ipv6CidrNum;
                        }
                        _ => {
                            state = ParserState::Error;
                            limit = i;
                        }
                    }
                }

                ParserState::Ipv6Colon => {
                    self.digit_count = 0;
                    self.tmp = 0;
                    if c == b':' {
                        if self.ipv6.ellision_index < 8 {
                            state = ParserState::Error;
                            limit = i;
                        } else {
                            self.ipv6.ellision_index = self.ipv6.index;
                            state = ParserState::Ipv6Colon;
                        }
                        continue;
                    }
                    state = ParserState::Ipv6Begin;
                    // fall through to Ipv6Begin
                    self.handle_ipv6_begin_next(c, &mut state, &mut limit, &mut i);
                }

                ParserState::Ipv6Begin | ParserState::Ipv6Next => {
                    self.handle_ipv6_begin_next(c, &mut state, &mut limit, &mut i);
                }

                ParserState::Ipv6End => {
                    // Finish off the trailing number
                    self.ipv6.tmp[self.ipv6.index as usize] = self.tmp as u16;
                    self.ipv6.index += 1;

                    // Do the final processing of this IPv6 address
                    if self.finish_ipv6().is_err() {
                        state = ParserState::Error;
                        limit = i;
                        continue;
                    }

                    // Now decide the next state
                    match c {
                        b'/' => {
                            result = ParserResult::StillWorking;
                            state = ParserState::Ipv6Cidr;
                        }
                        b'-' => {
                            result = ParserResult::StillWorking;
                            state = ParserState::Ipv6Next;
                        }
                        b'\n' => {
                            self.line_number += 1;
                            self.char_number = 0;
                            result = ParserResult::FoundIpv6;
                            state = ParserState::LineStart;
                            limit = i;
                        }
                        b' ' | b'\t' | b'\r' | b',' => {
                            result = ParserResult::FoundIpv6;
                            state = ParserState::LineStart;
                            limit = i;
                        }
                        _ => {
                            state = ParserState::Error;
                            limit = i;
                        }
                    }
                }

                ParserState::Comment => {
                    if c == b'\n' {
                        state = ParserState::LineStart;
                        self.line_number += 1;
                        self.char_number = 0;
                    }
                }

                ParserState::Ipv6CidrNum => {
                    match c {
                        b'0'..=b'9' => {
                            if self.digit_count == 4 {
                                state = ParserState::Error;
                                limit = i;
                            } else {
                                self.digit_count += 1;
                                self.tmp = self.tmp * 10 + (c - b'0') as u32;
                                if self.tmp > 128 {
                                    state = ParserState::Error;
                                    limit = i;
                                }
                                continue;
                            }
                        }
                        b':' | b',' | b' ' | b'\t' | b'\r' | b'\n' => {
                            ipv6_apply_cidr(&mut self.ipv6.begin, &mut self.ipv6.end, self.tmp);
                            state = ParserState::AddrStart;
                            limit = i;
                            if c == b'\n' {
                                self.line_number += 1;
                                self.char_number = 0;
                            }
                            *r_begin = self.begin;
                            *r_end = self.end;
                            result = ParserResult::FoundIpv6;
                        }
                        _ => {
                            state = ParserState::Error;
                            limit = i;
                        }
                    }
                }

                ParserState::Ipv4CidrNum => {
                    match c {
                        b'0'..=b'9' => {
                            if self.digit_count == 3 {
                                state = ParserState::Error;
                                limit = i;
                            } else {
                                self.digit_count += 1;
                                self.tmp = self.tmp * 10 + (c - b'0') as u32;
                                if self.tmp > 32 {
                                    state = ParserState::Error;
                                    limit = i;
                                }
                                continue;
                            }
                        }
                        b':' | b',' | b' ' | b'\t' | b'\r' | b'\n' => {
                            ipv4_apply_cidr(&mut self.begin, &mut self.end, self.tmp);
                            state = ParserState::AddrStart;
                            limit = i;
                            if c == b'\n' {
                                self.line_number += 1;
                                self.char_number = 0;
                            }
                            *r_begin = self.begin;
                            *r_end = self.end;
                            result = ParserResult::FoundIpv4;
                        }
                        _ => {
                            state = ParserState::Error;
                            limit = i;
                        }
                    }
                }

                ParserState::UniDash1 => {
                    if c == 0x80 {
                        state = ParserState::UniDash2;
                    } else {
                        state = ParserState::Error;
                        limit = i;
                    }
                }

                ParserState::UniDash2 => {
                    // This covers U+2010 through U+2015
                    if !(0x90..=0x95).contains(&c) {
                        state = ParserState::Error;
                        limit = i;
                    } else {
                        state = ParserState::Number3;
                        // fall through to Number3
                        self.handle_number_state(
                            b'-',
                            &mut state,
                            &mut limit,
                            &mut i,
                            r_begin,
                            r_end,
                            &mut result,
                        );
                    }
                }

                ParserState::Number0
                | ParserState::Number1
                | ParserState::Number2
                | ParserState::Number3
                | ParserState::Second0
                | ParserState::Second1
                | ParserState::Second2
                | ParserState::Second3 => {
                    self.handle_number_state(c, &mut state, &mut limit, &mut i, r_begin, r_end, &mut result);
                }

                _ => {
                    state = ParserState::Error;
                    limit = i;
                }
            }
        }

        *offset = i;
        self.state = state;

        if matches!(
            state,
            ParserState::Error | ParserState::NumberErr | ParserState::SecondErr
        ) {
            ParserResult::FoundError
        } else {
            result
        }
    }

    fn handle_ipv6_begin_next(
        &mut self,
        c: u8,
        state: &mut ParserState,
        limit: &mut usize,
        i: &mut usize,
    ) {
        match c {
            b'0'..=b'9' => {
                if self.digit_count >= 4 {
                    *state = ParserState::Error;
                    *limit = *i;
                } else {
                    self.tmp = self.tmp * 16 + (c - b'0') as u32;
                    self.digit_count += 1;
                }
            }
            b'a'..=b'f' => {
                if self.digit_count >= 4 {
                    *state = ParserState::Error;
                    *limit = *i;
                } else {
                    self.tmp = self.tmp * 16 + (c - b'a' + 10) as u32;
                    self.digit_count += 1;
                }
            }
            b'A'..=b'F' => {
                if self.digit_count >= 4 {
                    *state = ParserState::Error;
                    *limit = *i;
                } else {
                    self.tmp = self.tmp * 16 + (c - b'A' + 10) as u32;
                    self.digit_count += 1;
                }
            }
            b':' => {
                if self.ipv6.index >= 8 {
                    *state = ParserState::Error;
                    *limit = *i;
                } else {
                    self.ipv6.tmp[self.ipv6.index as usize] = self.tmp as u16;
                    self.ipv6.index += 1;
                    *state = ParserState::Ipv6Colon;
                }
            }
            b']' => {
                if !self.ipv6.is_bracket {
                    *state = ParserState::Error;
                    *limit = *i;
                } else {
                    *state = ParserState::Ipv6End;
                }
            }
            b'[' => {
                if self.ipv6.is_bracket {
                    *state = ParserState::Error;
                    *limit = *i;
                } else {
                    self.ipv6.is_bracket = true;
                }
            }
            b'/' | b' ' | b'\t' | b'\r' | b'\n' | b',' | b'-' => {
                *i -= 1; // push back
                *state = ParserState::Ipv6End;
            }
            _ => {
                *state = ParserState::Error;
                *limit = *i;
            }
        }
    }

    fn handle_number_state(
        &mut self,
        c: u8,
        state: &mut ParserState,
        limit: &mut usize,
        i: &mut usize,
        r_begin: &mut u32,
        r_end: &mut u32,
        result: &mut ParserResult,
    ) {
        match c {
            b'.' => {
                self.addr = (self.addr << 8) | self.tmp;
                self.tmp = 0;
                self.digit_count = 0;
                if matches!(state, ParserState::Number3 | ParserState::Second3) {
                    *limit = *i;
                    *state = ParserState::Error;
                } else {
                    // Advance to next state (Number0->Number1, etc.)
                    *state = match state {
                        ParserState::Number0 => ParserState::Number1,
                        ParserState::Number1 => ParserState::Number2,
                        ParserState::Number2 => ParserState::Number3,
                        ParserState::Second0 => ParserState::Second1,
                        ParserState::Second1 => ParserState::Second2,
                        ParserState::Second2 => ParserState::Second3,
                        _ => ParserState::Error,
                    };
                }
            }
            b'0'..=b'9' => {
                self.digit_count += 1;
                self.tmp = self.tmp * 10 + (c - b'0') as u32;
                if self.tmp > 255 || self.digit_count > 3 {
                    if *state == ParserState::Number0 {
                        // Assume that we've actually got an IPv6 number
                        self.switch_to_ipv6();
                        *state = ParserState::Ipv6Begin;
                    } else {
                        *state = ParserState::Error;
                        *limit = *i;
                    }
                }
                // continue (don't fall through)
            }
            b'a'..=b'f' | b'A'..=b'F' => {
                if matches!(state, ParserState::Number0 | ParserState::Second0) {
                    // Assume that we've actually got an IPv6 number
                    self.switch_to_ipv6();
                    *state = ParserState::Ipv6Begin;
                    *i -= 1; // go back one character
                } else {
                    *state = ParserState::Error;
                    *limit = *i;
                }
            }
            0xe2 => {
                if *state == ParserState::Number3 {
                    *state = ParserState::UniDash1;
                } else {
                    *state = ParserState::Error;
                    *limit = *i;
                }
            }
            b'-' | 0x96 => {
                if *state == ParserState::Number3 {
                    self.begin = (self.addr << 8) | self.tmp;
                    self.tmp = 0;
                    self.digit_count = 0;
                    self.addr = 0;
                    *state = ParserState::Second0;
                } else {
                    *state = ParserState::NumberErr;
                    *limit = *i;
                }
            }
            b'/' => {
                if *state == ParserState::Number3 {
                    self.begin = (self.addr << 8) | self.tmp;
                    self.tmp = 0;
                    self.digit_count = 0;
                    self.addr = 0;
                    *state = ParserState::Ipv4CidrNum;
                } else {
                    *state = ParserState::NumberErr;
                    *limit = *i;
                }
            }
            b':' => {
                if *state == ParserState::Number0 {
                    // Assume this is an IPv6 address instead of an IPv4 address
                    self.switch_to_ipv6();
                    *state = ParserState::Ipv6Begin;
                    *i -= 1;
                }
                // For other states, fall through to comma handling
                if *state != ParserState::Ipv6Begin {
                    self.handle_ipv4_terminator(c, state, limit, i, r_begin, r_end, result);
                }
            }
            b',' | b' ' | b'\t' | b'\r' | b'\n' => {
                self.handle_ipv4_terminator(c, state, limit, i, r_begin, r_end, result);
            }
            _ => {
                *state = ParserState::Error;
                *limit = *i;
            }
        }
    }

    fn handle_ipv4_terminator(
        &mut self,
        c: u8,
        state: &mut ParserState,
        limit: &mut usize,
        _i: &mut usize,
        r_begin: &mut u32,
        r_end: &mut u32,
        result: &mut ParserResult,
    ) {
        if *state == ParserState::Number3 {
            self.begin = (self.addr << 8) | self.tmp;
            self.end = self.begin;
            self.tmp = 0;
            self.digit_count = 0;
            self.addr = 0;
            *state = ParserState::AddrStart;
            *limit = *_i;
            if c == b'\n' {
                self.line_number += 1;
                self.char_number = 0;
            }
            *r_begin = self.begin;
            *r_end = self.end;
            *result = ParserResult::FoundIpv4;
        } else if *state == ParserState::Second3 {
            self.end = (self.addr << 8) | self.tmp;
            self.tmp = 0;
            self.digit_count = 0;
            self.addr = 0;
            *state = ParserState::AddrStart;
            *limit = *_i;
            if c == b'\n' {
                self.line_number += 1;
                self.char_number = 0;
            }
            *r_begin = self.begin;
            *r_end = self.end;
            *result = ParserResult::FoundIpv4;
        } else {
            *state = ParserState::NumberErr;
            *limit = *_i;
        }
    }
}

/// Applies a CIDR mask to an IPv4 address to create a begin/end address.
fn ipv4_apply_cidr(begin: &mut u32, end: &mut u32, bitcount: u32) {
    let mask: u64 = 0xFFFFFFFF00000000u64 >> bitcount;
    *begin &= mask as u32;
    *end = *begin | !(mask as u32);
}

/// Apply CIDR to an IPv6 address
fn ipv6_apply_cidr(begin: &mut Ipv6Address, end: &mut Ipv6Address, prefix: u32) {
    if prefix > 128 {
        let invalid = Ipv6Address {
            hi: u64::MAX,
            lo: u64::MAX,
        };
        *begin = invalid;
        *end = invalid;
        return;
    }

    let mask = if prefix > 64 {
        Ipv6Address {
            hi: u64::MAX,
            lo: if prefix == 128 {
                u64::MAX
            } else {
                u64::MAX << (128 - prefix)
            },
        }
    } else if prefix == 0 {
        Ipv6Address { hi: 0, lo: 0 }
    } else {
        Ipv6Address {
            hi: u64::MAX << (64 - prefix),
            lo: 0,
        }
    };

    begin.hi &= mask.hi;
    begin.lo &= mask.lo;
    end.hi = begin.hi | !mask.hi;
    end.lo = begin.lo | !mask.lo;
}

/// Parse a file, extracting all the IPv4 and IPv6 addresses and ranges.
pub fn massip_parse_file(massip: &mut MassIP, filename: &str) -> Result<(), String> {
    use std::io::Read;

    let mut buf = vec![0u8; 65536];
    let mut p = MassipParser::new();
    let mut is_error = false;
    let mut addr_count: u32 = 0;

    let mut file: Box<dyn Read> = if filename == "-" {
        Box::new(std::io::stdin())
    } else {
        match std::fs::File::open(filename) {
            Ok(f) => Box::new(f),
            Err(e) => {
                return Err(format!("{}: {}", filename, e));
            }
        }
    };

    loop {
        let count = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                return Err(format!("read error: {}", e));
            }
        };

        let mut offset = 0;
        while offset < count {
            let mut begin: u32 = 0;
            let mut end: u32 = 0;

            let err = p.next(&buf, &mut offset, count, &mut begin, &mut end);
            match err {
                ParserResult::StillWorking => {}
                ParserResult::FoundError => {
                    let line_number = p.line_number;
                    let char_number = p.char_number;
                    eprintln!(
                        "[-] {}:{}:{}: invalid IP address on line #{}",
                        filename, line_number, char_number, line_number
                    );
                    is_error = true;
                    break;
                }
                ParserResult::FoundIpv4 => {
                    massip.ipv4.add_range(begin, end);
                    addr_count += 1;
                }
                ParserResult::FoundIpv6 => {
                    let (found_begin, found_end) = p.get_ipv6();
                    massip.ipv6.add_range(found_begin, found_end);
                    addr_count += 1;
                }
            }
        }
        if is_error {
            break;
        }
    }

    // In case the file doesn't end with a newline, add one
    if !is_error {
        let mut offset = 0;
        let mut begin: u32 = 0;
        let mut end: u32 = 0;
        let err = p.next(b"\n", &mut offset, 1, &mut begin, &mut end);
        match err {
            ParserResult::StillWorking => {}
            ParserResult::FoundIpv4 => {
                massip.ipv4.add_range(begin, end);
                addr_count += 1;
            }
            ParserResult::FoundIpv6 => {
                let (found_begin, found_end) = p.get_ipv6();
                massip.ipv6.add_range(found_begin, found_end);
                addr_count += 1;
            }
            ParserResult::FoundError => {
                let line_number = p.line_number;
                let char_number = p.char_number;
                eprintln!(
                    "[-] {}:{}:{}: invalid IP address on line #{}",
                    filename, line_number, char_number, line_number
                );
                is_error = true;
            }
        }
    }

    log::info!("[+] {}: {} addresses read", filename, addr_count);

    massip.ipv4.sort();

    if is_error {
        Err("parse error".to_string())
    } else {
        Ok(())
    }
}

/// Parse a single IPv6 address from a string.
pub fn massip_parse_ipv6(line: &str) -> Option<Ipv6Address> {
    let bytes = line.as_bytes();
    let count = bytes.len();
    let mut p = MassipParser::new();
    let mut offset = 0;
    let mut begin: u32 = 0;
    let mut end: u32 = 0;

    let err = p.next(bytes, &mut offset, count, &mut begin, &mut end);

    match err {
        ParserResult::StillWorking => {
            if offset < count {
                return None;
            }
            // Try with a newline appended
            offset = 0;
            let err2 = p.next(b"\n", &mut offset, 1, &mut begin, &mut end);
            match err2 {
                ParserResult::StillWorking => return None,
                ParserResult::FoundIpv6 => {
                    let (result, range) = p.get_ipv6();
                    if !result.is_equal(range) {
                        return None;
                    }
                    Some(result)
                }
                _ => None,
            }
        }
        ParserResult::FoundIpv6 => {
            let (result, range) = p.get_ipv6();
            if !result.is_equal(range) {
                return None;
            }
            Some(result)
        }
        _ => None,
    }
}

/// Parse a single IPv4 address from a string.
pub fn massip_parse_ipv4(line: &str) -> Option<Ipv4Address> {
    let bytes = line.as_bytes();
    let count = bytes.len();
    let mut p = MassipParser::new();
    let mut offset = 0;
    let mut begin: u32 = 0;
    let mut end: u32 = 0;

    let err = p.next(bytes, &mut offset, count, &mut begin, &mut end);

    match err {
        ParserResult::StillWorking => {
            if offset < count {
                return None;
            }
            offset = 0;
            let err2 = p.next(b"\n", &mut offset, 1, &mut begin, &mut end);
            match err2 {
                ParserResult::StillWorking => None,
                ParserResult::FoundIpv4 => {
                    if begin != end {
                        return None;
                    }
                    Some(begin)
                }
                _ => None,
            }
        }
        ParserResult::FoundIpv4 => {
            if begin != end {
                return None;
            }
            Some(begin)
        }
        _ => None,
    }
}

/// Parse the next IPv4/IPv6 range from a string.
pub fn massip_parse_range(
    line: &[u8],
    offset: Option<&mut usize>,
    count: usize,
    ipv4: Option<&mut Range>,
    ipv6: Option<&mut Range6>,
) -> RangeParseResult {
    let mut p = MassipParser::new();
    let mut begin: u32 = 0;
    let mut end: u32 = 0;

    // The 'count' is optional. If zero and offset is None, use string length
    let actual_count = if count == 0 && offset.is_none() {
        line.len()
    } else {
        count
    };

    // The offset is optional
    let mut tmp_offset = 0usize;
    let offset_ref = match offset {
        Some(o) => o,
        None => &mut tmp_offset,
    };

    let err = p.next(line, offset_ref, actual_count, &mut begin, &mut end);

    match err {
        ParserResult::StillWorking => {
            if *offset_ref < actual_count {
                return RangeParseResult::BadAddress;
            }
            // Try with a newline appended
            let err2 = p.next(b"\n", &mut 0, 1, &mut begin, &mut end);
            match err2 {
                ParserResult::StillWorking => RangeParseResult::BadAddress,
                ParserResult::FoundIpv4 => {
                    if let Some(r) = ipv4 {
                        r.begin = begin;
                        r.end = end;
                    }
                    RangeParseResult::Ipv4Address
                }
                ParserResult::FoundIpv6 => {
                    if let Some(r) = ipv6 {
                        let (b, e) = p.get_ipv6();
                        r.begin = b;
                        r.end = e;
                    }
                    RangeParseResult::Ipv6Address
                }
                _ => RangeParseResult::BadAddress,
            }
        }
        ParserResult::FoundIpv4 => {
            if let Some(r) = ipv4 {
                r.begin = begin;
                r.end = end;
            }
            RangeParseResult::Ipv4Address
        }
        ParserResult::FoundIpv6 => {
            if let Some(r) = ipv6 {
                let (b, e) = p.get_ipv6();
                r.begin = b;
                r.end = e;
            }
            RangeParseResult::Ipv6Address
        }
        ParserResult::FoundError => RangeParseResult::BadAddress,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCase {
        string: &'static str,
        begin: Ipv6Address,
        end: Ipv6Address,
    }

    fn test_cases() -> Vec<TestCase> {
        vec![
            TestCase {
                string: "[1::1]/126",
                begin: Ipv6Address { hi: 0x0001000000000000, lo: 0 },
                end: Ipv6Address { hi: 0x0001000000000000, lo: 3 },
            },
            TestCase {
                string: "1::1/126",
                begin: Ipv6Address { hi: 0x0001000000000000, lo: 0 },
                end: Ipv6Address { hi: 0x0001000000000000, lo: 3 },
            },
            TestCase {
                string: "[1::1]-[2::3]",
                begin: Ipv6Address { hi: 0x0001000000000000, lo: 1 },
                end: Ipv6Address { hi: 0x0002000000000000, lo: 3 },
            },
            TestCase {
                string: "1::1-2::3",
                begin: Ipv6Address { hi: 0x0001000000000000, lo: 1 },
                end: Ipv6Address { hi: 0x0002000000000000, lo: 3 },
            },
            TestCase {
                string: "[1234:5678:9abc:def0:0fed:cba9:8765:4321]",
                begin: Ipv6Address { hi: 0x123456789abcdef0, lo: 0x0fedcba987654321 },
                end: Ipv6Address { hi: 0x123456789abcdef0, lo: 0x0fedcba987654321 },
            },
            TestCase {
                string: "22ab::1",
                begin: Ipv6Address { hi: 0x22ab000000000000, lo: 1 },
                end: Ipv6Address { hi: 0x22ab000000000000, lo: 1 },
            },
            TestCase {
                string: "240e:33c:2:c080:d08:d0e:b53:e74e",
                begin: Ipv6Address { hi: 0x240e033c0002c080, lo: 0x0d080d0e0b53e74e },
                end: Ipv6Address { hi: 0x240e033c0002c080, lo: 0x0d080d0e0b53e74e },
            },
            TestCase {
                string: "2a03:90c0:105::9",
                begin: Ipv6Address { hi: 0x2a0390c001050000, lo: 9 },
                end: Ipv6Address { hi: 0x2a0390c001050000, lo: 9 },
            },
            TestCase {
                string: "2a03:9060:0:400::2",
                begin: Ipv6Address { hi: 0x2a03906000000400, lo: 2 },
                end: Ipv6Address { hi: 0x2a03906000000400, lo: 2 },
            },
            TestCase {
                string: "2c0f:ff00:0:a:face:b00c:0:a7",
                begin: Ipv6Address { hi: 0x2c0fff000000000a, lo: 0xfaceb00c000000a7 },
                end: Ipv6Address { hi: 0x2c0fff000000000a, lo: 0xfaceb00c000000a7 },
            },
            TestCase {
                string: "2a01:5b40:0:4a01:0:e21d:789f:59b1",
                begin: Ipv6Address { hi: 0x2a015b4000004a01, lo: 0x0000e21d789f59b1 },
                end: Ipv6Address { hi: 0x2a015b4000004a01, lo: 0x0000e21d789f59b1 },
            },
            TestCase {
                string: "2001:1200:10::1",
                begin: Ipv6Address { hi: 0x2001120000100000, lo: 1 },
                end: Ipv6Address { hi: 0x2001120000100000, lo: 1 },
            },
            TestCase {
                string: "fec0:0:0:ffff::1",
                begin: Ipv6Address { hi: 0xfec000000000ffff, lo: 1 },
                end: Ipv6Address { hi: 0xfec000000000ffff, lo: 1 },
            },
            TestCase {
                string: "1234:5678:9abc:def0:0fed:cba9:8765:4321",
                begin: Ipv6Address { hi: 0x123456789abcdef0, lo: 0x0fedcba987654321 },
                end: Ipv6Address { hi: 0x123456789abcdef0, lo: 0x0fedcba987654321 },
            },
            TestCase {
                string: "[1111:2222:3333:4444:5555:6666:7777:8888]",
                begin: Ipv6Address { hi: 0x1111222233334444, lo: 0x5555666677778888 },
                end: Ipv6Address { hi: 0x1111222233334444, lo: 0x5555666677778888 },
            },
            TestCase {
                string: "1::1",
                begin: Ipv6Address { hi: 0x0001000000000000, lo: 1 },
                end: Ipv6Address { hi: 0x0001000000000000, lo: 1 },
            },
            TestCase {
                string: "1.2.3.4",
                begin: Ipv6Address { hi: 0, lo: 0x01020304 },
                end: Ipv6Address { hi: 0, lo: 0x01020304 },
            },
            TestCase {
                string: "1.2.3.4/24\n",
                begin: Ipv6Address { hi: 0, lo: 0x01020300 },
                end: Ipv6Address { hi: 0, lo: 0x010203ff },
            },
            TestCase {
                string: " 1.2.3.4-1.2.3.5\n",
                begin: Ipv6Address { hi: 0, lo: 0x01020304 },
                end: Ipv6Address { hi: 0, lo: 0x01020305 },
            },
        ]
    }

    fn rangefile6_test_buffer(
        parser: &mut MassipParser,
        buf: &str,
        expected_begin: Ipv6Address,
        expected_end: Ipv6Address,
    ) -> bool {
        let bytes = buf.as_bytes();
        let length = bytes.len();
        let mut offset = 0;
        let mut tmp1: u32 = 0;
        let mut tmp2: u32 = 0;

        let err = parser.next(bytes, &mut offset, length, &mut tmp1, &mut tmp2);
        let err = if err == ParserResult::StillWorking {
            offset = 0;
            parser.next(b"\n", &mut offset, 1, &mut tmp1, &mut tmp2)
        } else {
            err
        };

        match err {
            ParserResult::FoundIpv6 => {
                let (found_begin, found_end) = parser.get_ipv6();
                if !found_begin.is_equal(expected_begin) {
                    eprintln!(
                        "begin mismatch: found=[{}], expected=[{}]",
                        found_begin, expected_begin
                    );
                    return false;
                }
                if !found_end.is_equal(expected_end) {
                    eprintln!(
                        "end mismatch: found=[{}], expected=[{}]",
                        found_end, expected_end
                    );
                    return false;
                }
                true
            }
            ParserResult::FoundIpv4 => {
                if expected_begin.hi != 0 || expected_end.hi != 0 {
                    return false;
                }
                if tmp1 != expected_begin.lo as u32 || tmp2 != expected_end.lo as u32 {
                    return false;
                }
                true
            }
            ParserResult::StillWorking => false,
            ParserResult::FoundError => false,
        }
    }

    #[test]
    fn test_massip_parse_selftest() {
        let cases = test_cases();
        let mut parser = MassipParser::new();

        for (i, tc) in cases.iter().enumerate() {
            let result = rangefile6_test_buffer(
                &mut parser,
                tc.string,
                tc.begin,
                tc.end,
            );
            assert!(result, "test case {} failed: {}", i, tc.string);
            parser = MassipParser::new();
        }
    }

    #[test]
    fn test_selftest_massip_parse_range() {
        struct TestCase {
            line: &'static str,
            expected: Vec<Range>,
        }

        let cases = vec![
            TestCase {
                line: "0.0.1.0/24,0.0.3.0-0.0.4.0",
                expected: vec![
                    Range { begin: 0x100, end: 0x1ff },
                    Range { begin: 0x300, end: 0x400 },
                ],
            },
            TestCase {
                line: "0.0.1.0-0.0.1.255,0.0.3.0-0.0.4.0",
                expected: vec![
                    Range { begin: 0x100, end: 0x1ff },
                    Range { begin: 0x300, end: 0x400 },
                ],
            },
            TestCase {
                line: "0.0.1.0/24 0.0.3.0-0.0.4.0",
                expected: vec![
                    Range { begin: 0x100, end: 0x1ff },
                    Range { begin: 0x300, end: 0x400 },
                ],
            },
        ];

        for (i, tc) in cases.iter().enumerate() {
            let bytes = tc.line.as_bytes();
            let length = bytes.len();
            let mut offset = 0;
            let mut j = 0;

            while offset < length {
                let mut range4 = Range { begin: 0, end: 0 };
                let mut range6 = Range6 {
                    begin: Ipv6Address { hi: 0, lo: 0 },
                    end: Ipv6Address { hi: 0, lo: 0 },
                };

                let x = massip_parse_range(
                    bytes,
                    Some(&mut offset),
                    length,
                    Some(&mut range4),
                    Some(&mut range6),
                );

                match x {
                    RangeParseResult::Ipv4Address => {
                        assert!(j < tc.expected.len(), "too many ranges parsed at case {}", i);
                        assert_eq!(
                            range4.begin, tc.expected[j].begin,
                            "begin mismatch at case {} range {}",
                            i, j
                        );
                        assert_eq!(
                            range4.end, tc.expected[j].end,
                            "end mismatch at case {} range {}",
                            i, j
                        );
                    }
                    RangeParseResult::BadAddress => {
                        panic!("parse error at case {} range {}", i, j);
                    }
                    _ => {}
                }
                j += 1;
            }

            assert_eq!(
                j,
                tc.expected.len(),
                "not all expected ranges parsed at case {}",
                i
            );
        }
    }

    fn rangefile_test_error(
        buf: &str,
        in_line_number: u64,
        in_char_number: u64,
        which_test: u32,
    ) -> bool {
        let bytes = buf.as_bytes();
        let length = bytes.len();
        let mut offset = 0;
        let mut p = MassipParser::new();
        let mut out_begin: u32 = 0xa3a3a3a3;
        let mut out_end: u32 = 0xa3a3a3a3;

        let x = p.next(bytes, &mut offset, length, &mut out_begin, &mut out_end);
        if x != ParserResult::FoundError {
            eprintln!("[-] rangefile test fail, line={}", which_test);
            return false;
        }
        if p.line_number != in_line_number || p.char_number != in_char_number {
            eprintln!(
                "[-] rangefile test fail at line={}, expected {}:{}, got {}:{}",
                which_test, in_line_number, in_char_number, p.line_number, p.char_number
            );
            return false;
        }

        // Test one byte at a time
        let mut p = MassipParser::new();
        let mut offset = 0;
        out_begin = 0xa3a3a3a3;
        out_end = 0xa3a3a3a3;

        let mut x = ParserResult::StillWorking;
        while offset < length {
            let next_max = offset + 1;
            x = p.next(bytes, &mut offset, next_max, &mut out_begin, &mut out_end);
            if x == ParserResult::FoundError {
                break;
            }
        }
        if x != ParserResult::FoundError {
            eprintln!("[-] rangefile test fail (byte-by-byte), line={}", which_test);
            return false;
        }
        if p.line_number != in_line_number || p.char_number != in_char_number {
            eprintln!(
                "[-] rangefile test fail (byte-by-byte) at line={}, expected {}:{}, got {}:{}",
                which_test, in_line_number, in_char_number, p.line_number, p.char_number
            );
            return false;
        }

        true
    }

    #[test]
    fn test_error_detection() {
        assert!(rangefile_test_error(
            "#bad ipv4\n 257.1.1.1\n",
            2,
            5,
            line!() as u32
        ));
        assert!(rangefile_test_error(
            "#bad ipv4\n 1.257.1.1.1\n",
            2,
            6,
            line!() as u32
        ));
        assert!(rangefile_test_error(
            "#bad ipv4\n 1.10.257.1.1.1\n",
            2,
            9,
            line!() as u32
        ));
        assert!(rangefile_test_error(
            "#bad ipv4\n 1.10.255.256.1.1.1\n",
            2,
            13,
            line!() as u32
        ));
        assert!(rangefile_test_error(
            "#bad ipv4\n 1.1.1.1.1\n",
            2,
            9,
            line!() as u32
        ));
    }
}
