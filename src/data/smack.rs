//! Aho-Corasick multi-pattern string matching engine.
//!
//! This is a faithful port of the C "SMACK" engine, used for protocol
//! detection and pattern matching. It creates a state-machine out of
//! patterns (like a DFA implementation of a regex) and can search for
//! many patterns simultaneously in a single pass over the input.
//!
//! Supports:
//! - Case-sensitive and case-insensitive matching
//! - Anchor-begin (^) and anchor-end ($) patterns
//! - SNMP hack patterns
//! - Wildcard patterns
//! - Fragmented input (state carries across calls)

use super::smackqueue::SmackQueue;

/// Return value when no match is found.
pub const SMACK_NOT_FOUND: usize = !0;

// --- Anchor flag constants (matching the C header) ---

/// Pattern must match at the beginning of input.
pub const SMACK_ANCHOR_BEGIN: u32 = 0x01;
/// Pattern must match at the end of input.
pub const SMACK_ANCHOR_END: u32 = 0x02;
/// SNMP hack flag.
pub const SMACK_SNMP_HACK: u32 = 0x04;
/// Wildcards enabled for this pattern.
pub const SMACK_WILDCARDS: u32 = 0x08;

/// Case-sensitive matching.
pub const SMACK_CASE_SENSITIVE: u32 = 0;
/// Case-insensitive matching.
pub const SMACK_CASE_INSENSITIVE: u32 = 1;

/// Anchor-start pseudo-character.
const CHAR_ANCHOR_START: usize = 256;
/// Anchor-end pseudo-character.
const CHAR_ANCHOR_END: usize = 257;
/// Total alphabet size: 256 bytes + 2 anchor symbols.
const ALPHABET_SIZE: usize = 256 + 2;
/// The "fail" sentinel value during compilation.
const FAIL: u32 = u32::MAX;
/// Base state index.
const BASE_STATE: usize = 0;
/// Unanchored state index (swapped with base if anchors present).
const UNANCHORED_STATE: usize = 1;

/// Anchor flags for pattern registration.
#[derive(Debug, Clone, Copy)]
pub struct SmackFlags {
    bits: u32,
}

impl SmackFlags {
    pub const NONE: Self = Self { bits: 0 };
    pub const ANCHOR_BEGIN: Self = Self { bits: SMACK_ANCHOR_BEGIN };
    pub const ANCHOR_END: Self = Self { bits: SMACK_ANCHOR_END };
    pub const SNMP_HACK: Self = Self { bits: SMACK_SNMP_HACK };
    pub const WILDCARDS: Self = Self { bits: SMACK_WILDCARDS };

    pub const fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }

    pub const fn bits(self) -> u32 {
        self.bits
    }

    pub const fn union(self, other: Self) -> Self {
        Self { bits: self.bits | other.bits }
    }
}

/// Case-sensitivity mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmackCase {
    Sensitive,
    Insensitive,
}

/// Anchor mode for pattern registration.
#[derive(Debug, Clone, Copy)]
pub enum SmackAnchor {
    None,
    Begin,
    End,
    Both,
}

/// Search state, carried across fragmented input calls.
///
/// The lower 24 bits hold the current DFA row; the upper 8 bits hold
/// pending match count (for multi-match enumeration).
#[derive(Debug, Clone, Copy)]
pub struct SmackSearchState {
    raw: u32,
}

impl SmackSearchState {
    pub fn new() -> Self {
        Self { raw: 0 }
    }

    pub fn raw(&self) -> u32 {
        self.raw
    }
}

impl Default for SmackSearchState {
    fn default() -> Self {
        Self::new()
    }
}

/// Transition type — 16-bit states (supports up to 65535 states).
type TransitionT = u16;

// ---------------------------------------------------------------------------
// Internal structures
// ---------------------------------------------------------------------------

/// A registered pattern (held only during compilation, then discarded).
struct SmackPattern {
    /// The ID reported when this pattern matches.
    id: usize,
    /// Copy of the pattern bytes (lowered if nocase).
    pattern: Vec<u8>,
    /// Flags.
    is_anchor_begin: bool,
    is_anchor_end: bool,
    is_snmp_hack: bool,
    is_wildcards: bool,
}

/// Intermediate state row (held during compilation).
struct SmackRow {
    next_state: [u32; ALPHABET_SIZE],
    fail_state: u32,
}

impl SmackRow {
    fn new() -> Self {
        SmackRow {
            next_state: [FAIL; ALPHABET_SIZE],
            fail_state: 0,
        }
    }
}

/// Match information for a state.
struct SmackMatches {
    ids: Vec<usize>,
}

impl SmackMatches {
    fn new() -> Self {
        SmackMatches { ids: Vec::new() }
    }

    fn count(&self) -> usize {
        self.ids.len()
    }
}

/// The Aho-Corasick pattern matching engine.
pub struct Smack {
    /// Name for this engine instance.
    name: String,
    /// Case-insensitive mode.
    is_nocase: bool,
    /// Whether any pattern has anchor-begin.
    is_anchor_begin: bool,
    /// Whether any pattern has anchor-end.
    is_anchor_end: bool,

    // --- Compilation-time structures (freed after compile) ---
    patterns: Vec<SmackPattern>,
    state_table: Vec<SmackRow>,
    match_table: Vec<SmackMatches>,
    state_count: usize,

    // --- Symbol compression ---
    symbol_to_char: [usize; ALPHABET_SIZE],
    char_to_symbol: [u8; ALPHABET_SIZE],
    symbol_count: usize,

    // --- Final compiled table ---
    row_shift: usize,
    table: Vec<TransitionT>,
    match_limit: usize,
    /// Compiled match table (mirrors match_table but persists after compile).
    compiled_matches: Vec<SmackMatches>,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Compute the row shift (log2 of the nearest power-of-2 >= symbol_count+1).
fn row_shift_from_symbol_count(symbol_count: usize) -> usize {
    let mut row_shift = 1usize;
    let needed = symbol_count + 1;
    while (1usize << row_shift) < needed {
        row_shift += 1;
    }
    row_shift
}

/// Case-insensitive byte lowering.
fn to_lower(b: u8) -> u8 {
    if b.is_ascii_uppercase() {
        b + 32
    } else {
        b
    }
}

/// Merge match IDs, avoiding duplicates.
fn copy_matches(dst: &mut SmackMatches, new_ids: &[usize]) {
    for &id in new_ids {
        if !dst.ids.contains(&id) {
            dst.ids.push(id);
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

impl Smack {
    /// Create a new SMACK engine.
    ///
    /// `name` is a descriptive label. `nocase` selects case-insensitive mode.
    pub fn create(name: &str, nocase: SmackCase) -> Self {
        Smack {
            name: name.to_string(),
            is_nocase: nocase == SmackCase::Insensitive,
            is_anchor_begin: false,
            is_anchor_end: false,
            patterns: Vec::new(),
            state_table: Vec::new(),
            match_table: Vec::new(),
            state_count: 0,
            symbol_to_char: [0; ALPHABET_SIZE],
            char_to_symbol: [0u8; ALPHABET_SIZE],
            symbol_count: 0,
            row_shift: 0,
            table: Vec::new(),
            match_limit: 0,
            compiled_matches: Vec::new(),
        }
    }

    /// Register a pattern with the engine.
    ///
    /// Must be called before `compile()`.
    ///
    /// `pattern` — the byte sequence to match.
    /// `id` — value reported when the pattern matches.
    /// `flags` — anchor/wildcard/snmp flags.
    pub fn add_pattern(&mut self, pattern: &[u8], id: usize, flags: SmackFlags) {
        let is_anchor_begin = flags.contains(SmackFlags::ANCHOR_BEGIN);
        let is_anchor_end = flags.contains(SmackFlags::ANCHOR_END);
        let is_snmp_hack = flags.contains(SmackFlags::SNMP_HACK);
        let is_wildcards = flags.contains(SmackFlags::WILDCARDS);

        // Copy and optionally case-fold the pattern
        let pat_bytes: Vec<u8> = if self.is_nocase {
            pattern.iter().map(|&b| to_lower(b)).collect()
        } else {
            pattern.to_vec()
        };

        // Register symbols used by this pattern
        self.add_symbols(&pat_bytes);
        if is_snmp_hack {
            self.add_symbol(0x80);
        }

        if is_anchor_begin {
            self.is_anchor_begin = true;
        }
        if is_anchor_end {
            self.is_anchor_end = true;
        }

        self.patterns.push(SmackPattern {
            id,
            pattern: pat_bytes,
            is_anchor_begin,
            is_anchor_end,
            is_snmp_hack,
            is_wildcards,
        });
    }

    /// Compile all registered patterns into the search state machine.
    ///
    /// After calling this, you can no longer add patterns. You must call
    /// this before using any search function.
    pub fn compile(&mut self) {
        // Fix up symbol table for anchors and nocase
        if self.is_anchor_begin {
            self.add_symbol_raw(CHAR_ANCHOR_START);
        }
        if self.is_anchor_end {
            self.add_symbol_raw(CHAR_ANCHOR_END);
        }
        if self.is_nocase {
            for c in b'A'..=b'Z' {
                self.char_to_symbol[c as usize] =
                    self.char_to_symbol[to_lower(c) as usize];
            }
        }

        // Calculate maximum possible number of states
        let mut max_states = 1usize;
        for pat in &self.patterns {
            max_states += pat.pattern.len();
            if pat.is_anchor_begin {
                max_states += 1;
            }
            if pat.is_anchor_end {
                max_states += 1;
            }
        }

        // Allocate intermediate tables
        self.state_table = (0..max_states).map(|_| SmackRow::new()).collect();
        self.match_table = (0..max_states).map(|_| SmackMatches::new()).collect();
        self.state_count = 0;

        // Stage 0: Compile prefixes
        self.stage0_compile_prefixes();

        // Stage 1: Generate fail states (BFS)
        self.stage1_generate_fails();

        // Stage 2: Link fail states
        self.stage2_link_fails();

        // Swap base/unanchored states if anchors present
        if self.is_anchor_begin {
            self.swap_rows(BASE_STATE, UNANCHORED_STATE);
        }

        // Stage 3: Sort (matches at end)
        self.stage3_sort();

        // Stage 4: Build final compressed table
        self.stage4_make_final_table();

        // Fixup wildcard states
        self.fixup_wildcards();

        // Save compiled matches (so they persist after dropping intermediate tables)
        self.compiled_matches = self.match_table.clone();

        // Drop intermediate structures
        self.patterns.clear();
        self.patterns.shrink_to_fit();
        self.state_table.clear();
        self.state_table.shrink_to_fit();
    }

    // -----------------------------------------------------------------------
    // Search functions
    // -----------------------------------------------------------------------

    /// Run the state machine on a block of data, calling `cb_found` for
    /// each match.
    ///
    /// `state` carries DFA state across fragmented input — initialize to
    /// `SmackSearchState::new()` before the first fragment.
    ///
    /// Returns the total number of matches found.
    pub fn search<F>(
        &self,
        px: &[u8],
        cb_found: &mut F,
        state: &mut SmackSearchState,
    ) -> u32
    where
        F: FnMut(usize, usize),
    {
        let mut row = (state.raw & 0x00FF_FFFF) as usize;
        let mut found_count = 0u32;

        for (i, &c) in px.iter().enumerate() {
            let column = self.char_to_symbol[c as usize] as usize;
            row = self.table[(row << self.row_shift) + column] as usize;

            let m = &self.compiled_matches[row];
            if m.count() > 0 {
                found_count += self.handle_match(i, cb_found, row);
            }
        }

        state.raw = row as u32;
        found_count
    }

    /// Search for the next match in the input, advancing `offset`.
    ///
    /// Returns the pattern `id` on match, or `SMACK_NOT_FOUND`.
    /// When a match has multiple patterns, call `next_match()` to get
    /// additional matches at the same position.
    pub fn search_next(
        &self,
        state: &mut SmackSearchState,
        px: &[u8],
        offset: &mut usize,
    ) -> usize {
        let mut row = (state.raw & 0x00FF_FFFF) as usize;
        let mut current_matches = (state.raw >> 24) as usize;
        let match_limit = self.match_limit;

        let mut i = *offset;

        if current_matches == 0 {
            // Fast inner loop
            if self.row_shift == 7 {
                i += self.inner_match_shift7(px, i, &mut row, match_limit);
            } else {
                i += self.inner_match(px, i, &mut row, match_limit);
            }

            let m = &self.compiled_matches[row];
            if m.count() > 0 {
                i += 1; // points to first byte after match
                current_matches = m.count();
            }
        }

        *offset = i;

        let id = if current_matches > 0 {
            current_matches -= 1;
            self.compiled_matches[row].ids[current_matches]
        } else {
            SMACK_NOT_FOUND
        };

        state.raw = (row as u32) | ((current_matches as u32) << 24);
        id
    }

    /// Return the next match ID at the current state (for multi-match
    /// enumeration after `search_next`).
    pub fn next_match(&self, state: &mut SmackSearchState) -> usize {
        let row = (state.raw & 0x00FF_FFFF) as usize;
        let mut current_matches = (state.raw >> 24) as usize;

        let id = if current_matches > 0 {
            current_matches -= 1;
            self.compiled_matches[row].ids[current_matches]
        } else {
            SMACK_NOT_FOUND
        };

        state.raw = (row as u32) | ((current_matches as u32) << 24);
        id
    }

    /// Finalize a search and detect anchor-end patterns.
    ///
    /// Call after all fragments have been processed via `search()`.
    /// Returns the number of matches found.
    pub fn search_end<F>(
        &self,
        cb_found: &mut F,
        state: &mut SmackSearchState,
    ) -> u32
    where
        F: FnMut(usize, usize),
    {
        let column = self.char_to_symbol[CHAR_ANCHOR_END] as usize;
        let mut row = state.raw as usize;
        row = self.table[(row << self.row_shift) + column] as usize;

        let mut found_count = 0u32;
        let m = &self.compiled_matches[row];
        if m.count() > 0 {
            found_count += self.handle_match(0, cb_found, row);
        }

        state.raw = row as u32;
        found_count
    }

    /// Finalize a search_next sequence and detect anchor-end patterns.
    ///
    /// Call repeatedly until `SMACK_NOT_FOUND` is returned to enumerate
    /// all anchor-end matches.
    pub fn search_next_end(&self, state: &mut SmackSearchState) -> usize {
        let column = self.char_to_symbol[CHAR_ANCHOR_END] as usize;
        let mut row = (state.raw & 0x00FF_FFFF) as usize;
        let mut current_matches = (state.raw >> 24) as usize;

        // If already enumerating end matches, return the next one
        if current_matches == 0xFF {
            return SMACK_NOT_FOUND;
        }

        if current_matches > 0 {
            current_matches -= 1;
            let id = self.compiled_matches[row].ids[current_matches];
            state.raw = (row as u32) | ((current_matches as u32) << 24);
            return id;
        }

        // Transition on the anchor-end symbol
        row = self.table[(row << self.row_shift) + column] as usize;
        let m = &self.compiled_matches[row];
        if m.count() == 0 {
            state.raw = (row as u32) | (0xFF << 24);
            return SMACK_NOT_FOUND;
        }

        current_matches = m.count();
        let id = m.ids[current_matches - 1];
        current_matches -= 1;
        state.raw = (row as u32) | ((current_matches as u32) << 24);
        id
    }

    /// Get the engine name.
    pub fn name(&self) -> &str {
        &self.name
    }

    // -----------------------------------------------------------------------
    // Private: symbol management
    // -----------------------------------------------------------------------

    /// Add a symbol for a byte value.
    fn add_symbol(&mut self, c: u8) {
        let c_val = if self.is_nocase { to_lower(c) as usize } else { c as usize };
        self.add_symbol_raw(c_val);
    }

    /// Add a symbol for a raw character value (including anchors).
    fn add_symbol_raw(&mut self, c: usize) {
        // Check if already registered
        for i in 1..=self.symbol_count {
            if self.symbol_to_char[i] == c {
                return;
            }
        }
        self.symbol_count += 1;
        let sym = self.symbol_count;
        self.symbol_to_char[sym] = c;
        if c < ALPHABET_SIZE {
            self.char_to_symbol[c] = sym as u8;
        }
    }

    /// Add symbols for all bytes in a pattern.
    fn add_symbols(&mut self, pattern: &[u8]) {
        for &b in pattern {
            let c = if self.is_nocase { to_lower(b) as usize } else { b as usize };
            self.add_symbol_raw(c);
        }
    }

    // -----------------------------------------------------------------------
    // Private: compilation stages
    // -----------------------------------------------------------------------

    /// Stage 0: Build prefix trie from all patterns.
    fn stage0_compile_prefixes(&mut self) {
        // Initialize base state — all transitions to FAIL
        self.state_count = 1;
        for s in 0..self.state_table.len() {
            for a in 0..ALPHABET_SIZE {
                self.state_table[s].next_state[a] = FAIL;
            }
        }

        // Initialize anchor state
        if self.is_anchor_begin {
            let anchor_begin = self.state_count;
            self.state_count += 1;
            self.state_table[BASE_STATE].next_state[CHAR_ANCHOR_START] = anchor_begin as u32;
        }

        // Add all patterns' prefixes
        let patterns: Vec<_> = self.patterns.iter().map(|p| {
            (p.id, p.pattern.clone(), p.is_anchor_begin, p.is_anchor_end, p.is_snmp_hack)
        }).collect();

        for (id, pattern, is_anchor_begin, is_anchor_end, is_snmp_hack) in patterns {
            self.add_prefixes(&pattern, id, is_anchor_begin, is_anchor_end, is_snmp_hack);
        }

        // Set failed base-state transitions to loop back to base
        for a in 0..ALPHABET_SIZE {
            if self.state_table[BASE_STATE].next_state[a] == FAIL {
                self.state_table[BASE_STATE].next_state[a] = BASE_STATE as u32;
            }
        }
    }

    /// Add prefixes for a single pattern to the trie.
    fn add_prefixes(
        &mut self,
        pattern: &[u8],
        id: usize,
        is_anchor_begin: bool,
        is_anchor_end: bool,
        is_snmp_hack: bool,
    ) {
        let mut state: usize = 0;

        // If anchored at begin, follow anchor transition
        if is_anchor_begin {
            state = self.state_table[state].next_state[CHAR_ANCHOR_START] as usize;
        }

        // Match existing prefix
        let mut i = 0;
        while i < pattern.len()
            && self.state_table[state].next_state[pattern[i] as usize] != FAIL
        {
            state = self.state_table[state].next_state[pattern[i] as usize] as usize;
            i += 1;
        }

        // Create new states for remaining characters
        while i < pattern.len() {
            let new_state = self.state_count;
            self.state_count += 1;
            if is_snmp_hack {
                self.state_table[state].next_state[0x80] = state as u32;
            }
            self.state_table[state].next_state[pattern[i] as usize] = new_state as u32;
            state = new_state;
            i += 1;
        }

        // Anchor at end: create one more state
        if is_anchor_end {
            let new_state = self.state_count;
            self.state_count += 1;
            self.state_table[state].next_state[CHAR_ANCHOR_END] = new_state as u32;
            state = new_state;
        }

        // Mark final state as matching this pattern
        copy_matches(&mut self.match_table[state], &[id]);
    }

    /// Stage 1: Generate fail states using BFS.
    fn stage1_generate_fails(&mut self) {
        let mut queue = SmackQueue::new();

        // Seed BFS from base state transitions
        for a in 0..ALPHABET_SIZE {
            let s = self.state_table[BASE_STATE].next_state[a];
            if s != BASE_STATE as u32 {
                queue.enqueue(s);
                self.state_table[s as usize].fail_state = BASE_STATE as u32;
            }
        }

        // BFS
        while queue.has_more_items() {
            let r = queue.dequeue() as usize;

            for a in 0..ALPHABET_SIZE {
                let s = self.state_table[r].next_state[a];
                if s == FAIL || s == r as u32 {
                    // snmp_hack self-loop or no transition
                    continue;
                }

                queue.enqueue(s);

                let mut f = self.state_table[r].fail_state as usize;
                while self.state_table[f].next_state[a] == FAIL {
                    f = self.state_table[f].fail_state as usize;
                }

                self.state_table[s as usize].fail_state =
                    self.state_table[f].next_state[a];

                // Copy matches from fail state
                let fail_target = self.state_table[f].next_state[a] as usize;
                if self.match_table[fail_target].count() > 0 {
                    let fail_ids = self.match_table[fail_target].ids.clone();
                    copy_matches(&mut self.match_table[s as usize], &fail_ids);
                }
            }
        }
    }

    /// Stage 2: Link fail transitions into the goto table.
    fn stage2_link_fails(&mut self) {
        let mut queue = SmackQueue::new();

        for a in 0..ALPHABET_SIZE {
            if self.state_table[BASE_STATE].next_state[a] != BASE_STATE as u32 {
                queue.enqueue(self.state_table[BASE_STATE].next_state[a]);
            }
        }

        while queue.has_more_items() {
            let r = queue.dequeue() as usize;

            for a in 0..ALPHABET_SIZE {
                if self.state_table[r].next_state[a] == FAIL {
                    let fail = self.state_table[r].fail_state as usize;
                    self.state_table[r].next_state[a] =
                        self.state_table[fail].next_state[a];
                } else if self.state_table[r].next_state[a] == r as u32 {
                    // snmp_hack self-loop, skip
                } else {
                    queue.enqueue(self.state_table[r].next_state[a]);
                }
            }
        }
    }

    /// Stage 3: Sort so that match states are at the end.
    fn stage3_sort(&mut self) {
        let mut start = 0usize;
        let mut end = self.state_count;

        loop {
            while start < end && self.match_table[start].count() == 0 {
                start += 1;
            }
            while start < end && self.match_table[end - 1].count() != 0 {
                end -= 1;
            }
            if start >= end {
                break;
            }
            self.swap_rows(start, end - 1);
        }

        self.match_limit = start;
    }

    /// Swap two rows in the intermediate tables.
    fn swap_rows(&mut self, row0: usize, row1: usize) {
        self.state_table.swap(row0, row1);
        self.match_table.swap(row0, row1);

        // Fix up all references to the swapped states
        for s in 0..self.state_count {
            for a in 0..ALPHABET_SIZE {
                let val = self.state_table[s].next_state[a];
                if val == row0 as u32 {
                    self.state_table[s].next_state[a] = row1 as u32;
                } else if val == row1 as u32 {
                    self.state_table[s].next_state[a] = row0 as u32;
                }
            }
        }
    }

    /// Stage 4: Build the final compressed transition table.
    fn stage4_make_final_table(&mut self) {
        self.row_shift = row_shift_from_symbol_count(self.symbol_count);
        let column_count = 1usize << self.row_shift;
        let row_count = self.state_count;

        self.table = vec![0u16; row_count * column_count];

        for row in 0..row_count {
            for col in 0..ALPHABET_SIZE {
                let symbol = self.char_to_symbol[col] as usize;
                let transition = self.state_table[row].next_state[col];
                self.table[row * column_count + symbol] = transition as TransitionT;
            }
        }
    }

    /// Fixup wildcard states (narrow special case for SMB parser).
    fn fixup_wildcards(&mut self) {
        let patterns: Vec<_> = self.patterns.iter().map(|p| {
            (p.is_wildcards, p.pattern.clone())
        }).collect();

        for (is_wildcards, pattern) in patterns {
            if !is_wildcards {
                continue;
            }

            for j in 0..pattern.len() {
                if pattern[j] != b'*' {
                    continue;
                }

                // Navigate to the state leading up to the wildcard
                let mut row = 0usize;
                let mut offset = 0usize;
                while offset < j {
                    let id = self.search_next_inner(&mut row, &pattern, &mut offset, j);
                    let _ = id;
                }

                row = row & 0xFFFFFF;
                let row_size = 1usize << self.row_shift;
                let base_idx = row * row_size;
                let star_sym = self.char_to_symbol[b'*' as usize] as usize;
                let next_pattern = self.table[base_idx + star_sym];

                let base_state: TransitionT = if self.is_anchor_begin { 1 } else { 0 };

                for k in 0..row_size {
                    if self.table[base_idx + k] == base_state {
                        self.table[base_idx + k] = next_pattern;
                    }
                }
            }
        }
    }

    /// Minimal inner search used by wildcard fixup (no match_limit break).
    fn search_next_inner(
        &self,
        state: &mut usize,
        px: &[u8],
        offset: &mut usize,
        length: usize,
    ) -> usize {
        let mut row = *state & 0xFFFFFF;

        while *offset < length {
            let c = px[*offset];
            let column = self.char_to_symbol[c as usize] as usize;
            row = self.table[(row << self.row_shift) + column] as usize;
            *offset += 1;
        }

        *state = row;
        SMACK_NOT_FOUND
    }

    // -----------------------------------------------------------------------
    // Private: inner match loops
    // -----------------------------------------------------------------------

    /// Fast inner match loop (general row_shift).
    fn inner_match(
        &self,
        px: &[u8],
        start: usize,
        state: &mut usize,
        match_limit: usize,
    ) -> usize {
        let mut row = *state;
        let mut i = start;
        let len = px.len();

        while i < len {
            let column = self.char_to_symbol[px[i] as usize] as usize;
            row = self.table[(row << self.row_shift) + column] as usize;
            if row >= match_limit {
                break;
            }
            i += 1;
        }

        *state = row;
        i - start
    }

    /// Fast inner match loop specialized for row_shift=7.
    fn inner_match_shift7(
        &self,
        px: &[u8],
        start: usize,
        state: &mut usize,
        match_limit: usize,
    ) -> usize {
        let mut row = *state;
        let mut i = start;
        let len = px.len();

        while i < len {
            let column = self.char_to_symbol[px[i] as usize] as usize;
            row = self.table[(row << 7) + column] as usize;
            if row >= match_limit {
                break;
            }
            i += 1;
        }

        *state = row;
        i - start
    }

    /// Notify the callback of all matches at a given state.
    fn handle_match<F>(
        &self,
        index: usize,
        cb_found: &mut F,
        state: usize,
    ) -> u32
    where
        F: FnMut(usize, usize),
    {
        let m = &self.compiled_matches[state];
        for &id in &m.ids {
            cb_found(id, index);
        }
        m.count() as u32
    }

    // -----------------------------------------------------------------------
    // Self-test
    // -----------------------------------------------------------------------

    /// Run the built-in self-test.
    ///
    /// Returns 0 on success, non-zero on failure.
    pub fn selftest() -> i32 {
        let patterns: &[&str] = &[
            "GET", "PUT", "POST", "OPTIONS",
            "HEAD", "DELETE", "TRACE", "CONNECT",
            "PROPFIND", "PROPPATCH", "MKCOL", "MKWORKSPACE",
            "MOVE", "LOCK", "UNLOCK", "VERSION-CONTROL",
            "REPORT", "CHECKOUT", "CHECKIN", "UNCHECKOUT",
            "COPY", "UPDATE", "LABEL", "BASELINE-CONTROL",
            "MERGE", "SEARCH", "ACL", "ORDERPATCH",
            "PATCH", "MKACTIVITY",
        ];

        let text = b"ahpropfindhf;orderpatchposearchmoversion-controlockasldhf";

        const END_TEST_THINGY1: usize = 9001;
        const END_TEST_THINGY2: usize = 9002;

        let mut s = Smack::create("test1", SmackCase::Insensitive);

        for (i, pat) in patterns.iter().enumerate() {
            s.add_pattern(pat.as_bytes(), i, SmackFlags::NONE);
        }

        // Additional patterns for anchor-end testing
        s.add_pattern(b"dhf", END_TEST_THINGY1, SmackFlags::ANCHOR_END);
        s.add_pattern(b"ldhf", END_TEST_THINGY2, SmackFlags::ANCHOR_END);

        s.compile();

        let mut state = SmackSearchState::new();
        let mut i = 0usize;

        // Expected matches in order:
        let expected: &[(usize, usize, &str)] = &[
            (8, 10, "PROPFIND"),
            (28, 23, "PATCH"),
            (27, 23, "ORDERPATCH"),
            (25, 31, "SEARCH"),
            (12, 35, "MOVE"),
            (15, 48, "VERSION-CONTROL"),
            (13, 51, "LOCK"),
        ];

        for &(exp_id, exp_offset, name) in expected {
            let id = s.search_next(&mut state, text, &mut i);
            if id != exp_id || i != exp_offset {
                eprintln!("smack: fail {} (got id={}, offset={}, expected id={}, offset={})",
                    name, id, i, exp_id, exp_offset);
                return 1;
            }
        }

        // Should reach end of text with no more non-anchor matches
        let id = s.search_next(&mut state, text, &mut i);
        if id != SMACK_NOT_FOUND {
            eprintln!("smack: fail: expected NOT_FOUND at end of text, got {}", id);
            return 1;
        }

        // Anchor-end search
        let id = s.search_next_end(&mut state);
        if id != END_TEST_THINGY1 && id != END_TEST_THINGY2 {
            eprintln!("smack: fail: search_next_end didn't find anchor-end pattern");
            return 1;
        }

        // Second anchor-end match
        let id2 = s.search_next_end(&mut state);
        if id2 != END_TEST_THINGY1 && id2 != END_TEST_THINGY2 {
            eprintln!("smack: fail: second search_next_end failed");
            return 1;
        }
        if id2 == id {
            eprintln!("smack: fail: two ending patterns gave same result");
            return 1;
        }

        // Third call should return NOT_FOUND
        let id3 = s.search_next_end(&mut state);
        if id3 != SMACK_NOT_FOUND {
            eprintln!("smack: fail: third search_next_end should be NOT_FOUND");
            return 1;
        }

        0
    }
}

impl Clone for SmackMatches {
    fn clone(&self) -> Self {
        SmackMatches {
            ids: self.ids.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selftest() {
        assert_eq!(Smack::selftest(), 0);
    }

    #[test]
    fn test_basic_search() {
        let mut s = Smack::create("basic", SmackCase::Sensitive);
        s.add_pattern(b"hello", 1, SmackFlags::NONE);
        s.add_pattern(b"world", 2, SmackFlags::NONE);
        s.compile();

        let mut state = SmackSearchState::new();
        let text = b"say hello to the world";
        let mut found = Vec::new();

        s.search(text, &mut |id, _offset| {
            found.push(id);
        }, &mut state);

        assert!(found.contains(&1), "should find 'hello'");
        assert!(found.contains(&2), "should find 'world'");
    }

    #[test]
    fn test_case_insensitive() {
        let mut s = Smack::create("nocase", SmackCase::Insensitive);
        s.add_pattern(b"hello", 1, SmackFlags::NONE);
        s.compile();

        let mut state = SmackSearchState::new();
        let text = b"HELLO World";
        let mut found = Vec::new();

        s.search(text, &mut |id, _| {
            found.push(id);
        }, &mut state);

        assert!(found.contains(&1), "should find 'HELLO' case-insensitively");
    }

    #[test]
    fn test_anchor_begin() {
        let mut s = Smack::create("anchor_begin", SmackCase::Sensitive);
        s.add_pattern(b"start", 1, SmackFlags::ANCHOR_BEGIN);
        s.add_pattern(b"middle", 2, SmackFlags::NONE);
        s.compile();

        let mut state = SmackSearchState::new();
        let mut offset = 0;

        // "start" at beginning should match
        let text = b"start middle";
        let id = s.search_next(&mut state, text, &mut offset);
        assert_eq!(id, 1, "should find anchored 'start' at beginning");

        // Reset and try with "start" NOT at beginning
        let mut state2 = SmackSearchState::new();
        let mut offset2 = 0;
        let text2 = b"xx start middle";

        // Search through the whole thing
        let mut found_start = false;
        loop {
            let id = s.search_next(&mut state2, text2, &mut offset2);
            if id == SMACK_NOT_FOUND {
                break;
            }
            if id == 1 {
                found_start = true;
            }
            if offset2 >= text2.len() {
                break;
            }
        }
        assert!(!found_start, "should NOT find anchored 'start' in middle");
    }

    #[test]
    fn test_fragmented_input() {
        let mut s = Smack::create("fragmented", SmackCase::Sensitive);
        s.add_pattern(b"hello", 42, SmackFlags::NONE);
        s.compile();

        let mut state = SmackSearchState::new();
        let mut found = Vec::new();

        // Feed "hel" then "lo" across two calls
        s.search(b"hel", &mut |id, _| { found.push(id); }, &mut state);
        s.search(b"lo world", &mut |id, _| { found.push(id); }, &mut state);

        assert!(found.contains(&42), "should find 'hello' across fragment boundary");
    }

    #[test]
    fn test_search_next_multiple_matches() {
        let mut s = Smack::create("multi", SmackCase::Sensitive);
        s.add_pattern(b"AB", 1, SmackFlags::NONE);
        s.add_pattern(b"B", 2, SmackFlags::NONE);
        s.compile();

        let mut state = SmackSearchState::new();
        let text = b"AB";
        let mut offset = 0;
        let mut found = Vec::new();

        loop {
            let id = s.search_next(&mut state, text, &mut offset);
            if id == SMACK_NOT_FOUND {
                break;
            }
            found.push(id);
            // Drain additional matches at same position
            loop {
                let id2 = s.next_match(&mut state);
                if id2 == SMACK_NOT_FOUND {
                    break;
                }
                found.push(id2);
            }
            if offset >= text.len() {
                break;
            }
        }

        assert!(found.contains(&1), "should find 'AB'");
        assert!(found.contains(&2), "should find 'B'");
    }
}

/// Run benchmark for SMACK pattern matching.
pub fn benchmark() {
    println!("smack benchmark not yet implemented");
}

/// Module-level selftest wrapper.
pub fn selftest() -> bool { Smack::selftest() == 0 }
