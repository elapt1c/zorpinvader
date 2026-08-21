//! Greyhat module: API key pattern scanning, HTTP fetching, and provider verification.
//!
//! This module implements an internet-scale API key scanner that:
//! 1. Scans HTTP response bodies for known API key prefixes using Aho-Corasick ([`Smack`])
//! 2. Extracts candidate keys with heuristic filtering to reject false positives
//! 3. Deduplicates findings per (IP, key) pair
//! 4. Verifies candidates against provider APIs
//! 5. Outputs confirmed keys to CSV

pub mod greyhat;
pub mod fetcher;
pub mod verifier;

pub use greyhat::{GreyhatScanner, KeyPattern};
pub use fetcher::Fetcher;
pub use verifier::Verifier;
