//! Rate limiting / throttling for packet transmission.
//!
//! This module implements a bucket-based rate limiter that prevents
//! the scanner from overwhelming the network. It uses a rolling window
//! of 256 buckets to track recent transmission rates and dynamically
//! adjusts batch sizes to converge on the target rate.
//!
//! The key insight is that we throttle batches of packets rather than
//! individual packets, which reduces per-packet overhead significantly.

use crate::pixie::timer::{gettime, usleep};
use log::debug;

/// Number of buckets in the rolling window for rate calculation.
const BUCKET_COUNT: usize = 256;

/// Maximum batch size to prevent excessive bursts.
const MAX_BATCH_SIZE: f64 = 10000.0;

/// Rate limiter for packet transmission.
///
/// Uses a rolling window of timestamp/count buckets to calculate
/// the recent transmission rate and adjust batch sizes accordingly.
#[derive(Debug, Clone)]
pub struct Throttler {
    /// Target maximum packets per second
    pub max_rate: f64,

    /// Current calculated rate
    pub current_rate: f64,

    /// Current batch size (packets per batch)
    pub batch_size: f64,

    /// Current bucket index
    pub index: usize,

    /// Rolling window of timestamp/count pairs
    pub buckets: [Bucket; BUCKET_COUNT],

    /// Last recorded timestamp (for testing)
    pub test_timestamp: u64,

    /// Last recorded packet count (for testing)
    pub test_packet_count: u64,
}

/// A single bucket in the rolling rate window.
#[derive(Debug, Clone, Copy, Default)]
pub struct Bucket {
    /// Microsecond timestamp when this bucket was recorded
    pub timestamp: u64,

    /// Cumulative packet count at this timestamp
    pub packet_count: u64,
}

impl Default for Throttler {
    fn default() -> Self {
        Self::new()
    }
}

impl Throttler {
    /// Create a new throttler with default settings (no rate limit).
    pub fn new() -> Self {
        let now = gettime();
        Throttler {
            max_rate: f64::INFINITY,
            current_rate: 0.0,
            batch_size: 1.0,
            index: 0,
            buckets: [Bucket { timestamp: now, packet_count: 0 }; BUCKET_COUNT],
            test_timestamp: 0,
            test_packet_count: 0,
        }
    }

    /// Initialize the throttler with a specific maximum rate.
    ///
    /// # Arguments
    ///
    /// * `max_rate` - Maximum packets per second to allow
    pub fn start(&mut self, max_rate: f64) {
        let now = gettime();

        self.max_rate = max_rate;
        self.current_rate = 0.0;
        self.batch_size = 1.0;
        self.index = 0;

        for bucket in self.buckets.iter_mut() {
            bucket.timestamp = now;
            bucket.packet_count = 0;
        }

        debug!("[+] starting throttler: rate = {:.2}-pps", max_rate);
    }

    /// Get the number of packets that can be sent in the next batch.
    ///
    /// This function may block briefly if the current rate exceeds the
    /// maximum rate. It returns the number of packets to send before
    /// calling this function again.
    ///
    /// # Arguments
    ///
    /// * `packet_count` - Total packets sent so far
    ///
    /// # Returns
    ///
    /// Number of packets to send in the next batch (minimum 1)
    pub fn next_batch(&mut self, packet_count: u64) -> u64 {
        loop {
            let timestamp = gettime();

            // Record current state in this bucket
            let idx = self.index & 0xFF;
            self.buckets[idx].timestamp = timestamp;
            self.buckets[idx].packet_count = packet_count;

            // Get the oldest bucket for rate calculation
            self.index = self.index.wrapping_add(1);
            let old_idx = self.index & 0xFF;
            let old_timestamp = self.buckets[old_idx].timestamp;
            let old_packet_count = self.buckets[old_idx].packet_count;

            // If more than 1 second has elapsed, reset and retry
            if timestamp > old_timestamp && (timestamp - old_timestamp) > 1_000_000 {
                self.batch_size = 1.0;
                continue;
            }

            // Calculate recent rate
            let time_delta = timestamp.saturating_sub(old_timestamp) as f64 / 1_000_000.0;
            if time_delta <= 0.0 {
                continue;
            }

            let current_rate = (packet_count.saturating_sub(old_packet_count)) as f64 / time_delta;

            // If we're going too fast, pause and retry
            if current_rate > self.max_rate {
                // Calculate how long to wait
                let mut waittime = (current_rate - self.max_rate) / self.max_rate;

                // At high speeds, use shorter intervals for faster convergence
                waittime *= 0.1;

                // Cap at 100ms to prevent excessive delays
                if waittime > 0.1 {
                    waittime = 0.1;
                }

                // Gradually reduce batch size for convergence
                self.batch_size *= 0.999;

                // Sleep for the calculated time
                let sleep_us = (waittime * 1_000_000.0) as u64;
                if sleep_us > 0 {
                    usleep(sleep_us);
                }

                continue;
            }

            // We're within rate limits - increase batch size gradually
            self.batch_size *= 1.005;
            if self.batch_size > MAX_BATCH_SIZE {
                self.batch_size = MAX_BATCH_SIZE;
            }

            self.current_rate = current_rate;
            self.test_timestamp = timestamp;
            self.test_packet_count = packet_count;

            return self.batch_size as u64;
        }
    }

    /// Get the current transmission rate.
    pub fn rate(&self) -> f64 {
        self.current_rate
    }

    /// Get the current batch size.
    pub fn batch(&self) -> u64 {
        self.batch_size as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_throttler_new() {
        let throttler = Throttler::new();
        assert!(throttler.max_rate.is_infinite());
        assert_eq!(throttler.batch_size, 1.0);
    }

    #[test]
    fn test_throttler_start() {
        let mut throttler = Throttler::new();
        throttler.start(1000.0);
        assert_eq!(throttler.max_rate, 1000.0);
        assert_eq!(throttler.batch_size, 1.0);
    }

    #[test]
    fn test_throttler_batch_minimum() {
        let mut throttler = Throttler::new();
        throttler.start(1_000_000.0); // High rate, no throttling
        let batch = throttler.next_batch(0);
        assert!(batch >= 1);
    }
}
