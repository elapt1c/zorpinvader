//! Packet buffer pool and transmit queue.
//!
//! The network stack needs to format response packets (ACKs, RSTs, HTTP
//! requests, etc.) and hand them off to a separate transmit thread. This
//! module provides:
//!
//! - `PacketBuffer`: a fixed-size buffer for composing a single Ethernet frame.
//! - `Stack`: the top-level stack context holding the free-buffer pool,
//!   the transmit queue, the source MAC, and the source IP/port ranges.
//!
//! Converted from `c-src/stack-queue.h` and `c-src/stack-queue.c`.

use std::sync::Arc;

use crate::data::rte_ring::RteRing;
use crate::massip::addr::MacAddress;
use crate::rawsock::adapter::Adapter;
use super::src::StackSrc;

/// Maximum Ethernet frame size we support (slightly under 2048).
pub const PACKET_BUFFER_SIZE: usize = 2040;

/// Default number of packet buffers allocated in the pool.
pub const BUFFER_COUNT: usize = 16384;

/// A single packet buffer used to compose an outgoing Ethernet frame.
///
/// Callers obtain a buffer from [`Stack::get_packet_buffer`], fill in the
/// frame bytes up to `length`, then hand it to
/// [`Stack::transmit_packet_buffer`] for later transmission.
pub struct PacketBuffer {
    /// Number of valid bytes currently stored in `px`.
    pub length: usize,
    /// Raw frame bytes (Ethernet header + payload).
    pub px: [u8; PACKET_BUFFER_SIZE],
}

impl PacketBuffer {
    /// Create a new, empty packet buffer.
    pub fn new() -> Self {
        Self {
            length: 0,
            px: [0u8; PACKET_BUFFER_SIZE],
        }
    }
}

impl Default for PacketBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Top-level network stack context.
///
/// Holds the free-buffer pool, transmit queue, source MAC address, and the
/// source IP/port range configuration. Both the receive thread (which
/// formats responses) and the transmit thread (which drains the queue)
/// share this structure.
pub struct Stack {
    /// Ring of free `PacketBuffer` pointers available for formatting.
    pub packet_buffers: Arc<RteRing>,

    /// Ring of formatted packets waiting to be transmitted.
    pub transmit_queue: Arc<RteRing>,

    /// Source (our) MAC address used when composing Ethernet headers.
    pub source_mac: MacAddress,

    /// Source IP/port range configuration for spoofed scanning.
    pub src: Arc<StackSrc>,
}

impl Stack {
    /// Create a new stack context.
    ///
    /// Allocates `BUFFER_COUNT` packet buffers and initialises the two
    /// ring queues (free pool and transmit queue).
    pub fn new(source_mac: MacAddress, src: Arc<StackSrc>) -> Self {
        use crate::data::rte_ring::RingFlags;

        let flags = RingFlags::SP_ENQ.union(RingFlags::SC_DEQ);
        let packet_buffers = Arc::new(
            RteRing::new(BUFFER_COUNT as u32, flags)
                .expect("failed to create packet_buffers ring"),
        );
        let transmit_queue = Arc::new(
            RteRing::new(BUFFER_COUNT as u32, flags)
                .expect("failed to create transmit_queue ring"),
        );

        // Pre-populate the free pool with packet buffers.
        // We allocate BUFFER_COUNT-1 because ring capacity is count-1.
        for _ in 0..(BUFFER_COUNT - 1) {
            let buf = Box::new(PacketBuffer::new());
            let ptr = Box::into_raw(buf) as *const ();
            let _ = packet_buffers.sp_enqueue(ptr);
        }

        Self {
            packet_buffers,
            transmit_queue,
            source_mac,
            src,
        }
    }

    /// Obtain a free packet buffer from the pool.
    ///
    /// Spins briefly if none are available. In practice this should never
    /// block for long because the transmit thread continuously recycles
    /// buffers.
    pub fn get_packet_buffer(&self) -> Option<Box<PacketBuffer>> {
        // Try several times before giving up.
        for _ in 0..1000 {
            match self.packet_buffers.sc_dequeue() {
                Some(ptr) => {
                    let buf = unsafe { Box::from_raw(ptr as *mut PacketBuffer) };
                    return Some(buf);
                }
                None => {
                    // Briefly yield before retrying.
                    std::hint::spin_loop();
                }
            }
        }
        log::warn!("packet buffers exhausted (should be impossible)");
        None
    }

    /// Queue a formatted packet buffer for transmission.
    ///
    /// The packet is not sent immediately; it is placed on the transmit
    /// queue and will be drained by [`Stack::flush_packets`] running on
    /// the transmit thread.
    pub fn transmit_packet_buffer(&self, response: Box<PacketBuffer>) {
        let ptr = Box::into_raw(response) as *const ();
        loop {
            let rc = self.transmit_queue.sp_enqueue(ptr);
            if rc >= 0 {
                break;
            }
            log::error!("transmit queue full (should be impossible)");
            std::hint::spin_loop();
        }
    }

    /// Drain the transmit queue, sending packets through the adapter.
    ///
    /// Called periodically from the transmit thread. Each sent packet's
    /// buffer is recycled back into the free pool.
    ///
    /// `batch_size` is decremented for each packet sent (used by the
    /// throttler). Returns the number of packets actually sent.
    pub fn flush_packets(
        &self,
        adapter: &Adapter,
        packets_sent: &mut u64,
        batch_size: &mut u64,
    ) -> u64 {
        let mut sent: u64 = 0;

        while *batch_size > 0 {
            *batch_size -= 1;

            let ptr = match self.transmit_queue.sc_dequeue() {
                Some(p) => p,
                None => break, // queue empty
            };

            let buf = unsafe { Box::from_raw(ptr as *mut PacketBuffer) };

            // Actually transmit the frame.
            if let Err(e) = adapter.send_packet(&buf.px[..buf.length]) {
                log::error!("send_packet failed: {}", e);
            }

            // Recycle the buffer back into the free pool.
            let raw = Box::into_raw(buf) as *const ();
            loop {
                let rc = self.packet_buffers.sp_enqueue(raw);
                if rc >= 0 {
                    break;
                }
                log::error!("packet_buffers enqueue full (should be impossible)");
                std::hint::spin_loop();
            }

            *packets_sent += 1;
            sent += 1;
        }

        sent
    }
}
