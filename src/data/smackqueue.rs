//! Simple FIFO queue used internally by the SMACK (Aho-Corasick) engine
//! during breadth-first enumeration of sub-patterns.

use std::collections::VecDeque;

/// A simple FIFO queue of `u32` values, used by the SMACK engine during
/// compilation for BFS traversal of the state machine.
///
/// This is a faithful Rust equivalent of the C `Queue` / `QueueElement`
/// linked-list, implemented with `VecDeque` for efficiency.
pub struct SmackQueue {
    data: VecDeque<u32>,
}

impl SmackQueue {
    /// Create a new empty queue.
    pub fn new() -> Self {
        SmackQueue {
            data: VecDeque::new(),
        }
    }

    /// Add an item to the back of the queue.
    pub fn enqueue(&mut self, value: u32) {
        self.data.push_back(value);
    }

    /// Remove and return the front item. Returns 0 if empty (matching C behavior).
    pub fn dequeue(&mut self) -> u32 {
        self.data.pop_front().unwrap_or(0)
    }

    /// Returns `true` if the queue has at least one item.
    pub fn has_more_items(&self) -> bool {
        !self.data.is_empty()
    }
}

impl Default for SmackQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_operations() {
        let mut q = SmackQueue::new();
        assert!(!q.has_more_items());

        q.enqueue(10);
        q.enqueue(20);
        q.enqueue(30);
        assert!(q.has_more_items());

        assert_eq!(q.dequeue(), 10);
        assert_eq!(q.dequeue(), 20);
        assert_eq!(q.dequeue(), 30);
        assert!(!q.has_more_items());
    }

    #[test]
    fn test_dequeue_empty() {
        let mut q = SmackQueue::new();
        assert_eq!(q.dequeue(), 0); // matches C behavior
    }
}
