//! A queue of values keyed by an ordered index that keeps a bounded window of
//! the LOWEST indices seen. A node that starts a height late still has the
//! inputs for that height.

use std::collections::BTreeMap;

/// The maximum number of indices (heights) for which a [`WindowQueue`] keeps values.
///
/// A new lower index pushes the highest buffered index out of a full window.
pub const MAX_BUFFERED_HEIGHTS: usize = 32;

/// The maximum number of values (inputs) that a [`WindowQueue`] keeps for one index (height).
///
/// A full index drops every further value.
pub const MAX_INPUTS_PER_HEIGHT: usize = 1024;

/// A data structure that maintains a queue of values associated with ordered indices,
/// retaining the values of the `MAX_BUFFERED_HEIGHTS` lowest indices seen so far.
///
/// # Type Parameters
/// - `I`: The type of the index associated with each value in the queue.
/// - `T`: The type of values stored in the queue.
///
/// # Invariant
/// - At most `MAX_BUFFERED_HEIGHTS` indices are buffered, and they are the lowest indices accepted so far.
/// - Each index holds at most `MAX_INPUTS_PER_HEIGHT` values, in the order they are pushed.
#[derive(Clone, Debug)]
pub struct WindowQueue<I, T> {
    /// The values kept for each buffered index, in the order they are pushed.
    /// The map is ordered by index, its last key is the highest buffered index.
    entries: BTreeMap<I, Vec<T>>,
}

impl<I, T> Default for WindowQueue<I, T> {
    /// Creates a `WindowQueue` with an empty map of entries.
    ///
    /// # Returns
    /// - A `WindowQueue` instance with an empty `entries` map.
    fn default() -> Self {
        Self {
            entries: Default::default(),
        }
    }
}

impl<I, T> WindowQueue<I, T> {
    /// Constructs a new, empty `WindowQueue`.
    ///
    /// # Returns
    /// - A new `WindowQueue` with no buffered index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pushes a value into the queue with an associated index.
    ///
    /// - If the `index` is already buffered, the value is appended to the values of that index,
    ///   unless that index already holds `MAX_INPUTS_PER_HEIGHT` values, in which case the value is ignored.
    /// - If the `index` is new and the queue already buffers `MAX_BUFFERED_HEIGHTS` indices,
    ///   the value is ignored when the `index` is above the highest buffered index,
    ///   otherwise the highest buffered index is dropped to make room for the new one.
    ///
    /// # Arguments
    /// - `index`: The index associated with the value.
    /// - `value`: The value to be stored in the queue.
    ///
    /// # Returns
    /// - Whether or not the value was inserted into the queue.
    pub fn push(&mut self, index: I, value: T) -> bool
    where
        I: Ord,
    {
        if let Some(values) = self.entries.get_mut(&index) {
            if values.len() >= MAX_INPUTS_PER_HEIGHT {
                // Index is full, ignore the value
                return false;
            }
            // Buffered index, append the new value
            values.push(value);
            return true;
        }

        if self.entries.len() >= MAX_BUFFERED_HEIGHTS {
            let highest = self.entries.keys().next_back();
            if highest.is_some_and(|highest| index > *highest) {
                // Window is full, index above the highest buffered one, ignore the value
                return false;
            }
            // Window is full, drop the highest buffered index
            self.entries.pop_last();
        }

        // New index, insert the new value
        self.entries.insert(index, vec![value]);
        true
    }

    /// Removes and returns the values buffered for the given `index`, in the order they were pushed.
    ///
    /// Every entry below `index` is dropped first: a height jump can also make the entire batch
    /// stale, in which case there is nothing to replay. Entries above `index` stay queued.
    ///
    /// # Arguments
    /// - `index`: The index whose values to take.
    ///
    /// # Returns
    /// - The values buffered for `index`, or an empty `Vec` when there are none.
    pub fn take_at(&mut self, index: I) -> Vec<T>
    where
        I: Ord,
    {
        // Drop every entry below `index`, those are stale
        self.entries.retain(|buffered, _| *buffered >= index);
        // Remove and return the entry for `index`, if any
        self.entries.remove(&index).unwrap_or_default()
    }

    /// Returns how many values are stored in the queue, over all buffered indices.
    pub fn len(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }

    /// Returns whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns how many indices are buffered in the queue, at most `MAX_BUFFERED_HEIGHTS`.
    pub fn heights(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_height_survives_a_higher_one() {
        let mut queue = WindowQueue::new();
        queue.push(100, "proposal");
        queue.push(101, "vote");
        assert_eq!(queue.take_at(100), vec!["proposal"]);
    }

    #[test]
    fn take_at_returns_only_that_height_in_order() {
        let mut queue = WindowQueue::new();
        queue.push(100, "p100");
        queue.push(101, "p101");
        queue.push(100, "v100");
        queue.push(102, "p102");
        queue.push(101, "v101");
        assert_eq!(queue.take_at(100), vec!["p100", "v100"]);
        assert_eq!(queue.heights(), 2);
        assert_eq!(queue.take_at(101), vec!["p101", "v101"]);
        assert_eq!(queue.take_at(102), vec!["p102"]);
        assert!(queue.is_empty());
    }

    #[test]
    fn a_height_jump_clears_stale_heights() {
        let mut queue = WindowQueue::new();
        queue.push(100, "a");
        queue.push(101, "b");
        assert!(queue.take_at(102).is_empty());
        assert!(queue.is_empty());
    }

    #[test]
    fn full_window_keeps_the_lowest_heights() {
        let mut queue = WindowQueue::new();
        for height in 1..=32 {
            assert!(queue.push(height, "value"));
        }
        assert!(!queue.push(33, "x"));
        assert_eq!(queue.heights(), 32);
        assert!(queue.push(0, "zero"));
        assert_eq!(queue.heights(), 32);
        // take_at drops the lower heights, so check each height on a copy of the full window
        assert!(queue.clone().take_at(32).is_empty());
        assert_eq!(queue.clone().take_at(31), vec!["value"]);
        assert_eq!(queue.take_at(0), vec!["zero"]);
    }

    #[test]
    fn per_height_cap_drops_the_newest() {
        let mut queue = WindowQueue::new();
        for _ in 0..MAX_INPUTS_PER_HEIGHT {
            assert!(queue.push(5, "input"));
        }
        assert!(!queue.push(5, "input"));
        assert_eq!(queue.len(), MAX_INPUTS_PER_HEIGHT);
        assert_eq!(queue.take_at(5).len(), MAX_INPUTS_PER_HEIGHT);
    }

    #[test]
    fn catch_up_replays_only_at_the_buffered_height() {
        let mut queue = WindowQueue::new();
        queue.push(100, "proposal");
        queue.push(100, "vote");
        for height in 1..100 {
            assert!(queue.take_at(height).is_empty());
            assert_eq!(queue.len(), 2);
        }
        assert_eq!(queue.take_at(100), vec!["proposal", "vote"]);
        assert!(queue.take_at(100).is_empty());

        queue.push(101, "old vote");
        assert!(queue.take_at(102).is_empty());
        assert!(queue.is_empty());
    }

    #[test]
    fn default_is_empty() {
        let queue: WindowQueue<u64, &str> = WindowQueue::default();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.heights(), 0);
    }
}
