//! Bounded, persisted seen sets with origin tags (FIP A.5).
//!
//! There is one seen set for each origin network: the inbound set holds the
//! hashes that the relay read from snapchain, and the outbound set holds the
//! hashes that it read from Hypersnap. The set that holds a hash is its origin
//! tag. A direction never relays a hash that the other set holds, so a message
//! that came from network X is never sent back to X.
//!
//! On disk, each set is a directory of append-only segment files. A record is
//! `hash (20 bytes) || status (1 byte)`; the last record of a hash wins. The
//! relay fsyncs after each batch of records. When a set holds more than
//! `capacity` hashes, it deletes its oldest segment, so a set keeps between
//! about 15/16 of `capacity` and `capacity` hashes. A lost old hash costs one
//! duplicate submission (FIP A.5).
//!
//! A claim (a hash that the relay is submitting now) is in memory only. After a
//! crash the worker re-reads the block from its cursor and claims the hash
//! again, and a second submission gets a duplicate error.

use super::fsutil::{ensure_dir, sync_dir};
use crate::types::{Direction, MessageHash, Network, HASH_LEN};
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const RECORD_LEN: usize = HASH_LEN + 1;
const SEGMENT_SUFFIX: &str = ".seg";
/// Segment id of an in-memory claim.
const CLAIM_SEGMENT: u32 = u32::MAX;
const MAX_SEGMENT_RECORDS: usize = 1 << 20;

/// The status of a hash in a seen set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SeenStatus {
    /// Claimed by a worker that is submitting it now (memory only).
    Claimed,
    Relayed,
    Duplicate,
    Rejected,
    GaveUp,
    /// In the deferred queue of a shard worker.
    Deferred,
}

impl SeenStatus {
    fn to_byte(self) -> u8 {
        match self {
            SeenStatus::Claimed => 0,
            SeenStatus::Relayed => 1,
            SeenStatus::Duplicate => 2,
            SeenStatus::Rejected => 3,
            SeenStatus::GaveUp => 4,
            SeenStatus::Deferred => 5,
        }
    }

    /// 0 is never written, so a zero-filled tail after a crash reads as nothing.
    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            1 => SeenStatus::Relayed,
            2 => SeenStatus::Duplicate,
            3 => SeenStatus::Rejected,
            4 => SeenStatus::GaveUp,
            5 => SeenStatus::Deferred,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    /// Low 32 bits of the id of the segment with the last record. The live
    /// segments span far fewer than 2^32 ids, so equality is exact.
    segment: u32,
    status: SeenStatus,
}

struct ActiveSegment {
    id: u64,
    file: File,
    records: usize,
}

/// One seen set.
pub struct SeenLog {
    dir: PathBuf,
    capacity: usize,
    segment_records: usize,
    index: HashMap<MessageHash, Entry>,
    /// Segment ids, oldest first. The last one is the active segment.
    segments: VecDeque<u64>,
    active: Option<ActiveSegment>,
    /// Hashes with a persisted record (claims excluded).
    persisted: usize,
}

impl SeenLog {
    pub fn open(dir: &Path, capacity: usize) -> io::Result<Self> {
        ensure_dir(dir)?;
        let capacity = capacity.max(1);
        let segment_records = (capacity / 16).clamp(1, MAX_SEGMENT_RECORDS);
        let mut ids: Vec<u64> = fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                name.strip_suffix(SEGMENT_SUFFIX)?.parse::<u64>().ok()
            })
            .collect();
        ids.sort_unstable();

        let mut log = Self {
            dir: dir.to_path_buf(),
            capacity,
            segment_records,
            index: HashMap::new(),
            segments: VecDeque::new(),
            active: None,
            persisted: 0,
        };
        let mut last_records = 0;
        for id in ids {
            let path = log.segment_path(id);
            let mut bytes = fs::read(&path)?;
            let valid = bytes.len() - bytes.len() % RECORD_LEN;
            if valid != bytes.len() {
                // A torn final record from a crash. Drop it.
                let f = OpenOptions::new().write(true).open(&path)?;
                f.set_len(valid as u64)?;
                f.sync_all()?;
                bytes.truncate(valid);
            }
            for record in bytes.chunks_exact(RECORD_LEN) {
                let Some(status) = SeenStatus::from_byte(record[HASH_LEN]) else {
                    continue;
                };
                let hash = MessageHash::from_slice(&record[..HASH_LEN]).expect("record length");
                let prev = log.index.insert(
                    hash,
                    Entry {
                        segment: id as u32,
                        status,
                    },
                );
                if prev.is_none() {
                    log.persisted += 1;
                }
            }
            last_records = bytes.len() / RECORD_LEN;
            log.segments.push_back(id);
        }
        if let Some(&id) = log.segments.back() {
            if last_records < log.segment_records {
                let file = OpenOptions::new().append(true).open(log.segment_path(id))?;
                log.active = Some(ActiveSegment {
                    id,
                    file,
                    records: last_records,
                });
            }
        }
        log.evict()?;
        Ok(log)
    }

    fn segment_path(&self, id: u64) -> PathBuf {
        self.dir.join(format!("{id:020}{SEGMENT_SUFFIX}"))
    }

    pub fn get(&self, hash: &MessageHash) -> Option<SeenStatus> {
        self.index.get(hash).map(|e| e.status)
    }

    /// Hashes with a persisted record.
    pub fn len(&self) -> usize {
        self.persisted
    }

    pub fn is_empty(&self) -> bool {
        self.persisted == 0
    }

    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Adds an in-memory claim if the hash has no entry.
    fn claim(&mut self, hash: MessageHash) {
        self.index.entry(hash).or_insert(Entry {
            segment: CLAIM_SEGMENT,
            status: SeenStatus::Claimed,
        });
    }

    /// Drops an in-memory claim (the relay did not submit the message).
    fn release(&mut self, hash: &MessageHash) {
        if matches!(self.index.get(hash), Some(e) if e.status == SeenStatus::Claimed) {
            self.index.remove(hash);
        }
    }

    /// Appends outcome records and fsyncs them.
    pub fn record(&mut self, items: &[(MessageHash, SeenStatus)]) -> io::Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let mut updates: Vec<(MessageHash, Entry)> = Vec::with_capacity(items.len());
        let mut buf: Vec<u8> = Vec::with_capacity(items.len() * RECORD_LEN);
        for (hash, status) in items {
            assert!(*status != SeenStatus::Claimed, "claims are not persisted");
            let full = self
                .active
                .as_ref()
                .is_none_or(|a| a.records >= self.segment_records);
            if full {
                self.flush(&mut buf)?;
                self.roll()?;
            }
            let active = self.active.as_mut().expect("active segment");
            buf.extend_from_slice(hash.as_bytes());
            buf.push(status.to_byte());
            active.records += 1;
            updates.push((
                *hash,
                Entry {
                    segment: active.id as u32,
                    status: *status,
                },
            ));
        }
        self.flush(&mut buf)?;
        for (hash, entry) in updates {
            let prev = self.index.insert(hash, entry);
            if prev.is_none_or(|p| p.segment == CLAIM_SEGMENT) {
                self.persisted += 1;
            }
        }
        self.evict()
    }

    fn flush(&mut self, buf: &mut Vec<u8>) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let active = self.active.as_mut().expect("active segment");
        active.file.write_all(buf)?;
        active.file.sync_data()?;
        buf.clear();
        Ok(())
    }

    fn roll(&mut self) -> io::Result<()> {
        let id = self.segments.back().map(|id| id + 1).unwrap_or(1);
        let file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(self.segment_path(id))?;
        sync_dir(&self.dir)?;
        self.segments.push_back(id);
        self.active = Some(ActiveSegment {
            id,
            file,
            records: 0,
        });
        Ok(())
    }

    /// Deletes the oldest segments until the set is within its capacity.
    fn evict(&mut self) -> io::Result<()> {
        while self.persisted > self.capacity && self.segments.len() > 1 {
            let id = self.segments.pop_front().expect("segment");
            let path = self.segment_path(id);
            let bytes = fs::read(&path)?;
            for record in bytes.chunks_exact(RECORD_LEN) {
                let hash = MessageHash::from_slice(&record[..HASH_LEN]).expect("record length");
                if matches!(self.index.get(&hash), Some(e) if e.segment == id as u32) {
                    self.index.remove(&hash);
                    self.persisted -= 1;
                }
            }
            fs::remove_file(&path)?;
        }
        Ok(())
    }
}

/// The result of [`SeenStore::claim`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    /// The caller submits the message and then records its outcome.
    Claimed,
    /// The other set holds the hash: the message came from the target network,
    /// or the other direction relays it. Never send it (loop prevention).
    LoopBlocked { origin: Network },
    /// This direction already has an outcome for the hash.
    AlreadyHandled(SeenStatus),
}

struct Sets {
    inbound: SeenLog,
    outbound: SeenLog,
}

impl Sets {
    fn get_mut(&mut self, direction: Direction) -> &mut SeenLog {
        match direction {
            Direction::Inbound => &mut self.inbound,
            Direction::Outbound => &mut self.outbound,
        }
    }

    fn get(&self, direction: Direction) -> &SeenLog {
        match direction {
            Direction::Inbound => &self.inbound,
            Direction::Outbound => &self.outbound,
        }
    }
}

/// Both seen sets behind one lock, so that a check of both sets and a claim
/// are one atomic step.
pub struct SeenStore {
    sets: Mutex<Sets>,
}

impl SeenStore {
    /// Opens `<dir>/inbound` and `<dir>/outbound`.
    pub fn open(dir: &Path, capacity: usize) -> io::Result<Self> {
        Ok(Self {
            sets: Mutex::new(Sets {
                inbound: SeenLog::open(&dir.join("inbound"), capacity)?,
                outbound: SeenLog::open(&dir.join("outbound"), capacity)?,
            }),
        })
    }

    /// Checks both sets for `hash` and, if `direction` may relay it, claims it
    /// with the origin tag of `direction`.
    pub fn claim(&self, direction: Direction, hash: MessageHash) -> Claim {
        let mut sets = self.sets.lock().unwrap();
        if sets.get(direction.other()).get(&hash).is_some() {
            return Claim::LoopBlocked {
                origin: direction.target(),
            };
        }
        let own = sets.get_mut(direction);
        match own.get(&hash) {
            None => {
                own.claim(hash);
                Claim::Claimed
            }
            Some(SeenStatus::Claimed) => Claim::Claimed,
            Some(status) => Claim::AlreadyHandled(status),
        }
    }

    pub fn release(&self, direction: Direction, hash: &MessageHash) {
        self.sets.lock().unwrap().get_mut(direction).release(hash);
    }

    /// Persists outcomes (fsync before return).
    pub fn record(
        &self,
        direction: Direction,
        items: &[(MessageHash, SeenStatus)],
    ) -> io::Result<()> {
        self.sets.lock().unwrap().get_mut(direction).record(items)
    }

    pub fn status(&self, direction: Direction, hash: &MessageHash) -> Option<SeenStatus> {
        self.sets.lock().unwrap().get(direction).get(hash)
    }

    pub fn len(&self, direction: Direction) -> usize {
        self.sets.lock().unwrap().get(direction).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u32) -> MessageHash {
        let mut b = [0u8; HASH_LEN];
        b[..4].copy_from_slice(&n.to_be_bytes());
        b[19] = 0xEE;
        MessageHash(b)
    }

    #[test]
    fn records_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut log = SeenLog::open(dir.path(), 1000).unwrap();
            log.record(&[(h(1), SeenStatus::Relayed), (h(2), SeenStatus::Rejected)])
                .unwrap();
            log.record(&[(h(3), SeenStatus::Deferred)]).unwrap();
            log.record(&[(h(3), SeenStatus::Relayed)]).unwrap();
            assert_eq!(log.len(), 3);
        }
        let log = SeenLog::open(dir.path(), 1000).unwrap();
        assert_eq!(log.len(), 3);
        assert_eq!(log.get(&h(1)), Some(SeenStatus::Relayed));
        assert_eq!(log.get(&h(2)), Some(SeenStatus::Rejected));
        assert_eq!(
            log.get(&h(3)),
            Some(SeenStatus::Relayed),
            "last record wins"
        );
        assert_eq!(log.get(&h(4)), None);
    }

    #[test]
    fn bounded_by_capacity_and_evicts_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let cap = 64;
        let mut log = SeenLog::open(dir.path(), cap).unwrap();
        for batch in 0..100u32 {
            let items: Vec<_> = (0..10)
                .map(|i| (h(batch * 10 + i), SeenStatus::Relayed))
                .collect();
            log.record(&items).unwrap();
            assert!(log.len() <= cap);
        }
        assert!(log.len() >= cap - cap / 16);
        // The newest survive, the oldest are gone.
        assert_eq!(log.get(&h(999)), Some(SeenStatus::Relayed));
        assert_eq!(log.get(&h(0)), None);
        // Disk is bounded too: at most capacity/segment + 1 segment files.
        assert!(log.segment_count() <= cap / (cap / 16) + 1);
        let files = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(files, log.segment_count());
        drop(log);
        let log = SeenLog::open(dir.path(), cap).unwrap();
        assert!(log.len() <= cap);
        assert_eq!(log.get(&h(999)), Some(SeenStatus::Relayed));
    }

    #[test]
    fn eviction_keeps_hash_whose_last_record_is_newer() {
        let dir = tempfile::tempdir().unwrap();
        // Capacity 16 gives one record per segment.
        let mut log = SeenLog::open(dir.path(), 16).unwrap();
        log.record(&[(h(1), SeenStatus::Deferred)]).unwrap(); // segment 1
        log.record(&[(h(2), SeenStatus::Relayed)]).unwrap(); // segment 2
        log.record(&[(h(1), SeenStatus::Relayed)]).unwrap(); // segment 3
        for i in 3..=16 {
            log.record(&[(h(i), SeenStatus::Relayed)]).unwrap();
        }
        assert_eq!(log.len(), 16);
        // The 17th hash evicts segment 1 (only a stale record of h(1)) and
        // then segment 2 (h(2)).
        log.record(&[(h(17), SeenStatus::Relayed)]).unwrap();
        assert_eq!(log.len(), 16);
        assert_eq!(log.get(&h(1)), Some(SeenStatus::Relayed));
        assert_eq!(log.get(&h(2)), None);
        drop(log);
        let log = SeenLog::open(dir.path(), 16).unwrap();
        assert_eq!(log.get(&h(1)), Some(SeenStatus::Relayed));
        assert_eq!(log.get(&h(2)), None);
        assert_eq!(log.len(), 16);
    }

    #[test]
    fn torn_tail_is_truncated() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut log = SeenLog::open(dir.path(), 1000).unwrap();
            log.record(&[(h(1), SeenStatus::Relayed), (h(2), SeenStatus::Duplicate)])
                .unwrap();
        }
        let seg = fs::read_dir(dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut f = OpenOptions::new().append(true).open(&seg).unwrap();
        // A partial record, then nothing.
        f.write_all(&[0xAA; 7]).unwrap();
        drop(f);
        {
            let mut log = SeenLog::open(dir.path(), 1000).unwrap();
            assert_eq!(log.len(), 2);
            log.record(&[(h(3), SeenStatus::Relayed)]).unwrap();
        }
        // Zero-filled records (delayed allocation after a crash) are ignored.
        let mut f = OpenOptions::new().append(true).open(&seg).unwrap();
        f.write_all(&[0u8; RECORD_LEN * 2]).unwrap();
        drop(f);
        let log = SeenLog::open(dir.path(), 1000).unwrap();
        assert_eq!(log.len(), 3);
        assert_eq!(log.get(&h(3)), Some(SeenStatus::Relayed));
        assert_eq!(fs::metadata(&seg).unwrap().len() as usize, RECORD_LEN * 5);
    }

    #[test]
    fn claims_are_memory_only_and_tag_origin() {
        let dir = tempfile::tempdir().unwrap();
        let store = SeenStore::open(dir.path(), 1000).unwrap();
        let m = h(42);
        assert_eq!(store.claim(Direction::Inbound, m), Claim::Claimed);
        // Same direction, same block re-read: still claimable.
        assert_eq!(store.claim(Direction::Inbound, m), Claim::Claimed);
        // Other direction: the message came from snapchain; never send it back.
        assert_eq!(
            store.claim(Direction::Outbound, m),
            Claim::LoopBlocked {
                origin: Network::Snapchain
            }
        );
        store
            .record(Direction::Inbound, &[(m, SeenStatus::Relayed)])
            .unwrap();
        assert_eq!(
            store.claim(Direction::Inbound, m),
            Claim::AlreadyHandled(SeenStatus::Relayed)
        );
        assert_eq!(
            store.claim(Direction::Outbound, m),
            Claim::LoopBlocked {
                origin: Network::Snapchain
            }
        );

        // A claim that is not recorded is lost on restart (by design).
        let n = h(43);
        assert_eq!(store.claim(Direction::Outbound, n), Claim::Claimed);
        drop(store);
        let store = SeenStore::open(dir.path(), 1000).unwrap();
        assert_eq!(
            store.status(Direction::Inbound, &m),
            Some(SeenStatus::Relayed)
        );
        assert_eq!(store.status(Direction::Outbound, &n), None);
        assert_eq!(
            store.claim(Direction::Outbound, m),
            Claim::LoopBlocked {
                origin: Network::Snapchain
            }
        );
        assert_eq!(store.len(Direction::Inbound), 1);
        assert_eq!(store.len(Direction::Outbound), 0);
    }

    #[test]
    fn release_drops_only_claims() {
        let dir = tempfile::tempdir().unwrap();
        let store = SeenStore::open(dir.path(), 1000).unwrap();
        store.claim(Direction::Inbound, h(1));
        store.release(Direction::Inbound, &h(1));
        assert_eq!(store.status(Direction::Inbound, &h(1)), None);
        store
            .record(Direction::Inbound, &[(h(2), SeenStatus::Rejected)])
            .unwrap();
        store.release(Direction::Inbound, &h(2));
        assert_eq!(
            store.status(Direction::Inbound, &h(2)),
            Some(SeenStatus::Rejected)
        );
    }
}
