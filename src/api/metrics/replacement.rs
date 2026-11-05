//! Versioned metrics and per-engagement provenance. A replacement is built next
//! to the readable generation; only an atomic pointer update publishes it.
use super::*;
use crate::proto::MessageData;

pub(crate) const SCHEMA: u32 = 1;
const GENERATION_BIT: u8 = 0x10;

#[derive(Clone, Default, Serialize, Deserialize)]
struct Engagement {
    timestamp: u32,
    hash: Vec<u8>,
    removed: bool,
    active: bool,
    target: Option<CastIdRecord>,
}
#[derive(Clone, Serialize, Deserialize)]
struct CastIdRecord {
    fid: u64,
    hash: Vec<u8>,
}

impl Engagement {
    // Compact provenance matters here: there can be hundreds of millions of
    // reactions. Reaction targets already live in the key and aren't repeated.
    fn encode(&self, include_target: bool) -> Vec<u8> {
        let mut out = self.timestamp.to_be_bytes().to_vec();
        out.push(u8::from(self.active) | (u8::from(self.removed) << 1));
        out.push(self.hash.len() as u8);
        out.extend_from_slice(&self.hash);
        if include_target {
            if let Some(target) = &self.target {
                out.extend_from_slice(&target.fid.to_be_bytes());
                out.push(target.hash.len() as u8);
                out.extend_from_slice(&target.hash);
            }
        }
        out
    }
    fn decode(bytes: &[u8]) -> Result<Self, IndexerError> {
        let invalid = || storage("Invalid metrics membership record");
        let timestamp = u32::from_be_bytes(
            bytes
                .get(..4)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?,
        );
        let flags = *bytes.get(4).ok_or_else(invalid)?;
        let length = *bytes.get(5).ok_or_else(invalid)? as usize;
        let hash = bytes.get(6..6 + length).ok_or_else(invalid)?.to_vec();
        let remaining = bytes.get(6 + length..).ok_or_else(invalid)?;
        let target = if remaining.is_empty() {
            None
        } else {
            let fid = u64::from_be_bytes(
                remaining
                    .get(..8)
                    .ok_or_else(invalid)?
                    .try_into()
                    .map_err(|_| invalid())?,
            );
            let length = *remaining.get(8).ok_or_else(invalid)? as usize;
            if remaining.len() != 9 + length {
                return Err(invalid());
            }
            Some(CastIdRecord {
                fid,
                hash: remaining[9..].to_vec(),
            })
        };
        if flags > 3 {
            return Err(invalid());
        }
        Ok(Self {
            timestamp,
            hash,
            active: flags & 1 != 0,
            removed: flags & 2 != 0,
            target,
        })
    }
}

impl MetricsIndexer {
    pub(crate) fn generation(&self) -> u8 {
        self.generation.load(Ordering::SeqCst)
    }

    pub(super) fn read_generation(db: &RocksDB, key: u8) -> Result<Option<u8>, IndexerError> {
        match db.get(&[keys::METRICS_PREFIX, key]).map_err(storage)? {
            None => Ok(None),
            Some(v) if v == [0] || v == [GENERATION_BIT] => Ok(Some(v[0])),
            Some(_) => Err(IndexerError::Storage("Invalid metrics generation".into())),
        }
    }

    pub(crate) fn building_generation(&self) -> Result<Option<u8>, IndexerError> {
        Self::read_generation(&self.db, keys::BUILDING)
    }

    pub(crate) fn view(&self, generation: u8) -> Self {
        Self {
            config: self.config.clone(),
            db: self.db.clone(),
            checkpoint: AtomicU64::new(0),
            casts_tracked: AtomicU64::new(0),
            generation: AtomicU8::new(generation),
            writer: self.writer.clone(),
            readers: self.readers.clone(),
            fixed_generation: true,
            window_live_since: 0,
            window_pruned_hour: AtomicU64::new(0),
        }
    }

    /// Called in the background. Never deletes the readable generation.
    pub(crate) fn prepare(&self) -> Result<(), IndexerError> {
        let _guard = self.writer.lock();
        if self
            .db
            .get(&[keys::METRICS_PREFIX, keys::SCHEMA])
            .map_err(storage)?
            .as_deref()
            == Some(SCHEMA.to_be_bytes().as_slice())
        {
            return Ok(());
        }
        if self.building_generation()?.is_none() {
            let building = self.generation() ^ GENERATION_BIT;
            self.db
                .put(&[keys::METRICS_PREFIX, keys::BUILDING], &[building])
                .map_err(storage)?;
            tracing::info!(
                generation = building,
                "Metrics replacement rebuild started; current metrics remain available"
            );
        }
        Ok(())
    }

    pub(crate) fn switch_to(&self, generation: u8) -> Result<(), IndexerError> {
        let _guard = self.writer.lock();
        let _readers = self.readers.write();
        if self.building_generation()? != Some(generation) {
            return Err(IndexerError::Internal(
                "Metrics replacement is not ready".into(),
            ));
        }
        let mut txn = RocksDbTransactionBatch::new();
        txn.put(vec![keys::METRICS_PREFIX, keys::ACTIVE], vec![generation]);
        txn.put(
            vec![keys::METRICS_PREFIX, keys::SCHEMA],
            SCHEMA.to_be_bytes().to_vec(),
        );
        txn.put(
            vec![keys::METRICS_PREFIX, keys::DELETING],
            vec![self.generation()],
        );
        txn.delete(vec![keys::METRICS_PREFIX, keys::BUILDING]);
        self.commit(txn)?;
        self.generation.store(generation, Ordering::SeqCst);
        tracing::info!(
            generation,
            "Metrics replacement published; readers switched atomically"
        );
        Ok(())
    }

    /// Reclaim only the retired generation, after publication, in bounded batches.
    pub(crate) fn delete_retired(&self, budget: usize) -> Result<bool, IndexerError> {
        let _guard = self.writer.lock();
        let Some(old) = Self::read_generation(&self.db, keys::DELETING)? else {
            return Ok(true);
        };
        if old == self.generation() {
            return Err(IndexerError::Internal(
                "Refusing to delete active metrics".into(),
            ));
        }
        let mut found = vec![];
        for source in [
            keys::CAST_METRICS,
            keys::WINDOW_LIVE,
            keys::WINDOW_BACKFILL,
            keys::MEMBERSHIP,
            keys::REPLIES,
        ] {
            let source = source | old;
            self.db
                .for_each_iterator_by_prefix_paged(
                    Some(vec![keys::METRICS_PREFIX, source]),
                    Some(vec![keys::METRICS_PREFIX, source + 1]),
                    &PageOptions {
                        page_size: Some(budget - found.len()),
                        ..Default::default()
                    },
                    |key, _| {
                        found.push(key.to_vec());
                        Ok(found.len() >= budget)
                    },
                )
                .map_err(storage)?;
            if found.len() >= budget {
                break;
            }
        }
        let done = found.is_empty();
        let mut txn = RocksDbTransactionBatch::new();
        for key in found {
            txn.delete(key);
        }
        if done {
            let prefix = super::super::backfill::shard_checkpoint_prefix(&format!(
                "metrics_replacement_v1:{old}"
            ));
            self.db
                .for_each_iterator_by_prefix(
                    Some(prefix.clone()),
                    Some(crate::storage::util::increment_vec_u8(&prefix)),
                    &PageOptions::default(),
                    |key, _| {
                        txn.delete(key.to_vec());
                        Ok(false)
                    },
                )
                .map_err(storage)?;
            txn.delete(vec![keys::METRICS_PREFIX, keys::DELETING]);
        }
        self.commit(txn)?;
        Ok(done)
    }

    fn pending(
        &self,
        key: &[u8],
        txn: &RocksDbTransactionBatch,
    ) -> Result<Option<Vec<u8>>, IndexerError> {
        match txn.batch.get(key) {
            Some(value) => Ok(value.clone()),
            None => self.db.get(key).map_err(storage),
        }
    }

    pub(super) fn apply_engagement(
        &self,
        message: &Message,
        data: &MessageData,
        kind: MessageEventKind,
        txn: &mut RocksDbTransactionBatch,
    ) -> Result<(), IndexerError> {
        use crate::proto::cast_add_body::Parent;
        use crate::proto::reaction_body::Target;
        let ty = MessageType::try_from(data.r#type).unwrap_or(MessageType::None);
        let hash = if message.hash.is_empty() {
            // Test and synthetic messages still need a stable reply identity.
            blake3::hash(&prost::Message::encode_to_vec(data)).as_bytes()[..20].to_vec()
        } else {
            message.hash.clone()
        };
        let (key, target, reaction, removed) = match (&data.body, ty) {
            (
                Some(Body::ReactionBody(body)),
                MessageType::ReactionAdd | MessageType::ReactionRemove,
            ) => {
                let Some(Target::TargetCastId(target)) = &body.target else {
                    return Ok(());
                };
                let reaction = ReactionType::try_from(body.r#type).unwrap_or(ReactionType::None);
                if reaction == ReactionType::None {
                    return Ok(());
                }
                let mut key = self.cast_key(target.fid, &target.hash);
                key[1] = keys::MEMBERSHIP | self.generation();
                key.extend_from_slice(&data.fid.to_be_bytes());
                key.push(reaction as u8);
                (
                    key,
                    Some(target.clone()),
                    Some(reaction),
                    ty == MessageType::ReactionRemove,
                )
            }
            (Some(Body::CastAddBody(body)), MessageType::CastAdd) => {
                let Some(Parent::ParentCastId(target)) = &body.parent else {
                    return Ok(());
                };
                (
                    self.reply_key(data.fid, &hash),
                    Some(target.clone()),
                    None,
                    false,
                )
            }
            (Some(Body::CastRemoveBody(body)), MessageType::CastRemove)
                if kind == MessageEventKind::Merge =>
            {
                (
                    self.reply_key(data.fid, &body.target_hash),
                    None,
                    None,
                    true,
                )
            }
            _ => return Ok(()),
        };
        let previous: Option<Engagement> = self
            .pending(&key, txn)?
            .map(|v| Engagement::decode(&v))
            .transpose()?;
        let mut next = Engagement {
            timestamp: data.timestamp,
            hash,
            removed,
            active: !removed && kind == MessageEventKind::Merge,
            target: target
                .map(|c| CastIdRecord {
                    fid: c.fid,
                    hash: c.hash,
                })
                .or_else(|| previous.as_ref().and_then(|p| p.target.clone())),
        };
        if let Some(old) = &previous {
            if reaction.is_none() && old.removed {
                return Ok(());
            } // CastRemove wins permanently.
            if kind == MessageEventKind::Revoke {
                if old.hash != next.hash || !old.active {
                    return Ok(());
                }
                let target = next.target.clone();
                next = old.clone();
                next.target = next.target.or(target);
                next.active = false;
            } else if reaction.is_some() {
                // The reaction CRDT compares time, remove-before-add, then hash.
                if (next.timestamp, next.removed, &next.hash)
                    <= (old.timestamp, old.removed, &old.hash)
                {
                    return Ok(());
                }
            } else if !removed {
                return Ok(());
            }
        }
        let was_active = previous.as_ref().is_some_and(|p| p.active);
        let delta = i64::from(next.active) - i64::from(was_active);
        txn.put(key, next.encode(reaction.is_none()));
        if delta != 0 {
            if let Some(target) = &next.target {
                let weight = match reaction {
                    Some(ReactionType::Like) => LIKE_WEIGHT,
                    Some(_) => RECAST_WEIGHT,
                    None => REPLY_WEIGHT,
                };
                self.add_window_score(
                    target.fid,
                    &target.hash,
                    data.timestamp,
                    weight * delta,
                    txn,
                )?;
                if let Some(reaction) = reaction {
                    self.update_cast_metrics(target.fid, &target.hash, reaction, delta > 0, txn)?;
                } else {
                    self.adjust_reply_count(target.fid, &target.hash, delta, txn)?;
                }
            }
        }
        Ok(())
    }

    fn reply_key(&self, fid: u64, hash: &[u8]) -> Vec<u8> {
        let mut key = self.cast_key(fid, hash);
        key[1] = keys::REPLIES | self.generation();
        key
    }
}

fn storage(error: impl std::fmt::Display) -> IndexerError {
    IndexerError::Storage(error.to_string())
}
