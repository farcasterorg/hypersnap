//! Durable, per-shard restore installation. This runs before any node DB is opened.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const JOURNAL: &str = ".snapshot-restore.json";
const STAGING: &str = ".snapshot-restore-shard-";

fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

pub fn has_pending_snapshot_restore(root: &str) -> io::Result<bool> {
    let root = Path::new(root);
    if !root.exists() {
        return Ok(false);
    }
    if root.join(JOURNAL).exists() {
        return Ok(true);
    }
    for entry in fs::read_dir(root)? {
        if entry?
            .file_name()
            .to_string_lossy()
            .starts_with(".snapshot-restore-")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn needs_snapshot_restore(root: &str, shards: &[u32]) -> io::Result<bool> {
    Ok(has_pending_snapshot_restore(root)?
        || shards.iter().any(|id| {
            !Path::new(root)
                .join(format!("shard-{id}/CURRENT"))
                .is_file()
        }))
}

#[derive(Serialize, Deserialize)]
struct Journal {
    version: u32,
    network: i32,
    source: String,
    shards: BTreeSet<u32>,
    completed: BTreeSet<u32>,
    installing: Option<u32>,
}

pub(super) struct RestoreSession {
    root: PathBuf,
    journal: Journal,
}

impl RestoreSession {
    pub fn begin(
        root: &str,
        network: i32,
        source: &str,
        shards: &[u32],
        force: bool,
    ) -> io::Result<Self> {
        let root = PathBuf::from(root);
        fs::create_dir_all(&root)?;
        let shard_set: BTreeSet<_> = shards.iter().copied().collect();
        let source = source.trim_end_matches('/').to_owned();
        let journal = if root.join(JOURNAL).exists() {
            let journal: Journal = serde_json::from_slice(&fs::read(root.join(JOURNAL))?)?;
            if journal.version != 1
                || journal.network != network
                || journal.source != source
                || journal.shards != shard_set
                || !journal.completed.is_subset(&shard_set)
                || journal
                    .installing
                    .is_some_and(|id| !shard_set.contains(&id))
            {
                return Err(io::Error::other("unfinished snapshot restore does not match this network, source, or shard configuration"));
            }
            journal
        } else {
            Journal {
                version: 1,
                network,
                source,
                shards: shard_set,
                completed: shards
                    .iter()
                    .copied()
                    .filter(|id| !force && root.join(format!("shard-{id}/CURRENT")).is_file())
                    .collect(),
                installing: None,
            }
        };
        let mut session = Self { root, journal };
        // Persist intent before staging or replacing any database.
        session.save()?;
        if let Some(id) = session.journal.installing {
            session.finish_install(id)?;
        }
        for &id in &session.journal.completed {
            if !session.destination(id).join("CURRENT").is_file() {
                return Err(io::Error::other(format!("completed snapshot shard {id} is missing; refusing to start with incomplete databases")));
            }
        }
        // Interrupted imports are disposable. An old database is only disposable
        // after the durable completion record says its replacement was installed.
        for entry in fs::read_dir(&session.root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with(".snapshot-restore-") {
                continue;
            }
            if entry.path().join("previous").exists() {
                let id = name
                    .strip_prefix(STAGING)
                    .and_then(|s| s.parse::<u32>().ok());
                if !id.is_some_and(|id| session.journal.completed.contains(&id)) {
                    return Err(io::Error::other(format!(
                        "untracked previous database at {}; preserve it for recovery",
                        entry.path().display()
                    )));
                }
            }
            fs::remove_dir_all(entry.path())?;
        }
        sync_dir(&session.root)?;
        Ok(session)
    }

    fn save(&self) -> io::Result<()> {
        let mut file = tempfile::NamedTempFile::new_in(&self.root)?;
        file.write_all(&serde_json::to_vec(&self.journal)?)?;
        file.as_file().sync_all()?;
        file.persist(self.root.join(JOURNAL)).map_err(|e| e.error)?;
        sync_dir(&self.root)
    }

    fn destination(&self, id: u32) -> PathBuf {
        self.root.join(format!("shard-{id}"))
    }
    pub fn stage(&self, id: u32) -> PathBuf {
        self.root.join(format!("{STAGING}{id}"))
    }
    pub fn staged_db(&self, id: u32) -> PathBuf {
        self.stage(id).join(format!("shard-{id}"))
    }
    pub fn completed(&self, id: u32) -> bool {
        self.journal.completed.contains(&id)
    }

    pub fn prepare(&self, id: u32) -> io::Result<()> {
        fs::create_dir(self.stage(id))?;
        sync_dir(&self.root)
    }

    pub fn discard_import(&self, id: u32) -> io::Result<()> {
        if self.journal.installing.is_none() && self.stage(id).exists() {
            fs::remove_dir_all(self.stage(id))?;
            sync_dir(&self.root)?;
        }
        Ok(())
    }

    pub fn install(&mut self, id: u32) -> io::Result<()> {
        let db = self.staged_db(id);
        if !db.join("CURRENT").is_file() {
            return Err(io::Error::other(
                "snapshot did not contain a RocksDB database",
            ));
        }
        // Also covers legacy archives, whose extracted files have not been synced.
        for entry in walkdir::WalkDir::new(&db) {
            let entry = entry?;
            if entry.file_type().is_file() {
                File::open(entry.path())?.sync_all()?;
            }
        }
        sync_dir(&db)?;
        sync_dir(&self.stage(id))?;
        self.journal.installing = Some(id);
        self.save()?;
        self.finish_install(id)
    }

    fn finish_install(&mut self, id: u32) -> io::Result<()> {
        let staged = self.staged_db(id);
        let destination = self.destination(id);
        let previous = self.stage(id).join("previous");
        if staged.exists() {
            if destination.exists() {
                if previous.exists() {
                    return Err(io::Error::other(
                        "ambiguous snapshot install state; preserving all databases",
                    ));
                }
                fs::rename(&destination, &previous)?;
                sync_dir(&self.stage(id))?;
                sync_dir(&self.root)?;
            }
            fs::rename(&staged, &destination)?;
            sync_dir(&self.stage(id))?;
            sync_dir(&self.root)?;
        }
        if !destination.join("CURRENT").is_file() {
            return Err(io::Error::other(
                "snapshot install is incomplete; preserving previous database",
            ));
        }
        self.journal.completed.insert(id);
        self.journal.installing = None;
        self.save()?;
        if self.stage(id).exists() {
            fs::remove_dir_all(self.stage(id))?;
        }
        sync_dir(&self.root)
    }

    pub fn finish(self) -> io::Result<()> {
        if self.journal.completed != self.journal.shards || self.journal.installing.is_some() {
            return Err(io::Error::other(
                "snapshot restore still has unfinished shards",
            ));
        }
        fs::remove_file(self.root.join(JOURNAL))?;
        sync_dir(&self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database(path: &Path, value: &[u8]) {
        let mut options = rocksdb::Options::default();
        options.create_if_missing(true);
        let db = rocksdb::DB::open(&options, path).unwrap();
        db.put(b"value", value).unwrap();
        db.flush().unwrap();
    }

    #[test]
    fn snapshot_restore_recovers_each_install_crash_window() {
        for step in 0..4 {
            let root = tempfile::TempDir::new().unwrap();
            database(&root.path().join("shard-1"), b"old");
            let mut session =
                RestoreSession::begin(root.path().to_str().unwrap(), 1, "source", &[1], true)
                    .unwrap();
            session.prepare(1).unwrap();
            database(&session.staged_db(1), b"new");
            session.journal.installing = Some(1);
            session.save().unwrap();
            if step >= 1 {
                fs::rename(session.destination(1), session.stage(1).join("previous")).unwrap();
            }
            if step >= 2 {
                fs::rename(session.staged_db(1), session.destination(1)).unwrap();
            }
            if step >= 3 {
                session.journal.installing = None;
                session.journal.completed.insert(1);
                session.save().unwrap();
            }
            drop(session);
            let resumed =
                RestoreSession::begin(root.path().to_str().unwrap(), 1, "source", &[1], true)
                    .unwrap();
            assert!(resumed.completed(1));
            let db = rocksdb::DB::open_for_read_only(
                &rocksdb::Options::default(),
                resumed.destination(1),
                false,
            )
            .unwrap();
            assert_eq!(db.get(b"value").unwrap().unwrap(), b"new");
            assert!(!resumed.stage(1).exists());
            assert!(needs_snapshot_restore(root.path().to_str().unwrap(), &[1]).unwrap());
            resumed.finish().unwrap();
            assert!(!needs_snapshot_restore(root.path().to_str().unwrap(), &[1]).unwrap());
        }
    }

    #[test]
    fn snapshot_restore_discards_interrupted_import_but_preserves_old_db() {
        let root = tempfile::TempDir::new().unwrap();
        database(&root.path().join("shard-1"), b"original");
        let session =
            RestoreSession::begin(root.path().to_str().unwrap(), 1, "source", &[1], true).unwrap();
        session.prepare(1).unwrap();
        database(&session.staged_db(1), b"partial");
        drop(session);
        let resumed =
            RestoreSession::begin(root.path().to_str().unwrap(), 1, "source", &[1], true).unwrap();
        assert!(!resumed.completed(1));
        assert!(!resumed.stage(1).exists());
        let db = rocksdb::DB::open_for_read_only(
            &rocksdb::Options::default(),
            resumed.destination(1),
            false,
        )
        .unwrap();
        assert_eq!(db.get(b"value").unwrap().unwrap(), b"original");
        assert!(resumed.finish().is_err());
    }

    #[test]
    fn snapshot_restore_rejects_changed_source_and_missing_completed_shard() {
        let root = tempfile::TempDir::new().unwrap();
        database(&root.path().join("shard-1"), b"done");
        let session =
            RestoreSession::begin(root.path().to_str().unwrap(), 1, "source", &[1, 2], false)
                .unwrap();
        assert!(session.completed(1));
        drop(session);
        assert!(RestoreSession::begin(
            root.path().to_str().unwrap(),
            1,
            "different-chain",
            &[1, 2],
            false
        )
        .is_err());
        fs::remove_dir_all(root.path().join("shard-1")).unwrap();
        assert!(
            RestoreSession::begin(root.path().to_str().unwrap(), 1, "source", &[1, 2], false)
                .is_err()
        );
    }

    #[test]
    fn snapshot_restore_recognizes_old_orphans_and_missing_shards() {
        let root = tempfile::TempDir::new().unwrap();
        database(&root.path().join("shard-1"), b"done");
        assert!(needs_snapshot_restore(root.path().to_str().unwrap(), &[0, 1, 2]).unwrap());
        fs::create_dir(root.path().join(".snapshot-restore-old")).unwrap();
        assert!(has_pending_snapshot_restore(root.path().to_str().unwrap()).unwrap());
        let session =
            RestoreSession::begin(root.path().to_str().unwrap(), 1, "source", &[1, 2], false)
                .unwrap();
        assert!(session.completed(1));
        assert!(!root.path().join(".snapshot-restore-old").exists());
    }
}
