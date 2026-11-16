//! Versioned, bounded-memory key/value snapshot stream. No staging database or archive.
use super::{DBProvider, RocksDB};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use std::io::{self, Cursor, Read, Write};
use tokio::sync::mpsc;

pub const CHUNK_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_COMPRESSED_CHUNK: usize = CHUNK_BYTES + 1024 * 1024;
const MAGIC: &[u8; 8] = b"HSSNAP01";
const MAX_FIELD: usize = 256 * 1024 * 1024;

pub fn check_space(path: &str, minimum: u64) -> io::Result<()> {
    let stat = nix::sys::statvfs::statvfs(path).map_err(io::Error::other)?;
    let available = (stat.blocks_available() as u64).saturating_mul(stat.fragment_size() as u64);
    if available < minimum {
        return Err(io::Error::other(format!(
            "snapshot stopped: {available} bytes free at {path}, reserve is {minimum} bytes"
        )));
    }
    Ok(())
}

struct ChunkWriter<F> {
    encoder: GzEncoder<Vec<u8>>,
    used: usize,
    limit: usize,
    send: F,
}
impl<F: FnMut(Vec<u8>) -> io::Result<()>> ChunkWriter<F> {
    fn new(limit: usize, send: F) -> Self {
        Self {
            encoder: GzEncoder::new(Vec::new(), Compression::fast()),
            used: 0,
            limit,
            send,
        }
    }
    fn finish_chunk(&mut self) -> io::Result<()> {
        if self.used == 0 {
            return Ok(());
        }
        let encoder = std::mem::replace(
            &mut self.encoder,
            GzEncoder::new(Vec::new(), Compression::fast()),
        );
        let bytes = encoder.finish()?;
        (self.send)(bytes)?;
        self.used = 0;
        Ok(())
    }
}
impl<F: FnMut(Vec<u8>) -> io::Result<()>> Write for ChunkWriter<F> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.used == self.limit {
            self.finish_chunk()?;
        }
        let count = bytes.len().min(self.limit - self.used);
        self.encoder.write_all(&bytes[..count])?;
        self.used += count;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.encoder.flush()
    }
}

fn export_records<I, F>(records: I, limit: usize, send: F) -> io::Result<u64>
where
    I: IntoIterator<Item = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>>,
    F: FnMut(Vec<u8>) -> io::Result<()>,
{
    let mut writer = ChunkWriter::new(limit, send);
    writer.write_all(MAGIC)?;
    let mut count = 0u64;
    for record in records {
        let (key, value) = record.map_err(io::Error::other)?;
        if key.len() > MAX_FIELD || value.len() > MAX_FIELD {
            return Err(io::Error::other("snapshot record exceeds format limit"));
        }
        writer.write_all(&(key.len() as u32).to_be_bytes())?;
        writer.write_all(&(value.len() as u32).to_be_bytes())?;
        writer.write_all(&key)?;
        writer.write_all(&value)?;
        count += 1;
        if count % 1_000_000 == 0 {
            tracing::info!(records = count, "Streaming snapshot progress");
        }
    }
    writer.write_all(&u32::MAX.to_be_bytes())?;
    writer.write_all(&0u32.to_be_bytes())?;
    writer.write_all(&count.to_be_bytes())?;
    writer.finish_chunk()?;
    Ok(count)
}

pub fn export(db: &RocksDB, minimum_free_bytes: u64, tx: mpsc::Sender<Vec<u8>>) -> io::Result<u64> {
    check_space(&db.path, minimum_free_bytes)?;
    let provider = db.db();
    let mut send = |bytes| {
        // A consistent RocksDB snapshot can retain old versions during compaction.
        // Stop and release it before this retention exhausts the source disk.
        check_space(&db.path, minimum_free_bytes)?;
        tx.blocking_send(bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "snapshot upload cancelled"))
    };
    match provider.as_ref() {
        Some(DBProvider::Transaction(db)) => {
            let snapshot = db.snapshot();
            let mut options = rocksdb::ReadOptions::default();
            options.fill_cache(false);
            export_records(
                snapshot.iterator_opt(rocksdb::IteratorMode::Start, options),
                CHUNK_BYTES,
                &mut send,
            )
        }
        Some(DBProvider::ReadOnly(db)) => {
            let snapshot = db.snapshot();
            let mut options = rocksdb::ReadOptions::default();
            options.fill_cache(false);
            export_records(
                snapshot.iterator_opt(rocksdb::IteratorMode::Start, options),
                CHUNK_BYTES,
                &mut send,
            )
        }
        None => Err(io::Error::other("snapshot database is not open")),
    }
}

/// Concatenate independent gzip chunks without materializing the full stream.
struct ChunkReader {
    rx: mpsc::Receiver<Vec<u8>>,
    current: Option<GzDecoder<Cursor<Vec<u8>>>>,
}
impl Read for ChunkReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(reader) = &mut self.current {
                let read = reader.read(buf)?;
                if read > 0 {
                    return Ok(read);
                }
                self.current = None;
            }
            match self.rx.blocking_recv() {
                Some(chunk) => self.current = Some(GzDecoder::new(Cursor::new(chunk))),
                None => return Ok(0),
            }
        }
    }
}

fn import_records(reader: &mut impl Read, db: &rocksdb::DB) -> io::Result<u64> {
    let mut magic = [0; 8];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::other("invalid snapshot stream header"));
    }
    let mut count = 0u64;
    let mut previous: Option<Vec<u8>> = None;
    let mut batch = rocksdb::WriteBatch::default();
    let mut batch_bytes = 0;
    let mut options = rocksdb::WriteOptions::default();
    options.disable_wal(true);
    loop {
        let mut lengths = [0; 8];
        reader.read_exact(&mut lengths)?;
        let key_len = u32::from_be_bytes(lengths[..4].try_into().unwrap()) as usize;
        let value_len = u32::from_be_bytes(lengths[4..].try_into().unwrap()) as usize;
        if key_len == u32::MAX as usize && value_len == 0 {
            let mut footer = [0; 8];
            reader.read_exact(&mut footer)?;
            if u64::from_be_bytes(footer) != count || reader.read(&mut [0])? != 0 {
                return Err(io::Error::other(
                    "snapshot record count or trailer mismatch",
                ));
            }
            break;
        }
        if key_len > MAX_FIELD || value_len > MAX_FIELD {
            return Err(io::Error::other("snapshot record exceeds format limit"));
        }
        let mut key = vec![0; key_len];
        let mut value = vec![0; value_len];
        reader.read_exact(&mut key)?;
        reader.read_exact(&mut value)?;
        if previous.as_ref().is_some_and(|last| last >= &key) {
            return Err(io::Error::other("snapshot keys are not strictly ordered"));
        }
        batch.put(&key, &value);
        previous = Some(key);
        batch_bytes += key_len + value_len;
        count += 1;
        if batch_bytes >= 4 * 1024 * 1024 {
            db.write_opt(std::mem::take(&mut batch), &options)
                .map_err(io::Error::other)?;
            batch_bytes = 0;
        }
    }
    db.write_opt(batch, &options).map_err(io::Error::other)?;
    db.flush().map_err(io::Error::other)?;
    Ok(count)
}

pub fn restore(path: &str, rx: mpsc::Receiver<Vec<u8>>) -> io::Result<u64> {
    let mut options = rocksdb::Options::default();
    options.create_if_missing(true);
    options.set_compression_type(rocksdb::DBCompressionType::Lz4);
    options.set_write_buffer_size(16 * 1024 * 1024);
    options.set_max_open_files(128);
    let cache = rocksdb::Cache::new_lru_cache(32 * 1024 * 1024);
    let mut table = rocksdb::BlockBasedOptions::default();
    table.set_block_cache(&cache);
    options.set_block_based_table_factory(&table);
    let db = rocksdb::DB::open(&options, path).map_err(io::Error::other)?;
    import_records(&mut ChunkReader { rx, current: None }, &db)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn records() -> Vec<Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>> {
        (0..40u32)
            .map(|n| {
                Ok((
                    n.to_be_bytes().to_vec().into_boxed_slice(),
                    vec![n as u8; 150].into_boxed_slice(),
                ))
            })
            .collect()
    }
    fn chunks() -> Vec<Vec<u8>> {
        let mut chunks = Vec::new();
        assert_eq!(
            export_records(records(), 37, |bytes| {
                chunks.push(bytes);
                Ok(())
            })
            .unwrap(),
            40
        );
        chunks
    }
    fn reader(chunks: Vec<Vec<u8>>) -> ChunkReader {
        let (tx, rx) = mpsc::channel(chunks.len().max(1));
        for chunk in chunks {
            tx.blocking_send(chunk).unwrap();
        }
        drop(tx);
        ChunkReader { rx, current: None }
    }
    #[test]
    fn bounded_chunks_roundtrip_and_reopen_as_transaction_db() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("db");
        let chunks = chunks();
        assert!(
            chunks.len() > 100,
            "exercise headers and records split across chunks"
        );
        assert!(chunks.iter().all(|c| c.len() < 100));
        let mut options = rocksdb::Options::default();
        options.create_if_missing(true);
        let db = rocksdb::DB::open(&options, &path).unwrap();
        assert_eq!(import_records(&mut reader(chunks), &db).unwrap(), 40);
        drop(db);
        let restored = RocksDB::new(path.to_str().unwrap());
        restored.open().unwrap();
        for record in records() {
            let (key, value) = record.unwrap();
            assert_eq!(restored.get(&key).unwrap(), Some(value.to_vec()));
        }
    }
    #[test]
    fn rejects_missing_chunks_corrupt_gzip_and_truncated_footer() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut options = rocksdb::Options::default();
        options.create_if_missing(true);
        let db = rocksdb::DB::open(&options, dir.path().join("db")).unwrap();
        let mut incomplete = chunks();
        incomplete.pop();
        assert!(import_records(&mut reader(incomplete), &db).is_err());
        let mut corrupt = chunks();
        corrupt[0][0] ^= 255;
        assert!(import_records(&mut reader(corrupt), &db).is_err());
    }
    #[test]
    fn rejects_out_of_order_keys_and_incorrect_record_counts() {
        let mut bytes = Vec::new();
        for chunk in chunks() {
            GzDecoder::new(Cursor::new(chunk))
                .read_to_end(&mut bytes)
                .unwrap();
        }
        let dir = tempfile::TempDir::new().unwrap();
        let mut options = rocksdb::Options::default();
        options.create_if_missing(true);
        let db = rocksdb::DB::open(&options, dir.path().join("db")).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(import_records(&mut Cursor::new(&bytes), &db).is_err());
        let mut duplicate = Vec::new();
        export_records(
            vec![
                Ok((Box::from(&b"a"[..]), Box::from(&b"1"[..]))),
                Ok((Box::from(&b"a"[..]), Box::from(&b"2"[..]))),
            ],
            64,
            |bytes| {
                GzDecoder::new(Cursor::new(bytes)).read_to_end(&mut duplicate)?;
                Ok(())
            },
        )
        .unwrap();
        assert!(import_records(&mut Cursor::new(duplicate), &db).is_err());
    }
    #[test]
    fn export_is_consistent_while_live_database_changes_and_creates_no_staging_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(RocksDB::new(dir.path().join("source").to_str().unwrap()));
        db.open().unwrap();
        db.put(b"a", b"before").unwrap();
        db.put(b"b", b"before").unwrap();
        let provider = db.db();
        let Some(DBProvider::Transaction(main)) = provider.as_ref() else {
            panic!()
        };
        let snapshot = main.snapshot();
        let mut chunks = Vec::new();
        export_records(
            snapshot.iterator(rocksdb::IteratorMode::Start),
            8,
            |bytes| {
                db.put(b"b", b"after").map_err(io::Error::other)?;
                db.put(b"c", b"new").map_err(io::Error::other)?;
                chunks.push(bytes);
                Ok(())
            },
        )
        .unwrap();
        let mut options = rocksdb::Options::default();
        options.create_if_missing(true);
        let restored = rocksdb::DB::open(&options, dir.path().join("restore")).unwrap();
        assert_eq!(import_records(&mut reader(chunks), &restored).unwrap(), 2);
        assert_eq!(restored.get(b"b").unwrap(), Some(b"before".to_vec()));
        assert!(restored.get(b"c").unwrap().is_none());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }
    #[test]
    fn aborts_when_consumer_stops_or_disk_reserve_is_exceeded() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().join("source").to_str().unwrap());
        db.open().unwrap();
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        assert!(export(&db, 0, tx).is_err());
        let (tx, _rx) = mpsc::channel(1);
        assert!(export(&db, u64::MAX, tx)
            .unwrap_err()
            .to_string()
            .contains("reserve"));
    }
    #[test]
    fn empty_database_has_a_verified_footer() {
        let mut chunks = Vec::new();
        export_records(std::iter::empty(), 16, |bytes| {
            chunks.push(bytes);
            Ok(())
        })
        .unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("db");
        let (tx, rx) = mpsc::channel(chunks.len());
        for chunk in chunks {
            tx.blocking_send(chunk).unwrap();
        }
        drop(tx);
        assert_eq!(restore(path.to_str().unwrap(), rx).unwrap(), 0);
    }
}
