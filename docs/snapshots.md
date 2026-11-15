# Streaming Hypersnap snapshots

Snapshot uploads export a consistent RocksDB read snapshot directly to S3/R2.
They do not create a second RocksDB database, a local tar file, or a directory of
compressed chunks. A bounded channel sends independently compressed chunks as
soon as they are produced and pauses the database scan when uploads are slower.

Each chunk contains at most 16 MiB of uncompressed stream data. The producer,
one queued chunk, and uploader normally hold about three chunks in memory,
plus the current database record and compression/SDK buffers. Snapshot size does
not determine the size of these buffers. Scans do not populate the source block cache.
Compression uses gzip's fast setting and no second database compaction.

The snapshot still contains the full logical contents of each shard. Uploads
therefore still require a full scan and transfer; this is not an incremental
backup. Live writes continue during the scan. RocksDB may retain old record
versions while the read snapshot is open, so publishing is not completely free
of extra disk use. The publisher checks source free space during export and at
two-second intervals during upload, aborting and releasing the read snapshot if
free space falls below the configured reserve.

## Deployment

Upgrade read nodes to this version before publishing streaming snapshots. New
binaries restore both the existing chunked tar/gzip archives and the new
`key_value_v1` stream. Older binaries cannot restore the new format. Block and
consensus formats are unchanged.

The defaults use the dedicated Hypersnap bucket and public download URL shown
below. Keep the publisher credentials and admin upload RPC. The publisher
credentials need `GetObject`, `PutObject`, `ListBucket`, and `DeleteObject`
permissions: cleanup now reads the authoritative
metadata directly from S3. No new authentication scheme is introduced. Configure the
publishing node's generated `config.toml` under `[snapshot]`. For the repository's
Compose files, edit the Hypersnap service's `HYPERSNAP_CONFIG` block:

```toml
[snapshot]
endpoint_url = "https://5400535f796c891e31be1f53f6d89dc0.r2.cloudflarestorage.com"
s3_bucket = "snapshots"
snapshot_download_url = "https://snapshots.hypria.app"
backup_dir = ".rocks.backup"
# Keep credentials on the publishing node.
# Example reserve: 50 GiB. Default when omitted: 10 GiB.
min_free_disk_bytes = 53_687_091_200
backup_on_startup = false
# Defaults below; optional overrides.
min_retention_secs = 604800 # Seven days after a snapshot is replaced.
connect_timeout_secs = 10
read_timeout_secs = 60
request_timeout_secs = 600
```

`backup_on_startup` is the older, separate **local archive backup** path. It still
needs space for a database copy and archive. Leave it disabled on a publisher
using streaming uploads. Do not confuse it with the scheduled/admin S3 uploader.

Only one upload can run at a time in a node process; shards are uploaded
sequentially in shard ID order. Use one publishing node per bucket/network.
The admin RPC and scheduled job use the same streaming implementation. Upload
and cleanup failures are logged with the shard ID, and the job continues with
the remaining selected shards. After all shards have been attempted, failures
are returned together and logged by the admin task instead of being reported as
successful completion. A cleanup failure does not invalidate an already published
snapshot or prevent other shards from being published.

Existing files from interrupted legacy backups are not automatically removed,
nor do they block streaming uploads. Changing the binary does not reclaim the
space already consumed by those files.

## Publication and restore

The metadata pointer `NETWORK/shard/latest.json` is replaced only after the full
stream and every object upload succeed. A failure before publication leaves the
previous pointer unchanged. Cleanup always keeps the current and preceding
generations. Other generations remain for at least `min_retention_secs` after
replacement, including when operators trigger several uploads manually. A
`retired.json` object records this time; it is not based on the age of the first
chunk or when the export started. Generations without a retirement record,
including legacy snapshots and abandoned uploads, receive a full grace period
when cleanup first discovers them. They consume bucket space, not publisher disk
space. Seven days of retention can keep more than two full snapshots in the
bucket. Set the grace period longer than the slowest complete node restore you
intend to support, and ensure bucket lifecycle rules do not delete them earlier.

Metadata carries an explicit format, ordered chunk list, SHA-256 checksum for
each compressed chunk, and record count. The stream has a version header,
length-prefixed ordered binary keys/values, and a final record-count footer.
Restore rejects missing/corrupt chunks, invalid key ordering, truncation, or a
record-count mismatch. Keys and values are copied verbatim, including native
account records, shard headers, trie data, and indexes.

Streaming restores download and import chunks through a bounded channel into a
new temporary RocksDB on the destination filesystem, without writing compressed
chunks or an uncompressed archive. The database is installed only after full
verification and flush. On failure, the temporary database is removed and any
existing destination shard is preserved. Replacing an existing database still
requires space for the old and new databases until the new one is verified.
Restoring legacy archives retains their previous staging requirements.

Restore progress is recorded in `<rocksdb_dir>/.snapshot-restore.json`. Completed
shards are kept across restarts; an interrupted shard is imported again from its
first chunk, using current metadata. This is per-shard recovery, not a resumable
download within a shard. Abandoned staging files are removed before retrying.
The journal also records database replacement before either rename, so a crash
between moving the old database aside and installing the new one can be recovered
on startup. The old database is deleted only after installation and the completion
record have been synced to disk.

Once all shards are installed, restore completion is recorded before legacy
download scratch files are cleaned up. Cleanup keeps the download directory itself
(it can be a Docker volume mount). Cleanup failures emit warnings and leave the
remaining scratch files for manual removal; they do not block startup or trigger
another restore. Streaming imports do not require a writable legacy download
scratch directory.

Startup checks for the journal, abandoned staging directories, and missing shard
databases instead of assuming that any nonempty directory is initialized. It
will not start the node with an unfinished restore if snapshot loading has been
disabled. Keep the same network, snapshot URL, and shard selection while resuming;
changing them during a partial restore is rejected to avoid mixing sources.
Normal bootstrap preserves existing shard databases; `force_load_db_from_snapshot`
starts a replacement of all requested shards, while a restart resumes that same
replacement. Turn that force option off after a successful replacement to avoid
starting another replacement on a future restart.

Downloads share an HTTP client with connect, read-idle, and total-request deadlines.
Transient failures and timeouts are retried a bounded number of times. The same
deadlines cover metadata and legacy downloads. S3 operations also have explicit
deadlines, and metadata body consumption has its own deadline because the SDK's
operation deadline ends at response headers. Timeout settings must be positive;
the total deadline applies per request, not to the whole multi-hour snapshot.

The latest pointer is published with `Cache-Control: no-store`; chunks are
immutable. Old-snapshot cleanup reads the current pointer through authenticated
S3, so a cached public URL cannot cause deletion of the newly published generation.
Listing uses pagination and deletion uses batches of at most 1,000 objects.

## Verification

Tests cover consistent export during live writes, binary key/value round trips
into a reopened TransactionDB, bounded chunks split through record boundaries,
empty databases, corrupt/truncated streams, failed uploads and disk reserve
exhaustion, publication ordering, preservation of existing databases on restore
failure, legacy archive restores, multi-page cleanup, and concurrent publishers.
Regression tests also terminate a child process during import, exercise each
installation crash window, resume after a later-shard failure, time out stalled
HTTP headers and bodies, and retain older readers across repeated publications.
They also preserve the download directory during cleanup, complete restores when
scratch cleanup fails, and publish remaining shards after upload or cleanup errors.
The object-store tests use a local HTTP fixture; no production bucket is changed.
