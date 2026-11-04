use snapchain::api::{backfill, config, IndexEvent, Indexer, SearchIndexer, SearchSort};
use snapchain::proto::{message_data::Body, CastAddBody, Message, MessageData, MessageType};
use snapchain::storage::db::RocksDB;

const SEARCH_BACKFILL_CHECKPOINT: &str = "search_hyper_backfill";

fn backfill_checkpoint_name(name: &str) -> String {
    format!("api_block_backfill:{name}")
}

fn search_config() -> config::SearchConfig {
    config::SearchConfig {
        enabled: true,
        backfill_on_startup: true,
        memory_budget_mb: 50,
        ..Default::default()
    }
}

#[tokio::test]
async fn search_results_and_completion_survive_reopening() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("node-data");
    let config = search_config();
    {
        let db = RocksDB::open_shard_db(root.to_str().unwrap(), 0);
        let search = SearchIndexer::open(config.clone(), &db, &[1, 2]).unwrap();
        let message = Message {
            hash: vec![1, 2, 3, 4],
            data: Some(MessageData {
                fid: 123,
                r#type: MessageType::CastAdd as i32,
                body: Some(Body::CastAddBody(CastAddBody {
                    text: "Persistent search result".to_string(),
                    ..Default::default()
                })),
                ..Default::default()
            }),
            ..Default::default()
        };
        search
            .process_event(&IndexEvent::message(message, 1, 1))
            .await
            .unwrap();
        for shard_id in [1, 2] {
            backfill::save_shard_checkpoint(&db, SEARCH_BACKFILL_CHECKPOINT, shard_id, u64::MAX)
                .unwrap();
        }
    }

    // Reopen both databases, as happens after the process/container exits.
    let db = RocksDB::open_shard_db(root.to_str().unwrap(), 0);
    let search = SearchIndexer::open(config.clone(), &db, &[1, 2]).unwrap();
    assert!(root.join("search_index/meta.json").is_file());
    let results = search
        .search_casts("persistent", SearchSort::Relevance, 0, 10)
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].fid, 123);
    assert_eq!(search.stats().items_indexed, 1);
    assert!(search.stats().backfill_complete);

    // Adding a shard must not report completion until that shard is done.
    drop(search);
    let search = SearchIndexer::open(config.clone(), &db, &[1, 2, 3]).unwrap();
    assert!(!search.stats().backfill_complete);
}

#[test]
fn missing_search_index_resets_only_search_backfill_cursors() {
    let dir = tempfile::tempdir().unwrap();
    let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
    for shard_id in [1, 2] {
        for name in [
            SEARCH_BACKFILL_CHECKPOINT.to_string(),
            backfill_checkpoint_name("search"),
            backfill_checkpoint_name("social_graph"),
        ] {
            backfill::save_shard_checkpoint(&db, &name, shard_id, u64::MAX).unwrap();
        }
    }
    let search = SearchIndexer::open(search_config(), &db, &[1, 2]).unwrap();
    assert!(!search.stats().backfill_complete);
    for shard_id in [1, 2] {
        for name in [
            SEARCH_BACKFILL_CHECKPOINT.to_string(),
            backfill_checkpoint_name("search"),
        ] {
            assert_eq!(backfill::load_shard_checkpoint(&db, &name, shard_id), 0);
        }
        assert_eq!(
            backfill::load_shard_checkpoint(
                &db,
                &backfill_checkpoint_name("social_graph"),
                shard_id
            ),
            u64::MAX
        );
    }
}

#[test]
fn existing_search_index_keeps_partial_backfill_cursors() {
    let dir = tempfile::tempdir().unwrap();
    let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
    let config = search_config();
    drop(SearchIndexer::open(config.clone(), &db, &[1, 2]).unwrap());
    backfill::save_shard_checkpoint(&db, SEARCH_BACKFILL_CHECKPOINT, 1, u64::MAX).unwrap();
    backfill::save_shard_checkpoint(&db, SEARCH_BACKFILL_CHECKPOINT, 2, 123_000).unwrap();

    let search = SearchIndexer::open(config.clone(), &db, &[1, 2]).unwrap();
    assert!(!search.stats().backfill_complete);
    assert_eq!(
        backfill::load_shard_checkpoint(&db, SEARCH_BACKFILL_CHECKPOINT, 2),
        123_000
    );
}

#[test]
fn search_index_defaults_to_the_node_data_directory() {
    let config: config::SearchConfig = toml::from_str("enabled = true").unwrap();
    for root in [".rocks", ".rocks.testnet", "/srv/hypersnap"] {
        let root = std::path::Path::new(root);
        assert_eq!(config.resolved_index_path(root), root.join("search_index"));
    }
    for custom_path in ["./custom/search", "/mnt/search"] {
        let config = config::SearchConfig {
            index_path: custom_path.to_string(),
            ..Default::default()
        };
        assert_eq!(
            config.resolved_index_path(std::path::Path::new(".rocks")),
            std::path::PathBuf::from(custom_path)
        );
    }
}

fn cast(fid: u64, hash: u8, timestamp: u32, text: &str) -> Message {
    Message {
        hash: vec![hash; 20],
        data: Some(MessageData {
            fid,
            timestamp,
            r#type: MessageType::CastAdd as i32,
            body: Some(Body::CastAddBody(CastAddBody {
                text: text.to_string(),
                ..Default::default()
            })),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// An index as built before hashtags: no `tags`, timestamps not sortable.
fn write_legacy_index(path: &std::path::Path, text: &str) {
    use tantivy::schema::{Schema, STORED, TEXT};
    std::fs::create_dir_all(path).unwrap();
    let mut builder = Schema::builder();
    let fid = builder.add_u64_field("fid", STORED);
    let hash = builder.add_text_field("hash", STORED);
    let body = builder.add_text_field("text", TEXT | STORED);
    let timestamp = builder.add_u64_field("timestamp", STORED);
    let index = tantivy::Index::create_in_dir(path, builder.build()).unwrap();
    let mut writer: tantivy::IndexWriter = index.writer(15_000_000).unwrap();
    writer
        .add_document(tantivy::doc!(fid => 7u64, hash => "aa", body => text, timestamp => 1u64))
        .unwrap();
    writer.commit().unwrap();
}

#[tokio::test]
async fn legacy_index_keeps_serving_until_the_rebuild_completes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("node-data");
    let db = RocksDB::open_shard_db(root.to_str().unwrap(), 0);
    write_legacy_index(&root.join("search_index"), "old #history cast");
    backfill::save_shard_checkpoint(&db, SEARCH_BACKFILL_CHECKPOINT, 1, u64::MAX).unwrap();

    let search = SearchIndexer::open(search_config(), &db, &[1]).unwrap();
    // Moved aside, a fresh index in its place, and the walk starts over.
    assert!(root.join("search_index.legacy/meta.json").is_file());
    assert!(root.join("search_index/meta.json").is_file());
    assert!(!search.stats().backfill_complete);
    assert_eq!(
        backfill::load_shard_checkpoint(&db, SEARCH_BACKFILL_CHECKPOINT, 1),
        0
    );
    // Old history is still searchable, and live casts reach it too.
    let found = |q: &str| {
        search
            .search_casts(q, SearchSort::Relevance, 0, 10)
            .unwrap()
            .into_iter()
            .map(|r| r.fid)
            .collect::<Vec<_>>()
    };
    assert_eq!(found("history"), vec![7]);
    search
        .process_event(&IndexEvent::message(cast(8, 1, 100, "live #news"), 1, 1))
        .await
        .unwrap();
    wait_for(|| found("news") == vec![8]);

    // A restart mid-rebuild keeps the legacy index serving.
    drop(search);
    let search = SearchIndexer::open(search_config(), &db, &[1]).unwrap();
    assert!(root.join("search_index.legacy").exists());
    assert_eq!(
        search
            .search_casts("history", SearchSort::Relevance, 0, 10)
            .unwrap()
            .len(),
        1
    );

    // The walk finishing swaps to the new index and deletes the old one.
    backfill::save_shard_checkpoint(&db, SEARCH_BACKFILL_CHECKPOINT, 1, u64::MAX).unwrap();
    drop(search);
    let search = SearchIndexer::open(search_config(), &db, &[1]).unwrap();
    assert!(search.stats().backfill_complete);
    assert!(!root.join("search_index.legacy").exists());
    let tagged = search
        .search_casts("#news", SearchSort::Newest, 0, 10)
        .unwrap();
    assert_eq!(tagged.iter().map(|r| r.fid).collect::<Vec<_>>(), vec![8]);
}

#[test]
fn a_new_index_records_where_live_indexing_takes_over() {
    let dir = tempfile::tempdir().unwrap();
    let db = RocksDB::open_shard_db(dir.path().to_str().unwrap(), 0);
    let now = snapchain::core::util::FarcasterTime::current().to_u64();
    drop(SearchIndexer::open(search_config(), &db, &[1]).unwrap());
    let before = backfill::load_shard_checkpoint(&db, "search_backfill_before", 0);
    assert!(before >= now && before <= now + 5);
    // Reopening keeps it.
    drop(SearchIndexer::open(search_config(), &db, &[1]).unwrap());
    assert_eq!(
        backfill::load_shard_checkpoint(&db, "search_backfill_before", 0),
        before
    );
}

fn wait_for(ok: impl Fn() -> bool) {
    // the reader reloads shortly after a commit
    for _ in 0..100 {
        if ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("search never caught up");
}
