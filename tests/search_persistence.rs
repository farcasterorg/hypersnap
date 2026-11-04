use snapchain::api::{backfill, config, IndexEvent, Indexer, SearchIndexer};
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
    let results = search.search_casts("persistent", 10).unwrap();
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
