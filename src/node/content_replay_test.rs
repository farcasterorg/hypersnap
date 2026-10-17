//! The content replay (FIP §17.4) over a snapchain shard that pruned
//! messages.

use crate::node::content_replay::ContentReplay;
use crate::node::pivot_boot::snapchain_db_path;
use crate::proto::{self, FarcasterNetwork, IdRegisterEventType};
use crate::storage::db::RocksDB;
use crate::storage::store::account::CastStore;
use crate::storage::store::engine::ShardEngine;
use crate::storage::store::shard::ShardStore;
use crate::storage::store::test_helper::{self, EngineOptions, FID_FOR_TEST};
use crate::storage::trie::shadow_trie::{self, ShadowStatus};
use crate::utils::factory::{events_factory, messages_factory, signers, time};
use std::path::Path;
use std::sync::Arc;

fn casts_of(engine: &ShardEngine) -> Vec<Vec<u8>> {
    engine
        .get_casts_by_fid(FID_FOR_TEST)
        .unwrap()
        .messages
        .into_iter()
        .map(|m| m.hash)
        .collect()
}

async fn replay(rocks: &Path, source: &Arc<RocksDB>, to: u64) -> ContentReplay {
    let mut replay = ContentReplay::open(
        rocks,
        1,
        FarcasterNetwork::Devnet,
        test_helper::statsd_client(),
    )
    .await
    .unwrap();
    replay
        .replay_to(&ShardStore::new(source.clone(), 1), to)
        .await
        .unwrap();
    replay
}

#[tokio::test]
async fn the_replay_keeps_pruned_messages_under_the_snapchain_rules() {
    let dir = tempfile::TempDir::new().unwrap();
    let rocks = dir.path().join("rocks");
    std::fs::create_dir_all(&rocks).unwrap();
    let db = Arc::new(RocksDB::new(snapchain_db_path(&rocks, 1).to_str().unwrap()));
    db.open().unwrap();
    // The test limit is 4 casts.
    let (mut engine, _tmp) = test_helper::new_engine_with_options(EngineOptions {
        db: Some(db.clone()),
        shard_id: 1,
        ..Default::default()
    })
    .await;
    let signer = test_helper::default_signer();
    let second = signers::generate_signer();
    for event in [
        test_helper::default_storage_event(FID_FOR_TEST),
        events_factory::create_id_register_event(
            FID_FOR_TEST,
            IdRegisterEventType::Register,
            test_helper::default_custody_address(),
            None,
        ),
        events_factory::create_signer_event(
            FID_FOR_TEST,
            signer.clone(),
            proto::SignerEventType::Add,
            None,
            None,
        ),
        events_factory::create_signer_event(
            FID_FOR_TEST,
            second.clone(),
            proto::SignerEventType::Add,
            None,
            None,
        ),
    ] {
        test_helper::commit_event(&mut engine, &event).await;
    }
    let now = time::farcaster_time();
    let kept: Vec<_> = (0..6)
        .map(|i| {
            messages_factory::casts::create_cast_add(
                FID_FOR_TEST,
                &format!("cast {}", i),
                Some(now + i),
                Some(&signer),
            )
        })
        .collect();
    for cast in &kept {
        test_helper::commit_message(&mut engine, cast).await;
    }
    // A remove of a cast that snapchain pruned: the type rules apply.
    let remove = messages_factory::casts::create_cast_remove(
        FID_FOR_TEST,
        &kept[1].hash,
        Some(now + 9),
        Some(&signer),
    );
    test_helper::commit_message(&mut engine, &remove).await;
    // A cast of a signer that is removed later. The replay applies the
    // revocation rule of the chunk's version, as snapchain does.
    let of_removed_signer = messages_factory::casts::create_cast_add(
        FID_FOR_TEST,
        "removed signer",
        Some(now + 10),
        Some(&second),
    );
    test_helper::commit_message(&mut engine, &of_removed_signer).await;
    test_helper::commit_event(
        &mut engine,
        &events_factory::create_signer_event(
            FID_FOR_TEST,
            second.clone(),
            proto::SignerEventType::Remove,
            None,
            None,
        ),
    )
    .await;
    // A cast of a key that is not a signer: in the chunk, not valid.
    let invalid = messages_factory::casts::create_cast_add(
        FID_FOR_TEST,
        "invalid",
        Some(now + 11),
        Some(&signers::generate_signer()),
    );
    let change = engine.propose_state_change(
        1,
        vec![crate::storage::store::mempool_poller::MempoolMessage::UserMessage(invalid.clone())],
        None,
    );
    let chunk = test_helper::validate_and_commit_state_change(&mut engine, &change).await;
    assert!(chunk.transactions[0]
        .user_messages
        .iter()
        .any(|m| m.hash == invalid.hash));
    // Snapchain pruned the oldest casts.
    let snapchain = casts_of(&engine);
    assert!(snapchain.len() <= 4);
    assert!(!snapchain.contains(&kept[0].hash));
    let tip = engine.get_confirmed_height().block_number;
    drop(engine);

    let first = replay(&rocks, &db, tip).await;
    assert_eq!(first.height(), tip);
    let stores = first.stores();
    let has = |m: &proto::Message| {
        CastStore::get_cast_add(&stores.cast_store, FID_FOR_TEST, m.hash.clone())
            .unwrap()
            .is_some()
    };
    for (i, cast) in kept.iter().enumerate() {
        assert_eq!(has(cast), i != 1, "cast {}", i);
    }
    assert!(!has(&invalid));
    assert_eq!(
        has(&of_removed_signer),
        snapchain.contains(&of_removed_signer.hash)
    );
    let report = shadow_trie::report_from_db(first.db()).unwrap();
    assert_eq!(report.status, ShadowStatus::Live { height: tip });
    first.close();

    // Another node's replay of the same chunks has the same root; a replay
    // that resumes from its last chunk gives the same root too.
    let other = tempfile::TempDir::new().unwrap();
    let mut second_replay = replay(other.path(), &db, tip - 3).await;
    second_replay
        .replay_to(&ShardStore::new(db.clone(), 1), tip)
        .await
        .unwrap();
    let again = shadow_trie::report_from_db(second_replay.db()).unwrap();
    assert_eq!(again.root, report.root);
    second_replay.close();
    db.close();
}

#[tokio::test]
async fn the_replay_needs_the_chunks_from_the_first_one() {
    let dir = tempfile::TempDir::new().unwrap();
    let rocks = dir.path().join("rocks");
    std::fs::create_dir_all(&rocks).unwrap();
    let db = Arc::new(RocksDB::new(snapchain_db_path(&rocks, 1).to_str().unwrap()));
    db.open().unwrap();
    let (mut engine, _tmp) = test_helper::new_engine_with_options(EngineOptions {
        db: Some(db.clone()),
        shard_id: 1,
        ..Default::default()
    })
    .await;
    for fid in 1..=3 {
        test_helper::commit_event(&mut engine, &test_helper::default_storage_event(fid)).await;
    }
    let tip = engine.get_confirmed_height().block_number;
    drop(engine);
    let page = crate::storage::db::PageOptions::default();
    ShardStore::new(db.clone(), 1)
        .prune_until(2, &page, std::time::Duration::ZERO)
        .await
        .unwrap();

    let mut replay = ContentReplay::open(
        &rocks,
        1,
        FarcasterNetwork::Devnet,
        test_helper::statsd_client(),
    )
    .await
    .unwrap();
    let err = replay
        .replay_to(&ShardStore::new(db.clone(), 1), tip)
        .await
        .unwrap_err();
    assert!(err.contains("starts at chunk 2"), "{}", err);
    replay.close();
    db.close();
}
