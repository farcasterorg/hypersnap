//! The store walk of a genesis state snapshot (FIP §17.5).

use crate::node::content_replay::{replay_db_path, ContentReplay};
use crate::node::genesis_snapshot::walk_stores;
use crate::node::pivot_boot::{offline_stores, open, rebuild_shard_root};
use crate::proto::{
    self, reaction_body::Target, FarcasterNetwork, MessageType, ReactionType, UserDataType,
};
use crate::storage::constants::{OnChainEventPostfix, RootPrefix, UserPostfix};
use crate::storage::db::{PageOptions, RocksDB, RocksDbTransactionBatch};
use crate::storage::store::account::{
    get_app_nonce, get_gasless_key_count, get_user_nonce, UserDataStore, FID_BYTES,
};
use crate::storage::store::shard::ShardStore;
use crate::storage::store::test_helper::{self, EngineOptions, FID_FOR_TEST};
use crate::storage::trie::shadow_trie;
use crate::utils::factory::events_factory::{self, create_merge_message_event};
use crate::utils::factory::{messages_factory, signers::generate_signer, time};
use alloy_signer_local::PrivateKeySigner;
use prost::Message as _;
use std::path::Path;
use std::sync::Arc;

const NET: FarcasterNetwork = FarcasterNetwork::Devnet;

/// The snapchain DB of shard 1 with the kinds of objects that the walk
/// derives: casts (a reply, a removed cast), a link, a reaction, user data,
/// an fname proof, signer events (one signer added and removed), and
/// gasless keys (one removed by custody, one revoked by itself), for `fid`
/// and its app `fid + 100`. Returns the DB, its height, and a cast that is
/// in it.
pub(crate) async fn shard_with_content(
    path: &Path,
    fid: u64,
) -> (Arc<RocksDB>, u64, proto::Message) {
    let db = open(path).unwrap();
    let fname_signer = PrivateKeySigner::random();
    let (mut engine, _tmp) = test_helper::new_engine_with_options(EngineOptions {
        db: Some(db.clone()),
        shard_id: 1,
        fname_signer_address: Some(fname_signer.address()),
        ..Default::default()
    })
    .await;
    let app = fid + 100;
    let custody = PrivateKeySigner::random();
    let app_custody = PrivateKeySigner::random();
    let signer = test_helper::default_signer();
    test_helper::register_user(fid, signer.clone(), custody.address().to_vec(), &mut engine).await;
    test_helper::register_user(
        app,
        generate_signer(),
        app_custody.address().to_vec(),
        &mut engine,
    )
    .await;
    let second = generate_signer();
    for event_type in [proto::SignerEventType::Add, proto::SignerEventType::Remove] {
        let event =
            events_factory::create_signer_event(fid, second.clone(), event_type, None, None);
        test_helper::commit_event(&mut engine, &event).await;
    }
    test_helper::register_fname(
        fid,
        &"walker".to_string(),
        None,
        Some(custody.address().to_vec()),
        &mut engine,
        FarcasterNetwork::Mainnet,
        fname_signer,
    )
    .await;

    let now = time::farcaster_time();
    let cast = messages_factory::casts::create_cast_add(fid, "walk", Some(now), Some(&signer));
    let reply = messages_factory::casts::create_cast_with_parent(
        fid,
        "reply",
        fid,
        &cast.hash,
        Some(now + 1),
        Some(&signer),
    );
    let gone = messages_factory::casts::create_cast_add(fid, "gone", Some(now + 2), Some(&signer));
    let remove =
        messages_factory::casts::create_cast_remove(fid, &gone.hash, Some(now + 3), Some(&signer));
    let link =
        messages_factory::links::create_link_add(fid, "follow", app, Some(now + 4), Some(&signer));
    let reaction = messages_factory::reactions::create_reaction_add(
        fid,
        ReactionType::Like,
        Target::TargetCastId(proto::CastId {
            fid,
            hash: cast.hash.clone(),
        }),
        Some(now + 5),
        Some(&signer),
    );
    let bio = messages_factory::user_data::create_user_data_add(
        fid,
        UserDataType::Bio,
        &"walking".to_string(),
        Some(now + 6),
        Some(&signer),
    );
    for m in [&cast, &reply, &gone, &remove, &link, &reaction, &bio] {
        test_helper::commit_message(&mut engine, m).await;
    }
    // Three gasless keys: one stays, custody removes one (the user nonce),
    // and one revokes itself (the app nonce). The KEY_REMOVE messages are in
    // the trie, and only the block events keep them.
    let deadline = now + 1_000_000;
    let keys = [generate_signer(), generate_signer(), generate_signer()];
    let mut events = vec![];
    for (i, key) in keys.iter().enumerate() {
        let add = messages_factory::keys::create_key_add(
            fid,
            &custody,
            app,
            &app_custody,
            key,
            vec![MessageType::CastAdd],
            3_600,
            i as u32 + 1,
            deadline,
            Some(now + i as u32),
        );
        events.push(add);
    }
    events.push(messages_factory::keys::create_key_remove_custody(
        fid,
        &custody,
        &keys[1],
        &keys[1].verifying_key().to_bytes(),
        4,
        deadline,
        Some(now + 10),
    ));
    events.push(messages_factory::keys::create_key_remove_self_revoke(
        fid,
        &keys[2],
        1,
        deadline,
        Some(now + 11),
    ));
    let events: Vec<_> = events
        .into_iter()
        .enumerate()
        .map(|(i, m)| create_merge_message_event(m, i as u64 + 1))
        .collect();
    test_helper::commit_block_events(&mut engine, events.iter().collect()).await;
    let height = engine.get_confirmed_height().block_number;
    drop(engine);
    (db, height, cast)
}

fn first_key(db: &RocksDB, start: &[u8], stop: &[u8], pick: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    let mut found = None;
    db.for_each_iterator_by_prefix_paged(
        Some(start.to_vec()),
        Some(stop.to_vec()),
        &PageOptions::default(),
        |k, _| {
            if pick(k) {
                found = Some(k.to_vec());
                return Ok(true);
            }
            Ok(false)
        },
    )
    .unwrap();
    found.expect("no such record")
}

fn read_keys(db: &RocksDB, start: &[u8], stop: &[u8]) -> Vec<Vec<u8>> {
    let mut keys = vec![];
    db.for_each_iterator_by_prefix_paged(
        Some(start.to_vec()),
        Some(stop.to_vec()),
        &PageOptions::default(),
        |k, _| {
            keys.push(k.to_vec());
            Ok(false)
        },
    )
    .unwrap();
    keys
}

fn put(db: &RocksDB, key: Vec<u8>, value: Vec<u8>) {
    let mut txn = RocksDbTransactionBatch::new();
    txn.put(key, value);
    db.commit(txn).unwrap();
}

#[tokio::test]
async fn the_store_walk_accepts_the_state_and_rejects_records_that_no_object_derives() {
    let dir = tempfile::TempDir::new().unwrap();
    let (source, height, cast) = shard_with_content(&dir.path().join("shard"), FID_FOR_TEST).await;
    // The content replay of the shard, as a bootstrap validator exports it.
    let mut replay = ContentReplay::open(dir.path(), 1, NET, test_helper::statsd_client())
        .await
        .unwrap();
    replay
        .replay_to(&ShardStore::new(source.clone(), 1), height)
        .await
        .unwrap();
    replay.close();
    source.close();
    let db = open(&replay_db_path(dir.path(), 1)).unwrap();
    assert!(
        UserDataStore::get_username_proof(
            &offline_stores(&db, 1, NET).unwrap().user_data_store,
            &RocksDbTransactionBatch::new(),
            b"walker",
        )
        .unwrap()
        .is_some(),
        "the replay has the fname proof"
    );
    let none = RocksDbTransactionBatch::new();
    assert_eq!(get_user_nonce(&db, &none, FID_FOR_TEST).unwrap(), Some(4));
    assert_eq!(
        get_app_nonce(&db, &none, FID_FOR_TEST + 100).unwrap(),
        Some(1)
    );
    assert_eq!(get_gasless_key_count(&db, &none, FID_FOR_TEST).unwrap(), 1);
    let removes = RootPrefix::HyperKeyRemoveMessage as u8;
    assert_eq!(
        read_keys(&db, &[removes], &[removes + 1]).len(),
        2,
        "the replay keeps the KEY_REMOVE messages"
    );
    // As the import does: build the Keccak trie from the state, then walk.
    // The build gives the root of the replay's live trie, with the gasless
    // nonces and last-use times.
    let live = shadow_trie::report_from_db(db.clone()).unwrap().root;
    assert_eq!(rebuild_shard_root(&db, 1, height, NET).unwrap(), live);
    let walk = |db: &Arc<RocksDB>| walk_stores(db, &dir.path().join("walk"), 1, NET);
    walk(&db).unwrap();
    assert!(
        !dir.path().join("walk").exists(),
        "the scratch DB is removed"
    );

    let mut n = 0;
    let mut copy = |db: &Arc<RocksDB>| -> Arc<RocksDB> {
        n += 1;
        let path = dir.path().join(format!("copy-{}", n));
        db.create_checkpoint(path.to_str().unwrap()).unwrap();
        open(&path).unwrap()
    };
    let user = RootPrefix::User as u8;
    let fails = |db: &Arc<RocksDB>, expected: &str| {
        let err = walk(db).unwrap_err();
        assert!(err.contains(expected), "{}", err);
    };

    // A cast in the store only (not in the sync trie or the Keccak trie).
    let forged = copy(&db);
    let extra = messages_factory::casts::create_cast_add(
        FID_FOR_TEST,
        "forged",
        Some(time::farcaster_time() + 20),
        Some(&test_helper::default_signer()),
    );
    let mut txn = RocksDbTransactionBatch::new();
    offline_stores(&forged, 1, NET)
        .unwrap()
        .cast_store
        .put_message_records(&mut txn, &extra)
        .unwrap();
    forged.commit(txn).unwrap();
    fails(&forged, "is not in the Keccak trie");

    // An index entry that no cast makes: the cast under a parent that it
    // does not have.
    let forged = copy(&db);
    let parent = RootPrefix::CastsByParent as u8;
    let mut key = first_key(&forged, &[parent], &[parent + 1], |_| true);
    *key.last_mut().unwrap() ^= 1;
    put(&forged, key, vec![]);
    fails(&forged, "which no object derives");

    // An add-set entry that is missing: the cast is in the store, but a
    // merge would not find it.
    let forged = copy(&db);
    let key = first_key(&forged, &[user], &[user + 1], |k| {
        k.get(1 + FID_BYTES) == Some(&(UserPostfix::CastAdds as u8)) && k.ends_with(&cast.hash)
    });
    let mut txn = RocksDbTransactionBatch::new();
    txn.delete(key);
    forged.commit(txn).unwrap();
    fails(&forged, "does not have the derived record");

    // A signer index that names another event.
    let forged = copy(&db);
    let onchain = RootPrefix::OnChainEvent as u8;
    let signer_index = OnChainEventPostfix::SignerByFid as u8;
    let key = first_key(
        &forged,
        &[onchain, signer_index],
        &[onchain, signer_index + 1],
        |_| true,
    );
    put(&forged, key, vec![onchain, 1, 0]);
    fails(&forged, "is not the derived record");

    // A KEY_REMOVE record with another message.
    let forged = copy(&db);
    let key = first_key(&forged, &[removes], &[removes + 1], |_| true);
    let mut message =
        proto::Message::decode(forged.get(&key).unwrap().unwrap().as_slice()).unwrap();
    message.signature = vec![0u8; 64];
    put(&forged, key, message.encode_to_vec());
    fails(&forged, "is not the one in the Keccak trie");

    // A record under a prefix that the walk does not know.
    let forged = copy(&db);
    put(&forged, vec![RootPrefix::HyperFeeBalance as u8, 1], vec![1]);
    fails(&forged, "records under prefix");

    // A changed gasless nonce or last-use time: they are in the trie.
    let gasless = RootPrefix::GaslessKey as u8;
    for postfix in [
        UserPostfix::GaslessKeyUserNonce as u8,
        UserPostfix::GaslessKeyLastUsedAt as u8,
    ] {
        let forged = copy(&db);
        let key = first_key(
            &forged,
            &[gasless, postfix],
            &[gasless, postfix + 1],
            |_| true,
        );
        put(&forged, key, 9u32.to_be_bytes().to_vec());
        fails(&forged, "is not the one in the Keccak trie");
    }
}
