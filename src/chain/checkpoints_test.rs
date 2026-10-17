//! DA answers from the boundary checkpoints (FIP §5.1, §5.2).

use crate::chain::checkpoints::Checkpoints;
use crate::chain::shard0::keys::is_shard0_consensus_prefix;
use crate::node::content_replay::{replay_db_path, ContentReplay};
use crate::node::pivot_boot::open;
use crate::proto::{FarcasterNetwork, MessageType};
use crate::storage::constants::RootPrefix;
use crate::storage::store::shard::ShardStore;
use crate::storage::store::test_helper;
use crate::storage::trie::merkle_trie::TrieKey;
use crate::storage::trie::shadow_entries::is_gasless_state_key;
use crate::storage::trie::shadow_trie::RocksNodeStore;
use crate::storage::trie::state_walk_test::shard_with_content;
use hypersnap_ktrie::KTrie;

/// The path after `p`, or `None` after the last one.
fn next(mut p: [u8; 32]) -> Option<[u8; 32]> {
    for b in p.iter_mut().rev() {
        if *b == u8::MAX {
            *b = 0;
        } else {
            *b += 1;
            return Some(p);
        }
    }
    None
}

#[tokio::test]
async fn each_leaf_of_a_shard_state_has_a_da_answer() {
    let dir = tempfile::TempDir::new().unwrap();
    // An FID whose virtual shard (the first byte of its trie keys) is a
    // storage prefix of shard-0 records.
    let fid = (1..)
        .find(|f| TrieKey::fid_shard(*f) == RootPrefix::User as u8)
        .unwrap();
    let (source, height, _) = shard_with_content(&dir.path().join("shard"), fid).await;
    let mut replay = ContentReplay::open(
        dir.path(),
        1,
        FarcasterNetwork::Devnet,
        test_helper::statsd_client(),
    )
    .await
    .unwrap();
    replay
        .replay_to(&ShardStore::new(source.clone(), 1), height)
        .await
        .unwrap();
    replay.close();
    source.close();
    let db = open(&replay_db_path(dir.path(), 1)).unwrap();
    let checkpoints = Checkpoints::new(dir.path().join("checkpoints"), FarcasterNetwork::Devnet);
    checkpoints.take(&db, 1, 3).unwrap();

    let trie = KTrie::open(RocksNodeStore::new(db.clone())).unwrap();
    let (mut leaves, mut gasless_state, mut key_removes) = (0, 0, 0);
    let mut path = Some([0u8; 32]);
    while let Some(target) = path {
        let Some(leaf) = trie.first_at_or_after(&target).unwrap() else {
            break;
        };
        let answer = checkpoints
            .challenged_leaf(3, 1, &leaf.path)
            .unwrap_or_else(|| panic!("no answer for leaf {}", hex::encode(&leaf.key)));
        assert_eq!(answer.key, leaf.key);
        assert_eq!(hypersnap_ktrie::value_hash(&answer.value), leaf.value_hash);
        assert!(hypersnap_ktrie::proof::verify_proof_bytes(
            &answer.root,
            &answer.key,
            Some(&answer.value),
            &answer.proof
        ));
        leaves += 1;
        if is_gasless_state_key(&leaf.key) {
            gasless_state += 1;
        } else if TrieKey::decode(&leaf.key)
            .is_ok_and(|k| k.message_type == Some(MessageType::KeyRemove as u8))
        {
            key_removes += 1;
        }
        path = next(leaf.path);
    }
    // One nonce of each stream and the last-use time of the key that stays.
    assert_eq!(gasless_state, 3);
    assert_eq!(key_removes, 2);
    assert!(leaves > 20, "{} leaves", leaves);
    assert!(is_shard0_consensus_prefix(RootPrefix::User as u8));
}
