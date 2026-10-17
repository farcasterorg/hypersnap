//! `EXEMPT_RECOVERIES` (FIP §2): the recovery transfers before
//! `RECOVERY_EXEMPTION_CUTOFF`, as a list in the release. All nodes build the
//! same genesis from it, also a node whose recovery watcher missed a
//! `Recover` log. The watcher only checks the list.

use crate::chain::pivot::RECOVERY_EXEMPTION_CUTOFF;
use crate::proto::{FarcasterNetwork, HyperRecoveryEvent};
use alloy_primitives::keccak256;
use std::collections::BTreeSet;

/// (fid, transaction hash) of an exempt recovery transfer.
pub type ExemptRecovery = (u64, [u8; 32]);

const MAINNET: &str = include_str!("data/exempt_recoveries_mainnet.txt");

/// Parse a list: one `<fid> <transaction hash>` per line; `#` starts a
/// comment.
pub fn parse(text: &str) -> Result<Vec<ExemptRecovery>, String> {
    let mut out = BTreeSet::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let bad = |what: &str| format!("line {}: {}", n + 1, what);
        let mut parts = line.split_whitespace();
        let fid = parts
            .next()
            .and_then(|f| f.parse::<u64>().ok())
            .ok_or_else(|| bad("no FID"))?;
        let hash: [u8; 32] = parts
            .next()
            .and_then(|h| hex::decode(h.trim_start_matches("0x")).ok())
            .and_then(|h| h.try_into().ok())
            .ok_or_else(|| bad("no 32-byte transaction hash"))?;
        if parts.next().is_some() {
            return Err(bad("more than two fields"));
        }
        if !out.insert((fid, hash)) {
            return Err(bad("a second copy of an entry"));
        }
    }
    Ok(out.into_iter().collect())
}

/// Write a list in the format of [`parse`].
pub fn format(list: &[ExemptRecovery]) -> String {
    list.iter()
        .map(|(fid, hash)| format!("{} 0x{}\n", fid, hex::encode(hash)))
        .collect()
}

/// The list of the release for `network`. Devnets and testnets have none.
pub fn release_list(network: FarcasterNetwork) -> Vec<ExemptRecovery> {
    match network {
        FarcasterNetwork::Mainnet => parse(MAINNET).expect("the mainnet EXEMPT_RECOVERIES"),
        _ => vec![],
    }
}

/// The part of `params_hash` for the list (FIP §17.4).
pub fn list_hash(list: &[ExemptRecovery]) -> [u8; 32] {
    let mut pre = b"hypersnap-exempt-recoveries-v1".to_vec();
    for (fid, hash) in list {
        pre.extend_from_slice(&fid.to_be_bytes());
        pre.extend_from_slice(hash);
    }
    keccak256(&pre).0
}

/// The list that the `Recover` logs of a recovery watcher give.
pub fn from_watcher(events: &[HyperRecoveryEvent]) -> Vec<ExemptRecovery> {
    events
        .iter()
        .filter(|r| r.block_timestamp < RECOVERY_EXEMPTION_CUTOFF)
        .filter_map(|r| Some((r.fid, r.transaction_hash.as_slice().try_into().ok()?)))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The entries of the release list that the watcher does not have, and the
/// entries of the watcher that the release list does not have.
pub fn differences(
    release: &[ExemptRecovery],
    watcher: &[ExemptRecovery],
) -> (Vec<ExemptRecovery>, Vec<ExemptRecovery>) {
    let r: BTreeSet<_> = release.iter().collect();
    let w: BTreeSet<_> = watcher.iter().collect();
    (
        r.difference(&w).map(|e| **e).collect(),
        w.difference(&r).map(|e| **e).collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_parses_and_formats() {
        let text = "# comment\n7 0x".to_string() + &"ab".repeat(32) + "\n\n3 " + &"01".repeat(32);
        let list = parse(&text).unwrap();
        assert_eq!(list, vec![(3, [1u8; 32]), (7, [0xab; 32])]);
        assert_eq!(parse(&format(&list)).unwrap(), list);
        assert!(parse("3 0x12").is_err());
        assert!(parse(&format!("3 {0}\n3 {0}", "01".repeat(32))).is_err());
    }

    #[test]
    fn the_mainnet_list_parses() {
        let _ = release_list(FarcasterNetwork::Mainnet);
    }

    #[test]
    fn the_watcher_list_stops_at_the_cutoff() {
        let event = |fid, ts, h: u8| HyperRecoveryEvent {
            fid,
            block_timestamp: ts,
            transaction_hash: vec![h; 32],
            ..Default::default()
        };
        let watcher = from_watcher(&[
            event(5, RECOVERY_EXEMPTION_CUTOFF - 1, 1),
            event(6, RECOVERY_EXEMPTION_CUTOFF, 2),
            event(5, RECOVERY_EXEMPTION_CUTOFF - 1, 1),
        ]);
        assert_eq!(watcher, vec![(5, [1u8; 32])]);
        let (missing, extra) = differences(&[(4, [9u8; 32])], &watcher);
        assert_eq!(missing, vec![(4, [9u8; 32])]);
        assert_eq!(extra, watcher);
    }
}
