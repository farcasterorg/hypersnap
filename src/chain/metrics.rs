//! Statsd gauges of the committed Hypersnap blocks (plan WS14), with the
//! shard as a tag: the certified height, the delay from the block timestamp
//! to the commit (the time to a certificate, in seconds), the certificate
//! signers, and on shard 0 the epoch and the set size, on shards 1 and 2 the
//! outbox lag (the shard-0 tip minus `epoch_ref_height`).

use crate::proto::HypersnapBlock;
use crate::utils::statsd_wrapper::StatsdClientWrapper;

fn signers(block: &HypersnapBlock) -> u64 {
    block.certificate.as_ref().map_or(0, |c| {
        c.signer_bitmap.iter().map(|b| b.count_ones() as u64).sum()
    })
}

fn common(statsd: &StatsdClientWrapper, block: &HypersnapBlock) -> Option<u32> {
    let header = block.header.as_ref()?;
    let shard = header.shard_id;
    let now = crate::core::util::get_farcaster_time().unwrap_or(0);
    statsd.gauge_with_shard(shard, "hypersnap.block_height", header.height);
    statsd.gauge_with_shard(
        shard,
        "hypersnap.block_delay_seconds",
        now.saturating_sub(header.timestamp),
    );
    statsd.gauge_with_shard(shard, "hypersnap.certificate_signers", signers(block));
    Some(shard)
}

/// A committed shard-0 block of an epoch whose set has `set_size` members.
pub fn shard0_commit(statsd: &StatsdClientWrapper, block: &HypersnapBlock, set_size: usize) {
    if common(statsd, block).is_some() {
        let epoch = block.header.as_ref().map_or(0, |h| h.epoch);
        statsd.gauge_with_shard(0, "hypersnap.epoch", epoch);
        statsd.gauge_with_shard(0, "hypersnap.set_size", set_size as u64);
    }
}

/// A committed block of shard 1 or 2, with the local shard-0 tip.
pub fn shard_commit(statsd: &StatsdClientWrapper, block: &HypersnapBlock, shard0_tip: u64) {
    if let Some(shard) = common(statsd, block) {
        let reference = block.header.as_ref().map_or(0, |h| h.epoch_ref_height);
        statsd.gauge_with_shard(
            shard,
            "hypersnap.outbox_lag",
            shard0_tip.saturating_sub(reference),
        );
    }
}
