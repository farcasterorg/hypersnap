//! Bounded address discovery. Addresses are hints; the transport authenticates PeerId.
use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const MAX_PEERS: usize = 512;
const MAX_ADDRS: usize = 4;
const TTL: u64 = 24 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub enabled: bool,
    pub bootstrap_peers: Vec<String>,
    pub target_peers: usize,
    /// Empty means memory only. Main supplies a path under rocksdb_dir.
    pub cache_path: PathBuf,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            bootstrap_peers: Vec::new(),
            target_peers: 12,
            cache_path: PathBuf::new(),
        }
    }
}

pub fn protocol(network: i32) -> String {
    format!("/hypersnap/{network}/kad/1.0.0")
}
pub fn identify_protocol(network: i32) -> String {
    format!("/hypersnap/{network}/identify/1.0.0")
}
pub fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Strip a matching /p2p suffix. Never accept an address naming another identity.
/// Loopback/private addresses are permitted only on devnet.
pub fn address(peer: PeerId, mut addr: Multiaddr, local: bool) -> Option<Multiaddr> {
    if let Some(Protocol::P2p(id)) = addr.iter().last() {
        if id != peer {
            return None;
        }
        addr.pop();
    }
    if addr.to_string().len() > 256 {
        return None;
    }
    let mut host = false;
    let mut port = false;
    for part in addr.iter() {
        match part {
            Protocol::Ip4(ip) => {
                if ip.is_unspecified()
                    || ip.is_multicast()
                    || (!local
                        && (ip.is_loopback()
                            || ip.is_private()
                            || ip.is_link_local()
                            || ip.is_broadcast()))
                {
                    return None;
                }
                host = true;
            }
            Protocol::Ip6(ip) => {
                if ip.is_unspecified()
                    || ip.is_multicast()
                    || (!local
                        && (ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()))
                {
                    return None;
                }
                host = true;
            }
            Protocol::Dns(name) | Protocol::Dns4(name) | Protocol::Dns6(name) => {
                if name.is_empty()
                    || (!local && (name == "localhost" || name.ends_with(".localhost")))
                {
                    return None;
                }
                host = true;
            }
            Protocol::Udp(p) | Protocol::Tcp(p) if p > 0 => port = true,
            Protocol::QuicV1 => {}
            _ => return None,
        }
    }
    (host && port).then_some(addr)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SavedPeer {
    peer: String,
    addresses: Vec<String>,
    seen: u64,
}
struct Entry {
    addresses: Vec<Multiaddr>,
    seen: u64,
    verified: bool,
    seed: bool,
    seed_addresses: Vec<Multiaddr>,
    failures: u32,
    retry_at: Instant,
    priority: bool,
}
pub struct Book {
    peers: HashMap<PeerId, Entry>,
    pending: HashMap<PeerId, Instant>,
    lookups: HashMap<PeerId, Instant>,
    local_peer: PeerId,
    allow_local: bool,
}
impl Book {
    pub fn new(local_peer: PeerId, allow_local: bool) -> Self {
        Self {
            peers: HashMap::new(),
            pending: HashMap::new(),
            lookups: HashMap::new(),
            local_peer,
            allow_local,
        }
    }
    pub fn learn(
        &mut self,
        peer: PeerId,
        addr: Multiaddr,
        verified: bool,
        seed: bool,
        now: Instant,
    ) -> Option<Multiaddr> {
        if peer == self.local_peer {
            return None;
        }
        let addr = address(peer, addr, self.allow_local)?;
        if !self.peers.contains_key(&peer) && self.peers.len() >= MAX_PEERS {
            // Unverified advertisements cannot evict authenticated addresses or seeds.
            let victim = self
                .peers
                .iter()
                .filter(|(_, e)| !e.seed && (!e.verified || verified))
                .min_by_key(|(_, e)| e.seen)
                .map(|(p, _)| *p)?;
            self.peers.remove(&victim);
        }
        let priority = self.lookups.contains_key(&peer);
        let e = self.peers.entry(peer).or_insert_with(|| Entry {
            addresses: Vec::new(),
            seen: unix_seconds(),
            verified: false,
            seed: false,
            seed_addresses: Vec::new(),
            failures: 0,
            retry_at: now,
            priority: false,
        });
        if verified && !e.verified {
            e.addresses.clear();
        }
        if (!e.verified || verified)
            && !e.addresses.contains(&addr)
            && e.addresses.len() < MAX_ADDRS
        {
            e.addresses.push(addr.clone());
        }
        if verified {
            e.seen = unix_seconds();
            e.verified = true;
        }
        e.seed |= seed;
        if seed && !e.seed_addresses.contains(&addr) && e.seed_addresses.len() < MAX_ADDRS {
            e.seed_addresses.push(addr.clone());
        }
        e.priority |= priority;
        e.addresses.contains(&addr).then_some(addr)
    }
    /// An authenticated owner supplies a new address set. Remove stale hints
    /// before publishing the replacement into Kademlia, keeping both books bounded.
    pub fn verified_addresses(
        &mut self,
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        now: Instant,
    ) -> (Vec<Multiaddr>, Vec<Multiaddr>) {
        // Preserve configured seed hostnames across Identify updates so DNS
        // changes can still recover a seed after its advertised IP changes.
        let mut valid = self
            .peers
            .get(&peer)
            .map(|e| e.seed_addresses.clone())
            .unwrap_or_default();
        for addr in addresses
            .into_iter()
            .take(8)
            .filter_map(|a| address(peer, a, self.allow_local))
        {
            if !valid.contains(&addr) && valid.len() < MAX_ADDRS {
                valid.push(addr);
            }
        }
        if valid.is_empty() {
            return (vec![], vec![]);
        }
        let old = if let Some(e) = self.peers.get_mut(&peer) {
            e.verified = false;
            std::mem::take(&mut e.addresses)
        } else {
            vec![]
        };
        for addr in &valid {
            self.learn(peer, addr.clone(), true, false, now);
        }
        if !self.peers.contains_key(&peer) {
            return (vec![], vec![]);
        }
        let removed = old.into_iter().filter(|a| !valid.contains(a)).collect();
        (valid, removed)
    }
    pub fn load(&mut self, path: &std::path::Path, now: Instant) {
        if path.as_os_str().is_empty() {
            return;
        }
        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            let file = std::fs::File::open(path)?;
            if file.metadata()?.len() > 1024 * 1024 {
                return Err("peer cache too large".into());
            }
            let saved: Vec<SavedPeer> = serde_json::from_reader(file)?;
            for record in saved.into_iter().take(MAX_PEERS) {
                if record.seen > unix_seconds() || unix_seconds().saturating_sub(record.seen) > TTL
                {
                    continue;
                }
                let Ok(peer) = record.peer.parse() else {
                    continue;
                };
                for addr in record
                    .addresses
                    .into_iter()
                    .take(MAX_ADDRS)
                    .filter_map(|a| a.parse().ok())
                {
                    self.learn(peer, addr, false, false, now);
                }
                // Cached identities must re-authenticate, but preserve their original age.
                if let Some(e) = self.peers.get_mut(&peer) {
                    e.seen = record.seen;
                }
            }
            Ok(())
        })();
        if let Err(e) = result {
            if path.exists() {
                tracing::warn!(error=%e, "Ignoring invalid discovery cache");
            }
        }
    }
    pub fn snapshot(&self) -> Vec<SavedPeer> {
        self.peers
            .iter()
            .filter(|(_, e)| e.verified && unix_seconds().saturating_sub(e.seen) <= TTL)
            .map(|(p, e)| SavedPeer {
                peer: p.to_string(),
                addresses: e.addresses.iter().map(ToString::to_string).collect(),
                seen: e.seen,
            })
            .collect()
    }
    pub fn contains(&self, peer: &PeerId) -> bool {
        self.peers.contains_key(peer)
    }
    pub fn peer_ids(&self) -> impl Iterator<Item = &PeerId> {
        self.peers.keys()
    }
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
    pub fn connected(&mut self, peer: PeerId) {
        self.pending.remove(&peer);
        if let Some(e) = self.peers.get_mut(&peer) {
            e.failures = 0;
            e.priority = false;
        }
    }
    pub fn failed(&mut self, peer: PeerId, now: Instant) {
        self.pending.remove(&peer);
        if let Some(e) = self.peers.get_mut(&peer) {
            e.failures = (e.failures + 1).min(8);
            e.retry_at = now
                + Duration::from_secs((2u64.pow(e.failures)).min(300))
                + Duration::from_millis(rand::random::<u64>() % 500);
        }
    }
    pub fn request(&mut self, peer: PeerId, now: Instant) -> bool {
        if let Some(e) = self.peers.get_mut(&peer) {
            e.priority = true;
        }
        self.lookups
            .retain(|_, t| now.duration_since(*t) < Duration::from_secs(30));
        if peer == self.local_peer || self.lookups.contains_key(&peer) || self.lookups.len() >= 4 {
            return false;
        }
        self.lookups.insert(peer, now);
        true
    }
    pub fn candidates(
        &mut self,
        connected: &HashSet<PeerId>,
        target: usize,
        now: Instant,
    ) -> Vec<(PeerId, Vec<Multiaddr>)> {
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, t)| now.duration_since(**t) > Duration::from_secs(15))
            .map(|(p, _)| *p)
            .collect();
        for p in expired {
            self.failed(p, now);
        }
        self.peers
            .retain(|_, e| e.seed || unix_seconds().saturating_sub(e.seen) <= TTL);
        let known_connected = connected
            .iter()
            .filter(|p| self.peers.contains_key(p))
            .count();
        let mut choices: Vec<_> = self
            .peers
            .iter()
            .filter(|(p, e)| {
                !connected.contains(p)
                    && !self.pending.contains_key(p)
                    && e.retry_at <= now
                    && (e.seed || e.priority || known_connected + self.pending.len() < target)
            })
            .map(|(p, e)| (*p, e.seed, e.priority, e.verified))
            .collect();
        use rand::seq::SliceRandom;
        choices.shuffle(&mut rand::thread_rng());
        choices.sort_by_key(|(_, seed, priority, verified)| (!priority, !seed, !verified));
        let budget = 4usize.saturating_sub(self.pending.len());
        let mut result = Vec::new();
        for (peer, seed, priority, _) in choices {
            if known_connected + self.pending.len() >= 32 {
                break;
            }
            if result.len() >= budget {
                break;
            }
            if !seed && !priority && known_connected + self.pending.len() >= target {
                continue;
            }
            self.pending.insert(peer, now);
            result.push((peer, self.peers[&peer].addresses.clone()));
        }
        result
    }
}

pub async fn save(path: PathBuf, peers: Vec<SavedPeer>) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        tokio::fs::create_dir_all(parent).await?;
    }
    let temp = path.with_extension("json.tmp");
    tokio::fs::write(&temp, serde_json::to_vec(&peers)?).await?;
    tokio::fs::rename(temp, path).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_bounds_backoff_and_identity() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let now = Instant::now();
        let a: Multiaddr = "/ip4/127.0.0.1/udp/1234/quic-v1".parse().unwrap();
        assert!(address(peer, a.clone(), false).is_none());
        assert!(address(peer, a.clone().with(Protocol::P2p(local)), true).is_none());
        let mut b = Book::new(local, true);
        for _ in 0..MAX_PEERS + 20 {
            b.learn(PeerId::random(), a.clone(), false, false, now);
        }
        assert_eq!(b.peers.len(), MAX_PEERS);
        b.learn(peer, a, true, true, now);
        let c = b.candidates(&HashSet::new(), 12, now);
        assert_eq!(c.len(), 4);
        assert!(c.iter().any(|(p, _)| *p == peer));
        b.failed(peer, now);
        assert!(!b
            .candidates(&HashSet::new(), 12, now)
            .iter()
            .any(|(p, _)| *p == peer));
        assert!(!b.snapshot().is_empty());
        assert!(b.request(peer, now));
        assert!(!b.request(peer, now));
        assert_ne!(protocol(1), protocol(2));
        assert!(!protocol(1).contains("snapchain"));
    }
    #[test]
    fn discovery_prioritizes_requested_validator_even_after_target_is_full() {
        let now = Instant::now();
        let mut b = Book::new(PeerId::random(), true);
        let addr: Multiaddr = "/ip4/127.0.0.1/udp/1234/quic-v1".parse().unwrap();
        let existing = PeerId::random();
        let requested = PeerId::random();
        b.learn(existing, addr.clone(), true, false, now);
        assert!(b.request(requested, now));
        b.learn(requested, addr, false, false, now);
        let connected = [existing].into();
        assert_eq!(b.candidates(&connected, 1, now)[0].0, requested);
        b.failed(requested, now);
        assert!(
            b.candidates(&connected, 1, now).is_empty(),
            "demand discovery must respect backoff"
        );
    }
    #[test]
    fn discovery_does_not_persist_unverified_addresses_and_expires_old_records() {
        let now = Instant::now();
        let peer = PeerId::random();
        let mut b = Book::new(PeerId::random(), true);
        let unverified: Multiaddr = "/ip4/127.0.0.1/udp/1234/quic-v1".parse().unwrap();
        let verified: Multiaddr = "/ip4/127.0.0.1/udp/1235/quic-v1".parse().unwrap();
        b.learn(peer, unverified.clone(), false, false, now);
        assert!(b.snapshot().is_empty());
        b.learn(peer, verified.clone(), true, false, now);
        b.learn(peer, unverified, false, false, now);
        assert_eq!(b.snapshot()[0].addresses, vec![verified.to_string()]);
        let replacement: Multiaddr = "/ip4/127.0.0.1/udp/1236/quic-v1".parse().unwrap();
        let (added, removed) = b.verified_addresses(peer, vec![replacement.clone()], now);
        assert_eq!(added, vec![replacement.clone()]);
        assert_eq!(removed, vec![verified]);
        assert_eq!(b.snapshot()[0].addresses, vec![replacement.to_string()]);
        b.peers.get_mut(&peer).unwrap().seen = unix_seconds() - TTL - 1;
        assert!(b.candidates(&HashSet::new(), 12, now).is_empty());
    }
    #[tokio::test]
    async fn discovery_cache_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let local = PeerId::random();
        let peer = PeerId::random();
        let now = Instant::now();
        let mut b = Book::new(local, true);
        b.learn(
            peer,
            "/ip4/127.0.0.1/udp/1234/quic-v1".parse().unwrap(),
            true,
            false,
            now,
        );
        save(path.clone(), b.snapshot()).await.unwrap();
        let mut restored = Book::new(local, true);
        restored.load(&path, now);
        assert_eq!(restored.candidates(&HashSet::new(), 1, now)[0].0, peer);
    }
}
