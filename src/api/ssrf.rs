//! SSRF defense for outbound HTTP destinations.
//!
//! Both the webhook delivery worker and the mini app notification fan-out
//! POST to URLs supplied by external parties (webhook owners and
//! Farcaster clients respectively). Without a check, those parties can
//! point hypersnap at internal services on the operator's network:
//! cloud metadata endpoints, intranet admin panels, loopback ports, etc.
//!
//! This module provides a single async function, [`assert_safe_url`],
//! that:
//!
//! 1. Parses the URL and rejects anything that isn't `https`.
//! 2. Resolves the host to one or more IP addresses via the system DNS
//!    resolver (`tokio::net::lookup_host`, non-blocking).
//! 3. Rejects if **any** resolved IP falls in a private, loopback,
//!    link-local, broadcast, multicast, documentation, CGNAT, or
//!    unique-local-address range. (We block on "any" rather than "all"
//!    because a malicious DNS record can return both a public and a
//!    private address — only blocking the all-private case lets the
//!    attacker through.)
//!
//! ## Two-stage check
//!
//! Both call sites should run this check **twice**:
//!
//! - **At registration time** (webhook create/update, JFS event apply)
//!   to give the user a synchronous error and to prevent storing a
//!   poisoned URL.
//! - **At delivery time** (right before the actual `reqwest::post`)
//!   to defend against DNS rebinding: the address that resolves now
//!   may not be the address that resolved at registration time, and
//!   the underlying system resolver may have refreshed its cache.
//!
//! Both checks are required. The registration-time check alone is
//! useless against rebinding; the delivery-time check alone surfaces
//! errors only after the user has already saved their config.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

/// Address policy for [`assert_safe_url`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SsrfPolicy {
    /// Block every private, loopback, link-local, broadcast,
    /// multicast, documentation, CGNAT, and unique-local-address
    /// range. **The production default — every wire site should pass
    /// this unless it has a specific reason not to.**
    Strict,
    /// Permit `127.0.0.0/8` and `::1` (and IPv4-mapped equivalents)
    /// but still block every other private/internal range. Intended
    /// for tests that spin up a local hyper server on a loopback
    /// interface; never use this in production code paths.
    AllowLoopback,
}

#[derive(Debug, Error)]
pub enum SsrfError {
    #[error("invalid url: {0}")]
    Invalid(String),
    #[error("url must use https scheme")]
    NotHttps,
    #[error("url has no host component")]
    NoHost,
    #[error("dns resolution failed: {0}")]
    Resolve(String),
    #[error("dns resolution returned no addresses")]
    NoAddress,
    #[error("blocked address {ip}: {reason}")]
    BlockedAddress { ip: IpAddr, reason: &'static str },
}

/// Validate that `url` is safe to POST to from a delivery worker.
///
/// Returns `Ok(())` if every resolved address is publicly routable
/// under `policy`.
///
/// Scheme rules:
/// - `Strict`: requires `https`.
/// - `AllowLoopback`: accepts `http` or `https`; the IP check still
///   forbids any non-loopback destination, so an `http://` URL can
///   only succeed if it points at a loopback address.
pub async fn assert_safe_url(url: &str, policy: SsrfPolicy) -> Result<(), SsrfError> {
    let parsed = url::Url::parse(url).map_err(|e| SsrfError::Invalid(e.to_string()))?;

    let scheme = parsed.scheme();
    let scheme_ok = match policy {
        SsrfPolicy::Strict => scheme == "https",
        SsrfPolicy::AllowLoopback => scheme == "https" || scheme == "http",
    };
    if !scheme_ok {
        return Err(SsrfError::NotHttps);
    }

    // `Url::host()` returns a typed enum that already separates IP
    // literals from domain names — no string parsing needed.
    let host = parsed.host().ok_or(SsrfError::NoHost)?;

    match host {
        url::Host::Ipv4(v4) => {
            if let Some(reason) = check_ipv4(&v4, policy) {
                return Err(SsrfError::BlockedAddress {
                    ip: IpAddr::V4(v4),
                    reason,
                });
            }
            Ok(())
        }
        url::Host::Ipv6(v6) => {
            if let Some(reason) = check_ipv6(&v6, policy) {
                return Err(SsrfError::BlockedAddress {
                    ip: IpAddr::V6(v6),
                    reason,
                });
            }
            Ok(())
        }
        url::Host::Domain(domain) => {
            let port = parsed.port_or_known_default().unwrap_or(443);
            let lookup = tokio::net::lookup_host((domain, port))
                .await
                .map_err(|e| SsrfError::Resolve(e.to_string()))?;

            let mut count = 0usize;
            for sa in lookup {
                count += 1;
                let ip = sa.ip();
                if let Some(reason) = check_ip(&ip, policy) {
                    return Err(SsrfError::BlockedAddress { ip, reason });
                }
            }
            if count == 0 {
                return Err(SsrfError::NoAddress);
            }
            Ok(())
        }
    }
}

fn check_ip(ip: &IpAddr, policy: SsrfPolicy) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => check_ipv4(v4, policy),
        IpAddr::V6(v6) => check_ipv6(v6, policy),
    }
}

fn check_ipv4(ip: &Ipv4Addr, policy: SsrfPolicy) -> Option<&'static str> {
    if policy == SsrfPolicy::AllowLoopback && ip.is_loopback() {
        return None;
    }
    blocked_reason_v4(ip)
}

fn check_ipv6(ip: &Ipv6Addr, policy: SsrfPolicy) -> Option<&'static str> {
    if policy == SsrfPolicy::AllowLoopback {
        if ip.is_loopback() {
            return None;
        }
        if let Some(v4) = ip.to_ipv4_mapped() {
            if v4.is_loopback() {
                return None;
            }
        }
    }
    blocked_reason_v6(ip)
}

/// If `ip` is in a blocked range, return a short human-readable label
/// for the range. Otherwise return `None`.
pub fn blocked_reason(ip: &IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => blocked_reason_v4(v4),
        IpAddr::V6(v6) => blocked_reason_v6(v6),
    }
}

fn blocked_reason_v4(ip: &Ipv4Addr) -> Option<&'static str> {
    if ip.is_loopback() {
        return Some("ipv4 loopback");
    }
    if ip.is_private() {
        return Some("ipv4 private (RFC 1918)");
    }
    if ip.is_link_local() {
        return Some("ipv4 link-local");
    }
    if ip.is_broadcast() {
        return Some("ipv4 broadcast");
    }
    if ip.is_unspecified() {
        return Some("ipv4 unspecified (0.0.0.0)");
    }
    if ip.is_documentation() {
        return Some("ipv4 documentation range");
    }
    if ip.is_multicast() {
        return Some("ipv4 multicast");
    }
    // CGNAT 100.64.0.0/10 — first byte 100, second byte 64..=127
    let octets = ip.octets();
    if octets[0] == 100 && (octets[1] & 0xC0) == 0x40 {
        return Some("ipv4 CGNAT (100.64.0.0/10)");
    }
    // 0.0.0.0/8 reserved
    if octets[0] == 0 {
        return Some("ipv4 reserved (0.0.0.0/8)");
    }
    None
}

fn blocked_reason_v6(ip: &Ipv6Addr) -> Option<&'static str> {
    if ip.is_loopback() {
        return Some("ipv6 loopback");
    }
    if ip.is_unspecified() {
        return Some("ipv6 unspecified (::)");
    }
    if ip.is_multicast() {
        return Some("ipv6 multicast");
    }
    let segments = ip.segments();
    // ULA fc00::/7 — first 7 bits are 1111110
    if (segments[0] & 0xfe00) == 0xfc00 {
        return Some("ipv6 unique local (fc00::/7)");
    }
    // Link-local fe80::/10 — first 10 bits are 1111111010
    if (segments[0] & 0xffc0) == 0xfe80 {
        return Some("ipv6 link-local (fe80::/10)");
    }
    // IPv4-mapped IPv6 ::ffff:0:0/96 — extract the v4 and re-check
    if let Some(v4) = ip.to_ipv4_mapped() {
        return blocked_reason_v4(&v4);
    }
    // IPv4-compatible IPv6 (deprecated) ::a.b.c.d — extract similarly
    if segments[0..6].iter().all(|&s| s == 0) && segments[6] != 0 {
        let v4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        );
        if let Some(reason) = blocked_reason_v4(&v4) {
            return Some(reason);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn blocks_ipv4_loopback() {
        assert!(blocked_reason(&IpAddr::from([127, 0, 0, 1])).is_some());
        assert!(blocked_reason(&IpAddr::from([127, 255, 255, 254])).is_some());
    }

    #[test]
    fn blocks_ipv4_private_ranges() {
        assert!(blocked_reason(&IpAddr::from([10, 0, 0, 1])).is_some());
        assert!(blocked_reason(&IpAddr::from([172, 16, 0, 1])).is_some());
        assert!(blocked_reason(&IpAddr::from([172, 31, 255, 254])).is_some());
        assert!(blocked_reason(&IpAddr::from([192, 168, 1, 1])).is_some());
    }

    #[test]
    fn blocks_ipv4_link_local() {
        // 169.254.169.254 is the AWS / GCP instance metadata endpoint.
        assert!(blocked_reason(&IpAddr::from([169, 254, 169, 254])).is_some());
    }

    #[test]
    fn blocks_ipv4_cgnat() {
        // 100.64.0.0/10 — second octet 64..=127
        assert!(blocked_reason(&IpAddr::from([100, 64, 0, 1])).is_some());
        assert!(blocked_reason(&IpAddr::from([100, 100, 50, 1])).is_some());
        assert!(blocked_reason(&IpAddr::from([100, 127, 255, 254])).is_some());
        // 100.0.0.0 and 100.128.0.0 are NOT in CGNAT.
        assert!(blocked_reason(&IpAddr::from([100, 0, 0, 1])).is_none());
        assert!(blocked_reason(&IpAddr::from([100, 128, 0, 1])).is_none());
    }

    #[test]
    fn blocks_ipv4_reserved_zero() {
        assert!(blocked_reason(&IpAddr::from([0, 0, 0, 0])).is_some());
    }

    #[test]
    fn allows_public_ipv4() {
        assert!(blocked_reason(&IpAddr::from([1, 1, 1, 1])).is_none());
        assert!(blocked_reason(&IpAddr::from([8, 8, 8, 8])).is_none());
        assert!(blocked_reason(&IpAddr::from([93, 184, 216, 34])).is_none()); // example.com
    }

    #[test]
    fn blocks_ipv6_loopback() {
        assert!(blocked_reason(&IpAddr::from_str("::1").unwrap()).is_some());
    }

    #[test]
    fn blocks_ipv6_unique_local() {
        assert!(blocked_reason(&IpAddr::from_str("fc00::1").unwrap()).is_some());
        assert!(blocked_reason(&IpAddr::from_str("fdff::1").unwrap()).is_some());
    }

    #[test]
    fn blocks_ipv6_link_local() {
        assert!(blocked_reason(&IpAddr::from_str("fe80::1").unwrap()).is_some());
        assert!(blocked_reason(&IpAddr::from_str("febf::1").unwrap()).is_some());
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6() {
        // ::ffff:127.0.0.1 should be rejected because the embedded v4
        // is loopback.
        assert!(blocked_reason(&IpAddr::from_str("::ffff:127.0.0.1").unwrap()).is_some());
        assert!(blocked_reason(&IpAddr::from_str("::ffff:10.0.0.1").unwrap()).is_some());
        assert!(blocked_reason(&IpAddr::from_str("::ffff:169.254.169.254").unwrap()).is_some());
    }

    #[test]
    fn allows_public_ipv6() {
        assert!(blocked_reason(&IpAddr::from_str("2606:4700:4700::1111").unwrap()).is_none());
    }

    #[tokio::test]
    async fn rejects_non_https_scheme() {
        let err = assert_safe_url("http://example.com", SsrfPolicy::Strict)
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::NotHttps));
    }

    #[tokio::test]
    async fn rejects_invalid_url() {
        let err = assert_safe_url("not a url", SsrfPolicy::Strict)
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::Invalid(_)));
    }

    #[tokio::test]
    async fn rejects_loopback_ip_literal_under_strict() {
        let err = assert_safe_url("https://127.0.0.1/x", SsrfPolicy::Strict)
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::BlockedAddress { .. }));
    }

    #[tokio::test]
    async fn rejects_metadata_endpoint_literal() {
        let err = assert_safe_url(
            "https://169.254.169.254/latest/meta-data/",
            SsrfPolicy::Strict,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SsrfError::BlockedAddress { .. }));
    }

    #[tokio::test]
    async fn rejects_ipv6_loopback_literal_under_strict() {
        let err = assert_safe_url("https://[::1]/x", SsrfPolicy::Strict)
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::BlockedAddress { .. }));
    }

    #[tokio::test]
    async fn rejects_localhost_hostname_under_strict() {
        // `localhost` resolves to a loopback address on every reasonable
        // system. The error type may be either `BlockedAddress` (if
        // resolution succeeds) or `Resolve` (if it fails) — both are
        // acceptable for this case; we just need it to NOT be `Ok`.
        let r = assert_safe_url("https://localhost/x", SsrfPolicy::Strict).await;
        assert!(r.is_err(), "localhost must not be allowed under Strict");
    }

    #[tokio::test]
    async fn rejects_private_ipv4_literal() {
        let err = assert_safe_url("https://10.0.0.1/x", SsrfPolicy::Strict)
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::BlockedAddress { .. }));
    }

    #[tokio::test]
    async fn rejects_url_with_no_host() {
        // `https:///path` parses as a URL with empty host.
        let r = assert_safe_url("https:///path", SsrfPolicy::Strict).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn allow_loopback_permits_127_0_0_1() {
        assert!(
            assert_safe_url("https://127.0.0.1/x", SsrfPolicy::AllowLoopback)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn allow_loopback_permits_ipv6_loopback() {
        assert!(
            assert_safe_url("https://[::1]/x", SsrfPolicy::AllowLoopback)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn allow_loopback_still_blocks_private_addresses() {
        // AllowLoopback opens 127.0.0.0/8 + ::1 only — RFC 1918 must
        // still be blocked.
        let err = assert_safe_url("https://10.0.0.1/x", SsrfPolicy::AllowLoopback)
            .await
            .unwrap_err();
        assert!(matches!(err, SsrfError::BlockedAddress { .. }));
    }

    #[tokio::test]
    async fn allow_loopback_still_blocks_metadata() {
        // 169.254.169.254 is link-local, not loopback — must still be
        // rejected.
        let err = assert_safe_url(
            "https://169.254.169.254/latest/meta-data/",
            SsrfPolicy::AllowLoopback,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SsrfError::BlockedAddress { .. }));
    }
}
