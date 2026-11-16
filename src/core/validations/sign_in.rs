//! Sign In With Farcaster (FIP-11) messages as a KEY_ADD authorization.
//!
//! A Farcaster client that holds an account's custody key will not sign Hypersnap's EIP-712
//! `KeyAdd` payload, but it will sign an [EIP-4361] sign-in message whose `Nonce` the requesting
//! app chooses. When that nonce is a commitment to one specific `KeyAdd` payload, the signed
//! message proves the account approved that payload, and nothing else can be substituted for it.
//!
//! The requesting client also chooses the domain the wallet shows in its approval prompt. Each
//! use of a sign-in message here is tied to one reserved domain (`key::SIGN_IN_KEY_ADD_DOMAIN`,
//! `key::SIGN_IN_KEY_REMOVE_DOMAIN`), so the prompt names what is being granted and a sign-in to
//! any ordinary site can never be replayed as an authorization.
//!
//! This module is the pure half: it parses the message, checks every field this node gives
//! meaning to, and recovers the signing address. Whether that address is the fid's custody
//! address is state-dependent and decided by the caller.
//!
//! Everything here is a consensus rule once `ProtocolFeature::SignInKeyAuthorization` is active.
//! The parser is deliberately strict: a message is accepted only if it re-serializes to the exact
//! bytes that were signed, so two nodes can never read different fields out of the same message.
//!
//! [EIP-4361]: https://eips.ethereum.org/EIPS/eip-4361

use std::str::FromStr;

use alloy_primitives::{eip191_hash_message, Address};
use chrono::DateTime;

use crate::core::validations::error::ValidationError;
use crate::core::validations::key::recover_address_from_prehash;

/// Upper bound on the signed message. A FIP-11 message is a few hundred bytes; the cap keeps a
/// KEY_ADD from carrying an arbitrary payload.
pub const MAX_SIGN_IN_MESSAGE_BYTES: usize = 2048;

/// The statement FIP-11 fixes for every sign-in message.
pub const SIGN_IN_STATEMENT: &str = "Farcaster Auth";

/// FIP-11 messages are always issued for OP Mainnet. Like the EIP-712 chain id on the custody
/// path, nothing on that chain is read; the value is checked only because it is part of what the
/// wallet signed.
pub const SIGN_IN_CHAIN_ID: &str = "10";

pub const SIGN_IN_VERSION: &str = "1";

/// How long after `Issued At` a sign-in message may still authorize a KEY_ADD, in seconds.
pub const MAX_SIGN_IN_AGE_SECONDS: u64 = 60 * 60;

/// How far `Issued At` may sit ahead of the KEY_ADD's own timestamp, in seconds. The two clocks
/// belong to different devices.
pub const SIGN_IN_CLOCK_SKEW_SECONDS: u64 = 10 * 60;

const HEADER_SUFFIX: &str = " wants you to sign in with your Ethereum account:";
const FID_RESOURCE_PREFIX: &str = "farcaster://fid/";

/// The fields of an EIP-4361 message, borrowed from the signed text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInMessage<'a> {
    pub domain: &'a str,
    pub address: &'a str,
    pub statement: &'a str,
    pub uri: &'a str,
    pub version: &'a str,
    pub chain_id: &'a str,
    pub nonce: &'a str,
    pub issued_at: &'a str,
    pub expiration_time: Option<&'a str>,
    pub not_before: Option<&'a str>,
    pub request_id: Option<&'a str>,
    pub resources: Vec<&'a str>,
}

/// What a verified sign-in message establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSignIn {
    /// Address recovered from the signature. Equal to the address named in the message.
    pub signer: Address,
    /// The domain the user was shown when approving.
    pub domain: String,
}

impl<'a> SignInMessage<'a> {
    /// Parses the FIP-11 layout: header, address, statement, then the tagged fields in the order
    /// EIP-4361 fixes. Anything else is rejected, including a missing statement, a trailing
    /// newline, reordered or repeated tags and `\r\n` line endings.
    pub fn parse(text: &'a str) -> Result<Self, ValidationError> {
        if !text.is_ascii() {
            return Err(ValidationError::InvalidSignInMessage);
        }
        let mut lines = text.split('\n').peekable();

        let domain = lines
            .next()
            .and_then(|line| line.strip_suffix(HEADER_SUFFIX))
            .ok_or(ValidationError::InvalidSignInMessage)?;
        let address = lines.next().ok_or(ValidationError::InvalidSignInMessage)?;
        if lines.next() != Some("") {
            return Err(ValidationError::InvalidSignInMessage);
        }
        let statement = lines.next().ok_or(ValidationError::InvalidSignInMessage)?;
        if lines.next() != Some("") {
            return Err(ValidationError::InvalidSignInMessage);
        }

        let uri = required_field(lines.next(), "URI: ")?;
        let version = required_field(lines.next(), "Version: ")?;
        let chain_id = required_field(lines.next(), "Chain ID: ")?;
        let nonce = required_field(lines.next(), "Nonce: ")?;
        let issued_at = required_field(lines.next(), "Issued At: ")?;

        let expiration_time = optional_field(&mut lines, "Expiration Time: ");
        let not_before = optional_field(&mut lines, "Not Before: ");
        let request_id = optional_field(&mut lines, "Request ID: ");

        let mut resources = Vec::new();
        if lines.peek() == Some(&"Resources:") {
            lines.next();
            for line in lines.by_ref() {
                let resource = line
                    .strip_prefix("- ")
                    .ok_or(ValidationError::InvalidSignInMessage)?;
                resources.push(resource);
            }
        }
        if lines.next().is_some() {
            return Err(ValidationError::InvalidSignInMessage);
        }

        let message = SignInMessage {
            domain,
            address,
            statement,
            uri,
            version,
            chain_id,
            nonce,
            issued_at,
            expiration_time,
            not_before,
            request_id,
            resources,
        };
        // The parse above consumes every line under a fixed grammar, so this cannot fail today.
        // It stays as the invariant the rest of the module relies on: the fields read here are
        // exactly the bytes the wallet signed.
        if message.serialize() != text {
            return Err(ValidationError::InvalidSignInMessage);
        }
        Ok(message)
    }

    /// The canonical EIP-4361 text for these fields.
    pub fn serialize(&self) -> String {
        let mut out = format!(
            "{}{}\n{}\n\n{}\n\nURI: {}\nVersion: {}\nChain ID: {}\nNonce: {}\nIssued At: {}",
            self.domain,
            HEADER_SUFFIX,
            self.address,
            self.statement,
            self.uri,
            self.version,
            self.chain_id,
            self.nonce,
            self.issued_at,
        );
        if let Some(value) = self.expiration_time {
            out.push_str("\nExpiration Time: ");
            out.push_str(value);
        }
        if let Some(value) = self.not_before {
            out.push_str("\nNot Before: ");
            out.push_str(value);
        }
        if let Some(value) = self.request_id {
            out.push_str("\nRequest ID: ");
            out.push_str(value);
        }
        if !self.resources.is_empty() {
            out.push_str("\nResources:");
            for resource in &self.resources {
                out.push_str("\n- ");
                out.push_str(resource);
            }
        }
        out
    }
}

fn required_field<'a>(line: Option<&'a str>, tag: &str) -> Result<&'a str, ValidationError> {
    line.and_then(|line| line.strip_prefix(tag))
        .ok_or(ValidationError::InvalidSignInMessage)
}

/// Consumes the next line only if it carries `tag`.
fn optional_field<'a, I>(lines: &mut std::iter::Peekable<I>, tag: &str) -> Option<&'a str>
where
    I: Iterator<Item = &'a str>,
{
    let value = lines.peek()?.strip_prefix(tag)?;
    lines.next();
    Some(value)
}

/// RFC 3339 timestamp to unix seconds. Dates before 1970 are not valid sign-in times.
fn unix_seconds(value: &str) -> Result<u64, ValidationError> {
    let parsed =
        DateTime::parse_from_rfc3339(value).map_err(|_| ValidationError::InvalidSignInMessage)?;
    u64::try_from(parsed.timestamp()).map_err(|_| ValidationError::InvalidSignInMessage)
}

/// Verifies a sign-in message as the authorization for one KEY_ADD or KEY_REMOVE.
///
/// * `message` and `signature` are the body's `authorization_message` and its signature field.
/// * `expected_domain` is the reserved domain for this kind of authorization.
/// * `fid` is the account the key belongs to.
/// * `expected_nonce` is the commitment to the payload (see `key::sign_in_key_add_nonce` and
///   `key::sign_in_key_remove_nonce`).
/// * `now_unix` is the carrying message's own timestamp as unix seconds. Using the message's
///   timestamp rather than wall-clock time keeps the result identical on every node and on
///   replay.
///
/// On success the caller still has to check that the returned signer is the fid's custody
/// address.
pub fn verify_sign_in_message(
    message: &[u8],
    signature: &[u8],
    expected_domain: &str,
    fid: u64,
    expected_nonce: &str,
    now_unix: u64,
) -> Result<VerifiedSignIn, ValidationError> {
    if message.is_empty() || message.len() > MAX_SIGN_IN_MESSAGE_BYTES {
        return Err(ValidationError::InvalidSignInMessage);
    }
    let text = std::str::from_utf8(message).map_err(|_| ValidationError::InvalidSignInMessage)?;
    let parsed = SignInMessage::parse(text)?;

    if parsed.domain != expected_domain
        || parsed.statement != SIGN_IN_STATEMENT
        || parsed.version != SIGN_IN_VERSION
        || parsed.chain_id != SIGN_IN_CHAIN_ID
    {
        return Err(ValidationError::InvalidSignInMessage);
    }
    if parsed.nonce != expected_nonce {
        return Err(ValidationError::InvalidSignInMessage);
    }

    // Exactly one fid resource, naming this fid. A second one would make the message a sign-in
    // for two accounts at once.
    let expected_resource = format!("{}{}", FID_RESOURCE_PREFIX, fid);
    let mut fid_resources = parsed
        .resources
        .iter()
        .filter(|resource| resource.starts_with(FID_RESOURCE_PREFIX));
    if fid_resources.next() != Some(&expected_resource.as_str()) || fid_resources.next().is_some() {
        return Err(ValidationError::InvalidSignInMessage);
    }

    let issued_at = unix_seconds(parsed.issued_at)?;
    if issued_at > now_unix.saturating_add(SIGN_IN_CLOCK_SKEW_SECONDS) {
        return Err(ValidationError::SignInMessageExpired);
    }
    if now_unix > issued_at.saturating_add(MAX_SIGN_IN_AGE_SECONDS) {
        return Err(ValidationError::SignInMessageExpired);
    }
    if let Some(value) = parsed.expiration_time {
        if now_unix > unix_seconds(value)? {
            return Err(ValidationError::SignInMessageExpired);
        }
    }
    if let Some(value) = parsed.not_before {
        if now_unix.saturating_add(SIGN_IN_CLOCK_SKEW_SECONDS) < unix_seconds(value)? {
            return Err(ValidationError::SignInMessageExpired);
        }
    }

    // EIP-191 personal_sign over the exact message bytes.
    let prehash = eip191_hash_message(message);
    let signer = recover_address_from_prehash(&prehash, signature)?;
    let named =
        Address::from_str(parsed.address).map_err(|_| ValidationError::InvalidSignInMessage)?;
    if named != signer {
        return Err(ValidationError::InvalidSignature);
    }

    Ok(VerifiedSignIn {
        signer,
        domain: parsed.domain.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    const NOW: u64 = 1_800_000_000; // 2027-01-15T08:00:00Z
    const NONCE: &str = "3f2a9c0d6b1e48577a90c2d4e6f8a1b3c5d7e9f00112233445566778899aabbc";
    const FID: u64 = 284_063;
    const DOMAIN: &str = "grant-account-access.hypersnap";

    fn message_text(address: &Address, nonce: &str, fid: u64) -> String {
        format!(
            "grant-account-access.hypersnap wants you to sign in with your Ethereum account:\n\
             {address}\n\
             \n\
             Farcaster Auth\n\
             \n\
             URI: https://grant-account-access.hypersnap/\n\
             Version: 1\n\
             Chain ID: 10\n\
             Nonce: {nonce}\n\
             Issued At: 2027-01-15T07:59:30.000Z\n\
             Expiration Time: 2027-01-15T08:09:30.000Z\n\
             Resources:\n\
             - farcaster://fid/{fid}"
        )
    }

    fn sign(signer: &PrivateKeySigner, text: &str) -> Vec<u8> {
        signer.sign_message_sync(text.as_bytes()).unwrap().into()
    }

    #[test]
    fn parses_and_round_trips_a_fip11_message() {
        let signer = PrivateKeySigner::random();
        let text = message_text(&signer.address(), NONCE, FID);
        let parsed = SignInMessage::parse(&text).unwrap();
        assert_eq!(parsed.domain, DOMAIN);
        assert_eq!(parsed.statement, SIGN_IN_STATEMENT);
        assert_eq!(parsed.nonce, NONCE);
        assert_eq!(parsed.expiration_time, Some("2027-01-15T08:09:30.000Z"));
        assert_eq!(parsed.not_before, None);
        assert_eq!(parsed.resources, vec!["farcaster://fid/284063"]);
        assert_eq!(parsed.serialize(), text);
    }

    #[test]
    fn accepts_a_message_signed_by_the_named_address() {
        let signer = PrivateKeySigner::random();
        let text = message_text(&signer.address(), NONCE, FID);
        let verified = verify_sign_in_message(
            text.as_bytes(),
            &sign(&signer, &text),
            DOMAIN,
            FID,
            NONCE,
            NOW,
        )
        .unwrap();
        assert_eq!(verified.signer, signer.address());
        assert_eq!(verified.domain, DOMAIN);
    }

    #[test]
    fn rejects_a_nonce_that_commits_to_another_payload() {
        let signer = PrivateKeySigner::random();
        let text = message_text(&signer.address(), NONCE, FID);
        let other = "0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            verify_sign_in_message(
                text.as_bytes(),
                &sign(&signer, &text),
                DOMAIN,
                FID,
                other,
                NOW
            ),
            Err(ValidationError::InvalidSignInMessage)
        );
    }

    /// A sign-in to any other domain, however valid as a sign-in, authorizes nothing. This is
    /// what stops an ordinary site login from being turned into a key.
    #[test]
    fn rejects_a_sign_in_to_any_other_domain() {
        let signer = PrivateKeySigner::random();
        let text = message_text(&signer.address(), NONCE, FID)
            .replace("grant-account-access.hypersnap", "some-site.example");
        let signature = sign(&signer, &text);
        assert!(verify_sign_in_message(
            text.as_bytes(),
            &signature,
            "some-site.example",
            FID,
            NONCE,
            NOW
        )
        .is_ok());
        assert_eq!(
            verify_sign_in_message(text.as_bytes(), &signature, DOMAIN, FID, NONCE, NOW),
            Err(ValidationError::InvalidSignInMessage)
        );
        // Nor does an approval for one reserved domain satisfy another.
        let text = message_text(&signer.address(), NONCE, FID);
        assert_eq!(
            verify_sign_in_message(
                text.as_bytes(),
                &sign(&signer, &text),
                "revoke-account-access.hypersnap",
                FID,
                NONCE,
                NOW
            ),
            Err(ValidationError::InvalidSignInMessage)
        );
    }

    #[test]
    fn rejects_a_message_for_another_fid() {
        let signer = PrivateKeySigner::random();
        let text = message_text(&signer.address(), NONCE, FID + 1);
        assert_eq!(
            verify_sign_in_message(
                text.as_bytes(),
                &sign(&signer, &text),
                DOMAIN,
                FID,
                NONCE,
                NOW
            ),
            Err(ValidationError::InvalidSignInMessage)
        );
    }

    #[test]
    fn rejects_a_second_fid_resource() {
        let signer = PrivateKeySigner::random();
        let text = format!(
            "{}\n- farcaster://fid/1",
            message_text(&signer.address(), NONCE, FID)
        );
        assert_eq!(
            verify_sign_in_message(
                text.as_bytes(),
                &sign(&signer, &text),
                DOMAIN,
                FID,
                NONCE,
                NOW
            ),
            Err(ValidationError::InvalidSignInMessage)
        );
    }

    #[test]
    fn rejects_a_signature_from_a_different_key() {
        let signer = PrivateKeySigner::random();
        let other = PrivateKeySigner::random();
        let text = message_text(&signer.address(), NONCE, FID);
        assert_eq!(
            verify_sign_in_message(
                text.as_bytes(),
                &sign(&other, &text),
                DOMAIN,
                FID,
                NONCE,
                NOW
            ),
            Err(ValidationError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_a_tampered_message() {
        let signer = PrivateKeySigner::random();
        let text = message_text(&signer.address(), NONCE, FID);
        let signature = sign(&signer, &text);
        let tampered = text.replace("hypersnap/\n", "hypersnap/elsewhere\n");
        assert_eq!(
            verify_sign_in_message(tampered.as_bytes(), &signature, DOMAIN, FID, NONCE, NOW),
            Err(ValidationError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_a_different_statement() {
        let signer = PrivateKeySigner::random();
        let text = message_text(&signer.address(), NONCE, FID).replace("Farcaster Auth", "Log in");
        assert_eq!(
            verify_sign_in_message(
                text.as_bytes(),
                &sign(&signer, &text),
                DOMAIN,
                FID,
                NONCE,
                NOW
            ),
            Err(ValidationError::InvalidSignInMessage)
        );
    }

    #[test]
    fn rejects_messages_outside_their_validity_window() {
        let signer = PrivateKeySigner::random();
        let text = message_text(&signer.address(), NONCE, FID);
        let signature = sign(&signer, &text);
        // After `Expiration Time`.
        assert_eq!(
            verify_sign_in_message(text.as_bytes(), &signature, DOMAIN, FID, NONCE, NOW + 601),
            Err(ValidationError::SignInMessageExpired)
        );
        // `Issued At` further ahead of the KEY_ADD than the allowed skew.
        assert_eq!(
            verify_sign_in_message(
                text.as_bytes(),
                &signature,
                DOMAIN,
                FID,
                NONCE,
                NOW - 30 - SIGN_IN_CLOCK_SKEW_SECONDS - 1
            ),
            Err(ValidationError::SignInMessageExpired)
        );
    }

    #[test]
    fn rejects_an_old_message_with_no_expiration() {
        let signer = PrivateKeySigner::random();
        let text = message_text(&signer.address(), NONCE, FID)
            .replace("\nExpiration Time: 2027-01-15T08:09:30.000Z", "");
        let signature = sign(&signer, &text);
        assert!(
            verify_sign_in_message(text.as_bytes(), &signature, DOMAIN, FID, NONCE, NOW).is_ok()
        );
        assert_eq!(
            verify_sign_in_message(
                text.as_bytes(),
                &signature,
                DOMAIN,
                FID,
                NONCE,
                NOW + MAX_SIGN_IN_AGE_SECONDS
            ),
            Err(ValidationError::SignInMessageExpired)
        );
    }

    #[test]
    fn rejects_malformed_layouts() {
        let signer = PrivateKeySigner::random();
        let good = message_text(&signer.address(), NONCE, FID);
        let cases = [
            // Trailing newline.
            format!("{good}\n"),
            // CRLF line endings.
            good.replace('\n', "\r\n"),
            // Tags out of order.
            good.replace("Version: 1\nChain ID: 10", "Chain ID: 10\nVersion: 1"),
            // Missing statement block.
            good.replace("\nFarcaster Auth\n", ""),
            // Unknown trailing field.
            format!("{good}\nExtra: 1"),
            // Non-ASCII.
            good.replace(
                "https://grant-account-access.hypersnap/",
                "https://grant-accéss.hypersnap/",
            ),
        ];
        for text in cases {
            assert_eq!(
                verify_sign_in_message(
                    text.as_bytes(),
                    &sign(&signer, &text),
                    DOMAIN,
                    FID,
                    NONCE,
                    NOW
                ),
                Err(ValidationError::InvalidSignInMessage),
                "accepted: {text:?}"
            );
        }
    }

    #[test]
    fn rejects_oversized_and_empty_messages() {
        let signer = PrivateKeySigner::random();
        assert_eq!(
            verify_sign_in_message(&[], &[0u8; 65], DOMAIN, FID, NONCE, NOW),
            Err(ValidationError::InvalidSignInMessage)
        );
        let padded = format!(
            "{}\n- {}",
            message_text(&signer.address(), NONCE, FID),
            "a".repeat(MAX_SIGN_IN_MESSAGE_BYTES)
        );
        assert_eq!(
            verify_sign_in_message(
                padded.as_bytes(),
                &sign(&signer, &padded),
                DOMAIN,
                FID,
                NONCE,
                NOW
            ),
            Err(ValidationError::InvalidSignInMessage)
        );
    }
}
