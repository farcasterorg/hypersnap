//! Casts (FIP §16.8). A cast goes to the shard of the FID.
//!
//! An FID that is not migrated signs with Ed25519
//! ([`MessageSigner::Ed25519`]). A migrated FID signs with a signer pair
//! ([`MessageSigner::Pair`]; the relay keeps the Ed25519 half for snapchain)
//! or a Falcon-512 signer ([`MessageSigner::Falcon`]).

use super::{Header, MessageSigner};
use crate::error::WalletError;
use hypersnap_falcon::{CryptoRng, RngCore};
use hypersnap_proto::{
    message_data::Body, CastAddBody, CastType, Message, MessageData, MessageType,
};

/// The data of a plain `CAST_ADD` with `text`.
pub fn cast_add_data(h: &Header, text: &str) -> MessageData {
    h.data(
        MessageType::CastAdd,
        Body::CastAddBody(CastAddBody {
            text: text.to_string(),
            r#type: CastType::Cast as i32,
            ..Default::default()
        }),
    )
}

pub fn build_cast_add<R: CryptoRng + RngCore>(
    h: &Header,
    text: &str,
    signer: &MessageSigner,
    rng: &mut R,
) -> Result<Message, WalletError> {
    signer.sign(cast_add_data(h, text), rng)
}
