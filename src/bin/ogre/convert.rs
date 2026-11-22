//! The node's HTTP API returns messages and onchain events as JSON and has no
//! `data_bytes`. These functions rebuild the protobuf the JSON was made from, so
//! a seeded devnet stores real mainnet data with its original hashes and
//! signatures. A message whose rebuilt `data` doesn't hash to the original hash
//! is reported by the caller and left out, never re-signed.

use snapchain::network::http_server as json;
use snapchain::proto;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

fn hex0x(s: &str) -> Result<Vec<u8>, Error> {
    Ok(hex::decode(s.strip_prefix("0x").unwrap_or(s))?)
}

fn cast_id(c: &json::CastId) -> Result<proto::CastId, Error> {
    Ok(proto::CastId {
        fid: c.fid,
        hash: hex0x(&c.hash)?,
    })
}

fn named<T>(kind: &str, name: &str, parse: impl Fn(&str) -> Option<T>) -> Result<T, Error> {
    parse(name).ok_or_else(|| format!("unknown {kind} {name}").into())
}

fn cast_add(b: &json::CastAddBody) -> Result<proto::CastAddBody, Error> {
    use proto::cast_add_body::Parent;
    use proto::embed::Embed;
    let parent = match (&b.parent_cast_id, &b.parent_url) {
        (Some(c), _) => Some(Parent::ParentCastId(cast_id(c)?)),
        (None, Some(url)) => Some(Parent::ParentUrl(url.clone())),
        (None, None) => None,
    };
    let embeds = b
        .embeds
        .iter()
        .map(|e| {
            Ok(proto::Embed {
                embed: Some(match e {
                    json::EmbedUrlOrCastId::Url(u) => Embed::Url(u.url.clone()),
                    json::EmbedUrlOrCastId::CastId(c) => Embed::CastId(cast_id(&c.cast_id)?),
                }),
            })
        })
        .collect::<Result<_, Error>>()?;
    Ok(proto::CastAddBody {
        embeds_deprecated: b.embeds_deprecated.clone(),
        mentions: b.mentions.clone(),
        parent,
        text: b.text.clone(),
        mentions_positions: b.mentions_positions.clone(),
        embeds,
        r#type: named("cast type", &b.cast_type, proto::CastType::from_str_name)? as i32,
        format_version: b.format_version.unwrap_or(0),
        chain: b
            .chain
            .as_ref()
            .map(|c| -> Result<_, Error> {
                Ok(proto::ChainCast {
                    root: c.root.as_ref().map(cast_id).transpose()?,
                    index: c.index,
                    count: c.count,
                })
            })
            .transpose()?,
    })
}

fn address(protocol: i32, s: &str) -> Result<Vec<u8>, Error> {
    if protocol == proto::Protocol::Ethereum as i32 {
        hex0x(s)
    } else {
        Ok(bs58::decode(s).into_vec()?)
    }
}

fn body(d: &json::MessageData) -> Result<Option<proto::message_data::Body>, Error> {
    use proto::message_data::Body;
    if let Some(b) = &d.cast_add_body {
        return Ok(Some(Body::CastAddBody(cast_add(b)?)));
    }
    if let Some(b) = &d.cast_remove_body {
        return Ok(Some(Body::CastRemoveBody(proto::CastRemoveBody {
            target_hash: b.target_hash.clone(),
        })));
    }
    if let Some(b) = &d.reaction_body {
        use proto::reaction_body::Target;
        let target = match (&b.target_cast_id, &b.target_url) {
            (Some(c), _) => Some(Target::TargetCastId(cast_id(c)?)),
            (None, Some(url)) => Some(Target::TargetUrl(url.clone())),
            (None, None) => None,
        };
        return Ok(Some(Body::ReactionBody(proto::ReactionBody {
            r#type: named(
                "reaction type",
                &b.reaction_type,
                proto::ReactionType::from_str_name,
            )? as i32,
            target,
        })));
    }
    if let Some(b) = &d.link_body {
        return Ok(Some(Body::LinkBody(proto::LinkBody {
            r#type: b.link_type.clone(),
            display_timestamp: b.display_timestamp,
            target: Some(proto::link_body::Target::TargetFid(b.target_fid)),
        })));
    }
    if let Some(b) = &d.user_data_body {
        return Ok(Some(Body::UserDataBody(proto::UserDataBody {
            r#type: named(
                "user data type",
                &b.user_data_type,
                proto::UserDataType::from_str_name,
            )? as i32,
            value: b.value.clone(),
        })));
    }
    if let Some(b) = &d.verification_add_address_body {
        let protocol = named("protocol", &b.protocol, proto::Protocol::from_str_name)? as i32;
        return Ok(Some(Body::VerificationAddAddressBody(
            proto::VerificationAddAddressBody {
                address: address(protocol, &b.address)?,
                claim_signature: b.claim_signature.clone(),
                block_hash: address(protocol, &b.block_hash)?,
                verification_type: b.verification_type,
                chain_id: b.chain_id,
                protocol,
            },
        )));
    }
    if let Some(b) = &d.username_proof_body {
        return Ok(Some(Body::UsernameProofBody(proto::UserNameProof {
            timestamp: b.timestamp,
            name: b.name.as_bytes().to_vec(),
            owner: hex0x(&b.owner)?,
            signature: b.signature.clone(),
            fid: b.fid,
            r#type: named(
                "username type",
                &b.username_proof_type,
                proto::UserNameType::from_str_name,
            )? as i32,
        })));
    }
    if let Some(b) = &d.key_add_body {
        return Ok(Some(Body::KeyAddBody(proto::KeyAddBody {
            key: b.key.clone(),
            key_type: b.key_type,
            custody_signature: b.custody_signature.clone(),
            deadline: b.deadline,
            nonce: b.nonce,
            metadata: b.metadata.clone(),
            metadata_type: b.metadata_type,
            registration_tx_hash: b.registration_tx_hash.clone(),
            scopes: b
                .scopes
                .iter()
                .map(|s| Ok(named("scope", s, proto::MessageType::from_str_name)? as i32))
                .collect::<Result<_, Error>>()?,
            ttl: b.ttl,
        })));
    }
    Err(format!("unsupported message type {}", d.message_type).into())
}

/// Encodings of a cast body that some clients produce and prost doesn't: empty
/// packed `mentions` and `mentions_positions` written out, and `parent_url`
/// (field 7) written where it is declared, before `text`. The JSON looks the
/// same for all of them; only the original hash tells them apart.
fn cast_add_encodings(b: &proto::CastAddBody) -> Vec<Vec<u8>> {
    use prost::Message as _;
    let only = |f: &dyn Fn(&mut proto::CastAddBody)| {
        let mut part = proto::CastAddBody::default();
        f(&mut part);
        part.encode_to_vec()
    };
    let embeds_deprecated = only(&|p| p.embeds_deprecated = b.embeds_deprecated.clone());
    let mentions = only(&|p| p.mentions = b.mentions.clone());
    let parent = only(&|p| p.parent = b.parent.clone());
    let text = only(&|p| p.text = b.text.clone());
    let positions = only(&|p| p.mentions_positions = b.mentions_positions.clone());
    let rest = only(&|p| {
        p.embeds = b.embeds.clone();
        p.r#type = b.r#type;
        p.format_version = b.format_version;
        p.chain = b.chain.clone();
    });
    let url_parent = matches!(b.parent, Some(proto::cast_add_body::Parent::ParentUrl(_)));
    let mut out = Vec::new();
    for empty_mentions in [false, true] {
        for empty_positions in [false, true] {
            for declared_order in [false, true] {
                if (empty_mentions && !b.mentions.is_empty())
                    || (empty_positions && !b.mentions_positions.is_empty())
                    || (declared_order && !url_parent)
                {
                    continue;
                }
                let mut body = embeds_deprecated.clone();
                body.extend(if empty_mentions {
                    &[0x12, 0][..]
                } else {
                    &mentions
                });
                if declared_order {
                    body.extend(&parent);
                    body.extend(&text);
                } else if url_parent {
                    body.extend(&text);
                } else {
                    body.extend(&parent);
                    body.extend(&text);
                }
                body.extend(if empty_positions {
                    &[0x2a, 0][..]
                } else {
                    &positions
                });
                if url_parent && !declared_order {
                    // tag order: embeds (6) before parent_url (7)
                    let (embeds, tail) = split_embeds(&rest, b);
                    body.extend(embeds);
                    body.extend(&parent);
                    body.extend(tail);
                } else {
                    body.extend(&rest);
                }
                out.push(body);
            }
        }
    }
    out
}

/// `rest` holds embeds (6), then type (8), format_version (9), chain (10).
fn split_embeds<'a>(rest: &'a [u8], b: &proto::CastAddBody) -> (&'a [u8], &'a [u8]) {
    use prost::Message as _;
    let n = proto::CastAddBody {
        embeds: b.embeds.clone(),
        ..Default::default()
    }
    .encoded_len();
    rest.split_at(n)
}

/// Rebuilds a message, or says why it can't. A returned message always hashes
/// to its original hash; `data_bytes` carries the encoding when it isn't
/// prost's.
pub fn message(m: &json::Message) -> Result<proto::Message, Error> {
    use prost::Message as _;
    let d = &m.data;
    let data = proto::MessageData {
        r#type: named(
            "message type",
            &d.message_type,
            proto::MessageType::from_str_name,
        )? as i32,
        fid: d.fid,
        timestamp: d.timestamp,
        network: named(
            "network",
            &d.network,
            proto::FarcasterNetwork::from_str_name,
        )? as i32,
        body: body(d)?,
        native_onboard_body: None,
    };
    let hash = hex0x(&m.hash)?;
    let matches = |bytes: &[u8]| snapchain::core::util::calculate_message_hash(bytes) == hash;
    let canonical = data.encode_to_vec();
    let data_bytes = if matches(&canonical) {
        None
    } else if let Some(proto::message_data::Body::CastAddBody(b)) = &data.body {
        let head = proto::MessageData {
            body: None,
            ..data.clone()
        }
        .encode_to_vec();
        cast_add_encodings(b)
            .into_iter()
            .map(|body| {
                let mut bytes = head.clone();
                bytes.push(0x2a); // field 5, length-delimited
                prost::encoding::encode_varint(body.len() as u64, &mut bytes);
                bytes.extend(body);
                bytes
            })
            .find(|bytes| matches(bytes))
            .map(Some)
            .ok_or("rebuilt data doesn't match the hash")?
    } else {
        return Err("rebuilt data doesn't match the hash".into());
    };
    Ok(proto::Message {
        data: Some(data),
        hash,
        hash_scheme: named(
            "hash scheme",
            &m.hash_scheme,
            proto::HashScheme::from_str_name,
        )? as i32,
        signature: m.signature.clone(),
        signature_scheme: named(
            "signature scheme",
            &m.signature_scheme,
            proto::SignatureScheme::from_str_name,
        )? as i32,
        signer: hex0x(&m.signer)?,
        data_bytes,
    })
}

pub fn onchain_event(e: &json::OnChainEvent) -> Result<proto::OnChainEvent, Error> {
    use proto::on_chain_event::Body;
    let body = if let Some(b) = &e.signer_event_body {
        Body::SignerEventBody(proto::SignerEventBody {
            key: b.key.clone(),
            key_type: b.key_type,
            event_type: b.event_type.clone() as i32,
            metadata: b.metadata.clone(),
            metadata_type: b.metadata_type,
        })
    } else if let Some(b) = &e.id_register_event_body {
        Body::IdRegisterEventBody(proto::IdRegisterEventBody {
            to: b.to.clone(),
            event_type: b.event_type.clone() as i32,
            from: b.from.clone(),
            recovery_address: b.recovery_address.clone(),
        })
    } else if let Some(b) = &e.storage_rent_event_body {
        Body::StorageRentEventBody(proto::StorageRentEventBody {
            payer: b.payer.clone(),
            units: b.units,
            expiry: b.expiry,
        })
    } else if let Some(b) = &e.signer_migrated_event_body {
        Body::SignerMigratedEventBody(proto::SignerMigratedEventBody {
            migrated_at: b.migrated_at,
        })
    } else if let Some(b) = &e.tier_purchase_event_body {
        Body::TierPurchaseEventBody(proto::TierPurchaseBody {
            tier_type: b.tier_type.clone() as i32,
            for_days: b.for_days,
            payer: b.payer.clone(),
        })
    } else {
        return Err(format!("unsupported onchain event {:?}", e.r#type).into());
    };
    Ok(proto::OnChainEvent {
        r#type: e.r#type.clone() as i32,
        chain_id: e.chain_id,
        block_number: e.block_number,
        block_hash: e.block_hash.clone(),
        block_timestamp: e.block_timestamp,
        transaction_hash: e.transaction_hash.clone(),
        log_index: e.log_index,
        fid: e.fid,
        body: Some(body),
        tx_index: e.tx_index,
        version: e.version,
    })
}

pub fn username_proof(p: &json::UserNameProof) -> Result<proto::UserNameProof, Error> {
    Ok(proto::UserNameProof {
        timestamp: p.timestamp,
        name: p.name.as_bytes().to_vec(),
        owner: hex0x(&p.owner)?,
        signature: p.signature.clone(),
        fid: p.fid,
        r#type: named(
            "username type",
            &p.r#type,
            proto::UserNameType::from_str_name,
        )? as i32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real mainnet cast whose client wrote empty `mentions` and
    /// `mentions_positions` out (`12 00`, `2a 00`); the JSON can't show that.
    #[test]
    fn rebuilds_a_cast_from_its_json_with_its_original_bytes() {
        let m: json::Message = serde_json::from_str(r#"{"data":{"type":"MESSAGE_TYPE_CAST_ADD","fid":3,"timestamp":185074080,"network":"FARCASTER_NETWORK_MAINNET","castAddBody":{"embedsDeprecated":[],"mentions":[],"parentCastId":null,"parentUrl":null,"text":"Good book","embeds":[{"castId":{"fid":1,"hash":"0x39c77976ededc0946c4ee7e9e6bd25b4160265c3"}}],"mentionsPositions":[],"type":"CAST"}},"hash":"0x868360949ea7ac68b242e088fb58b829fcb9d188","hashScheme":"HASH_SCHEME_BLAKE3","signature":"napwMStaCJwBIbEVrMb3FJvWKpQYt3MmIvISnBdxzzRG/mJXmkL/J7G/YFYHEk1Hrc9r0sRJnPf55+8ZNFwICQ==","signatureScheme":"SIGNATURE_SCHEME_ED25519","signer":"0xc887f5bf385a4718eaee166481f1832198938cf33e98a82dc81a0b4b81ffe33d"}"#).unwrap();
        let rebuilt = message(&m).unwrap();
        assert_eq!(
            hex::encode(rebuilt.data_bytes.unwrap()),
            "0801100318a083a05820012a2b12002209476f6f6420626f6f6b2a00321a12180801121439c77976ededc0946c4ee7e9e6bd25b4160265c3"
        );
        let mut tampered = m.clone();
        tampered.data.cast_add_body.as_mut().unwrap().text = "Bad book".into();
        assert!(message(&tampered).is_err());
    }
}
