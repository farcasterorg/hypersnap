use crate::core::types::FARCASTER_EPOCH;
use crate::proto as message;
use crate::proto::{OnChainEvent, OnChainEventType};
use alloy_signer::SignerSync;
use ed25519_dalek::{SecretKey, Signer, SigningKey};
use hex::FromHex;
use message::MessageType;
use message::{CastAddBody, FarcasterNetwork, MessageData};
use prost::Message;

pub mod signers {
    use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
    use rand::Rng;

    pub fn generate_signer() -> SigningKey {
        let mut rng = rand::thread_rng();
        let bytes: [u8; SECRET_KEY_LENGTH] = rng.gen();
        SigningKey::from_bytes(&bytes)
    }
}

pub mod address {
    pub fn generate_random_address() -> Vec<u8> {
        (0..32).map(|_| rand::random::<u8>()).collect()
    }
}

pub mod time {
    use super::*;

    pub fn farcaster_time() -> u32 {
        current_timestamp() - (FARCASTER_EPOCH / 1000) as u32
    }

    pub fn farcaster_time_with_offset(offset: i32) -> u32 {
        (farcaster_time() as i32 + offset) as u32
    }

    // Returns the current timestamp in seconds since the unix epoch
    pub fn current_timestamp() -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32
    }

    pub fn current_timestamp_with_offset(offset: i32) -> u32 {
        (current_timestamp() as i32 + offset as i32) as u32
    }
}

pub mod events_factory {
    use super::*;
    use crate::{
        proto::{
            self, BlockEvent, BlockEventData, BlockEventType, HeartbeatEventBody,
            MergeMessageEventBody, StorageUnitType, TierPurchaseBody, TierType,
        },
        storage::store::account::{StorageSlot, UNIT_TYPE_LEGACY_CUTOFF_TIMESTAMP},
    };

    pub fn create_heartbeat_event(seqnum: u64) -> BlockEvent {
        let data = BlockEventData {
            seqnum,
            r#type: BlockEventType::Heartbeat as i32,
            block_number: 0,
            event_index: 0,
            block_timestamp: 0,
            body: Some(message::block_event_data::Body::HeartbeatEventBody(
                HeartbeatEventBody {},
            )),
        };
        let hash = blake3::hash(data.encode_to_vec().as_slice())
            .as_bytes()
            .to_vec();
        BlockEvent {
            hash,
            data: Some(data),
        }
    }

    pub fn create_merge_message_event(message: proto::Message, seqnum: u64) -> BlockEvent {
        let data = BlockEventData {
            seqnum,
            r#type: BlockEventType::MergeMessage as i32,
            block_number: 0,
            event_index: 0,
            block_timestamp: 0,
            body: Some(message::block_event_data::Body::MergeMessageEventBody(
                MergeMessageEventBody {
                    message: Some(message),
                },
            )),
        };
        let hash = blake3::hash(data.encode_to_vec().as_slice())
            .as_bytes()
            .to_vec();
        BlockEvent {
            hash,
            data: Some(data),
        }
    }

    pub fn create_onchain_event(fid: u64) -> OnChainEvent {
        OnChainEvent {
            r#type: OnChainEventType::EventTypeIdRegister as i32,
            chain_id: 10,
            block_number: rand::random::<u32>(),
            block_hash: vec![],
            block_timestamp: 0,
            transaction_hash: rand::random::<[u8; 32]>().to_vec(),
            log_index: 0,
            fid,
            tx_index: 0,
            version: 1,
            body: None,
        }
    }

    pub fn create_rent_event(
        fid: u64,
        rent_units: u32,
        unit_type: StorageUnitType,
        expired: bool,
        network: FarcasterNetwork,
    ) -> OnChainEvent {
        let one_year_in_seconds = 365 * 24 * 60 * 60;
        let timestamp;
        match unit_type {
            StorageUnitType::UnitTypeLegacy => {
                if expired {
                    timestamp = UNIT_TYPE_LEGACY_CUTOFF_TIMESTAMP - (3 * one_year_in_seconds);
                } else {
                    timestamp = UNIT_TYPE_LEGACY_CUTOFF_TIMESTAMP - 1;
                }
            }
            StorageUnitType::UnitType2024 => {
                timestamp = StorageSlot::unit_type_2024_cutoff(network) - 1;
                if expired {
                    panic!("2024 storage units can't be expired");
                }
            }
            StorageUnitType::UnitType2025 => {
                timestamp = StorageSlot::unit_type_2024_cutoff(network) + 1;
                if expired {
                    panic!("2025 storage units can't be expired");
                }
            }
        }
        create_rent_event_with_timestamp(fid, rent_units, timestamp)
    }

    pub fn create_rent_event_with_timestamp(fid: u64, units: u32, timestamp: u32) -> OnChainEvent {
        let rent_event_body = proto::StorageRentEventBody {
            expiry: 0, // This field is ignored, we use block_timestamp to calculate expiry
            units,
            payer: rand::random::<[u8; 32]>().to_vec(),
        };
        let random_number_under_1000 = rand::random::<u32>() % 1000;
        // Ensure higher timestamp always has higher block number by left shifting the timestamp by 10 bits (1024)
        let block_number = timestamp.checked_shl(10).unwrap() + random_number_under_1000;
        OnChainEvent {
            r#type: OnChainEventType::EventTypeStorageRent as i32,
            chain_id: 10,
            block_number,
            block_hash: vec![],
            block_timestamp: timestamp as u64,
            transaction_hash: rand::random::<[u8; 32]>().to_vec(),
            log_index: 0,
            fid,
            tx_index: 0,
            version: 1,
            body: Some(proto::on_chain_event::Body::StorageRentEventBody(
                rent_event_body,
            )),
        }
    }

    pub fn create_signer_event(
        fid: u64,
        signer: SigningKey,
        event_type: proto::SignerEventType,
        timestamp: Option<u32>,
        key_type: Option<u32>,
    ) -> OnChainEvent {
        if timestamp.is_some() && !(timestamp.unwrap() > (FARCASTER_EPOCH / 1000) as u32) {
            panic!("Block timestamps must be unix epoch in seconds");
        }
        let signer_event_body = proto::SignerEventBody {
            key: signer.verifying_key().as_bytes().to_vec(),
            event_type: event_type as i32,
            metadata: vec![],
            key_type: key_type.unwrap_or(1),
            metadata_type: 1,
        };
        let block_timestamp = timestamp.unwrap_or_else(|| time::current_timestamp_with_offset(-10));
        let random_number_under_1000 = rand::random::<u32>() % 1000;
        // Ensure higher timestamp always has higher block number by left shifting the timestamp by 10 bits (1024)
        let block_number = block_timestamp.checked_shl(10).unwrap() + random_number_under_1000;
        OnChainEvent {
            r#type: OnChainEventType::EventTypeSigner as i32,
            chain_id: 10,
            block_number,
            block_hash: vec![],
            block_timestamp: block_timestamp as u64,
            transaction_hash: rand::random::<[u8; 32]>().to_vec(),
            log_index: 0,
            fid,
            tx_index: 0,
            version: 1,
            body: Some(proto::on_chain_event::Body::SignerEventBody(
                signer_event_body,
            )),
        }
    }

    pub fn create_id_register_event(
        fid: u64,
        event_type: proto::IdRegisterEventType,
        custody_address: Vec<u8>,
        timestamp: Option<u32>,
    ) -> OnChainEvent {
        if timestamp.is_some() && !(timestamp.unwrap() > (FARCASTER_EPOCH / 1000) as u32) {
            panic!("Block timestamps must be unix epoch in seconds");
        }
        let id_register_event_body = proto::IdRegisterEventBody {
            to: custody_address,
            event_type: event_type as i32,
            from: vec![],
            recovery_address: vec![],
        };
        let block_timestamp = timestamp.unwrap_or_else(|| time::current_timestamp_with_offset(-10));
        let random_number_under_1000 = rand::random::<u32>() % 1000;
        // Ensure higher timestamp always has higher block number by left shifting the timestamp by 10 bits (1024)
        let block_number = block_timestamp.checked_shl(10).unwrap() + random_number_under_1000;
        OnChainEvent {
            r#type: OnChainEventType::EventTypeIdRegister as i32,
            chain_id: 10,
            block_number,
            block_hash: vec![],
            block_timestamp: block_timestamp as u64,
            transaction_hash: rand::random::<[u8; 32]>().to_vec(),
            log_index: 0,
            fid,
            tx_index: 0,
            version: 1,
            body: Some(proto::on_chain_event::Body::IdRegisterEventBody(
                id_register_event_body,
            )),
        }
    }

    pub fn create_pro_user_event(
        fid: u64,
        for_days: u64,
        block_timestamp: Option<u32>,
    ) -> OnChainEvent {
        let block_timestamp = block_timestamp.unwrap_or(time::current_timestamp_with_offset(-10));
        let random_number_under_1000 = rand::random::<u32>() % 1000;
        // Ensure higher timestamp always has higher block number by left shifting the timestamp by 10 bits (1024)
        let block_number = block_timestamp.checked_shl(10).unwrap() + random_number_under_1000;
        OnChainEvent {
            r#type: OnChainEventType::EventTypeTierPurchase as i32,
            chain_id: 10,
            block_number,
            block_hash: vec![],
            block_timestamp: block_timestamp as u64,
            transaction_hash: rand::random::<[u8; 32]>().to_vec(),
            log_index: 0,
            fid,
            tx_index: 0,
            version: 1,
            body: Some(proto::on_chain_event::Body::TierPurchaseEventBody(
                TierPurchaseBody {
                    for_days,
                    tier_type: TierType::Pro as i32,
                    payer: rand::random::<[u8; 32]>().to_vec(),
                },
            )),
        }
    }
}

pub mod messages_factory {
    use super::*;
    use crate::core::util::calculate_message_hash;

    pub fn farcaster_time() -> u32 {
        time::farcaster_time()
    }

    pub fn generate_random_message_hash() -> Vec<u8> {
        (0..20).map(|_| rand::random::<u8>()).collect()
    }

    pub fn create_message_with_data(
        fid: u64,
        msg_type: MessageType,
        body: message::message_data::Body,
        timestamp: Option<u32>,
        private_key: Option<&SigningKey>,
    ) -> message::Message {
        let key = match private_key {
            Some(key) => key,
            None => &SigningKey::from_bytes(
                &SecretKey::from_hex(
                    "1000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
            ),
        };
        let network = FarcasterNetwork::Mainnet;

        let timestamp = timestamp.unwrap_or_else(|| farcaster_time());

        let msg_data = MessageData {
            fid,
            r#type: msg_type as i32,
            timestamp,
            network: network as i32,
            body: Some(body),
        };

        let msg_data_bytes = msg_data.encode_to_vec();
        let hash = calculate_message_hash(&msg_data_bytes);

        let signature = key.sign(&hash).to_bytes();
        message::Message {
            data: Some(msg_data),
            hash_scheme: message::HashScheme::Blake3 as i32,
            hash: hash.clone(),
            signature_scheme: message::SignatureScheme::Ed25519 as i32,
            signature: signature.to_vec(),
            signer: key.verifying_key().to_bytes().to_vec(),
            data_bytes: None,
        }
    }

    pub mod casts {
        use super::*;
        use crate::proto::{self, cast_add_body::Parent, CastRemoveBody, CastType, Embed};

        pub fn create_cast_add_rich(
            fid: u64,
            text: &str,
            cast_type: Option<CastType>,
            embeds: Vec<Embed>,
            parent: Option<Parent>,
            mentions: Vec<u64>,
            timestamp: Option<u32>,
            private_key: Option<&SigningKey>,
        ) -> message::Message {
            let cast_add = CastAddBody {
                text: text.to_string(),
                embeds,
                embeds_deprecated: vec![],
                mentions,
                mentions_positions: vec![],
                parent,
                r#type: cast_type.unwrap_or(CastType::Cast) as i32,
            };
            create_message_with_data(
                fid,
                MessageType::CastAdd,
                message::message_data::Body::CastAddBody(cast_add),
                timestamp,
                private_key,
            )
        }

        pub fn create_cast_add(
            fid: u64,
            text: &str,
            timestamp: Option<u32>,
            private_key: Option<&SigningKey>,
        ) -> message::Message {
            create_cast_add_rich(
                fid,
                text,
                Some(CastType::Cast),
                vec![],
                None,
                vec![],
                timestamp,
                private_key,
            )
        }

        pub fn create_cast_with_parent(
            fid: u64,
            text: &str,
            parent_fid: u64,
            parent_hash: &Vec<u8>,
            timestamp: Option<u32>,
            private_key: Option<&SigningKey>,
        ) -> message::Message {
            create_cast_add_rich(
                fid,
                text,
                Some(CastType::Cast),
                vec![],
                Some(Parent::ParentCastId(proto::CastId {
                    fid: parent_fid,
                    hash: parent_hash.clone(),
                })),
                vec![],
                timestamp,
                private_key,
            )
        }

        pub fn create_cast_remove(
            fid: u64,
            target_hash: &Vec<u8>,
            timestamp: Option<u32>,
            private_key: Option<&SigningKey>,
        ) -> crate::proto::Message {
            let cast_remove = CastRemoveBody {
                target_hash: target_hash.clone(),
            };
            create_message_with_data(
                fid,
                MessageType::CastRemove,
                message::message_data::Body::CastRemoveBody(cast_remove),
                timestamp,
                private_key,
            )
        }
    }

    pub mod links {
        use message::{link_body::Target, LinkBody, LinkCompactStateBody};

        use super::*;

        pub fn create_link_add(
            fid: u64,
            link_type: &str,
            target_fid: u64,
            timestamp: Option<u32>,
            private_key: Option<&SigningKey>,
        ) -> message::Message {
            let link_body = LinkBody {
                r#type: link_type.to_string(),
                display_timestamp: None,
                target: Some(Target::TargetFid(target_fid)),
            };
            create_message_with_data(
                fid,
                MessageType::LinkAdd,
                message::message_data::Body::LinkBody(link_body),
                timestamp,
                private_key,
            )
        }

        pub fn create_link_remove(
            fid: u64,
            link_type: &str,
            target_fid: u64,
            timestamp: Option<u32>,
            private_key: Option<&SigningKey>,
        ) -> crate::proto::Message {
            let link_body = LinkBody {
                r#type: link_type.to_string(),
                display_timestamp: None,
                target: Some(Target::TargetFid(target_fid)),
            };
            create_message_with_data(
                fid,
                MessageType::LinkRemove,
                message::message_data::Body::LinkBody(link_body),
                timestamp,
                private_key,
            )
        }

        pub fn create_link_compact_state(
            fid: u64,
            link_type: &str,
            target_fids: Vec<u64>,
            timestamp: Option<u32>,
            private_key: Option<&SigningKey>,
        ) -> crate::proto::Message {
            let link_compact_state_body = LinkCompactStateBody {
                r#type: link_type.to_string(),
                target_fids,
            };

            create_message_with_data(
                fid,
                MessageType::LinkCompactState,
                message::message_data::Body::LinkCompactStateBody(link_compact_state_body),
                timestamp,
                private_key,
            )
        }
    }

    pub mod reactions {
        use message::{reaction_body::Target, ReactionBody, ReactionType};

        use super::*;

        pub fn create_reaction_add(
            fid: u64,
            reaction_type: ReactionType,
            target: Target,
            timestamp: Option<u32>,
            private_key: Option<&SigningKey>,
        ) -> message::Message {
            let reaction_body = ReactionBody {
                r#type: reaction_type as i32,
                target: Some(target),
            };
            create_message_with_data(
                fid,
                MessageType::ReactionAdd,
                message::message_data::Body::ReactionBody(reaction_body),
                timestamp,
                private_key,
            )
        }

        pub fn create_reaction_remove(
            fid: u64,
            reaction_type: ReactionType,
            target: Target,
            timestamp: Option<u32>,
            private_key: Option<&SigningKey>,
        ) -> message::Message {
            let reaction_body = ReactionBody {
                r#type: reaction_type as i32,
                target: Some(target),
            };
            create_message_with_data(
                fid,
                MessageType::ReactionRemove,
                message::message_data::Body::ReactionBody(reaction_body),
                timestamp,
                private_key,
            )
        }
    }
    pub mod user_data {
        use message::{UserDataBody, UserDataType};

        use super::*;

        pub fn create_user_data_add(
            fid: u64,
            user_data_type: UserDataType,
            value: &String,
            timestamp: Option<u32>,
            private_key: Option<&SigningKey>,
        ) -> message::Message {
            let user_data_body = UserDataBody {
                r#type: user_data_type as i32,
                value: value.clone(),
            };
            create_message_with_data(
                fid,
                MessageType::UserDataAdd,
                message::message_data::Body::UserDataBody(user_data_body),
                timestamp,
                private_key,
            )
        }
    }

    pub mod storage_lend {
        use message::LendStorageBody;

        use super::*;

        pub fn create_storage_lend(
            from_fid: u64,
            to_fid: u64,
            units: u64,
            unit_type: message::StorageUnitType,
            timestamp: Option<u32>,
            private_key: Option<&SigningKey>,
        ) -> message::Message {
            let lend_storage_body = LendStorageBody {
                to_fid,
                num_units: units,
                unit_type: unit_type as i32,
            };
            create_message_with_data(
                from_fid,
                MessageType::LendStorage,
                message::message_data::Body::LendStorageBody(lend_storage_body),
                timestamp,
                private_key,
            )
        }
    }

    pub mod verifications {
        use message::{VerificationAddAddressBody, VerificationRemoveBody};

        use super::*;

        pub fn create_verification_add(
            fid: u64,
            verification_type: u32,
            address: Vec<u8>,
            claim_signature: Vec<u8>,
            block_hash: Vec<u8>,
            timestamp: Option<u32>,
            private_key: Option<&SigningKey>,
        ) -> message::Message {
            let body = VerificationAddAddressBody {
                address: address,
                claim_signature: claim_signature,
                block_hash: block_hash,
                verification_type,
                chain_id: 0,
                protocol: 0,
            };
            create_message_with_data(
                fid,
                MessageType::VerificationAddEthAddress,
                message::message_data::Body::VerificationAddAddressBody(body),
                timestamp,
                private_key,
            )
        }

        pub fn create_verification_remove(
            fid: u64,
            address: Vec<u8>,
            timestamp: Option<u32>,
            private_key: Option<&SigningKey>,
        ) -> message::Message {
            let body = VerificationRemoveBody {
                address: address,
                protocol: 0,
            };
            create_message_with_data(
                fid,
                MessageType::VerificationRemove,
                message::message_data::Body::VerificationRemoveBody(body),
                timestamp,
                private_key,
            )
        }
    }

    pub mod username_proof {
        use super::*;
        use crate::proto::UserNameProof;

        pub fn create_username_proof(
            fid: u64,
            username_type: crate::proto::UserNameType,
            name: String,
            owner: Vec<u8>,
            signature: String,
            timestamp: u64,
            private_key: Option<&SigningKey>,
        ) -> message::Message {
            let proof = UserNameProof {
                timestamp,
                name: name.as_bytes().to_vec(),
                owner,
                signature: signature.encode_to_vec(),
                fid,
                r#type: username_type as i32,
            };

            create_message_with_data(
                fid,
                MessageType::UsernameProof,
                message::message_data::Body::UsernameProofBody(proof),
                Some(timestamp as u32),
                private_key,
            )
        }

        pub fn create_from_proof(
            proof: &UserNameProof,
            private_key: Option<&SigningKey>,
        ) -> message::Message {
            create_message_with_data(
                proof.fid,
                MessageType::UsernameProof,
                message::message_data::Body::UsernameProofBody(proof.clone()),
                Some(proof.timestamp as u32),
                private_key,
            )
        }
    }
}

pub mod username_factory {
    use alloy_dyn_abi::TypedData;
    use serde_json::json;

    use super::*;
    use crate::core::validations::verification::eip_712_domain;
    use crate::core::validations::verification::name_registry_domain;
    use crate::proto::FnameTransfer;
    use crate::proto::UserNameProof;
    use crate::storage::store::test_helper::default_custody_address;
    use crate::utils::factory::address::generate_random_address;

    pub fn create_username_proof(
        fid: u64,
        username_type: crate::proto::UserNameType,
        name: &String,
        timestamp: Option<u64>,
        owner: Option<Vec<u8>>,
    ) -> UserNameProof {
        let timestamp = timestamp
            .map(|t| t as u64)
            .unwrap_or_else(|| time::current_timestamp() as u64);
        UserNameProof {
            timestamp,
            name: name.as_bytes().to_vec(),
            owner: owner.unwrap_or(generate_random_address()),
            signature: rand::random::<[u8; 32]>().to_vec(),
            fid,
            r#type: username_type as i32,
        }
    }

    pub fn create_transfer(
        fid: u64,
        name: &str,
        timestamp: Option<u32>,
        from_fid: Option<u64>,
        owner: Option<Vec<u8>>,
        fname_signer: alloy_signer_local::PrivateKeySigner,
    ) -> FnameTransfer {
        let usable_timestamp = timestamp.unwrap_or_else(|| time::current_timestamp() as u32);
        let usable_owner = owner.unwrap_or_else(|| default_custody_address());
        let username = name;

        let json = json!({
            "types": eip_712_domain(),
            "primaryType": "UserNameProof",
            "domain": name_registry_domain(),
            "message": {
                "name": username,
                "timestamp": usable_timestamp,
                "owner": hex::encode(usable_owner.clone())
            }
        });

        let typed_data = serde_json::from_value::<TypedData>(json);
        if typed_data.is_err() {
            panic!("invalid typed data");
        }

        let data = typed_data.unwrap();
        let prehash = data.eip712_signing_hash();
        if prehash.is_err() {
            panic!("invalid hash: {}", prehash.unwrap_err());
        }
        let sig = fname_signer.sign_hash_sync(&prehash.unwrap());
        let proof = UserNameProof {
            timestamp: usable_timestamp.into(),
            name: name.as_bytes().to_vec(),
            owner: usable_owner,
            signature: sig.unwrap().into(),
            fid,
            r#type: crate::proto::UserNameType::UsernameTypeFname as i32,
        };

        FnameTransfer {
            id: rand::random::<u64>(),
            from_fid: from_fid.unwrap_or_else(|| 0),
            proof: Some(proof),
        }
    }
}

pub mod frame_action_factory {
    use crate::proto::{CastId, FrameActionBody, Message};

    use super::messages_factory::create_message_with_data;

    pub fn create_frame_action(
        fid: u64,
        url: String,
        button_index: u32,
        cast_id: Option<CastId>,
        input_text: Option<String>,
        state: Option<String>,
        transaction_id: Option<String>,
        address: Option<String>,
    ) -> Message {
        let body = FrameActionBody {
            url: url.as_bytes().to_vec(),
            button_index,
            cast_id,
            input_text: input_text.unwrap_or("".to_string()).as_bytes().to_vec(),
            state: state.unwrap_or("".to_string()).as_bytes().to_vec(),
            transaction_id: transaction_id.unwrap_or("".to_string()).as_bytes().to_vec(),
            address: address.unwrap_or("".to_string()).as_bytes().to_vec(),
        };
        create_message_with_data(
            fid,
            crate::proto::MessageType::FrameAction,
            crate::proto::message_data::Body::FrameActionBody(body),
            None,
            None,
        )
    }
}

pub mod shard_chunk_factory {
    use crate::proto;
    use crate::proto::Height;
    use crate::utils::factory::time;

    pub fn create_shard_chunk(
        shard_id: u32,
        height: Option<u64>,
        timestamp: Option<u64>,
    ) -> proto::ShardChunk {
        let height = height.unwrap_or_else(|| rand::random::<u64>());
        let timestamp = timestamp.unwrap_or_else(|| time::current_timestamp() as u64);
        proto::ShardChunk {
            header: Some(proto::ShardHeader {
                parent_hash: vec![],
                timestamp,
                height: Some(Height::new(shard_id, height)),
                shard_root: vec![],
            }),
            hash: vec![],
            commits: None,
            transactions: vec![],
        }
    }
}

pub mod hyper_signer_factory {
    use super::*;
    use alloy_dyn_abi::TypedData;
    use alloy_signer_local::PrivateKeySigner;
    use prost::Message;
    use serde_json::json;

    fn signer_authorization_types() -> serde_json::Value {
        json!({
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "SignerAuthorization": [
                { "name": "fid", "type": "uint256" },
                { "name": "key", "type": "bytes" },
                { "name": "deadline", "type": "uint256" },
                { "name": "nonce", "type": "uint256" }
            ]
        })
    }

    fn signer_revocation_types() -> serde_json::Value {
        json!({
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "SignerRevocation": [
                { "name": "fid", "type": "uint256" },
                { "name": "key", "type": "bytes" },
                { "name": "deadline", "type": "uint256" },
                { "name": "nonce", "type": "uint256" }
            ]
        })
    }

    fn signer_authorization_domain() -> serde_json::Value {
        json!({
            "name": "Farcaster SignerAuthorization",
            "version": "1",
            "chainId": 10,
            "verifyingContract": "0x0000000000000000000000000000000000000000"
        })
    }

    /// Create a valid HyperMessage for signer add with EIP-712 custody signature.
    pub fn create_hyper_signer_add(
        fid: u64,
        signer_key: &SigningKey,
        custody_signer: PrivateKeySigner,
        nonce: u64,
        deadline: u64,
    ) -> crate::proto::HyperMessage {
        let key = signer_key.verifying_key().as_bytes().to_vec();

        let body = crate::proto::SignerAddBody {
            key: key.clone(),
            key_type: 1,
            deadline,
            nonce,
            metadata: None,
            metadata_type: None,
        };

        let data = crate::proto::HyperMessageData {
            r#type: crate::proto::HyperMessageType::SignerAdd as i32,
            fid,
            timestamp: time::farcaster_time(),
            network: FarcasterNetwork::Mainnet as i32,
            body: Some(crate::proto::hyper_message_data::Body::SignerAddBody(body)),
        };

        let data_bytes = data.encode_to_vec();
        let hash = blake3::hash(&data_bytes).as_bytes()[..20].to_vec();

        // EIP-712 signature
        let typed_data_json = json!({
            "types": signer_authorization_types(),
            "primaryType": "SignerAuthorization",
            "domain": signer_authorization_domain(),
            "message": {
                "fid": fid,
                "key": hex::encode(&key),
                "deadline": deadline,
                "nonce": nonce,
            },
        });

        let typed_data = serde_json::from_value::<TypedData>(typed_data_json).unwrap();
        let prehash = typed_data.eip712_signing_hash().unwrap();
        let sig = custody_signer.sign_hash_sync(&prehash).unwrap();
        let signature: Vec<u8> = sig.into();

        let custody_address = custody_signer.address().to_vec();

        crate::proto::HyperMessage {
            data: Some(data),
            hash: hash.clone(),
            hash_scheme: crate::proto::HashScheme::Blake3 as i32,
            signature,
            signature_scheme: crate::proto::SignatureScheme::Eip712 as i32,
            signer: custody_address,
            data_bytes: Some(data_bytes),
        }
    }

    /// Create a valid HyperMessage for signer remove with EIP-712 custody signature.
    pub fn create_hyper_signer_remove(
        fid: u64,
        signer_key: &SigningKey,
        custody_signer: PrivateKeySigner,
        nonce: u64,
        deadline: u64,
    ) -> crate::proto::HyperMessage {
        let key = signer_key.verifying_key().as_bytes().to_vec();

        let body = crate::proto::SignerRemoveBody {
            key: key.clone(),
            deadline,
            nonce,
        };

        let data = crate::proto::HyperMessageData {
            r#type: crate::proto::HyperMessageType::SignerRemove as i32,
            fid,
            timestamp: time::farcaster_time(),
            network: FarcasterNetwork::Mainnet as i32,
            body: Some(crate::proto::hyper_message_data::Body::SignerRemoveBody(
                body,
            )),
        };

        let data_bytes = data.encode_to_vec();
        let hash = blake3::hash(&data_bytes).as_bytes()[..20].to_vec();

        // EIP-712 signature
        let typed_data_json = json!({
            "types": signer_revocation_types(),
            "primaryType": "SignerRevocation",
            "domain": signer_authorization_domain(),
            "message": {
                "fid": fid,
                "key": hex::encode(&key),
                "deadline": deadline,
                "nonce": nonce,
            },
        });

        let typed_data = serde_json::from_value::<TypedData>(typed_data_json).unwrap();
        let prehash = typed_data.eip712_signing_hash().unwrap();
        let sig = custody_signer.sign_hash_sync(&prehash).unwrap();
        let signature: Vec<u8> = sig.into();

        let custody_address = custody_signer.address().to_vec();

        crate::proto::HyperMessage {
            data: Some(data),
            hash: hash.clone(),
            hash_scheme: crate::proto::HashScheme::Blake3 as i32,
            signature,
            signature_scheme: crate::proto::SignatureScheme::Eip712 as i32,
            signer: custody_address,
            data_bytes: Some(data_bytes),
        }
    }
}

pub mod hub_events_factory {
    use crate::proto;

    pub fn create_merge_event(message: &proto::Message) -> proto::HubEvent {
        proto::HubEvent {
            id: rand::random::<u64>(),
            r#type: proto::HubEventType::MergeMessage as i32,
            body: Some(proto::hub_event::Body::MergeMessageBody(
                proto::MergeMessageBody {
                    message: Some(message.clone()),
                    deleted_messages: vec![],
                },
            )),
            block_number: 0,
            shard_index: 0,
            timestamp: 0,
        }
    }
}
