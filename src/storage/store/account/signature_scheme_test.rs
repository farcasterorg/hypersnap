#[cfg(test)]
mod tests {
    //! Every message store must classify a message the same way whether it is
    //! signed with Ed25519 alone or with one of the Hypersnap schemes
    //! (FIP-proof-of-work-tokenization §16.8). If a store only recognises
    //! Ed25519, a validated scheme-3/4 message is rejected as "invalid message
    //! type" at merge time and never reaches state: a silent drop.
    use crate::proto::reaction_body::Target;
    use crate::proto::{self, ReactionType, SignatureScheme, StorageUnitType, UserDataType};
    use crate::storage::db::RocksDB;
    use crate::storage::store::account::{
        CastStore, LinkStore, ReactionStore, StorageLendStore, StoreDef, StoreEventHandler,
        UserDataStore, UsernameProofStore, VerificationStore,
    };
    use crate::utils::factory::messages_factory;
    use std::sync::Arc;
    use tempfile::TempDir;

    const ACCEPTED: [SignatureScheme; 3] = [
        SignatureScheme::Ed25519,
        SignatureScheme::Ed25519Falcon512,
        SignatureScheme::Falcon512,
    ];
    const REJECTED: [SignatureScheme; 2] = [SignatureScheme::None, SignatureScheme::Eip712];

    fn with_scheme(message: &proto::Message, scheme: SignatureScheme) -> proto::Message {
        let mut m = message.clone();
        m.signature_scheme = scheme as i32;
        m
    }

    fn assert_add<D: StoreDef>(def: &D, message: proto::Message) {
        for scheme in ACCEPTED {
            assert!(
                def.is_add_type(&with_scheme(&message, scheme)),
                "{:?} add rejected under {:?}",
                message.data.as_ref().unwrap().r#type,
                scheme
            );
        }
        for scheme in REJECTED {
            assert!(!def.is_add_type(&with_scheme(&message, scheme)));
        }
    }

    fn assert_remove<D: StoreDef>(def: &D, message: proto::Message) {
        for scheme in ACCEPTED {
            assert!(
                def.is_remove_type(&with_scheme(&message, scheme)),
                "{:?} remove rejected under {:?}",
                message.data.as_ref().unwrap().r#type,
                scheme
            );
        }
        for scheme in REJECTED {
            assert!(!def.is_remove_type(&with_scheme(&message, scheme)));
        }
    }

    fn db() -> (Arc<RocksDB>, TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let db = RocksDB::new(dir.path().join("test.db").to_str().unwrap());
        db.open().unwrap();
        (Arc::new(db), dir)
    }

    #[test]
    fn every_store_accepts_ed25519_and_hypersnap_schemes() {
        let (db, _dir) = db();
        let handler = StoreEventHandler::new();
        let fid = 1234;

        let casts = CastStore::new(db.clone(), handler.clone(), 10).store_def();
        let cast = messages_factory::casts::create_cast_add(fid, "hi", None, None);
        assert_add(&casts, cast.clone());
        assert_remove(
            &casts,
            messages_factory::casts::create_cast_remove(fid, &cast.hash, None, None),
        );

        let links = LinkStore::new(db.clone(), handler.clone(), 10).store_def();
        assert_add(
            &links,
            messages_factory::links::create_link_add(fid, "follow", 99, None, None),
        );
        assert_remove(
            &links,
            messages_factory::links::create_link_remove(fid, "follow", 99, None, None),
        );
        let compact =
            messages_factory::links::create_link_compact_state(fid, "follow", vec![99], None, None);
        for scheme in ACCEPTED {
            assert!(links.is_compact_state_type(&with_scheme(&compact, scheme)));
        }
        for scheme in REJECTED {
            assert!(!links.is_compact_state_type(&with_scheme(&compact, scheme)));
        }

        let reactions = ReactionStore::new(db.clone(), handler.clone(), 10).store_def();
        let target = Target::TargetUrl("https://example.com".to_string());
        assert_add(
            &reactions,
            messages_factory::reactions::create_reaction_add(
                fid,
                ReactionType::Like,
                target.clone(),
                None,
                None,
            ),
        );
        assert_remove(
            &reactions,
            messages_factory::reactions::create_reaction_remove(
                fid,
                ReactionType::Like,
                target,
                None,
                None,
            ),
        );

        let user_data = UserDataStore::new(db.clone(), handler.clone(), 10).store_def();
        assert_add(
            &user_data,
            messages_factory::user_data::create_user_data_add(
                fid,
                UserDataType::Bio,
                &"bio".to_string(),
                None,
                None,
            ),
        );

        let verifications = VerificationStore::new(db.clone(), handler.clone(), 10).store_def();
        let address = vec![0x11; 20];
        assert_add(
            &verifications,
            messages_factory::verifications::create_verification_add(
                fid,
                0,
                address.clone(),
                vec![0; 65],
                vec![0; 32],
                None,
                None,
            ),
        );
        assert_remove(
            &verifications,
            messages_factory::verifications::create_verification_remove(fid, address, None, None),
        );

        let proofs = UsernameProofStore::new(db.clone(), handler.clone(), 10).store_def();
        assert_add(
            &proofs,
            messages_factory::username_proof::create_username_proof(
                fid,
                proto::UserNameType::UsernameTypeEnsL1,
                "name.eth".to_string(),
                vec![0x22; 20],
                "sig".to_string(),
                1_700_000_000,
                None,
            ),
        );

        let lends = StorageLendStore::new(db.clone(), handler.clone(), 10).store_def();
        assert_add(
            &lends,
            messages_factory::storage_lend::create_storage_lend(
                fid,
                fid + 1,
                1,
                StorageUnitType::UnitTypeLegacy,
                None,
                None,
            ),
        );
    }
}
