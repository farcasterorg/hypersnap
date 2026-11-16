//! End-to-end merge tests for KEY_ADD, focused on the resubmission semantics added by
//! NEYN-10624: a same-FID KEY_ADD from the same originating app should upsert scope/TTL on an
//! existing gasless record rather than being rejected. Tests build fully-signed KEY_ADD
//! messages (SignedKeyRequest metadata + EIP-712 custody signature) so they exercise the real
//! crypto validation path alongside the state transitions.

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_signer_local::PrivateKeySigner;
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;

    use crate::core::validations::error::ValidationError;
    use crate::core::validations::key::{SIGN_IN_KEY_ADD_DOMAIN, SIGN_IN_KEY_REMOVE_DOMAIN};
    use crate::proto::{self, message_data::Body, IdRegisterEventType, MessageType};
    use crate::storage::db::{self, RocksDbTransactionBatch};
    use crate::storage::store::account::{
        get_gasless_key_owner_fid, get_gasless_key_record, get_last_used_at, merge_key_add,
        merge_key_add_with_options, merge_key_remove, merge_key_remove_with_options,
        OnchainEventStore, StoreEventHandler,
    };
    use crate::storage::store::engine::MessageValidationError;
    use crate::utils::factory::{events_factory, messages_factory, signers};

    /// Returns the 20-byte Ethereum address for a `PrivateKeySigner`, encoded as the custody
    /// address form expected by `IdRegisterEventBody.to`.
    fn address_bytes(signer: &PrivateKeySigner) -> Vec<u8> {
        signer.address().as_slice().to_vec()
    }

    /// Test scratch-pad: every ingredient `merge_key_add` inspects, in one mutable place. Callers
    /// tweak fields (scopes, ttl, nonce) and call [`Fixture::build`], which delegates to
    /// `messages_factory::keys::create_key_add` so the EIP-712 + envelope signing logic lives in
    /// exactly one place.
    struct Fixture {
        fid: u64,
        fid_custody: PrivateKeySigner,
        request_fid: u64,
        app_custody: PrivateKeySigner,
        envelope_signer: SigningKey,
        envelope_signer_pubkey: [u8; 32],
        scopes: Vec<i32>,
        ttl: u32,
        nonce: u32,
        deadline: u32,
        timestamp: u32,
    }

    impl Fixture {
        fn build(&self) -> proto::Message {
            let scopes: Vec<MessageType> = self
                .scopes
                .iter()
                .map(|s| MessageType::try_from(*s).unwrap())
                .collect();
            messages_factory::keys::create_key_add(
                self.fid,
                &self.fid_custody,
                self.request_fid,
                &self.app_custody,
                &self.envelope_signer,
                scopes,
                self.ttl,
                self.nonce,
                self.deadline,
                Some(self.timestamp),
            )
        }
    }

    struct World {
        db: Arc<db::RocksDB>,
        store: OnchainEventStore,
        _dir: TempDir,
    }

    fn new_world() -> World {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("gasless_key_merge.db");
        let rocks = db::RocksDB::new(db_path.to_str().unwrap());
        rocks.open().unwrap();
        let rocks = Arc::new(rocks);
        let store = OnchainEventStore::new(rocks.clone(), StoreEventHandler::new());
        World {
            db: rocks,
            store,
            _dir: dir,
        }
    }

    /// Registers the custody address for `fid` so `get_id_register_event_by_fid` resolves it
    /// during `merge_key_add`.
    fn register_custody(world: &World, fid: u64, custody: &PrivateKeySigner) {
        let event = events_factory::create_id_register_event(
            fid,
            IdRegisterEventType::Register,
            address_bytes(custody),
            None,
        );
        let mut txn = RocksDbTransactionBatch::new();
        world.store.merge_onchain_event(event, &mut txn).unwrap();
        world.db.commit(txn).unwrap();
    }

    fn fresh_fixture(fid: u64, request_fid: u64) -> Fixture {
        let envelope = signers::generate_signer();
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(envelope.verifying_key().as_bytes());
        Fixture {
            fid,
            fid_custody: PrivateKeySigner::random(),
            request_fid,
            app_custody: PrivateKeySigner::random(),
            envelope_signer: envelope,
            envelope_signer_pubkey: pubkey,
            scopes: vec![MessageType::CastAdd as i32],
            ttl: 3600,
            nonce: 1,
            deadline: 1_700_000_000,
            timestamp: 1_000_000_000,
        }
    }

    fn commit_merge(world: &World, msg: &proto::Message) {
        let mut txn = RocksDbTransactionBatch::new();
        merge_key_add(&world.db, &world.store, msg, &mut txn, false).unwrap();
        world.db.commit(txn).unwrap();
    }

    #[test]
    fn first_time_key_add_succeeds_and_persists_record() {
        let world = new_world();
        let f = fresh_fixture(7, 99);
        register_custody(&world, f.fid, &f.fid_custody);
        register_custody(&world, f.request_fid, &f.app_custody);

        commit_merge(&world, &f.build());

        let txn = RocksDbTransactionBatch::new();
        assert_eq!(
            get_gasless_key_owner_fid(&world.db, &txn, &f.envelope_signer_pubkey).unwrap(),
            Some(f.fid),
        );
        let stored = get_gasless_key_record(&world.db, &txn, f.fid, &f.envelope_signer_pubkey)
            .unwrap()
            .expect("record should exist");
        assert_eq!(stored.request_fid, f.request_fid);
    }

    #[test]
    fn resubmit_with_modified_scope_upserts_record() {
        let world = new_world();
        let mut f = fresh_fixture(7, 99);
        register_custody(&world, f.fid, &f.fid_custody);
        register_custody(&world, f.request_fid, &f.app_custody);

        // First KEY_ADD: scope = [CastAdd], ttl = 3600, nonce = 1.
        commit_merge(&world, &f.build());

        // Second KEY_ADD: broaden scope, bump TTL and timestamp, advance nonce. Same app
        // (same request_fid + same app_custody) and same envelope key as before.
        f.scopes = vec![MessageType::CastAdd as i32, MessageType::ReactionAdd as i32];
        f.ttl = 7200;
        f.nonce = 2;
        f.timestamp = 1_000_000_500;
        commit_merge(&world, &f.build());

        // The stored record's embedded message reflects the new scope/TTL — `active_key.rs`
        // re-derives the scope mask and TTL from `record.message` on every read, so updating
        // the embedded message is sufficient to change admission behavior.
        let txn = RocksDbTransactionBatch::new();
        let stored = get_gasless_key_record(&world.db, &txn, f.fid, &f.envelope_signer_pubkey)
            .unwrap()
            .unwrap();
        let body = match stored
            .message
            .as_ref()
            .unwrap()
            .data
            .as_ref()
            .unwrap()
            .body
            .as_ref()
            .unwrap()
        {
            Body::KeyAddBody(b) => b,
            _ => panic!("expected KeyAddBody"),
        };
        assert_eq!(
            body.scopes,
            vec![MessageType::CastAdd as i32, MessageType::ReactionAdd as i32],
        );
        assert_eq!(body.ttl, 7200);

        // last_used_at resets to the resubmission's timestamp — the sliding-TTL window
        // restarts on each accepted KEY_ADD (NEYN-10624 policy).
        let last_used = get_last_used_at(&world.db, &txn, f.fid, &f.envelope_signer_pubkey)
            .unwrap()
            .unwrap();
        assert_eq!(last_used, 1_000_000_500);
    }

    #[test]
    fn resubmit_returns_prior_message_in_deleted_messages() {
        let world = new_world();
        let mut f = fresh_fixture(7, 99);
        register_custody(&world, f.fid, &f.fid_custody);
        register_custody(&world, f.request_fid, &f.app_custody);

        let first = f.build();
        commit_merge(&world, &first);

        f.scopes = vec![MessageType::LinkAdd as i32];
        f.nonce = 2;
        f.timestamp = 1_000_000_500;
        let second = f.build();

        let mut txn = RocksDbTransactionBatch::new();
        let event = merge_key_add(&world.db, &world.store, &second, &mut txn, false).unwrap();

        let body = match event.body.as_ref().unwrap() {
            proto::hub_event::Body::MergeMessageBody(b) => b,
            _ => panic!("expected MergeMessageBody"),
        };
        assert_eq!(
            body.deleted_messages.len(),
            1,
            "upsert should surface prior KEY_ADD in deleted_messages",
        );
        // Cheap identity check: the prior embedded message carries the first nonce; the new
        // top-level `message` carries the second.
        let prior_body = match body.deleted_messages[0]
            .data
            .as_ref()
            .unwrap()
            .body
            .as_ref()
            .unwrap()
        {
            Body::KeyAddBody(b) => b,
            _ => panic!(),
        };
        assert_eq!(prior_body.nonce, 1);
        let new_body = match body
            .message
            .as_ref()
            .unwrap()
            .data
            .as_ref()
            .unwrap()
            .body
            .as_ref()
            .unwrap()
        {
            Body::KeyAddBody(b) => b,
            _ => panic!(),
        };
        assert_eq!(new_body.nonce, 2);
    }

    #[test]
    fn resubmit_with_stale_nonce_rejected() {
        let world = new_world();
        let mut f = fresh_fixture(7, 99);
        register_custody(&world, f.fid, &f.fid_custody);
        register_custody(&world, f.request_fid, &f.app_custody);

        f.nonce = 5;
        commit_merge(&world, &f.build());

        // Same nonce again: `check_and_set_user_nonce` rejects `new_nonce <= stored`.
        f.scopes = vec![MessageType::LinkAdd as i32];
        f.timestamp = 1_000_000_500;
        let mut txn = RocksDbTransactionBatch::new();
        let err = merge_key_add(&world.db, &world.store, &f.build(), &mut txn, false).unwrap_err();
        assert!(
            matches!(err, MessageValidationError::StoreError(_)),
            "expected StoreError from nonce CAS, got {err:?}",
        );
    }

    #[test]
    fn resubmit_by_different_app_rejected() {
        let world = new_world();
        let mut f = fresh_fixture(7, 99);
        register_custody(&world, f.fid, &f.fid_custody);
        register_custody(&world, f.request_fid, &f.app_custody);

        commit_merge(&world, &f.build());

        // Same fid + envelope key, but a different app custody signs a metadata for a
        // different request_fid. Register that app so the metadata verification passes, then
        // expect `merge_key_add` to reject because the stored record's `request_fid` differs.
        let different_app = PrivateKeySigner::random();
        let different_request_fid = 123;
        register_custody(&world, different_request_fid, &different_app);

        f.request_fid = different_request_fid;
        f.app_custody = different_app;
        f.nonce = 2;
        f.timestamp = 1_000_000_500;
        let mut txn = RocksDbTransactionBatch::new();
        let err = merge_key_add(&world.db, &world.store, &f.build(), &mut txn, false).unwrap_err();
        match err {
            MessageValidationError::MessageValidationError(
                ValidationError::KeyRegisteredByDifferentRequestingFid,
            ) => {}
            other => panic!("expected KeyRegisteredByDifferentRequestingFid, got {other:?}"),
        }
    }

    #[test]
    fn cross_user_collision_rejected() {
        // Two different FIDs can't both hold a gasless registration for the same Ed25519 key.
        // The first KEY_ADD establishes the owner; the second (different fid, otherwise valid)
        // hits the owner-mismatch branch and is rejected.
        let world = new_world();
        let f = fresh_fixture(7, 99);
        register_custody(&world, f.fid, &f.fid_custody);
        register_custody(&world, f.request_fid, &f.app_custody);
        commit_merge(&world, &f.build());

        // Second FID, different custody, same app, same envelope key.
        let fid_b = 8;
        let fid_b_custody = PrivateKeySigner::random();
        register_custody(&world, fid_b, &fid_b_custody);

        // Reuse the same envelope key + app from `f` so this attempt targets the existing
        // owner's key and passes metadata verification.
        let mut f_b = fresh_fixture(fid_b, f.request_fid);
        f_b.fid = fid_b;
        f_b.fid_custody = fid_b_custody;
        f_b.nonce = 1;
        f_b.timestamp = 1_000_000_500;
        f_b.envelope_signer = f.envelope_signer.clone();
        f_b.envelope_signer_pubkey = f.envelope_signer_pubkey;
        f_b.app_custody = f.app_custody.clone();

        let mut txn = RocksDbTransactionBatch::new();
        let err =
            merge_key_add(&world.db, &world.store, &f_b.build(), &mut txn, false).unwrap_err();
        match err {
            MessageValidationError::MessageValidationError(
                ValidationError::KeyClaimedByDifferentFid,
            ) => {}
            other => panic!("expected KeyClaimedByDifferentFid, got {other:?}"),
        }
    }

    // -- Sign-in authorization (ProtocolFeature::SignInKeyAuthorization) --------------------------

    /// The fixture's KEY_ADD, authorized by `sign_in_signer` approving a sign-in to `domain`
    /// instead of signing the EIP-712 payload.
    fn build_sign_in_for(
        f: &Fixture,
        sign_in_signer: &PrivateKeySigner,
        domain: &str,
    ) -> proto::Message {
        let scopes: Vec<MessageType> = f
            .scopes
            .iter()
            .map(|s| MessageType::try_from(*s).unwrap())
            .collect();
        messages_factory::keys::create_key_add_with_sign_in(
            f.fid,
            sign_in_signer,
            domain,
            f.request_fid,
            &f.app_custody,
            &f.envelope_signer,
            scopes,
            f.ttl,
            f.nonce,
            f.deadline,
            f.timestamp,
        )
    }

    fn build_sign_in(f: &Fixture, sign_in_signer: &PrivateKeySigner) -> proto::Message {
        build_sign_in_for(f, sign_in_signer, SIGN_IN_KEY_ADD_DOMAIN)
    }

    fn merge_sign_in(
        world: &World,
        msg: &proto::Message,
        enabled: bool,
    ) -> Result<proto::HubEvent, MessageValidationError> {
        let mut txn = RocksDbTransactionBatch::new();
        let result =
            merge_key_add_with_options(&world.db, &world.store, msg, &mut txn, false, enabled);
        if result.is_ok() {
            world.db.commit(txn).unwrap();
        }
        result
    }

    fn merge_remove(
        world: &World,
        msg: &proto::Message,
        enabled: bool,
    ) -> Result<proto::HubEvent, MessageValidationError> {
        let mut txn = RocksDbTransactionBatch::new();
        let result = merge_key_remove_with_options(&world.db, &world.store, msg, &mut txn, enabled);
        if result.is_ok() {
            world.db.commit(txn).unwrap();
        }
        result
    }

    /// A removal of the fixture's key, approved by `sign_in_signer` as a sign-in to `domain`.
    fn build_sign_in_remove(
        f: &Fixture,
        sign_in_signer: &PrivateKeySigner,
        domain: &str,
        nonce: u32,
    ) -> proto::Message {
        messages_factory::keys::create_key_remove_sign_in(
            f.fid,
            sign_in_signer,
            domain,
            &f.envelope_signer,
            &f.envelope_signer_pubkey,
            nonce,
            f.deadline,
            f.timestamp + 60,
        )
    }

    fn key_owner(world: &World, f: &Fixture) -> Option<u64> {
        let txn = RocksDbTransactionBatch::new();
        get_gasless_key_owner_fid(&world.db, &txn, &f.envelope_signer_pubkey).unwrap()
    }

    fn expect_validation_error(
        result: Result<proto::HubEvent, MessageValidationError>,
        expected: ValidationError,
    ) {
        match result {
            Err(MessageValidationError::MessageValidationError(err)) if err == expected => {}
            other => panic!("expected {expected:?}, got {other:?}"),
        }
    }

    fn sign_in_world() -> (World, Fixture) {
        let world = new_world();
        let f = fresh_fixture(7, 99);
        register_custody(&world, f.fid, &f.fid_custody);
        register_custody(&world, f.request_fid, &f.app_custody);
        (world, f)
    }

    #[test]
    fn sign_in_by_custody_address_adds_key() {
        let (world, f) = sign_in_world();
        let msg = build_sign_in(&f, &f.fid_custody);

        merge_sign_in(&world, &msg, true).unwrap();

        assert_eq!(key_owner(&world, &f), Some(f.fid));
        // The stored record keeps the whole message, so how the key was authorized stays
        // readable for as long as it exists.
        let txn = RocksDbTransactionBatch::new();
        let record = get_gasless_key_record(&world.db, &txn, f.fid, &f.envelope_signer_pubkey)
            .unwrap()
            .unwrap();
        match record.message.unwrap().data.unwrap().body.unwrap() {
            Body::KeyAddBody(body) => {
                assert_eq!(body.authorization_type, 200);
                let text = String::from_utf8(body.authorization_message).unwrap();
                assert!(text.starts_with("grant-account-access.hypersnap wants you to sign in"));
            }
            other => panic!("expected KeyAddBody, got {other:?}"),
        }
    }

    /// The reserved domain is the consent: a sign-in to any other name, signed by the right
    /// custody key and committing to the right payload, adds nothing.
    #[test]
    fn sign_in_to_any_other_domain_adds_nothing() {
        for domain in [
            "client.example",
            "onterminus.com",
            "grant-account-access.hypersnap.evil.example",
            "revoke-account-access.hypersnap",
        ] {
            let (world, f) = sign_in_world();
            expect_validation_error(
                merge_sign_in(&world, &build_sign_in_for(&f, &f.fid_custody, domain), true),
                ValidationError::InvalidSignInMessage,
            );
            assert_eq!(key_owner(&world, &f), None);
        }
    }

    #[test]
    fn sign_in_by_unrelated_address_rejected() {
        let (world, f) = sign_in_world();
        let stranger = PrivateKeySigner::random();

        expect_validation_error(
            merge_sign_in(&world, &build_sign_in(&f, &stranger), true),
            ValidationError::InvalidSignature,
        );
    }

    /// Only the custody address counts. An auth address (KeyRegistry key type 2) exists to
    /// approve sign-ins, but it is not accepted here.
    #[test]
    fn sign_in_by_auth_address_rejected() {
        let (world, f) = sign_in_world();
        let auth = PrivateKeySigner::random();
        let mut event = events_factory::create_signer_event(
            f.fid,
            signers::generate_signer(),
            proto::SignerEventType::Add,
            Some(1_700_000_000),
            Some(2),
        );
        let mut key = vec![0u8; 12];
        key.extend_from_slice(auth.address().as_slice());
        match &mut event.body {
            Some(proto::on_chain_event::Body::SignerEventBody(body)) => body.key = key,
            other => panic!("expected a signer event, got {other:?}"),
        }
        let mut txn = RocksDbTransactionBatch::new();
        world.store.merge_onchain_event(event, &mut txn).unwrap();
        world.db.commit(txn).unwrap();

        expect_validation_error(
            merge_sign_in(&world, &build_sign_in(&f, &auth), true),
            ValidationError::InvalidSignature,
        );
    }

    /// The approval commits to the payload: changing anything the nonce covers after the user
    /// approved invalidates it.
    #[test]
    fn sign_in_does_not_cover_a_changed_payload() {
        let (world, f) = sign_in_world();
        let mut msg = build_sign_in(&f, &f.fid_custody);
        match msg.data.as_mut().unwrap().body.as_mut().unwrap() {
            Body::KeyAddBody(body) => body.scopes.push(MessageType::ReactionAdd as i32),
            other => panic!("expected KeyAddBody, got {other:?}"),
        }

        expect_validation_error(
            merge_sign_in(&world, &msg, true),
            ValidationError::InvalidSignInMessage,
        );
    }

    /// A key added by sign-in is not a lesser key: it may hold every scope a custody-authorized
    /// key may.
    #[test]
    fn sign_in_can_grant_every_admissible_scope() {
        let (world, mut f) = sign_in_world();
        f.scopes = [
            MessageType::CastAdd,
            MessageType::CastRemove,
            MessageType::ReactionAdd,
            MessageType::ReactionRemove,
            MessageType::LinkAdd,
            MessageType::LinkRemove,
            MessageType::LinkCompactState,
            MessageType::VerificationAddEthAddress,
            MessageType::VerificationRemove,
            MessageType::UserDataAdd,
            MessageType::UsernameProof,
            MessageType::FrameAction,
            MessageType::LendStorage,
        ]
        .iter()
        .map(|s| *s as i32)
        .collect();

        merge_sign_in(&world, &build_sign_in(&f, &f.fid_custody), true).unwrap();
        assert_eq!(key_owner(&world, &f), Some(f.fid));
    }

    #[test]
    fn sign_in_key_ttl_is_capped_below_the_custody_limit() {
        use crate::core::validations::key::MAX_SIGN_IN_KEY_TTL_SECONDS;

        let (world, mut f) = sign_in_world();
        f.ttl = MAX_SIGN_IN_KEY_TTL_SECONDS + 1;
        expect_validation_error(
            merge_sign_in(&world, &build_sign_in(&f, &f.fid_custody), true),
            ValidationError::InvalidTtl(MAX_SIGN_IN_KEY_TTL_SECONDS),
        );

        f.ttl = MAX_SIGN_IN_KEY_TTL_SECONDS;
        merge_sign_in(&world, &build_sign_in(&f, &f.fid_custody), true).unwrap();
    }

    #[test]
    fn sign_in_message_must_be_recent() {
        use crate::core::validations::sign_in::MAX_SIGN_IN_AGE_SECONDS;

        let (world, f) = sign_in_world();
        let mut msg = build_sign_in(&f, &f.fid_custody);
        // Submit the KEY_ADD long after the sign-in was approved. The envelope is not
        // re-verified by `merge_key_add`, so moving the timestamp is enough.
        msg.data.as_mut().unwrap().timestamp = f.timestamp + MAX_SIGN_IN_AGE_SECONDS as u32 + 1;

        expect_validation_error(
            merge_sign_in(&world, &msg, true),
            ValidationError::SignInMessageExpired,
        );
    }

    /// Before the feature activates the field is not read: the same message takes the custody
    /// path, where a sign-in signature does not recover the custody address. This is what a
    /// binary that predates the field does with it.
    #[test]
    fn sign_in_is_ignored_until_the_feature_is_active() {
        let (world, f) = sign_in_world();
        let msg = build_sign_in(&f, &f.fid_custody);

        expect_validation_error(
            merge_sign_in(&world, &msg, false),
            ValidationError::InvalidSignature,
        );
        // `merge_key_add` is the pre-feature entry point and behaves the same.
        let mut txn = RocksDbTransactionBatch::new();
        expect_validation_error(
            merge_key_add(&world.db, &world.store, &msg, &mut txn, false),
            ValidationError::InvalidSignature,
        );

        merge_sign_in(&world, &msg, true).unwrap();
    }

    #[test]
    fn unknown_authorization_type_rejected_once_active() {
        let (world, f) = sign_in_world();
        let mut msg = f.build();
        match msg.data.as_mut().unwrap().body.as_mut().unwrap() {
            Body::KeyAddBody(body) => body.authorization_type = 3,
            other => panic!("expected KeyAddBody, got {other:?}"),
        }

        expect_validation_error(
            merge_sign_in(&world, &msg, true),
            ValidationError::InvalidSignatureType,
        );
        // Dormant: the field is ignored and the valid custody signature is accepted.
        merge_sign_in(&world, &msg, false).unwrap();
    }

    #[test]
    fn custody_signature_still_accepted_once_active() {
        let (world, f) = sign_in_world();
        merge_sign_in(&world, &f.build(), true).unwrap();
    }

    // -- Removal by sign-in -----------------------------------------------------------------------

    #[test]
    fn sign_in_removes_a_key_added_by_sign_in() {
        let (world, f) = sign_in_world();
        merge_sign_in(&world, &build_sign_in(&f, &f.fid_custody), true).unwrap();
        assert_eq!(key_owner(&world, &f), Some(f.fid));

        let remove = build_sign_in_remove(&f, &f.fid_custody, SIGN_IN_KEY_REMOVE_DOMAIN, 2);
        merge_remove(&world, &remove, true).unwrap();

        assert_eq!(key_owner(&world, &f), None);
        let txn = RocksDbTransactionBatch::new();
        assert!(
            get_gasless_key_record(&world.db, &txn, f.fid, &f.envelope_signer_pubkey)
                .unwrap()
                .is_none()
        );
    }

    /// Removal by sign-in is not limited to keys that were added by sign-in.
    #[test]
    fn sign_in_removes_a_custody_authorized_key() {
        let (world, f) = sign_in_world();
        commit_merge(&world, &f.build());

        let remove = build_sign_in_remove(&f, &f.fid_custody, SIGN_IN_KEY_REMOVE_DOMAIN, 2);
        merge_remove(&world, &remove, true).unwrap();
        assert_eq!(key_owner(&world, &f), None);
    }

    #[test]
    fn sign_in_removal_needs_the_removal_domain() {
        let (world, f) = sign_in_world();
        merge_sign_in(&world, &build_sign_in(&f, &f.fid_custody), true).unwrap();

        // An approval to add keys, or to sign in anywhere else, removes nothing.
        for domain in [SIGN_IN_KEY_ADD_DOMAIN, "client.example"] {
            expect_validation_error(
                merge_remove(
                    &world,
                    &build_sign_in_remove(&f, &f.fid_custody, domain, 2),
                    true,
                ),
                ValidationError::InvalidSignInMessage,
            );
        }
        assert_eq!(key_owner(&world, &f), Some(f.fid));
    }

    #[test]
    fn sign_in_removal_by_unrelated_address_rejected() {
        let (world, f) = sign_in_world();
        merge_sign_in(&world, &build_sign_in(&f, &f.fid_custody), true).unwrap();
        let stranger = PrivateKeySigner::random();

        expect_validation_error(
            merge_remove(
                &world,
                &build_sign_in_remove(&f, &stranger, SIGN_IN_KEY_REMOVE_DOMAIN, 2),
                true,
            ),
            ValidationError::InvalidSignature,
        );
        assert_eq!(key_owner(&world, &f), Some(f.fid));
    }

    /// One approval removes one key once. The nonce commits to the key and to the user nonce,
    /// so it cannot be pointed at another key or replayed after the key is added again.
    #[test]
    fn sign_in_removal_cannot_be_replayed_or_retargeted() {
        let (world, mut f) = sign_in_world();
        merge_sign_in(&world, &build_sign_in(&f, &f.fid_custody), true).unwrap();
        let remove = build_sign_in_remove(&f, &f.fid_custody, SIGN_IN_KEY_REMOVE_DOMAIN, 2);

        // Pointed at a different key: the nonce no longer matches.
        let mut retargeted = remove.clone();
        let other_key = signers::generate_signer().verifying_key().to_bytes();
        match retargeted.data.as_mut().unwrap().body.as_mut().unwrap() {
            Body::KeyRemoveBody(body) => body.key = other_key.to_vec(),
            other => panic!("expected KeyRemoveBody, got {other:?}"),
        }
        expect_validation_error(
            merge_remove(&world, &retargeted, true),
            ValidationError::KeyNotRegistered,
        );

        merge_remove(&world, &remove, true).unwrap();

        // The same key added again under a later nonce: the old removal is stale.
        f.nonce = 3;
        merge_sign_in(&world, &build_sign_in(&f, &f.fid_custody), true).unwrap();
        let replay = merge_remove(&world, &remove, true);
        assert!(
            matches!(replay, Err(MessageValidationError::StoreError(_))),
            "expected the nonce check to reject the replay, got {replay:?}"
        );
        assert_eq!(key_owner(&world, &f), Some(f.fid));
    }

    /// Dormant: type 200 is rejected the way binaries that predate it reject it.
    #[test]
    fn sign_in_removal_rejected_until_the_feature_is_active() {
        let (world, f) = sign_in_world();
        commit_merge(&world, &f.build());
        let remove = build_sign_in_remove(&f, &f.fid_custody, SIGN_IN_KEY_REMOVE_DOMAIN, 2);

        expect_validation_error(
            merge_remove(&world, &remove, false),
            ValidationError::InvalidSignatureType,
        );
        let mut txn = RocksDbTransactionBatch::new();
        expect_validation_error(
            merge_key_remove(&world.db, &world.store, &remove, &mut txn),
            ValidationError::InvalidSignatureType,
        );
        assert_eq!(key_owner(&world, &f), Some(f.fid));
    }
}
