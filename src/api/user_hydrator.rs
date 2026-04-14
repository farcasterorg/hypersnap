//! User hydration service for populating User objects from hub data.
//!
//! Fetches user data, verifications, and custody address from the hub service
//! to build complete User objects for API responses.

use crate::api::http::UserHydrator;
use crate::api::social_graph::SocialGraphIndexer;
use crate::api::types::{Bio, User, UserProfile, VerifiedAddresses};
use crate::api::webhooks::CustodyAddressLookup;
use crate::proto::{self, message_data::Body, Protocol, UserDataType};
use alloy_primitives::Address;
use async_trait::async_trait;
use std::sync::Arc;
use tonic::Request;

/// User hydrator backed by a HubService implementation.
pub struct HubUserHydrator<S> {
    hub_service: Arc<S>,
    social_graph: Option<Arc<SocialGraphIndexer>>,
}

impl<S> HubUserHydrator<S> {
    pub fn new(hub_service: Arc<S>, social_graph: Option<Arc<SocialGraphIndexer>>) -> Self {
        Self {
            hub_service,
            social_graph,
        }
    }
}

#[async_trait]
impl<S> UserHydrator for HubUserHydrator<S>
where
    S: proto::hub_service_server::HubService + Send + Sync + 'static,
{
    async fn hydrate_user(&self, fid: u64) -> Option<User> {
        let mut user = User {
            object: "user".to_string(),
            fid,
            username: format!("fid:{}", fid),
            display_name: None,
            custody_address: String::new(),
            pfp_url: None,
            registered_at: String::new(),
            profile: UserProfile {
                bio: Bio {
                    text: String::new(),
                },
                location: None,
                banner: None,
            },
            follower_count: 0,
            following_count: 0,
            verifications: Vec::new(),
            auth_addresses: Vec::new(),
            verified_addresses: VerifiedAddresses::default(),
            verified_accounts: Vec::new(),
            viewer_context: None,
            score: None,
            followed_at: None,
        };

        // Fire the three independent hub reads in parallel — they each
        // hit different stores, so there's no contention.
        let (ud, verifications, custody) = tokio::join!(
            self.fetch_user_data(fid),
            self.fetch_verifications(fid),
            self.fetch_custody_info(fid),
        );

        if let Some(fields) = ud {
            if let Some(v) = fields.username {
                user.username = v;
            }
            user.display_name = fields.display_name;
            user.pfp_url = fields.pfp_url;
            if let Some(bio) = fields.bio {
                user.profile.bio.text = bio;
            }
        }

        for (addr, proto) in verifications {
            user.verifications.push(addr.clone());
            match proto {
                Some(Protocol::Ethereum) => {
                    user.verified_addresses.eth_addresses.push(addr.clone());
                    if user.verified_addresses.primary.eth_address.is_none() {
                        user.verified_addresses.primary.eth_address = Some(addr);
                    }
                }
                Some(Protocol::Solana) => {
                    user.verified_addresses.sol_addresses.push(addr.clone());
                    if user.verified_addresses.primary.sol_address.is_none() {
                        user.verified_addresses.primary.sol_address = Some(addr);
                    }
                }
                _ => {}
            }
        }

        if let Some(info) = custody {
            user.custody_address = format!("0x{}", hex::encode(info.address.as_slice()));
            if info.block_timestamp > 0 {
                user.registered_at =
                    chrono::DateTime::from_timestamp(info.block_timestamp as i64, 0)
                        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
                        .unwrap_or_default();
            }
        }

        // Follower/following counts are direct RocksDB gets on the
        // API-layer index — no gRPC round-trip.
        if let Some(ref sg) = self.social_graph {
            if let Ok(count) = sg.get_follower_count(fid) {
                user.follower_count = count;
            }
            if let Ok(count) = sg.get_following_count(fid) {
                user.following_count = count;
            }
        }

        Some(user)
    }

    async fn hydrate_users(&self, fids: &[u64]) -> Vec<User> {
        // Parallelize: N independent hydrations can run concurrently.
        let futures = fids.iter().map(|&fid| async move {
            match self.hydrate_user(fid).await {
                Some(user) => user,
                None => User {
                    fid,
                    username: format!("fid:{}", fid),
                    ..Default::default()
                },
            }
        });
        futures::future::join_all(futures).await
    }
}

/// Extracted user-data fields from a single `get_user_data_by_fid` call.
struct UserDataFields {
    username: Option<String>,
    display_name: Option<String>,
    pfp_url: Option<String>,
    bio: Option<String>,
}

impl<S> HubUserHydrator<S>
where
    S: proto::hub_service_server::HubService + Send + Sync + 'static,
{
    async fn fetch_user_data(&self, fid: u64) -> Option<UserDataFields> {
        let request = Request::new(proto::FidRequest {
            fid,
            page_size: None,
            page_token: None,
            reverse: None,
        });

        let response = self.hub_service.get_user_data_by_fid(request).await.ok()?;

        let mut fields = UserDataFields {
            username: None,
            display_name: None,
            pfp_url: None,
            bio: None,
        };

        for message in &response.get_ref().messages {
            let Some(data) = &message.data else {
                continue;
            };
            let Some(Body::UserDataBody(body)) = &data.body else {
                continue;
            };

            match UserDataType::try_from(body.r#type) {
                Ok(UserDataType::Username) => fields.username = Some(body.value.clone()),
                Ok(UserDataType::Display) => fields.display_name = Some(body.value.clone()),
                Ok(UserDataType::Pfp) => fields.pfp_url = Some(body.value.clone()),
                Ok(UserDataType::Bio) => fields.bio = Some(body.value.clone()),
                _ => {}
            }
        }

        Some(fields)
    }

    /// Returns `(formatted_address, protocol)` pairs. Solana addresses
    /// are returned pre-encoded in base58.
    async fn fetch_verifications(&self, fid: u64) -> Vec<(String, Option<Protocol>)> {
        let request = Request::new(proto::FidRequest {
            fid,
            page_size: None,
            page_token: None,
            reverse: None,
        });

        let Ok(response) = self.hub_service.get_verifications_by_fid(request).await else {
            return Vec::new();
        };

        let mut out = Vec::new();
        for message in &response.get_ref().messages {
            let Some(data) = &message.data else {
                continue;
            };
            let Some(Body::VerificationAddAddressBody(body)) = &data.body else {
                continue;
            };

            let proto_enum = Protocol::try_from(body.protocol).ok();
            let addr = match proto_enum {
                Some(Protocol::Solana) => bs58::encode(&body.address).into_string(),
                _ => format!("0x{}", hex::encode(&body.address)),
            };
            out.push((addr, proto_enum));
        }
        out
    }

    /// Fetch the FID's current custody address along with the on-chain
    /// block timestamp of the registration event. Returns `None` when
    /// the FID has no `IdRegistry` event yet, or when the event body
    /// is malformed.
    async fn fetch_custody_info(&self, fid: u64) -> Option<CustodyInfo> {
        let request = Request::new(proto::FidRequest {
            fid,
            page_size: None,
            page_token: None,
            reverse: None,
        });

        let response = self
            .hub_service
            .get_id_registry_on_chain_event(request)
            .await
            .ok()?;
        let event = response.get_ref();
        let block_timestamp = event.block_timestamp;
        let proto::on_chain_event::Body::IdRegisterEventBody(body) = event.body.as_ref()? else {
            return None;
        };
        if body.to.len() != 20 {
            return None;
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&body.to);
        Some(CustodyInfo {
            address: Address::from(bytes),
            block_timestamp,
        })
    }
}

/// Snapshot of the data the hydrator extracts from a single
/// `IdRegistry` on-chain event.
struct CustodyInfo {
    address: Address,
    block_timestamp: u64,
}

#[async_trait]
impl<S> CustodyAddressLookup for HubUserHydrator<S>
where
    S: proto::hub_service_server::HubService + Send + Sync + 'static,
{
    async fn get_custody_address(&self, fid: u64) -> Option<Address> {
        self.fetch_custody_info(fid).await.map(|info| info.address)
    }
}
