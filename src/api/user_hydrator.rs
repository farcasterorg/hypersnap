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
            profile: UserProfile {
                bio: Bio {
                    text: String::new(),
                },
            },
            follower_count: 0,
            following_count: 0,
            verifications: Vec::new(),
            verified_addresses: VerifiedAddresses::default(),
            viewer_context: None,
        };

        // Fetch user data (username, display name, pfp, bio)
        self.populate_user_data(fid, &mut user).await;

        // Fetch verifications
        self.populate_verifications(fid, &mut user).await;

        // Fetch custody address
        self.populate_custody_address(fid, &mut user).await;

        // Fetch follower/following counts from social graph index
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
        let mut users = Vec::with_capacity(fids.len());
        for &fid in fids {
            match self.hydrate_user(fid).await {
                Some(user) => users.push(user),
                None => {
                    // Shouldn't happen since hydrate_user always returns Some,
                    // but fall back to stub if it ever does
                    users.push(User {
                        object: "user".to_string(),
                        fid,
                        username: format!("fid:{}", fid),
                        ..Default::default()
                    });
                }
            }
        }
        users
    }
}

impl<S> HubUserHydrator<S>
where
    S: proto::hub_service_server::HubService + Send + Sync + 'static,
{
    async fn populate_user_data(&self, fid: u64, user: &mut User) {
        let request = Request::new(proto::FidRequest {
            fid,
            page_size: None,
            page_token: None,
            reverse: None,
        });

        let Ok(response) = self.hub_service.get_user_data_by_fid(request).await else {
            return;
        };

        for message in &response.get_ref().messages {
            let Some(data) = &message.data else {
                continue;
            };
            let Some(Body::UserDataBody(body)) = &data.body else {
                continue;
            };

            match UserDataType::try_from(body.r#type) {
                Ok(UserDataType::Username) => {
                    user.username = body.value.clone();
                }
                Ok(UserDataType::Display) => {
                    user.display_name = Some(body.value.clone());
                }
                Ok(UserDataType::Pfp) => {
                    user.pfp_url = Some(body.value.clone());
                }
                Ok(UserDataType::Bio) => {
                    user.profile.bio.text = body.value.clone();
                }
                _ => {}
            }
        }
    }

    async fn populate_verifications(&self, fid: u64, user: &mut User) {
        let request = Request::new(proto::FidRequest {
            fid,
            page_size: None,
            page_token: None,
            reverse: None,
        });

        let Ok(response) = self.hub_service.get_verifications_by_fid(request).await else {
            return;
        };

        for message in &response.get_ref().messages {
            let Some(data) = &message.data else {
                continue;
            };
            let Some(Body::VerificationAddAddressBody(body)) = &data.body else {
                continue;
            };

            let addr = format!("0x{}", hex::encode(&body.address));
            user.verifications.push(addr.clone());

            match Protocol::try_from(body.protocol) {
                Ok(Protocol::Ethereum) => {
                    user.verified_addresses.eth_addresses.push(addr);
                }
                Ok(Protocol::Solana) => {
                    // Solana addresses are base58, not hex
                    let sol_addr = bs58::encode(&body.address).into_string();
                    user.verified_addresses.sol_addresses.push(sol_addr);
                }
                _ => {}
            }
        }
    }

    async fn populate_custody_address(&self, fid: u64, user: &mut User) {
        if let Some(addr) = self.fetch_custody_address(fid).await {
            user.custody_address = format!("0x{}", hex::encode(addr.as_slice()));
        }
    }

    async fn fetch_custody_address(&self, fid: u64) -> Option<Address> {
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
        let proto::on_chain_event::Body::IdRegisterEventBody(body) = event.body.as_ref()? else {
            return None;
        };
        if body.to.len() != 20 {
            return None;
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&body.to);
        Some(Address::from(bytes))
    }
}

#[async_trait]
impl<S> CustodyAddressLookup for HubUserHydrator<S>
where
    S: proto::hub_service_server::HubService + Send + Sync + 'static,
{
    async fn get_custody_address(&self, fid: u64) -> Option<Address> {
        self.fetch_custody_address(fid).await
    }
}
