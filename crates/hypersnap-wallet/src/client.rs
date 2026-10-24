//! A client of the submit endpoint of a Hypersnap node (`submit_address`).
//!
//! `POST /v1/submitMessage` takes a protobuf `Message`. The node checks it
//! with the rules of the gRPC `SubmitMessage` (shard 0 simulates it in
//! block order) and answers 200, or 400 with the reason.

use crate::error::WalletError;
use hypersnap_proto::Message;
use prost::Message as _;

pub struct HypersnapClient {
    base_url: String,
    authorization: Option<String>,
    http: reqwest::Client,
}

/// The tip of shard 0 (`GET /v1/shard0/tip`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shard0Tip {
    pub height: u64,
    pub hash: String,
    pub epoch: u64,
}

impl HypersnapClient {
    pub fn new(node_url: &str) -> Self {
        Self {
            base_url: node_url.trim_end_matches('/').to_string(),
            authorization: None,
            http: reqwest::Client::new(),
        }
    }

    /// The `authorization` header value for a node with `rpc_auth` (for
    /// example `Basic <base64(user:password)>`).
    pub fn with_authorization(mut self, value: impl Into<String>) -> Self {
        self.authorization = Some(value.into());
        self
    }

    /// Submit a signed message.
    pub async fn submit(&self, message: &Message) -> Result<(), WalletError> {
        let mut request = self
            .http
            .post(format!("{}/v1/submitMessage", self.base_url))
            .header("content-type", "application/octet-stream")
            .body(message.encode_to_vec());
        if let Some(auth) = &self.authorization {
            request = request.header("authorization", auth);
        }
        let resp = request.send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(WalletError::NodeError { status, body })
        }
    }

    pub async fn shard0_tip(&self) -> Result<Shard0Tip, WalletError> {
        let resp = self
            .http
            .get(format!("{}/v1/shard0/tip", self.base_url))
            .send()
            .await?;
        let status = resp.status().as_u16();
        let body = resp.text().await?;
        if status != 200 {
            return Err(WalletError::NodeError { status, body });
        }
        let v: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| WalletError::NodeError {
                status,
                body: e.to_string(),
            })?;
        Ok(Shard0Tip {
            height: v["height"].as_u64().unwrap_or(0),
            hash: v["hash"].as_str().unwrap_or_default().to_string(),
            epoch: v["epoch"].as_u64().unwrap_or(0),
        })
    }
}
