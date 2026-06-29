use crate::error::WalletError;
use hypersnap_proto as proto;
use prost::Message;

pub struct HypersnapClient {
    base_url: String,
    http: reqwest::Client,
}

impl HypersnapClient {
    pub fn new(node_url: &str) -> Self {
        Self {
            base_url: node_url.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn balance(&self, fid: u64) -> Result<u64, WalletError> {
        let url = format!("{}/hyper/v1/rewards/{}", self.base_url, fid);
        let resp = self.http.get(&url).send().await?;
        self.check_status(&resp).await?;
        let body: serde_json::Value = resp.json().await?;
        Ok(body["balance"].as_u64().unwrap_or(0))
    }

    pub async fn fee_balance(&self, fid: u64) -> Result<u64, WalletError> {
        let url = format!("{}/hyper/v1/rewards/{}", self.base_url, fid);
        let resp = self.http.get(&url).send().await?;
        self.check_status(&resp).await?;
        let body: serde_json::Value = resp.json().await?;
        Ok(body["fee_balance"].as_u64().unwrap_or(0))
    }

    pub async fn nonce(&self, fid: u64) -> Result<u64, WalletError> {
        let url = format!("{}/hyper/v1/nonce/{}", self.base_url, fid);
        let resp = self.http.get(&url).send().await?;
        self.check_status(&resp).await?;
        let body: serde_json::Value = resp.json().await?;
        Ok(body["nonce"].as_u64().unwrap_or(0))
    }

    pub async fn staked_breakdown(&self, fid: u64) -> Result<serde_json::Value, WalletError> {
        let url = format!("{}/hyper/v1/staked/{}", self.base_url, fid);
        let resp = self.http.get(&url).send().await?;
        self.check_status(&resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn nullifier_spent(&self, nullifier_hex: &str) -> Result<bool, WalletError> {
        let url = format!("{}/hyper/v1/nullifier/{}", self.base_url, nullifier_hex);
        let resp = self.http.get(&url).send().await?;
        self.check_status(&resp).await?;
        let body: serde_json::Value = resp.json().await?;
        Ok(body["spent"].as_bool().unwrap_or(false))
    }

    pub async fn head(&self) -> Result<serde_json::Value, WalletError> {
        let url = format!("{}/hyper/v1/head", self.base_url);
        let resp = self.http.get(&url).send().await?;
        self.check_status(&resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn epoch(&self) -> Result<u64, WalletError> {
        let url = format!("{}/hyper/v1/epoch", self.base_url);
        let resp = self.http.get(&url).send().await?;
        self.check_status(&resp).await?;
        let body: serde_json::Value = resp.json().await?;
        Ok(body["epoch"].as_u64().unwrap_or(0))
    }

    /// Submit a snapchain user message (`CastAdd`, `LinkAdd`,
    /// `ReactionAdd`, etc.) via `POST /v1/submitMessage`. Distinct
    /// from `submit` which sends to the hyper endpoint.
    pub async fn submit_snapchain_message(&self, msg: &proto::Message) -> Result<(), WalletError> {
        use prost::Message as _;
        let body = msg.encode_to_vec();
        let resp = self
            .http
            .post(format!("{}/v1/submitMessage", self.base_url))
            .header("content-type", "application/octet-stream")
            .body(body)
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(WalletError::NodeError { status, body })
        }
    }

    pub async fn submit(&self, msg: &proto::HyperMessage) -> Result<(), WalletError> {
        let body = msg.encode_to_vec();
        let resp = self
            .http
            .post(format!("{}/hyper/v1/messages", self.base_url))
            .header("content-type", "application/octet-stream")
            .body(body)
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            Err(WalletError::NodeError { status, body: text })
        }
    }

    /// Devnet-only: POST a prost-encoded `HyperWireEvidence` body to
    /// `/hyper/v1/admin/inject_evidence`. The route returns 404 if
    /// the receiving node was built without
    /// `[hyper] devnet_admin_endpoints_enabled = true`.
    pub async fn admin_inject_evidence(
        &self,
        wire: &proto::HyperWireEvidence,
    ) -> Result<(), WalletError> {
        let body = wire.encode_to_vec();
        let resp = self
            .http
            .post(format!("{}/hyper/v1/admin/inject_evidence", self.base_url))
            .header("content-type", "application/octet-stream")
            .body(body)
            .send()
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            Err(WalletError::NodeError { status, body: text })
        }
    }

    async fn check_status(&self, resp: &reqwest::Response) -> Result<(), WalletError> {
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(WalletError::NodeError {
                status: resp.status().as_u16(),
                body: format!("GET {}", resp.url()),
            })
        }
    }
}
