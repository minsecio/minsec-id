//! Thin HTTP client for the minsec.io API (after minsec-sync's). Non-2xx
//! responses become `ApiError` with the server's error code, so callers can
//! react to specific codes (`already_enrolled`, `quota_exceeded`, …).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use minsec_proto::types;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const AGENT_VERSION: &str = concat!("minsec-id-sync/", env!("CARGO_PKG_VERSION"));

pub struct Api {
    agent: ureq::Agent,
    server: String,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub retry_after: Option<u64>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "server said {} ({})", self.code, self.status)?;
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        if let Some(s) = self.retry_after {
            write!(f, " [retry after {s}s]")?;
        }
        Ok(())
    }
}

impl std::error::Error for ApiError {}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn transport(e: impl std::fmt::Display) -> ApiError {
    ApiError {
        status: 0,
        code: "transport".into(),
        message: e.to_string(),
        retry_after: None,
    }
}

impl Api {
    pub fn new(server: &str) -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(120)))
            .user_agent(AGENT_VERSION)
            .build();
        Self {
            agent: config.into(),
            server: server.trim_end_matches('/').to_string(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.server)
    }

    fn read<T: serde::de::DeserializeOwned>(mut resp: ureq::http::Response<ureq::Body>) -> Result<T, ApiError> {
        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let body = resp.body_mut().read_to_string().unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err(match serde_json::from_str::<types::ErrorResponse>(&body) {
                Ok(e) => ApiError {
                    status,
                    code: e.error,
                    message: e.message,
                    retry_after,
                },
                Err(_) => ApiError {
                    status,
                    code: format!("http_{status}"),
                    message: body.chars().take(200).collect(),
                    retry_after,
                },
            });
        }
        serde_json::from_str(&body).map_err(|e| ApiError {
            status,
            code: "bad_response".into(),
            message: e.to_string(),
            retry_after: None,
        })
    }

    pub fn challenge(&self, install_token: Option<&str>) -> anyhow::Result<types::Challenge> {
        let req = types::ChallengeRequest {
            install_token: install_token.map(str::to_string),
        };
        let resp = self
            .agent
            .post(self.url("/v1/enroll/challenge"))
            .header("Content-Type", "application/json")
            .send(serde_json::to_string(&req).expect("serializable"))
            .map_err(transport)?;
        let ch: types::Challenge = Self::read(resp)?;
        if ch.algo != types::POW_ALGO {
            anyhow::bail!(
                "server wants unknown PoW algorithm {:?}; upgrade minsec-id-sync",
                ch.algo
            );
        }
        Ok(ch)
    }

    pub fn enroll(&self, req: &types::EnrollRequest) -> Result<types::EnrollResponse, ApiError> {
        let resp = self
            .agent
            .post(self.url("/v1/enroll"))
            .header("Content-Type", "application/json")
            .send(serde_json::to_string(req).expect("serializable"))
            .map_err(transport)?;
        Self::read(resp)
    }

    /// POST a body signed for `purpose`. The signature covers the exact bytes
    /// sent, so the body is serialized here, once.
    pub fn post_signed<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        purpose: &str,
        key: &SigningKey,
        host_id: &str,
        body: &T,
    ) -> Result<R, ApiError> {
        let body = serde_json::to_vec(body).expect("serializable");
        let ts = now_unix() as i64;
        let sig = minsec_proto::sign::sign_for(purpose, key, host_id, ts, &body);
        let resp = self
            .agent
            .post(self.url(path))
            .header("Content-Type", "application/json")
            .header(minsec_proto::HEADER_HOST, host_id)
            .header(minsec_proto::HEADER_TIMESTAMP, ts.to_string())
            .header(minsec_proto::HEADER_SIGNATURE, B64.encode(sig))
            .send(&body[..])
            .map_err(transport)?;
        Self::read(resp)
    }
}
