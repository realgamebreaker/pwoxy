use std::time::Duration;

use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::crypto::OutboundPayload;
use crate::error::AppError;

const SERVER_POST_RETRIES: u32 = 3;
const RETRY_DELAY_SECS: u64 = 2;

#[derive(Serialize)]
pub struct HandshakeRequest {
    pub client_name: String,
    pub client_version: String,
    pub device_id: String,
    pub timestamp: String,
}

#[derive(Deserialize)]
pub struct HandshakeResponse {
    pub status: String,
    pub session_token: Option<String>,
    pub server_version: Option<String>,
    #[allow(dead_code)]
    pub message: Option<String>,
}

pub async fn handshake(
    client: &Client,
    base_server_url: &Url,
    device_id: &str,
) -> Result<HandshakeResponse, AppError> {
    let mut handshake_url = base_server_url.clone();
    handshake_url.set_path(&format!("{}handshake", handshake_url.path()));

    let request = HandshakeRequest {
        client_name: "IronNZB-Proxy".to_string(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        device_id: device_id.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    let response = client
        .post(handshake_url)
        .json(&request)
        .send()
        .await?;

    if response.status().is_success() {
        let handshake_response: HandshakeResponse = response.json().await?;
        if let Some(ref _token) = handshake_response.session_token {
            info!(
                status = %handshake_response.status,
                server_version = %handshake_response.server_version.as_deref().unwrap_or("unknown"),
                "handshake successful, received session token"
            );
        } else {
            warn!("handshake successful but no session token received");
        }
        Ok(handshake_response)
    } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        Err(AppError::DeviceUnauthorized("Unknown Device ID.".to_string()))
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(AppError::ServerPost(format!(
            "handshake failed with status {}: {}",
            status,
            truncate(&body)
        )))
    }
}

pub async fn send(
    client: &Client,
    base_server_url: &Url,
    payload: &OutboundPayload,
    session_token: Option<&str>,
) -> Result<(), AppError> {
    let mut status_url = base_server_url.clone();
    status_url.set_path(&format!("{}status", status_url.path()));

    let mut attempt = 0;
    loop {
        attempt += 1;
        let mut request = client.post(status_url.clone()).json(payload);
        
        // Add session token header if available
        if let Some(token) = session_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }
        
        let response = request.send().await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    debug!(status = ?resp.status(), "sent encrypted payload");
                    return Ok(());
                } else if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                    return Err(AppError::SessionExpired);
                }

                let status = resp.status();
                let body_preview = resp.text().await.unwrap_or_default();
                warn!(
                    status = %status,
                    attempt,
                    body = %truncate(&body_preview),
                    "server responded with error status"
                );
            }
            Err(err) => {
                warn!(attempt, error = %err, "failed to post to server");
            }
        }

        if attempt >= SERVER_POST_RETRIES {
            return Err(AppError::ServerPost(format!(
                "failed after {attempt} attempts"
            )));
        }

        tokio::time::sleep(Duration::from_secs(RETRY_DELAY_SECS)).await;
    }
}

fn truncate(input: &str) -> String {
    const MAX_LEN: usize = 200;
    if input.len() <= MAX_LEN {
        return input.to_string();
    }

    let mut end = MAX_LEN;
    while !input.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &input[..end])
}
