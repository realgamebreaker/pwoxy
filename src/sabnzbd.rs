use std::time::Duration;

use reqwest::{Client, Url};
use serde_json::Value;
use tracing::warn;

use crate::error::AppError;

const SAB_REQUEST_RETRIES: u32 = 3;
const RETRY_DELAY_SECS: u64 = 2;

pub async fn fetch_sab_data(
    client: &Client,
    base_url: &Url,
    apikey: &str,
    mode: &str,
) -> Result<Value, AppError> {
    let request_url = build_sab_url(base_url, apikey, mode)?;

    let mut attempt = 0;
    loop {
        attempt += 1;
        match client.get(request_url.clone()).send().await {
            Ok(response) => match response.error_for_status() {
                Ok(success) => return Ok(success.json::<Value>().await?),
                Err(err) => {
                    warn!(mode = %mode, attempt, error = %err, "SABnzbd returned error status");
                }
            },
            Err(err) => {
                warn!(mode = %mode, attempt, error = %err, "SABnzbd request failed");
            }
        }

        if attempt >= SAB_REQUEST_RETRIES {
            return Err(AppError::Sab(format!(
                "{mode} endpoint did not succeed after {attempt} attempts"
            )));
        }

        tokio::time::sleep(Duration::from_secs(RETRY_DELAY_SECS)).await;
    }
}

fn build_sab_url(base_url: &Url, apikey: &str, mode: &str) -> Result<Url, AppError> {
    let mut url = base_url.clone();
    url.set_query(None);
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("mode", mode);
        pairs.append_pair("output", "json");
        pairs.append_pair("apikey", apikey);
    }
    Ok(url)
}
