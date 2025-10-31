use std::path::PathBuf;
use std::time::Duration;

use reqwest::Url;
use serde::Deserialize;
use tokio::fs;

use crate::error::AppError;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub interval_seconds: u64,
    pub sab_url: String,
    pub sab_apikey: String,
    pub server_url: String,
    pub device_id: String,
    pub public_key: String,
}

pub struct PreparedConfig {
    pub interval: Duration,
    pub sab_url: Url,
    pub sab_apikey: String,
    pub server_url: Url,
}

impl TryFrom<Config> for PreparedConfig {
    type Error = AppError;

    fn try_from(value: Config) -> Result<Self, Self::Error> {
        if value.interval_seconds == 0 {
            return Err(AppError::Config(
                "interval_seconds must be greater than zero".into(),
            ));
        }

        let sab_url = Url::parse(&value.sab_url)
            .map_err(|err| AppError::Config(format!("invalid sab_url: {err}")))?;
        let server_url = Url::parse(&value.server_url)
            .map_err(|err| AppError::Config(format!("invalid server_url: {err}")))?;

        Ok(Self {
            interval: Duration::from_secs(value.interval_seconds),
            sab_url,
            sab_apikey: value.sab_apikey,
            server_url,
        })
    }
}

pub async fn load_config(path: &PathBuf) -> Result<Config, AppError> {
    let raw = fs::read_to_string(path).await?;
    let config: Config = toml::from_str(&raw)?;
    Ok(config)
}
