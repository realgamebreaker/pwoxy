use thiserror::Error;


// different error types
#[derive(Error, Debug)]
pub enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::errors::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("SABnzbd request failed after retries: {0}")]
    Sab(String),
    #[error("Server post failed after retries: {0}")]
    ServerPost(String),
    #[error("Public key error: {0}")]
    PublicKey(String),
    #[error("Symmetric crypto error: {0}")]
    Symmetric(&'static str),
    #[error("Device unauthorized: {0}")]
    DeviceUnauthorized(String),
    #[error("Session expired - need to re-authenticate")]
    SessionExpired,
}
