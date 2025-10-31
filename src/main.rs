use std::path::PathBuf;
use std::time::Duration;

use chrono::Utc;
use clap::Parser;
use reqwest::Client;
use rsa::RsaPublicKey;
use tokio::time;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

mod config;
mod crypto;
mod error;
mod sabnzbd;
mod server;

use config::{Config, PreparedConfig, load_config};
use crypto::{EncryptedBody, OutboundPayload, encrypt_payload, hash_sha256_hex, load_public_key};
use error::AppError;
use sabnzbd::fetch_sab_data;
use server::{handshake, send};

#[derive(Parser, Debug)]
#[command(author, version, about = "SABnzbd status proxy")]
struct Cli {
    /// Path to the config file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

struct Proxy {
    config: PreparedConfig,
    client: Client,
    public_key: RsaPublicKey,
    device_id: String,
    session_token: Option<String>,
}

impl Proxy {
    fn new(config: Config) -> Result<Self, AppError> {
        let public_key = load_public_key(&config.public_key)?;
        let device_id = config.device_id.clone();
        let prepared = PreparedConfig::try_from(config)?;

        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("pwoxy/0.1")
            .build()?;

        Ok(Self {
            config: prepared,
            client,
            public_key,
            device_id,
            session_token: None,
        })
    }

    async fn run(mut self) {
        // Perform handshake with server first
        match self.perform_handshake().await {
            Ok(()) => info!("handshake successful"),
            Err(AppError::DeviceUnauthorized(msg)) => {
                error!("Device unauthorized: {}", msg);
                std::process::exit(1);
            }
            Err(err) => {
                error!(%err, "handshake failed");
                std::process::exit(1);
            }
        }

        match self.poll_and_send().await {
            Ok(()) => info!("initial poll cycle succeeded"),
            Err(err) => error!(%err, "initial poll failed"),
        }

        let mut ticker = time::interval(self.config.interval);
        loop {
            ticker.tick().await;
            match self.poll_and_send().await {
                Ok(()) => debug!("poll cycle succeeded"),
                Err(AppError::SessionExpired) => {
                    warn!("renewing session");
                    match self.perform_handshake().await {
                        Ok(()) => {
                            info!("success");
                            // Retry the poll after successful re-auth
                            if let Err(err) = self.poll_and_send().await {
                                warn!(%err, "poll cycle failed after renewing");
                            }
                        }
                        Err(AppError::DeviceUnauthorized(msg)) => {
                            error!("Device unauthorized during re-authentication: {}", msg);
                            std::process::exit(1);
                        }
                        Err(err) => {
                            error!(%err, "re-authentication failed");
                        }
                    }
                }
                Err(err) => {
                    warn!(%err, "poll cycle failed");
                }
            }
        }
    }

    async fn perform_handshake(&mut self) -> Result<(), AppError> {
        let response = handshake(&self.client, &self.config.server_url, &self.device_id).await?;
        self.session_token = response.session_token;
        Ok(())
    }

    async fn poll_and_send(&self) -> Result<(), AppError> {
        let (queue, history) = tokio::try_join!(
            fetch_sab_data(
                &self.client,
                &self.config.sab_url,
                &self.config.sab_apikey,
                "queue"
            ),
            fetch_sab_data(
                &self.client,
                &self.config.sab_url,
                &self.config.sab_apikey,
                "history"
            ),
        )?;

        let payload = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "queue": queue,
            "history": history,
        });

        let payload_bytes = serde_json::to_vec(&payload)?;
        let hash = hash_sha256_hex(&payload_bytes);

        // Encrypt the payload with the server's public key so only it can read it.
        let EncryptedBody {
            encrypted_key_base64,
            nonce_base64,
            tag_base64,
            ciphertext_base64,
        } = encrypt_payload(&payload_bytes, &self.public_key)?;

        let outbound = OutboundPayload {
            hash_sha256: hash,
            encrypted_key_base64,
            nonce_base64,
            tag_base64,
            ciphertext_base64,
        };

        send(&self.client, &self.config.server_url, &outbound, self.session_token.as_deref()).await
    }
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init();
}

#[tokio::main]
async fn main() {
    init_tracing();
    let cli = Cli::parse();

    match load_config(&cli.config)
        .await
        .and_then(|config| Proxy::new(config))
    {
        Ok(proxy) => proxy.run().await,
        Err(err) => {
            error!(%err, "failed to start proxy");
            std::process::exit(1);
        }
    }
}
