use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};
use sha2::{Digest, Sha256};

use crate::error::AppError;

// encryption stuff for e2e encryption

#[derive(serde::Serialize)]
pub struct OutboundPayload {
    pub hash_sha256: String,
    pub encrypted_key_base64: String,
    pub nonce_base64: String,
    pub tag_base64: String,
    pub ciphertext_base64: String,
}

pub struct EncryptedBody {
    pub encrypted_key_base64: String,
    pub nonce_base64: String,
    pub tag_base64: String,
    pub ciphertext_base64: String,
}

pub fn load_public_key(public_key_pem: &str) -> Result<RsaPublicKey, AppError> {
    let public_key_pem = public_key_pem.trim();
    if public_key_pem.is_empty() {
        return Err(AppError::Config("public key not set. check config.toml".into()));
    }
    RsaPublicKey::from_public_key_pem(public_key_pem)
        .map_err(|err| AppError::PublicKey(err.to_string()))
}

pub fn hash_sha256_hex(data: &[u8]) -> String {
    // hash the plain JSON to let the server verify integrity after decrypting
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    hex::encode(digest)
}

pub fn encrypt_payload(
    payload: &[u8],
    public_key: &RsaPublicKey,
) -> Result<EncryptedBody, AppError> {
    let mut rng = OsRng;

    let aes_key = Aes256Gcm::generate_key(&mut rng);
    let cipher = Aes256Gcm::new(&aes_key);

    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let mut buffer = payload.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(&nonce, &[], &mut buffer)
        .map_err(|_| AppError::Symmetric("AES-GCM encryption failed"))?;

    let aes_key_bytes: [u8; 32] = aes_key.into();
    let encrypted_key = public_key.encrypt(&mut rng, Oaep::new::<Sha256>(), &aes_key_bytes)?;
    let tag_bytes: [u8; 16] = tag.into();

    Ok(EncryptedBody {
        encrypted_key_base64: general_purpose::STANDARD.encode(encrypted_key),
        nonce_base64: general_purpose::STANDARD.encode(nonce_bytes),
        tag_base64: general_purpose::STANDARD.encode(tag_bytes),
        ciphertext_base64: general_purpose::STANDARD.encode(buffer),
    })
}
