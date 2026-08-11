use p256::{
    ecdh::diffie_hellman,
    PublicKey, SecretKey,
};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct ECDH {
    secret: SecretKey,
    public_key: PublicKey,
}

impl ECDH {
    pub fn new() -> Self {
        let secret = SecretKey::random(&mut rand::rng());
        let public_key = secret.public_key();
        Self { secret, public_key }
    }

    // Rebuilds the keypair from a 32-byte P-256 private scalar, so the server's
    // identity key can be persisted across restarts.
    pub fn from_private_key(bytes: &[u8]) -> Result<Self, String> {
        let secret = SecretKey::from_slice(bytes).map_err(|e| format!("invalid private key: {:?}", e))?;
        let public_key = secret.public_key();
        Ok(Self { secret, public_key })
    }

    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes().into()
    }

    pub fn get_public_key(&self) -> Vec<u8> {
        self.public_key.to_sec1_bytes().to_vec()
    }

    pub fn compute_secret(&self, peer_pub_key_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let peer_pub = PublicKey::from_sec1_bytes(peer_pub_key_bytes).map_err(|_| "Invalid peer public key")?;
        let shared = diffie_hellman(self.secret.to_nonzero_scalar(), peer_pub.as_affine());
        let secret_bytes = shared.raw_secret_bytes();
        Ok(secret_bytes.to_vec())
    }

    // Derives the per-sender MAC key shared with a peer: SHA-256(ECDH(priv,
    // peerPub)). Both sides compute the same value from their own private key,
    // so a third member cannot derive it and cannot forge the other member's
    // control frames.
    pub fn pairwise_key(&self, peer_pub_key_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let secret = self.compute_secret(peer_pub_key_bytes)?;
        Ok(Sha256::digest(&secret).to_vec())
    }
}
