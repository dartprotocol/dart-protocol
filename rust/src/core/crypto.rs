use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};

pub fn encrypt_gcm(key: &[u8], iv: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(iv);
    cipher.encrypt(nonce, Payload { msg: plaintext, aad })
}

pub fn decrypt_gcm(key: &[u8], iv: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(iv);
    cipher.decrypt(nonce, Payload { msg: ciphertext, aad })
}
