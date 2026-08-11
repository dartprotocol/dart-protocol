use byteorder::{BigEndian, ByteOrder};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};

fn write_u24(buf: &mut [u8], val: u32) {
    buf[0] = (val >> 16) as u8;
    buf[1] = (val >> 8) as u8;
    buf[2] = val as u8;
}

fn main() {
    let conv_key = vec![0x11; 32];
    let nonce_bytes: [u8; 12] = [0x33; 12];

    // New 17-byte header: type(1) | convId(2) | senderId(2) | nonce(12).
    let mut header = vec![0u8; 17];
    header[0] = 0x03;
    BigEndian::write_u16(&mut header[1..3], 1);
    BigEndian::write_u16(&mut header[3..5], 2);
    header[5..17].copy_from_slice(&nonce_bytes);

    let mut payload = vec![0u8; 3];
    write_u24(&mut payload[0..3], 3);

    let cipher = Aes256Gcm::new_from_slice(&conv_key).unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, Payload { msg: &payload, aad: &header }).unwrap();

    let mut res = header.clone();
    res.extend_from_slice(&ciphertext);

    let hex_string: String = res.iter().map(|b| format!("{:02x}", b)).collect();
    println!("Rust Sync: {}", hex_string);
}
