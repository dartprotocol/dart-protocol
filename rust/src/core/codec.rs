#![allow(dead_code)]
use std::collections::HashMap;
use byteorder::{BigEndian, ByteOrder};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use super::{
    crypto::{decrypt_gcm, encrypt_gcm}, 
    AckDart, ChainShareDart, ChainState, DataDart, DecryptedData, DictResetDart, KeyReqDart, KeyShareDart, Member, MemberInfo, NackDart, SyncDart,
    TYPE_ACK, TYPE_CHAIN_SHARE, TYPE_DATA, TYPE_DICT_RESET, TYPE_KEY_REQ, TYPE_KEY_SHARE, TYPE_MEMBER_INFO, TYPE_NACK, TYPE_SYNC,
};

type HmacSha256 = Hmac<Sha256>;

pub struct Codec {
    pub conv_keys: HashMap<u16, Vec<u8>>,            // current group key per conv (set on adopt)
    pub room_keys: HashMap<u16, HashMap<u16, Vec<u8>>>, // epoch -> key
    pub current_epochs: HashMap<u16, u16>,
}

impl Codec {
    pub fn new() -> Self {
        Self {
            conv_keys: HashMap::new(),
            room_keys: HashMap::new(),
            current_epochs: HashMap::new(),
        }
    }

    fn get_conv_key(&self, conv_id: u16) -> Result<Vec<u8>, String> {
        self.conv_keys
            .get(&conv_id)
            .cloned()
            .ok_or_else(|| format!("no conversation key established for conv {}", conv_id))
    }

    pub fn encode_data(&self, dart: &DataDart, dict: &[u8], message_key: &[u8], idx: u32, nonce: Option<[u8; 12]>) -> Result<Vec<u8>, String> {
        let epoch = *self.current_epochs.get(&dart.conv_id).unwrap_or(&1);

        let mut compressor = Compress::new(Compression::default(), false);
        if !dict.is_empty() {
            compressor.set_dictionary(dict).map_err(|e| format!("dict err: {:?}", e))?;
        }
        
        let mut compressed = vec![0u8; dart.payload.len() + 1024];
        let _status = compressor.compress(dart.payload.as_bytes(), &mut compressed, FlushCompress::Finish)
            .map_err(|e| format!("compress err: {:?}", e))?;
        compressed.truncate(compressor.total_out() as usize);

        // 7-byte cleartext header + 24-byte cleartext extension (all AAD):
        //   senderId(2) | nonce(12) | epoch(2) | dictFp(4) | idx(4).
        // The payload is the deflated message; the key is the sender's
        // per-message ratchet key.
        let nonce = nonce.unwrap_or_else(rand::random);
        let dict_fp = dict_fingerprint(dict);

        let mut prefix = vec![0u8; 7 + 24];
        prefix[0] = dart.type_id();
        BigEndian::write_u16(&mut prefix[1..3], dart.conv_id);
        write_u24(&mut prefix[3..6], dart.seq);
        prefix[6] = 24;
        BigEndian::write_u16(&mut prefix[7..9], dart.sender_id);
        prefix[9..21].copy_from_slice(&nonce);
        BigEndian::write_u16(&mut prefix[21..23], epoch);
        prefix[23..27].copy_from_slice(&dict_fp);
        BigEndian::write_u32(&mut prefix[27..31], idx);

        let ciphertext = encrypt_gcm(message_key, &nonce, &compressed, &prefix)
            .map_err(|e| format!("encrypt err: {:?}", e))?;

        let mut res = prefix;
        res.extend_from_slice(&ciphertext);
        Ok(res)
    }

    pub fn decrypt_data(&self, buf: &[u8], message_key: &[u8]) -> Result<DecryptedData, String> {
        if buf.len() < 7 {
            return Err("buffer too short".to_string());
        }
        let conv_id = BigEndian::read_u16(&buf[1..3]);
        let seq = read_u24(&buf[3..6]);
        let ext_len = buf[6] as usize;

        if buf.len() < 7 + ext_len + 16 {
            return Err("invalid payload length".to_string());
        }
        let prefix = &buf[..7 + ext_len];
        let sender_id = BigEndian::read_u16(&prefix[7..9]);
        let nonce = &prefix[9..21];
        let epoch = BigEndian::read_u16(&prefix[21..23]);
        let dict_fp_raw = &prefix[23..27];
        let idx = BigEndian::read_u32(&prefix[27..31]);
        let encrypted_with_tag = &buf[7 + ext_len..];

        let compressed = decrypt_gcm(message_key, nonce, encrypted_with_tag, prefix)
            .map_err(|e| format!("decrypt err: {:?}", e))?;

        let mut dict_fp = [0u8; 4];
        dict_fp.copy_from_slice(dict_fp_raw);

        Ok(DecryptedData {
            conv_id,
            sender_id,
            seq,
            compressed,
            dict_fp,
            epoch,
            idx,
        })
    }

    pub fn inflate_data(compressed: &[u8], dict: &[u8]) -> Result<String, String> {
        let mut decompressor = Decompress::new(false);
        if !dict.is_empty() {
            let _res = decompressor.decompress(&[], &mut [], FlushDecompress::None);
            decompressor.set_dictionary(dict).map_err(|e| format!("dict err: {:?}", e))?;
        }

        let mut payload_bytes = vec![0u8; compressed.len() * 10 + 1024]; // estimate
        let _status = decompressor.decompress(compressed, &mut payload_bytes, FlushDecompress::Finish)
            .map_err(|e| format!("decompress err: {:?}", e))?;
        payload_bytes.truncate(decompressor.total_out() as usize);

        String::from_utf8(payload_bytes).map_err(|_| "invalid utf8".to_string())
    }

    pub fn encode_nack(&self, nack: &NackDart, nonce: Option<[u8; 12]>) -> Result<Vec<u8>, String> {
        let conv_key = self.get_conv_key(nack.conv_id)?;

        // 19-byte cleartext header: type(1) | convId(2) | senderId(2) |
        // targetId(2) | nonce(12). senderId is the member who detected the gap
        // (the signer); targetId is the member whose stream has the gap.
        let nonce = nonce.unwrap_or_else(rand::random);

        let mut header = vec![0u8; 19];
        header[0] = TYPE_NACK;
        BigEndian::write_u16(&mut header[1..3], nack.conv_id);
        BigEndian::write_u16(&mut header[3..5], nack.sender_id);
        BigEndian::write_u16(&mut header[5..7], nack.target_id);
        header[7..19].copy_from_slice(&nonce);

        let mut payload = vec![0u8; 2 + nack.missing_seq.len() * 3];
        BigEndian::write_u16(&mut payload[0..2], nack.missing_seq.len() as u16);
        let mut offset = 2;
        for &seq in &nack.missing_seq {
            write_u24(&mut payload[offset..offset + 3], seq);
            offset += 3;
        }

        let mut res = header.clone();
        let ciphertext = encrypt_gcm(&conv_key, &nonce, &payload, &header)
            .map_err(|e| format!("encrypt err: {:?}", e))?;
        res.extend_from_slice(&ciphertext);
        Ok(res)
    }

    pub fn decode_nack(&self, buf: &[u8]) -> Result<NackDart, String> {
        if buf.len() < 19 {
            return Err("buffer too short".to_string());
        }
        let conv_id = BigEndian::read_u16(&buf[1..3]);
        let sender_id = BigEndian::read_u16(&buf[3..5]);
        let target_id = BigEndian::read_u16(&buf[5..7]);
        let header = &buf[..19];
        let nonce = &buf[7..19];
        let encrypted = &buf[19..];

        let conv_key = self.get_conv_key(conv_id)?;

        let payload = decrypt_gcm(&conv_key, nonce, encrypted, header)
            .map_err(|e| format!("decrypt err: {:?}", e))?;

        if payload.len() < 2 {
            return Err("invalid nack payload".to_string());
        }
        let count = BigEndian::read_u16(&payload[0..2]) as usize;
        let mut missing_seq = Vec::with_capacity(count);
        let mut offset = 2;
        for _ in 0..count {
            if payload.len() < offset + 3 {
                break;
            }
            missing_seq.push(read_u24(&payload[offset..offset + 3]));
            offset += 3;
        }

        Ok(NackDart {
            conv_id,
            sender_id,
            target_id,
            missing_seq,
        })
    }

    pub fn encode_sync(&self, sync: &SyncDart, nonce: Option<[u8; 12]>) -> Result<Vec<u8>, String> {
        let conv_key = self.get_conv_key(sync.conv_id)?;

        // 17-byte cleartext header: type(1) | convId(2) | senderId(2) | nonce(12).
        let nonce = nonce.unwrap_or_else(rand::random);

        let mut header = vec![0u8; 17];
        header[0] = TYPE_SYNC;
        BigEndian::write_u16(&mut header[1..3], sync.conv_id);
        BigEndian::write_u16(&mut header[3..5], sync.sender_id);
        header[5..17].copy_from_slice(&nonce);

        let mut payload = vec![0u8; 3];
        write_u24(&mut payload[0..3], sync.highest_seq);

        let mut res = header.clone();
        let ciphertext = encrypt_gcm(&conv_key, &nonce, &payload, &header)
            .map_err(|e| format!("encrypt err: {:?}", e))?;
        res.extend_from_slice(&ciphertext);
        Ok(res)
    }

    pub fn decode_sync(&self, buf: &[u8]) -> Result<SyncDart, String> {
        if buf.len() < 17 {
            return Err("buffer too short".to_string());
        }
        let conv_id = BigEndian::read_u16(&buf[1..3]);
        let sender_id = BigEndian::read_u16(&buf[3..5]);
        let header = &buf[..17];
        let nonce = &buf[5..17];
        let encrypted = &buf[17..];

        let conv_key = self.get_conv_key(conv_id)?;

        let payload = decrypt_gcm(&conv_key, nonce, encrypted, header)
            .map_err(|e| format!("decrypt err: {:?}", e))?;

        if payload.len() < 3 {
            return Err("invalid sync payload".to_string());
        }

        Ok(SyncDart {
            conv_id,
            sender_id,
            highest_seq: read_u24(&payload[0..3]),
        })
    }

    pub fn encode_key_req(&self, req: &KeyReqDart) -> Vec<u8> {
        let mut res = vec![0u8; 5];
        res[0] = TYPE_KEY_REQ;
        BigEndian::write_u16(&mut res[1..3], req.conv_id);
        BigEndian::write_u16(&mut res[3..5], req.sender_id);
        res.extend_from_slice(&req.req_nonce);
        res.extend_from_slice(&req.client_pub_key);
        res
    }

    pub fn decode_key_req(&self, buf: &[u8]) -> Result<KeyReqDart, String> {
        if buf.len() < 21 {
            return Err("buffer too short".to_string());
        }
        let mut req_nonce = [0u8; 16];
        req_nonce.copy_from_slice(&buf[5..21]);
        Ok(KeyReqDart {
            conv_id: BigEndian::read_u16(&buf[1..3]),
            sender_id: BigEndian::read_u16(&buf[3..5]),
            req_nonce,
            client_pub_key: buf[21..].to_vec(),
        })
    }

    // KEY_SHARE: member -> member group-key delivery, relayed opaquely by the
    // server. transport_key = SHA-256(ECDH(sharer's key, target's pubkey)).
    pub fn encode_key_share(&self, share: &KeyShareDart, transport_key: &[u8]) -> Result<Vec<u8>, String> {
        let mut header = vec![0u8; 21];
        header[0] = TYPE_KEY_SHARE;
        BigEndian::write_u16(&mut header[1..3], share.conv_id);
        BigEndian::write_u16(&mut header[3..5], share.sender_id);
        BigEndian::write_u16(&mut header[5..7], share.target_id);
        BigEndian::write_u16(&mut header[7..9], share.epoch);
        header[9..].copy_from_slice(&share.nonce);

        let plaintext = share.encrypted_key.clone(); // 32-byte group key
        let mut encrypted = encrypt_gcm(transport_key, &share.nonce, &plaintext, &header)
            .map_err(|e| format!("encrypt err: {:?}", e))?;
        let mut res = header;
        res.append(&mut encrypted);
        Ok(res)
    }

    pub fn decode_key_share(&self, buf: &[u8], transport_key: &[u8]) -> Result<(u16, Vec<u8>), String> {
        if buf.len() < 21 + 48 {
            return Err("buffer too short".to_string());
        }
        let epoch = BigEndian::read_u16(&buf[7..9]);
        let header = &buf[..21];
        let nonce = &buf[9..21];
        let encrypted_with_tag = &buf[21..];
        let group_key = decrypt_gcm(transport_key, nonce, encrypted_with_tag, header)
            .map_err(|e| format!("decrypt err: {:?}", e))?;
        Ok((epoch, group_key))
    }

    // Returns the server public key embedded in a MEMBER_INFO packet, so a
    // client can verify the pin before deriving the transport key.
    pub fn member_info_server_key(buf: &[u8]) -> Result<Vec<u8>, String> {
        if buf.len() < 70 {
            return Err("buffer too short".to_string());
        }
        Ok(buf[5..70].to_vec())
    }

    pub fn encode_member_info(&self, info: &MemberInfo, transport_key: &[u8], nonce: Option<[u8; 12]>) -> Result<Vec<u8>, String> {
        let mut header = vec![0u8; 5];
        header[0] = TYPE_MEMBER_INFO;
        BigEndian::write_u16(&mut header[1..3], info.conv_id);
        BigEndian::write_u16(&mut header[3..5], info.sender_id);

        let nonce = nonce.unwrap_or_else(rand::random);
        let mut payload = Vec::with_capacity(3 + info.members.len() * 67);
        payload.push(if info.creator { 1 } else { 0 });
        payload.extend_from_slice(&(info.members.len() as u16).to_be_bytes());
        for m in &info.members {
            payload.extend_from_slice(&m.sender_id.to_be_bytes());
            payload.extend_from_slice(&m.pub_key);
        }

        let mut aad = header.clone();
        aad.extend_from_slice(&info.server_pub_key);
        aad.extend_from_slice(&nonce);

        let mut encrypted = encrypt_gcm(transport_key, &nonce, &payload, &aad)
            .map_err(|e| format!("encrypt err: {:?}", e))?;
        let mut res = aad;
        res.append(&mut encrypted);
        Ok(res)
    }

    pub fn decode_member_info(&self, buf: &[u8], transport_key: &[u8]) -> Result<MemberInfo, String> {
        if buf.len() < 5 + 65 + 12 + 16 {
            return Err("buffer too short".to_string());
        }
        let conv_id = BigEndian::read_u16(&buf[1..3]);
        let sender_id = BigEndian::read_u16(&buf[3..5]);
        let server_pub_key = buf[5..70].to_vec();
        let nonce = &buf[70..82];
        let encrypted = &buf[82..];
        let header = &buf[..5];

        let mut aad = header.to_vec();
        aad.extend_from_slice(&server_pub_key);
        aad.extend_from_slice(nonce);

        let payload = decrypt_gcm(transport_key, nonce, encrypted, &aad)
            .map_err(|e| format!("decrypt err: {:?}", e))?;
        if payload.len() < 3 {
            return Err("invalid member info payload".to_string());
        }
        let creator = payload[0] == 1;
        let count = BigEndian::read_u16(&payload[1..3]) as usize;
        let mut members = Vec::with_capacity(count);
        let mut offset = 3;
        for _ in 0..count {
            if payload.len() < offset + 67 {
                break;
            }
            members.push(Member {
                sender_id: BigEndian::read_u16(&payload[offset..offset + 2]),
                pub_key: payload[offset + 2..offset + 67].to_vec(),
            });
            offset += 67;
        }

        Ok(MemberInfo {
            conv_id,
            sender_id,
            server_pub_key,
            creator,
            members,
        })
    }

    pub fn encode_dict_reset(&self, reset: &DictResetDart, nonce: Option<[u8; 12]>) -> Result<Vec<u8>, String> {
        let conv_key = self.get_conv_key(reset.conv_id)?;

        // 19-byte cleartext header: type(1) | convId(2) | senderId(2) | targetId(2)
        // | nonce(12). The whole header is the AEAD AAD, so an outsider can't
        // forge a reset.
        let nonce = nonce.unwrap_or_else(rand::random);

        let mut header = vec![0u8; 19];
        header[0] = TYPE_DICT_RESET;
        BigEndian::write_u16(&mut header[1..3], reset.conv_id);
        BigEndian::write_u16(&mut header[3..5], reset.sender_id);
        BigEndian::write_u16(&mut header[5..7], reset.target_id);
        header[7..19].copy_from_slice(&nonce);

        let ciphertext = encrypt_gcm(&conv_key, &nonce, &[], &header)
            .map_err(|e| format!("encrypt err: {:?}", e))?;

        let mut res = header;
        res.extend_from_slice(&ciphertext);
        Ok(res)
    }

    pub fn decode_dict_reset(&self, buf: &[u8]) -> Result<DictResetDart, String> {
        if buf.len() < 19 {
            return Err("buffer too short".to_string());
        }
        let conv_id = BigEndian::read_u16(&buf[1..3]);
        let sender_id = BigEndian::read_u16(&buf[3..5]);
        let target_id = BigEndian::read_u16(&buf[5..7]);
        let header = &buf[..19];
        let nonce = &buf[7..19];
        let tag = &buf[19..];

        let conv_key = self.get_conv_key(conv_id)?;

        decrypt_gcm(&conv_key, nonce, tag, header)
            .map_err(|e| format!("decrypt err: {:?}", e))?;

        Ok(DictResetDart {
            conv_id,
            sender_id,
            target_id,
        })
    }

    pub fn encode_ack(&self, ack: &AckDart, nonce: Option<[u8; 12]>) -> Result<Vec<u8>, String> {
        let conv_key = self.get_conv_key(ack.conv_id)?;

        // 22-byte cleartext header: type(1) | convId(2) | senderId(2) | targetId(2)
        // | seq(3) | nonce(12). The whole header is the AEAD AAD, so an outsider
        // can't forge a delivery confirmation.
        let nonce = nonce.unwrap_or_else(rand::random);

        let mut header = vec![0u8; 22];
        header[0] = TYPE_ACK;
        BigEndian::write_u16(&mut header[1..3], ack.conv_id);
        BigEndian::write_u16(&mut header[3..5], ack.sender_id);
        BigEndian::write_u16(&mut header[5..7], ack.target_id);
        write_u24(&mut header[7..10], ack.seq);
        header[10..22].copy_from_slice(&nonce);

        let ciphertext = encrypt_gcm(&conv_key, &nonce, &[], &header)
            .map_err(|e| format!("encrypt err: {:?}", e))?;

        let mut res = header;
        res.extend_from_slice(&ciphertext);
        Ok(res)
    }

    pub fn decode_ack(&self, buf: &[u8]) -> Result<AckDart, String> {
        if buf.len() < 22 {
            return Err("buffer too short".to_string());
        }
        let conv_id = BigEndian::read_u16(&buf[1..3]);
        let sender_id = BigEndian::read_u16(&buf[3..5]);
        let target_id = BigEndian::read_u16(&buf[5..7]);
        let seq = read_u24(&buf[7..10]);
        let header = &buf[..22];
        let nonce = &buf[10..22];
        let tag = &buf[22..];

        let conv_key = self.get_conv_key(conv_id)?;

        decrypt_gcm(&conv_key, nonce, tag, header)
            .map_err(|e| format!("decrypt err: {:?}", e))?;

        Ok(AckDart {
            conv_id,
            sender_id,
            target_id,
            seq,
        })
    }

    // CHAIN_SHARE: member -> member per-sender ratchet-chain delivery, relayed
    // opaquely by the server, ECDH-encrypted like a KeyShare.
    pub fn encode_chain_share(&self, share: &ChainShareDart, transport_key: &[u8]) -> Result<Vec<u8>, String> {
        let mut header = vec![0u8; 21];
        header[0] = TYPE_CHAIN_SHARE;
        BigEndian::write_u16(&mut header[1..3], share.conv_id);
        BigEndian::write_u16(&mut header[3..5], share.sender_id);
        BigEndian::write_u16(&mut header[5..7], share.target_id);
        BigEndian::write_u16(&mut header[7..9], share.epoch);
        header[9..].copy_from_slice(&share.nonce);

        let mut payload = Vec::with_capacity(36);
        payload.extend_from_slice(&share.chain_key);
        payload.extend_from_slice(&share.chain_index.to_be_bytes());

        let mut encrypted = encrypt_gcm(transport_key, &share.nonce, &payload, &header)
            .map_err(|e| format!("encrypt err: {:?}", e))?;
        let mut res = header;
        res.append(&mut encrypted);
        Ok(res)
    }

    pub fn decode_chain_share(&self, buf: &[u8], transport_key: &[u8]) -> Result<ChainShareDart, String> {
        if buf.len() < 21 + 36 + 16 {
            return Err("buffer too short".to_string());
        }
        let conv_id = BigEndian::read_u16(&buf[1..3]);
        let sender_id = BigEndian::read_u16(&buf[3..5]);
        let target_id = BigEndian::read_u16(&buf[5..7]);
        let epoch = BigEndian::read_u16(&buf[7..9]);
        let header = &buf[..21];
        let nonce = &buf[9..21];
        let encrypted_with_tag = &buf[21..];

        let payload = decrypt_gcm(transport_key, nonce, encrypted_with_tag, header)
            .map_err(|e| format!("decrypt err: {:?}", e))?;
        if payload.len() < 36 {
            return Err("invalid chain share payload".to_string());
        }
        let mut chain_key = [0u8; 32];
        chain_key.copy_from_slice(&payload[..32]);
        let chain_index = BigEndian::read_u32(&payload[32..36]);
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce);

        Ok(ChainShareDart {
            conv_id,
            sender_id,
            target_id,
            epoch,
            nonce: nonce_arr,
            chain_key: chain_key.to_vec(),
            chain_index,
        })
    }
}

// Per-message key for a chain key at the given index.
pub fn chain_message_key(chain_key: &[u8], index: u32) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(chain_key).expect("hmac accepts any key length");
    mac.update(b"DartMsgKey");
    mac.update(&index.to_be_bytes());
    mac.finalize().into_bytes().to_vec()
}

// The chain key that follows chain_key after one message.
pub fn chain_next_key(chain_key: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(chain_key).expect("hmac accepts any key length");
    mac.update(b"DartChainKey");
    mac.finalize().into_bytes().to_vec()
}

// Advance a chain state to target_index (skipping lost messages) and consume
// the message key at target_index. Returns the message key and the advanced
// state (whose index is target_index + 1).
pub fn advance_chain(state: &ChainState, target_index: u32) -> (Vec<u8>, ChainState) {
    let mut key = state.key.clone();
    let mut index = state.index;
    while index < target_index {
        key = chain_next_key(&key);
        index += 1;
    }
    let message_key = chain_message_key(&key, index);
    (message_key, ChainState { key: chain_next_key(&key), index: index + 1 })
}

fn write_u24(buf: &mut [u8], val: u32) {
    buf[0] = (val >> 16) as u8;
    buf[1] = (val >> 8) as u8;
    buf[2] = val as u8;
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// SHA-256 hex fingerprint of the server's static ECDH public key. Clients pin
// this value to authenticate the server (SSH-style host-key verification), so
// an active MITM can't substitute its own key.
pub fn server_fingerprint(server_pub_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(server_pub_key);
    to_hex(&hasher.finalize())
}

// First 4 bytes of SHA-256(dict). Both the sender and every receiver compute
// this over their own (windowed) dictionary; a mismatch means lost history.
pub fn dict_fingerprint(dict: &[u8]) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(dict);
    let result = hasher.finalize();
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&result[..4]);
    fp
}

fn read_u24(buf: &[u8]) -> u32 {
    ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32)
}

impl DataDart {
    pub fn type_id(&self) -> u8 {
        TYPE_DATA
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn rep(b: u8, n: usize) -> Vec<u8> {
        std::iter::repeat(b).take(n).collect()
    }

    const NONCE: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    const REQ_NONCE: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    fn test_codec() -> Codec {
        let mut c = Codec::new();
        let gk = rep(0x11, 32);
        c.room_keys.insert(1, std::iter::once((1, gk.clone())).collect());
        c.conv_keys.insert(1, gk);
        c.current_epochs.insert(1, 1);
        c
    }

    fn assert_hex(name: &str, got: &[u8], want: &str) {
        let w = unhex(want);
        assert_eq!(got, &w[..], "{} mismatch", name);
    }

    // ---- Round-trips ----

    #[test]
    fn roundtrip_data() {
        let c = test_codec();
        let dart = DataDart { conv_id: 1, sender_id: 7, seq: 9, payload: "hello dart".to_string() };
        let buf = c.encode_data(&dart, &[], &rep(0x22, 32), 3, Some(NONCE)).unwrap();
        let dec = c.decrypt_data(&buf, &rep(0x22, 32)).unwrap();
        assert_eq!(dec.conv_id, 1);
        assert_eq!(dec.sender_id, 7);
        assert_eq!(dec.seq, 9);
        assert_eq!(dec.idx, 3);
        let payload = Codec::inflate_data(&dec.compressed, &[]).unwrap();
        assert_eq!(payload, "hello dart");
    }

    #[test]
    fn roundtrip_nack() {
        let c = test_codec();
        let nack = NackDart { conv_id: 1, sender_id: 7, target_id: 9, missing_seq: vec![1, 2, 3] };
        let buf = c.encode_nack(&nack, Some(NONCE)).unwrap();
        let dec = c.decode_nack(&buf).unwrap();
        assert_eq!((dec.sender_id, dec.target_id, dec.missing_seq), (7, 9, vec![1, 2, 3]));
    }

    #[test]
    fn roundtrip_sync() {
        let c = test_codec();
        let sync = SyncDart { conv_id: 1, sender_id: 7, highest_seq: 99 };
        let buf = c.encode_sync(&sync, Some(NONCE)).unwrap();
        let dec = c.decode_sync(&buf).unwrap();
        assert_eq!((dec.sender_id, dec.highest_seq), (7, 99));
    }

    #[test]
    fn roundtrip_ack() {
        let c = test_codec();
        let ack = AckDart { conv_id: 1, sender_id: 7, target_id: 9, seq: 12 };
        let buf = c.encode_ack(&ack, Some(NONCE)).unwrap();
        let dec = c.decode_ack(&buf).unwrap();
        assert_eq!((dec.sender_id, dec.target_id, dec.seq), (7, 9, 12));
    }

    #[test]
    fn roundtrip_dict_reset() {
        let c = test_codec();
        let reset = DictResetDart { conv_id: 1, sender_id: 7, target_id: 9 };
        let buf = c.encode_dict_reset(&reset, Some(NONCE)).unwrap();
        let dec = c.decode_dict_reset(&buf).unwrap();
        assert_eq!((dec.sender_id, dec.target_id), (7, 9));
    }

    #[test]
    fn roundtrip_key_req() {
        let c = Codec::new();
        let req = KeyReqDart { conv_id: 1, sender_id: 7, req_nonce: REQ_NONCE, client_pub_key: {
            let mut k = vec![0x04]; k.extend(rep(0x01, 64)); k
        } };
        let buf = c.encode_key_req(&req);
        let dec = c.decode_key_req(&buf).unwrap();
        assert_eq!(dec.sender_id, 7);
        assert_eq!(dec.req_nonce, REQ_NONCE);
    }

    #[test]
    fn roundtrip_key_share() {
        let c = Codec::new();
        let share = KeyShareDart { conv_id: 1, sender_id: 7, target_id: 9, epoch: 2, nonce: NONCE, encrypted_key: rep(0xBB, 32) };
        let buf = c.encode_key_share(&share, &rep(0x33, 32)).unwrap();
        let (epoch, key) = c.decode_key_share(&buf, &rep(0x33, 32)).unwrap();
        assert_eq!(epoch, 2);
        assert_eq!(key, rep(0xBB, 32));
    }

    #[test]
    fn roundtrip_chain_share() {
        let c = Codec::new();
        let share = ChainShareDart { conv_id: 1, sender_id: 7, target_id: 9, epoch: 2, nonce: NONCE, chain_key: rep(0xCC, 32), chain_index: 5 };
        let buf = c.encode_chain_share(&share, &rep(0x33, 32)).unwrap();
        let dec = c.decode_chain_share(&buf, &rep(0x33, 32)).unwrap();
        assert_eq!((dec.sender_id, dec.target_id, dec.epoch, dec.chain_index), (7, 9, 2, 5));
        assert_eq!(dec.chain_key, rep(0xCC, 32));
    }

    #[test]
    fn roundtrip_member_info() {
        let c = Codec::new();
        let server_pub = {
            let mut k = vec![0x04]; k.extend(rep(0x03, 64)); k
        };
        let pub_a = { let mut k = vec![0x04]; k.extend(rep(0x01, 64)); k };
        let pub_b = { let mut k = vec![0x04]; k.extend(rep(0x02, 64)); k };
        let info = MemberInfo {
            conv_id: 1,
            sender_id: 7,
            server_pub_key: server_pub.clone(),
            creator: true,
            members: vec![Member { sender_id: 7, pub_key: pub_a }, Member { sender_id: 9, pub_key: pub_b }],
        };
        let buf = c.encode_member_info(&info, &rep(0x33, 32), Some(NONCE)).unwrap();
        let dec = c.decode_member_info(&buf, &rep(0x33, 32)).unwrap();
        assert_eq!(dec.conv_id, 1);
        assert!(dec.creator);
        assert_eq!(dec.members.len(), 2);
        assert_eq!(dec.members[1].sender_id, 9);
    }

    // ---- Cross-language golden wire vectors (generated by the TS reference) ----

    #[test]
    fn golden_data() {
        let c = test_codec();
        // Decode compat: TS-produced bytes decrypt + inflate to the payload.
        // (raw-deflate encoding differs per implementation; decompression doesn't.)
        let buf = unhex("010001000009180007000102030405060708090a0b0001e3b0c442000000038d885ad6727ac08d141c148997d24140046f48e9cd6bee431f1c2400");
        let dec = c.decrypt_data(&buf, &rep(0x22, 32)).unwrap();
        assert_eq!(dec.conv_id, 1);
        assert_eq!(dec.sender_id, 7);
        assert_eq!(dec.seq, 9);
        assert_eq!(dec.idx, 3);
        assert_eq!(Codec::inflate_data(&dec.compressed, &[]).unwrap(), "hello dart");
    }

    #[test]
    fn golden_control_frames() {
        let c = test_codec();
        let nack = NackDart { conv_id: 1, sender_id: 7, target_id: 9, missing_seq: vec![1, 2, 3] };
        assert_hex("nack", &c.encode_nack(&nack, Some(NONCE)).unwrap(),
            "02000100070009000102030405060708090a0b13e0b6137aa335f614b8d0b1113eab3b1b2b9066d92634fe4bc878");
        let sync = SyncDart { conv_id: 1, sender_id: 7, highest_seq: 99 };
        assert_hex("sync", &c.encode_sync(&sync, Some(NONCE)).unwrap(),
            "0300010007000102030405060708090a0b13e3d5bb7fdb1913e44d8c593cb1542f296d51");
        let ack = AckDart { conv_id: 1, sender_id: 7, target_id: 9, seq: 12 };
        assert_hex("ack", &c.encode_ack(&ack, Some(NONCE)).unwrap(),
            "0700010007000900000c000102030405060708090a0b0fb7689169b3345bda3ae1045175b099");
        let reset = DictResetDart { conv_id: 1, sender_id: 7, target_id: 9 };
        assert_hex("dictReset", &c.encode_dict_reset(&reset, Some(NONCE)).unwrap(),
            "06000100070009000102030405060708090a0bdb933a8972efd7d1cacd06a9bf4bc2d8");
    }

    #[test]
    fn golden_key_exchange_frames() {
        let c = Codec::new();
        let req = KeyReqDart { conv_id: 1, sender_id: 7, req_nonce: REQ_NONCE, client_pub_key: {
            let mut k = vec![0x04]; k.extend(rep(0x01, 64)); k
        } };
        assert_hex("keyReq", &c.encode_key_req(&req),
            "0400010007000102030405060708090a0b0c0d0e0f0401010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101");
        let share = KeyShareDart { conv_id: 1, sender_id: 7, target_id: 9, epoch: 2, nonce: NONCE, encrypted_key: rep(0xBB, 32) };
        assert_hex("keyShare", &c.encode_key_share(&share, &rep(0x33, 32)).unwrap(),
            "080001000700090002000102030405060708090a0ba31cb58150dbb540a0b545dfffd009276cf071ff3e94649889b646f34315fb543dbfbdd04e3baad9e9c1810dda634d79");
        let cshare = ChainShareDart { conv_id: 1, sender_id: 7, target_id: 9, epoch: 2, nonce: NONCE, chain_key: rep(0xCC, 32), chain_index: 5 };
        assert_hex("chainShare", &c.encode_chain_share(&cshare, &rep(0x33, 32)).unwrap(),
            "0a0001000700090002000102030405060708090a0bd46bc2f627acc237d7c232a888a77e501b87068849e313effec1318434628c23e2b4c62dab2e8efe054b548df0acafe21afb1498");
        let server_pub = { let mut k = vec![0x04]; k.extend(rep(0x03, 64)); k };
        let pub_a = { let mut k = vec![0x04]; k.extend(rep(0x01, 64)); k };
        let pub_b = { let mut k = vec![0x04]; k.extend(rep(0x02, 64)); k };
        let info = MemberInfo {
            conv_id: 1, sender_id: 7, server_pub_key: server_pub, creator: true,
            members: vec![Member { sender_id: 7, pub_key: pub_a }, Member { sender_id: 9, pub_key: pub_b }],
        };
        assert_hex("memberInfo", &c.encode_member_info(&info, &rep(0x33, 32), Some(NONCE)).unwrap(),
            "09000100070403030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303000102030405060708090a0b19a70c3aec640ffa1a0fff65456ab39dd64acb45842ede22330cfc49f9af41eee3b5c729051ea802c02ae8667a8c11890320ab4b93afb203a980e77d49e2448ad66521f98c5011290b33bd659c289254ac2d969150609df3e08f699eba5b9b82cc1eafbf1836fc188a521e967fe33cf64bf96a1fbc554a1949ebb842c194a331bcbf673bf6349e1ad08a6f949d74a5dedb3598f1352d2d2fc4");
    }

    // ---- Deterministic ratchet-chain vectors (cross-language) ----

    #[test]
    fn chain_golden_vectors() {
        let seed = rep(0x44, 32);
        assert_hex("chainMsgKey0", &chain_message_key(&seed, 0), "e4b4d1bdd01191ce786b8f5efe2202757d94378135ad772bb9e01ed22d8ce688");
        assert_hex("chainNext0", &chain_next_key(&seed), "4f174eacd84d526c6e0ebd801d14be1a17b4b87d740f1d9518349204546d5e38");
        assert_hex("chainMsgKey1", &chain_message_key(&chain_next_key(&seed), 1), "44714fbdde4e6e726f97c386f8eb631ff12959963e732f878122ef5d6d1d8dac");
        let (msg_key, _) = advance_chain(&ChainState { key: seed, index: 0 }, 2);
        assert_hex("advance", &msg_key, "1ded480040e14f6fba5be12a1666a3542dec36f01629c21411b9d5f80bce05a0");
    }

    #[test]
    fn chain_properties() {
        let seed = rep(0x44, 32);
        let (m0, s1) = advance_chain(&ChainState { key: seed.clone(), index: 0 }, 0);
        let (m1, s2) = advance_chain(&s1, 1);
        let (m2, _) = advance_chain(&s2, 2);
        assert_ne!(m0, m1);
        assert_ne!(m1, m2);
        assert_ne!(m0, m2);
        assert_ne!(s2.key, seed, "chain did not ratchet");
        let (skipped, _) = advance_chain(&s1, 3);
        let (sequential, _) = advance_chain(&s2, 3);
        assert_eq!(skipped, sequential, "gap derivation not consistent");
    }
}
