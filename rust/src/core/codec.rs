#![allow(dead_code)]
use std::collections::HashMap;
use byteorder::{BigEndian, ByteOrder};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};
use sha2::{Digest, Sha256};
use super::{
    crypto::{decrypt_gcm, encrypt_gcm}, 
    AckDart, DataDart, DecryptedData, DictResetDart, KeyReqDart, KeyShareDart, Member, MemberInfo, NackDart, SyncDart,
    TYPE_ACK, TYPE_DATA, TYPE_DICT_RESET, TYPE_KEY_REQ, TYPE_KEY_SHARE, TYPE_MEMBER_INFO, TYPE_NACK, TYPE_SYNC,
};

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

    pub fn encode_data(&self, dart: &DataDart, dict: &[u8]) -> Result<Vec<u8>, String> {
        let epoch = *self.current_epochs.get(&dart.conv_id).unwrap_or(&1);
        let conv_key = self.room_keys.get(&dart.conv_id).and_then(|m| m.get(&epoch)).cloned()
            .ok_or_else(|| format!("no group key for conv {} epoch {}", dart.conv_id, epoch))?;

        let mut compressor = Compress::new(Compression::default(), false);
        if !dict.is_empty() {
            compressor.set_dictionary(dict).map_err(|e| format!("dict err: {:?}", e))?;
        }
        
        let mut compressed = vec![0u8; dart.payload.len() + 1024];
        let _status = compressor.compress(dart.payload.as_bytes(), &mut compressed, FlushCompress::Finish)
            .map_err(|e| format!("compress err: {:?}", e))?;
        compressed.truncate(compressor.total_out() as usize);

        // 7-byte cleartext header: type(1) | convId(2) | seq(3) | extLen(1).
        // The 18-byte extension carries nonce(12) + epoch(2) + dict fingerprint(4).
        let nonce: [u8; 12] = rand::random();
        let dict_fp = dict_fingerprint(dict);

        let mut header = vec![0u8; 7];
        header[0] = dart.type_id();
        BigEndian::write_u16(&mut header[1..3], dart.conv_id);
        write_u24(&mut header[3..6], dart.seq);
        header[6] = 12 + 2 + 4; // ext_len = nonce + epoch + dict fingerprint

        let mut aad = header.clone();
        aad.extend_from_slice(&nonce);
        aad.extend_from_slice(&epoch.to_be_bytes());
        aad.extend_from_slice(&dict_fp);

        let mut plaintext = Vec::with_capacity(2 + compressed.len());
        plaintext.extend_from_slice(&dart.sender_id.to_be_bytes());
        plaintext.extend_from_slice(&compressed);

        let ciphertext = encrypt_gcm(&conv_key, &nonce, &plaintext, &aad)
            .map_err(|e| format!("encrypt err: {:?}", e))?;

        let mut res = aad;
        res.extend_from_slice(&ciphertext);
        Ok(res)
    }

    pub fn decrypt_data(&self, buf: &[u8]) -> Result<DecryptedData, String> {
        if buf.len() < 7 {
            return Err("buffer too short".to_string());
        }
        let conv_id = BigEndian::read_u16(&buf[1..3]);
        let seq = read_u24(&buf[3..6]);
        let ext_len = buf[6] as usize;

        if buf.len() < 7 + ext_len + 16 {
            return Err("invalid payload length".to_string());
        }
        let aad = &buf[..7 + ext_len];
        let nonce = &buf[7..7 + 12];
        let epoch = BigEndian::read_u16(&buf[7 + 12..7 + 14]);
        let dict_fp_raw = &buf[7 + 14..7 + ext_len];
        let encrypted_with_tag = &buf[7 + ext_len..];

        let conv_key = self.room_keys.get(&conv_id).and_then(|m| m.get(&epoch)).cloned()
            .ok_or_else(|| format!("no group key for conv {} epoch {}", conv_id, epoch))?;

        let plaintext = decrypt_gcm(&conv_key, nonce, encrypted_with_tag, aad)
            .map_err(|e| format!("decrypt err: {:?}", e))?;

        if plaintext.len() < 2 {
            return Err("invalid plaintext length".to_string());
        }
        let sender_id = BigEndian::read_u16(&plaintext[0..2]);
        let compressed = plaintext[2..].to_vec();

        let mut dict_fp = [0u8; 4];
        dict_fp.copy_from_slice(dict_fp_raw);

        Ok(DecryptedData {
            conv_id,
            sender_id,
            seq,
            compressed,
            dict_fp,
            epoch,
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

    pub fn encode_nack(&self, nack: &NackDart) -> Result<Vec<u8>, String> {
        let conv_key = self.get_conv_key(nack.conv_id)?;

        // 17-byte cleartext header: type(1) | convId(2) | senderId(2) | nonce(12).
        // A fresh random nonce per packet eliminates the GCM nonce-reuse the old
        // fixed sentinel IV (0xFFFFFFFE) allowed.
        let nonce: [u8; 12] = rand::random();

        let mut header = vec![0u8; 17];
        header[0] = TYPE_NACK;
        BigEndian::write_u16(&mut header[1..3], nack.conv_id);
        BigEndian::write_u16(&mut header[3..5], nack.sender_id);
        header[5..17].copy_from_slice(&nonce);

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
            missing_seq,
        })
    }

    pub fn encode_sync(&self, sync: &SyncDart) -> Result<Vec<u8>, String> {
        let conv_key = self.get_conv_key(sync.conv_id)?;

        // 17-byte cleartext header: type(1) | convId(2) | senderId(2) | nonce(12).
        let nonce: [u8; 12] = rand::random();

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

    pub fn encode_member_info(&self, info: &MemberInfo, transport_key: &[u8]) -> Result<Vec<u8>, String> {
        let mut header = vec![0u8; 5];
        header[0] = TYPE_MEMBER_INFO;
        BigEndian::write_u16(&mut header[1..3], info.conv_id);
        BigEndian::write_u16(&mut header[3..5], info.sender_id);

        let nonce: [u8; 12] = rand::random();
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

    pub fn encode_dict_reset(&self, reset: &DictResetDart) -> Result<Vec<u8>, String> {
        let conv_key = self.get_conv_key(reset.conv_id)?;

        // 19-byte cleartext header: type(1) | convId(2) | senderId(2) | targetId(2)
        // | nonce(12). The whole header is the AEAD AAD, so an outsider can't
        // forge a reset.
        let nonce: [u8; 12] = rand::random();

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

    pub fn encode_ack(&self, ack: &AckDart) -> Result<Vec<u8>, String> {
        let conv_key = self.get_conv_key(ack.conv_id)?;

        // 22-byte cleartext header: type(1) | convId(2) | senderId(2) | targetId(2)
        // | seq(3) | nonce(12). The whole header is the AEAD AAD, so an outsider
        // can't forge a delivery confirmation.
        let nonce: [u8; 12] = rand::random();

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
