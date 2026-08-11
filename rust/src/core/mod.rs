#![allow(dead_code)]
pub mod codec;
pub mod crypto;
pub mod ecdh;

pub const TYPE_DATA: u8 = 0x01;
pub const TYPE_NACK: u8 = 0x02;
pub const TYPE_SYNC: u8 = 0x03;
pub const TYPE_KEY_REQ: u8 = 0x04;
pub const TYPE_KEY_SHARE: u8 = 0x08;
pub const TYPE_MEMBER_INFO: u8 = 0x09;
pub const TYPE_DICT_RESET: u8 = 0x06;
pub const TYPE_ACK: u8 = 0x07;

// Bounds the per-sender compression window so both sides build identical
// dictionaries deterministically and clients can prune older history.
pub const DICT_WINDOW: u32 = 200;

#[derive(Debug, Clone)]
pub struct DataDart {
    pub conv_id: u16,
    pub sender_id: u16,
    pub seq: u32,
    pub payload: String,
}

// First stage of decoding a Data dart: decrypted but not yet inflated.
// Inflation needs the per-sender dictionary, which requires sender_id.
#[derive(Debug, Clone)]
pub struct DecryptedData {
    pub conv_id: u16,
    pub sender_id: u16,
    pub seq: u32,
    pub compressed: Vec<u8>,
    pub dict_fp: [u8; 4],
    pub epoch: u16,
}

#[derive(Debug, Clone)]
pub struct NackDart {
    pub conv_id: u16,
    pub sender_id: u16,
    pub missing_seq: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct SyncDart {
    pub conv_id: u16,
    pub sender_id: u16,
    pub highest_seq: u32,
}

#[derive(Debug, Clone)]
pub struct KeyReqDart {
    pub conv_id: u16,
    pub sender_id: u16,
    pub req_nonce: [u8; 16],
    pub client_pub_key: Vec<u8>,
}

// A member-to-member group-key delivery, relayed opaquely by the server. The
// 32-byte group key is ECDH-encrypted to the target member.
#[derive(Debug, Clone)]
pub struct KeyShareDart {
    pub conv_id: u16,
    pub sender_id: u16,
    pub target_id: u16,
    pub epoch: u16,
    pub nonce: [u8; 12],
    pub encrypted_key: Vec<u8>, // GCM ciphertext+tag of the group key
}

#[derive(Debug, Clone)]
pub struct Member {
    pub sender_id: u16,
    pub pub_key: Vec<u8>,
}

// Server-authenticated membership roster.
#[derive(Debug, Clone)]
pub struct MemberInfo {
    pub conv_id: u16,
    pub sender_id: u16,
    pub server_pub_key: Vec<u8>,
    pub creator: bool,
    pub members: Vec<Member>,
}

#[derive(Debug, Clone)]
pub struct DictResetDart {
    pub conv_id: u16,
    pub sender_id: u16,
    pub target_id: u16,
}

#[derive(Debug, Clone)]
pub struct AckDart {
    pub conv_id: u16,
    pub sender_id: u16,
    pub target_id: u16,
    pub seq: u32,
}
