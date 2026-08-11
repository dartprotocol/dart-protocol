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
pub const TYPE_CHAIN_SHARE: u8 = 0x0A;

// Bounds the per-sender compression window so both sides build identical
// dictionaries deterministically and clients can prune older history.
pub const DICT_WINDOW: u32 = 200;

// Sequence numbers are 24 bits on the wire. Internally we keep them in this
// same modular space so the counter wraps cleanly at 2^24 instead of drifting
// away from the wire encoding (which would silently stop delivery at the wrap
// boundary).
pub const SEQ_MOD: u32 = 1 << 24;

/// Number of sequence steps from `from` to `to`, modulo the 24-bit space.
/// 0 means equal; values in (0, SEQ_MOD/2) mean `to` is ahead of `from`;
/// values >= SEQ_MOD/2 mean `to` is behind (a stale/duplicate).
pub fn seq_delta(from: u32, to: u32) -> u32 {
    (to.wrapping_sub(from)) & 0xFFFFFF
}

/// Next sequence number in the 24-bit space. The value 0 is a legitimate
/// message (right after 0xFFFFFF); callers distinguish "no messages seen yet"
/// by checking whether a per-sender entry exists in their highest-seen map,
/// never by the numeric value alone.
pub fn seq_next(s: u32) -> u32 {
    (s + 1) & 0xFFFFFF
}

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
    pub idx: u32,
}

// A sender's per-message ratchet chain state. `key` is the chain key for the
// NEXT message (at `index`); each message consumes it and advances the chain.
#[derive(Debug, Clone)]
pub struct ChainState {
    pub key: Vec<u8>,
    pub index: u32,
}

// CHAIN_SHARE payload: a sender distributes its current chain state so a peer
// can decrypt its future messages. ECDH-encrypted to the target member.
#[derive(Debug, Clone)]
pub struct ChainShareDart {
    pub conv_id: u16,
    pub sender_id: u16,
    pub target_id: u16,
    pub epoch: u16,
    pub nonce: [u8; 12],
    pub chain_key: Vec<u8>,
    pub chain_index: u32,
}

#[derive(Debug, Clone)]
pub struct NackDart {
    pub conv_id: u16,
    pub sender_id: u16, // the member who detected the gap (the signer)
    pub target_id: u16, // the member whose stream has the gap
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
