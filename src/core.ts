import * as crypto from 'crypto';
import * as pako from 'pako';

export const TYPE_DATA = 0x01;
export const TYPE_NACK = 0x02;
export const TYPE_SYNC = 0x03;
export const TYPE_KEY_REQ = 0x04;
export const TYPE_KEY_SHARE = 0x08;
export const TYPE_MEMBER_INFO = 0x09;
export const TYPE_CHAIN_SHARE = 0x0A;
export const TYPE_DICT_RESET = 0x06;
export const TYPE_ACK = 0x07;

// Delta compression is bounded to the last DICT_WINDOW messages of a sender,
// so sender and receiver build identical dictionaries deterministically and
// clients can prune older history (bounded memory).
export const DICT_WINDOW = 200;

// 4-byte SHA-256 fingerprint of the dictionary, carried in the Data header's
// extension area. Receivers verify it before inflating so a dictionary
// desync is detected immediately and recovered in a single step.
export const DICT_FP_LEN = 4;

export interface DataDart {
  type: number;
  convId: number;
  senderId: number;
  seq: number;
  payload: string; 
}

export interface NackDart {
  type: number;
  convId: number;
  senderId: number; // the member who detected the gap (the signer)
  targetId: number; // the member whose stream has the gap
  missingSeq: number[];
}

export interface SyncDart {
  type: number;
  convId: number;
  senderId: number;
  highestSeq: number;
}

export interface KeyReqDart {
  type: number;
  convId: number;
  senderId: number;
  reqNonce: Buffer;
  clientPubKey: Buffer;
}

// A member-to-member group-key share, relayed opaquely by the server. The
// payload (the 32-byte group key) is ECDH-encrypted to the target member.
export interface KeyShareDart {
  type: number;
  convId: number;
  senderId: number;
  targetId: number;
  epoch: number;
  nonce: Buffer;
  encryptedKey: Buffer; // GCM ciphertext+tag of the group key
}

// Server-authenticated membership roster. The server encrypts it to the member
// using the server's long-term key + the member's public key, so a client that
// pins the server's fingerprint can trust it.
export interface MemberInfo {
  type: number;
  convId: number;
  senderId: number;
  serverPubKey: Buffer;
  creator: boolean;
  members: { senderId: number; pubKey: Buffer }[];
}

export interface DictResetDart {
  type: number;
  convId: number;
  senderId: number;
  targetId: number;
}

export interface AckDart {
  type: number;
  convId: number;
  senderId: number;
  targetId: number;
  seq: number;
}

export interface DecryptedData {
  type: number;
  convId: number;
  senderId: number;
  seq: number;
  compressed: Buffer;
  dictFp: Buffer;
  idx: number;
}

// A sender's per-message ratchet chain state. `key` is the chain key for the
// NEXT message (at `index`); each message consumes it and advances the chain.
export interface ChainState {
  key: Buffer;
  index: number;
}

// Payload of a CHAIN_SHARE: a sender distributes its current chain state so a
// peer can decrypt its future messages. ECDH-encrypted to the target member.
export interface ChainShareDart {
  type: number;
  convId: number;
  senderId: number; // the member whose chain this is
  targetId: number;
  epoch: number;
  nonce: Buffer;
  chainKey: Buffer;
  chainIndex: number;
}

// First 4 bytes of SHA-256(dict). Both the sender and every receiver compute
// this over their own (windowed) dictionary; a mismatch means lost history.
export function dictFingerprint(dict: Buffer): Buffer {
  return crypto.createHash('sha256').update(dict).digest().subarray(0, DICT_FP_LEN);
}

// Sequence numbers are 24 bits on the wire. Internally we keep them in this
// same modular space so the counter wraps cleanly at 2^24 instead of drifting
// away from the wire encoding (which would silently stop delivery at the wrap
// boundary, and crash Node's writeUIntBE when the value exceeds 3 bytes).
export const SEQ_MOD = 1 << 24;

// Number of sequence steps from `from` to `to`, modulo the 24-bit space.
// 0 means equal; values in (0, SEQ_MOD / 2) mean `to` is ahead of `from`;
// values >= SEQ_MOD / 2 mean `to` is behind (a stale/duplicate).
export function seqDelta(from: number, to: number): number {
  return (to - from) & 0xFFFFFF;
}

// Next sequence number in the 24-bit space. The value 0 is a legitimate
// message (right after 0xFFFFFF); callers distinguish "no messages seen yet"
// by checking whether a per-sender entry exists in their highest-seen map,
// never by the numeric value alone.
export function seqNext(s: number): number {
  return (s + 1) & 0xFFFFFF;
}

// ---------------------------------------------------------------------------
// Per-sender control-frame authentication.
//
// Control frames are already GCM-authenticated with the group key, which only
// proves "some group member". To attribute a frame to a specific member (and
// stop a group member forging another member's ACK/NACK/SYNC/Dict-Reset) we
// append an HMAC keyed with an ECDH-derived pairwise key:
//
//   pairKey(myPriv, peerPub) = SHA-256(ECDH(myPriv, peerPub))
//
// Only the sender and the intended peer can derive it, so a third member can't
// forge the frame. Directed frames (ACK, NACK) are keyed to their TARGET member
// and verified by that member; broadcast frames (SYNC, Dict-Reset) are keyed
// to the relay server (which holds every member's public key) and verified by
// the server before it relays them. These primitives only need ECDH + HMAC, so
// they also work in the browser (crypto-browserify) client.
// ---------------------------------------------------------------------------

export const CTRL_MAC_LEN = 32;

export function safeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// Derive the per-sender MAC key between `myEcdh` (this member) and a peer's
// public key. Both sides compute the same value from their own private key.
export function pairwiseKey(myEcdh: crypto.ECDH, peerPubKey: Buffer): Buffer {
  const secret = myEcdh.computeSecret(peerPubKey);
  return crypto.createHash('sha256').update(secret).digest();
}

// Append HMAC-SHA256(key, frame) to a control frame.
export function signControlFrame(frame: Buffer, key: Buffer): Buffer {
  const mac = crypto.createHmac('sha256', key).update(frame).digest();
  return Buffer.concat([frame, mac]);
}

// Verify and strip the trailing HMAC. Returns the stripped frame or null.
export function verifyControlFrame(frame: Buffer, key: Buffer): Buffer | null {
  if (frame.length < CTRL_MAC_LEN) return null;
  const payload = frame.subarray(0, frame.length - CTRL_MAC_LEN);
  const mac = frame.subarray(frame.length - CTRL_MAC_LEN);
  const expected = crypto.createHmac('sha256', key).update(payload).digest();
  if (!safeEqual(expected, mac)) return null;
  return Buffer.from(payload);
}

// Strip the trailing HMAC without verifying (used by the relay server, which
// cannot derive member-to-member keys, and by members trusting server-verified
// SYNC/Dict-Reset frames).
export function stripControlFrame(frame: Buffer): Buffer | null {
  if (frame.length < CTRL_MAC_LEN) return null;
  return Buffer.from(frame.subarray(0, frame.length - CTRL_MAC_LEN));
}

// ---------------------------------------------------------------------------
// Per-sender message ratchet (sender keys).
//
// Each member owns a one-way ratchet chain per (conversation, epoch). A message
// is encrypted with a key derived from the chain, and the chain ratchets forward
// on every message, so:
//   * every message has a UNIQUE key (a compromised message key decrypts only
//     that one message), and
//   * the chain is one-way (a compromised chain state reveals future messages
//     but NOT past ones - forward secrecy).
// The chain state is distributed member-to-member via CHAIN_SHARE so peers can
// decrypt; a fresh peer receives the CURRENT state (no history decryption).
// ---------------------------------------------------------------------------

// Per-message key for a chain key at the given index.
export function chainMessageKey(chainKey: Buffer, index: number): Buffer {
  const idxBuf = Buffer.alloc(4);
  idxBuf.writeUInt32BE(index >>> 0, 0);
  return crypto.createHmac('sha256', chainKey).update(Buffer.concat([Buffer.from('DartMsgKey'), idxBuf])).digest();
}

// The chain key that follows `chainKey` after one message.
export function chainNextKey(chainKey: Buffer): Buffer {
  return crypto.createHmac('sha256', chainKey).update(Buffer.from('DartChainKey')).digest();
}

// Advance a chain state to `targetIndex` (>= state.index, skipping any lost
// messages) and consume the message key at `targetIndex`. Returns the message
// key and the advanced state (whose index is targetIndex + 1).
export function advanceChain(state: ChainState, targetIndex: number): { messageKey: Buffer; state: ChainState } {
  let key = state.key;
  let index = state.index;
  while (index < targetIndex) {
    key = chainNextKey(key);
    index++;
  }
  const messageKey = chainMessageKey(key, index);
  return { messageKey, state: { key: chainNextKey(key), index: index + 1 } };
}

export class Codec {
  static encodeDataHelper(dart: DataDart, dict: Buffer, messageKey: Buffer, idx: number, epoch: number, nonce?: Buffer): Buffer {

    const payload = Buffer.from(dart.payload, 'utf-8');
    const compressed = Buffer.from(pako.deflateRaw(payload, { dictionary: dict }));

    // 7-byte cleartext header: type(1) | convId(2) | seq(3) | extLen(1).
    // 24-byte cleartext extension (whole prefix is the AEAD AAD):
    //   senderId(2) | nonce(12) | epoch(2) | dictFp(4) | idx(4).
    // senderId is cleartext so the receiver can select the sender's ratchet
    // chain before decrypting; idx is the monotonic per-chain message index.
    // The encrypted payload is just the deflated message; the cipher key is the
    // per-message key derived from the sender's chain.
    nonce = nonce || crypto.randomBytes(12);
    const dictFp = dictFingerprint(dict);

    const prefix = Buffer.alloc(7 + 24);
    prefix.writeUInt8(dart.type, 0);
    prefix.writeUInt16BE(dart.convId, 1);
    prefix.writeUIntBE(dart.seq & 0xFFFFFF, 3, 3);
    prefix.writeUInt8(24, 6);
    prefix.writeUInt16BE(dart.senderId, 7);
    nonce.copy(prefix, 9);
    prefix.writeUInt16BE(epoch, 21);
    dictFp.copy(prefix, 23);
    prefix.writeUInt32BE(idx >>> 0, 27);

    const cipher = crypto.createCipheriv('aes-256-gcm', messageKey, nonce);
    cipher.setAAD(prefix);

    const encryptedPayload = Buffer.concat([cipher.update(compressed), cipher.final()]);
    const tag = cipher.getAuthTag();

    return Buffer.concat([prefix, encryptedPayload, tag]);
  }

  static decryptData(buf: Buffer, messageKey: Buffer): DecryptedData {
    const type = buf.readUInt8(0);
    const convId = buf.readUInt16BE(1);
    const seq = buf.readUIntBE(3, 3);
    const extLen = buf.readUInt8(6);

    const prefix = Buffer.from(buf.subarray(0, 7 + extLen));
    const senderId = prefix.readUInt16BE(7);
    const nonce = Buffer.from(prefix.subarray(9, 9 + 12));
    const epoch = prefix.readUInt16BE(21);
    const dictFp = Buffer.from(prefix.subarray(23, 23 + 4));
    const idx = prefix.readUInt32BE(27);
    const encryptedPayload = Buffer.from(buf.subarray(7 + extLen, buf.length - 16));
    const tag = Buffer.from(buf.subarray(buf.length - 16));

    const decipher = crypto.createDecipheriv('aes-256-gcm', messageKey, nonce);
    decipher.setAAD(prefix);
    decipher.setAuthTag(tag);

    const compressed = Buffer.concat([decipher.update(encryptedPayload), decipher.final()]);

    return { type, convId, senderId, seq, compressed, dictFp, idx };
  }

  static inflateData(compressed: Buffer, dict: Buffer): string {
    const payloadBuffer = Buffer.from(pako.inflateRaw(compressed, { dictionary: dict }));
    return payloadBuffer.toString('utf-8');
  }

  // Gap list is cleartext so a blind relay can repair from cache without the
  // group key. GCM authenticates an empty plaintext; the whole prefix is AAD.
  static nackPrefixLen(missingCount: number): number {
    return 21 + missingCount * 3;
  }

  static parseNack(buf: Buffer): NackDart {
    if (buf.length < 21) {
      throw new Error('buffer too short');
    }
    const type = buf.readUInt8(0);
    const convId = buf.readUInt16BE(1);
    const senderId = buf.readUInt16BE(3);
    const targetId = buf.readUInt16BE(5);
    const count = buf.readUInt16BE(19);
    const headerLen = Codec.nackPrefixLen(count);
    if (buf.length < headerLen) {
      throw new Error('buffer too short');
    }
    const missingSeq: number[] = [];
    for (let i = 0; i < count; i++) {
      missingSeq.push(buf.readUIntBE(21 + i * 3, 3));
    }
    return { type, convId, senderId, targetId, missingSeq };
  }

  static encodeNack(nack: NackDart, convKey: Buffer, nonce?: Buffer): Buffer {
    // Cleartext prefix: type(1) | convId(2) | senderId(2) | targetId(2)
    // | nonce(12) | count(2) | seqs(3*count). senderId is the member who
    // detected the gap (the signer); targetId is the member whose stream has
    // the gap. The target verifies the per-sender HMAC.
    nonce = nonce || crypto.randomBytes(12);
    const count = nack.missingSeq.length;
    const header = Buffer.alloc(Codec.nackPrefixLen(count));
    header.writeUInt8(nack.type, 0);
    header.writeUInt16BE(nack.convId, 1);
    header.writeUInt16BE(nack.senderId, 3);
    header.writeUInt16BE(nack.targetId, 5);
    nonce.copy(header, 7);
    header.writeUInt16BE(count, 19);
    for (let i = 0; i < count; i++) {
      header.writeUIntBE(nack.missingSeq[i] & 0xFFFFFF, 21 + i * 3, 3);
    }

    const cipher = crypto.createCipheriv('aes-256-gcm', convKey, nonce);
    cipher.setAAD(header);
    cipher.final();
    const tag = cipher.getAuthTag();
    return Buffer.concat([header, tag]);
  }

  static decodeNack(buf: Buffer, convKey: Buffer): NackDart {
    const nack = Codec.parseNack(buf);
    const headerLen = Codec.nackPrefixLen(nack.missingSeq.length);
    if (buf.length < headerLen + 16) {
      throw new Error('buffer too short');
    }
    const header = Buffer.from(buf.subarray(0, headerLen));
    const nonce = Buffer.from(header.subarray(7, 19));
    const tag = Buffer.from(buf.subarray(headerLen, headerLen + 16));

    const decipher = crypto.createDecipheriv('aes-256-gcm', convKey, nonce);
    decipher.setAAD(header);
    decipher.setAuthTag(tag);
    decipher.final();
    return nack;
  }
  
  static encodeSync(sync: SyncDart, convKey: Buffer, nonce?: Buffer): Buffer {

    // 17-byte cleartext header: type(1) | convId(2) | senderId(2) | nonce(12).
    nonce = nonce || crypto.randomBytes(12);

    const header = Buffer.alloc(17);
    header.writeUInt8(sync.type, 0);
    header.writeUInt16BE(sync.convId, 1);
    header.writeUInt16BE(sync.senderId, 3);
    nonce.copy(header, 5);

    const payload = Buffer.alloc(3);
    payload.writeUIntBE(sync.highestSeq & 0xFFFFFF, 0, 3);

    const cipher = crypto.createCipheriv('aes-256-gcm', convKey, nonce);
    cipher.setAAD(header);
    const encryptedPayload = Buffer.concat([cipher.update(payload), cipher.final()]);
    const tag = cipher.getAuthTag();
    
    return Buffer.concat([header, encryptedPayload, tag]);
  }

  static decodeSync(buf: Buffer, convKey: Buffer): SyncDart {
    const type = buf.readUInt8(0);
    const convId = buf.readUInt16BE(1);
    const senderId = buf.readUInt16BE(3);
    const header = Buffer.from(buf.subarray(0, 17));
    const nonce = Buffer.from(header.subarray(5));
    const encryptedPayload = Buffer.from(buf.subarray(17, buf.length - 16));
    const tag = Buffer.from(buf.subarray(buf.length - 16));
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', convKey, nonce);
    decipher.setAAD(header);
    decipher.setAuthTag(tag);
    
    const payload = Buffer.concat([decipher.update(encryptedPayload), decipher.final()]);
    const highestSeq = payload.readUIntBE(0, 3);
    return { type, convId, senderId, highestSeq };
  }

  static encodeKeyReq(req: KeyReqDart): Buffer {
    const header = Buffer.alloc(5);
    header.writeUInt8(req.type, 0);
    header.writeUInt16BE(req.convId, 1);
    header.writeUInt16BE(req.senderId, 3);
    return Buffer.concat([header, req.reqNonce, req.clientPubKey]);
  }

  static decodeKeyReq(buf: Buffer): KeyReqDart {
    const type = buf.readUInt8(0);
    const convId = buf.readUInt16BE(1);
    const senderId = buf.readUInt16BE(3);
    const reqNonce = Buffer.from(buf.subarray(5, 21));
    const clientPubKey = Buffer.from(buf.subarray(21));
    return { type, convId, senderId, reqNonce, clientPubKey };
  }

  // SHA-256 hex fingerprint of the server's static ECDH public key. Clients pin
  // this value to authenticate the server (SSH-style host-key verification), so
  // an active man-in-the-middle can't substitute its own key.
  static serverFingerprint(serverPubKey: Buffer): string {
    return crypto.createHash('sha256').update(serverPubKey).digest('hex');
  }

  // KEY_SHARE: member -> member group-key delivery, relayed opaquely by the
  // server. transportKey = SHA-256(ECDH(sharer's key, target's pubkey)).
  static encodeKeyShare(share: KeyShareDart, transportKey: Buffer): Buffer {
    const header = Buffer.alloc(21);
    header.writeUInt8(share.type, 0);
    header.writeUInt16BE(share.convId, 1);
    header.writeUInt16BE(share.senderId, 3);
    header.writeUInt16BE(share.targetId, 5);
    header.writeUInt16BE(share.epoch, 7);
    share.nonce.copy(header, 9);

    const cipher = crypto.createCipheriv('aes-256-gcm', transportKey, share.nonce);
    cipher.setAAD(header);
    const encryptedKey = Buffer.concat([cipher.update(share.encryptedKey), cipher.final(), cipher.getAuthTag()]);
    return Buffer.concat([header, encryptedKey]);
  }

  static decodeKeyShare(buf: Buffer, transportKey: Buffer): { epoch: number; groupKey: Buffer } {
    if (buf.length < 21 + 48) {
      throw new Error('buffer too short');
    }
    const epoch = buf.readUInt16BE(7);
    const header = Buffer.from(buf.subarray(0, 21));
    const nonce = Buffer.from(header.subarray(9));
    const encryptedKey = Buffer.from(buf.subarray(21, buf.length - 16));
    const tag = Buffer.from(buf.subarray(buf.length - 16));

    const decipher = crypto.createDecipheriv('aes-256-gcm', transportKey, nonce);
    decipher.setAAD(header);
    decipher.setAuthTag(tag);
    const groupKey = Buffer.concat([decipher.update(encryptedKey), decipher.final()]);
    return { epoch, groupKey };
  }

  // CHAIN_SHARE: member -> member per-sender ratchet-chain delivery, relayed
  // opaquely by the server. transportKey = SHA-256(ECDH(sharer's key,
  // target's pubkey)). A member distributes its CURRENT chain state so peers
  // can decrypt its future messages (and no history, so forward secrecy).
  static encodeChainShare(share: ChainShareDart, transportKey: Buffer): Buffer {
    const header = Buffer.alloc(21);
    header.writeUInt8(share.type, 0);
    header.writeUInt16BE(share.convId, 1);
    header.writeUInt16BE(share.senderId, 3);
    header.writeUInt16BE(share.targetId, 5);
    header.writeUInt16BE(share.epoch, 7);
    share.nonce.copy(header, 9);

    const payload = Buffer.alloc(36);
    share.chainKey.copy(payload, 0);
    payload.writeUInt32BE(share.chainIndex >>> 0, 32);

    const cipher = crypto.createCipheriv('aes-256-gcm', transportKey, share.nonce);
    cipher.setAAD(header);
    const encrypted = Buffer.concat([cipher.update(payload), cipher.final(), cipher.getAuthTag()]);
    return Buffer.concat([header, encrypted]);
  }

  static decodeChainShare(buf: Buffer, transportKey: Buffer): ChainShareDart {
    if (buf.length < 21 + 36 + 16) {
      throw new Error('buffer too short');
    }
    const type = buf.readUInt8(0);
    const convId = buf.readUInt16BE(1);
    const senderId = buf.readUInt16BE(3);
    const targetId = buf.readUInt16BE(5);
    const epoch = buf.readUInt16BE(7);
    const header = Buffer.from(buf.subarray(0, 21));
    const nonce = Buffer.from(header.subarray(9));
    const encrypted = Buffer.from(buf.subarray(21, buf.length - 16));
    const tag = Buffer.from(buf.subarray(buf.length - 16));

    const decipher = crypto.createDecipheriv('aes-256-gcm', transportKey, nonce);
    decipher.setAAD(header);
    decipher.setAuthTag(tag);
    const payload = Buffer.concat([decipher.update(encrypted), decipher.final()]);

    return {
      type,
      convId,
      senderId,
      targetId,
      epoch,
      nonce,
      chainKey: Buffer.from(payload.subarray(0, 32)),
      chainIndex: payload.readUInt32BE(32),
    };
  }

  // MEMBER_INFO: server -> member roster. transportKey = SHA-256(ECDH(server
  // key, member pubkey)). The AAD binds the header + the server's public key,
  // so a client that pins the server fingerprint trusts the roster.
  static encodeMemberInfo(info: MemberInfo, transportKey: Buffer, nonce?: Buffer): Buffer {
    const header = Buffer.alloc(5);
    header.writeUInt8(info.type, 0);
    header.writeUInt16BE(info.convId, 1);
    header.writeUInt16BE(info.senderId, 3);

    nonce = nonce || crypto.randomBytes(12);
    const payload = Buffer.alloc(1 + 2 + info.members.length * 67);
    payload.writeUInt8(info.creator ? 1 : 0, 0);
    payload.writeUInt16BE(info.members.length, 1);
    let offset = 3;
    for (const m of info.members) {
      payload.writeUInt16BE(m.senderId, offset);
      m.pubKey.copy(payload, offset + 2);
      offset += 67;
    }

    const aad = Buffer.concat([header, info.serverPubKey, nonce]);
    const cipher = crypto.createCipheriv('aes-256-gcm', transportKey, nonce);
    cipher.setAAD(aad);
    const encrypted = Buffer.concat([cipher.update(payload), cipher.final(), cipher.getAuthTag()]);

    return Buffer.concat([header, info.serverPubKey, nonce, encrypted]);
  }

  // Returns the server public key embedded in a MEMBER_INFO packet, so a client
  // can verify the pin and derive the transport key BEFORE decrypting.
  static memberInfoServerKey(buf: Buffer): Buffer {
    if (buf.length < 70) {
      throw new Error('buffer too short');
    }
    return Buffer.from(buf.subarray(5, 70));
  }

  static decodeMemberInfo(buf: Buffer, transportKey: Buffer): MemberInfo {
    if (buf.length < 5 + 65 + 12 + 16) {
      throw new Error('buffer too short');
    }
    const type = buf.readUInt8(0);
    const convId = buf.readUInt16BE(1);
    const senderId = buf.readUInt16BE(3);
    const serverPubKey = Buffer.from(buf.subarray(5, 70));
    const nonce = Buffer.from(buf.subarray(70, 82));
    const encrypted = Buffer.from(buf.subarray(82));

    const header = Buffer.from(buf.subarray(0, 5));
    const aad = Buffer.concat([header, serverPubKey, nonce]);
    const decipher = crypto.createDecipheriv('aes-256-gcm', transportKey, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(Buffer.from(encrypted.subarray(encrypted.length - 16)));
    const payload = Buffer.concat([decipher.update(encrypted.subarray(0, encrypted.length - 16)), decipher.final()]);

    const creator = payload.readUInt8(0) === 1;
    const count = payload.readUInt16BE(1);
    const members: { senderId: number; pubKey: Buffer }[] = [];
    let offset = 3;
    for (let i = 0; i < count; i++) {
      const mSenderId = payload.readUInt16BE(offset);
      const pubKey = Buffer.from(payload.subarray(offset + 2, offset + 67));
      members.push({ senderId: mSenderId, pubKey });
      offset += 67;
    }
    return { type, convId, senderId, serverPubKey, creator, members };
  }

  static encodeDictReset(reset: DictResetDart, convKey: Buffer, nonce?: Buffer): Buffer {

    // 19-byte cleartext header: type(1) | convId(2) | senderId(2) | targetId(2) | nonce(12).
    // The whole header is the AEAD AAD, so an outsider can't forge a reset.
    nonce = nonce || crypto.randomBytes(12);

    const header = Buffer.alloc(19);
    header.writeUInt8(reset.type, 0);
    header.writeUInt16BE(reset.convId, 1);
    header.writeUInt16BE(reset.senderId, 3);
    header.writeUInt16BE(reset.targetId, 5);
    nonce.copy(header, 7);

    const cipher = crypto.createCipheriv('aes-256-gcm', convKey, nonce);
    cipher.setAAD(header);
    cipher.final();
    const tag = cipher.getAuthTag();
    return Buffer.concat([header, tag]);
  }

  static decodeDictReset(buf: Buffer, convKey: Buffer): DictResetDart {
    if (buf.length < 19) {
      throw new Error('buffer too short');
    }
    const type = buf.readUInt8(0);
    const convId = buf.readUInt16BE(1);
    const senderId = buf.readUInt16BE(3);
    const targetId = buf.readUInt16BE(5);
    const header = Buffer.from(buf.subarray(0, 19));
    const nonce = Buffer.from(header.subarray(7));
    const encryptedPayload = Buffer.from(buf.subarray(19, buf.length - 16));
    const tag = Buffer.from(buf.subarray(buf.length - 16));

    const decipher = crypto.createDecipheriv('aes-256-gcm', convKey, nonce);
    decipher.setAAD(header);
    decipher.setAuthTag(tag);
    Buffer.concat([decipher.update(encryptedPayload), decipher.final()]);

    return { type, convId, senderId, targetId };
  }

  static encodeAck(ack: AckDart, convKey: Buffer, nonce?: Buffer): Buffer {

    // 22-byte cleartext header: type(1) | convId(2) | senderId(2) | targetId(2)
    // | seq(3) | nonce(12). The whole header is the AEAD AAD, so an outsider
    // can't forge a delivery confirmation.
    nonce = nonce || crypto.randomBytes(12);

    const header = Buffer.alloc(22);
    header.writeUInt8(ack.type, 0);
    header.writeUInt16BE(ack.convId, 1);
    header.writeUInt16BE(ack.senderId, 3);
    header.writeUInt16BE(ack.targetId, 5);
    header.writeUIntBE(ack.seq & 0xFFFFFF, 7, 3);
    nonce.copy(header, 10);

    const cipher = crypto.createCipheriv('aes-256-gcm', convKey, nonce);
    cipher.setAAD(header);
    cipher.final();
    const tag = cipher.getAuthTag();
    return Buffer.concat([header, tag]);
  }

  static decodeAck(buf: Buffer, convKey: Buffer): AckDart {
    if (buf.length < 22) {
      throw new Error('buffer too short');
    }
    const type = buf.readUInt8(0);
    const convId = buf.readUInt16BE(1);
    const senderId = buf.readUInt16BE(3);
    const targetId = buf.readUInt16BE(5);
    const seq = buf.readUIntBE(7, 3);
    const header = Buffer.from(buf.subarray(0, 22));
    const nonce = Buffer.from(header.subarray(10));
    const encryptedPayload = Buffer.from(buf.subarray(22, buf.length - 16));
    const tag = Buffer.from(buf.subarray(buf.length - 16));

    const decipher = crypto.createDecipheriv('aes-256-gcm', convKey, nonce);
    decipher.setAAD(header);
    decipher.setAuthTag(tag);
    Buffer.concat([decipher.update(encryptedPayload), decipher.final()]);

    return { type, convId, senderId, targetId, seq };
  }
}
