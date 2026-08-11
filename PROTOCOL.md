# Dart Protocol Specification

## 1. Overview
Dart is an experimental chat protocol designed for low latency and minimal bandwidth. It uses a UDP-first approach where **silence is success**. Unlike TCP or traditional protocols that require positive ACKs for every packet, a Dart receiver stays silent when a message is received correctly and in order, and only speaks when it detects a gap (loss) or needs to terminate a quiet transaction.

**Status:** This is a working prototype. The wire format below matches the current implementations (TypeScript, Go, Rust) and has been verified to interoperate across all three. It is **not** a finalized, audited specification.

## 2. Core Principles
* **UDP First:** Darts are sent over UDP for the lowest possible latency.
* **Silence = Success:** Successful, in-order reception generates zero return traffic.
* **Negative Acknowledgements (NACK):** The receiver only responds if a sequence number is skipped (detecting loss) or a packet fails authentication.
* **Delta Compression:** Payloads are delta-compressed against a *bounded window* (last 200 messages) of the *per-sender* history of the conversation (acting as a zlib dictionary). Because only the same sender's stream is used and the window is deterministic, both sides build identical dictionaries as long as that stream arrives in order. Each Data dart carries a 4-byte SHA-256 fingerprint of the dictionary in its header, so a lost-message desync is detected before inflation and recovered in a single step. The bounded window also lets clients prune older history (bounded memory).
* **Hybrid Cumulative ACK:** To terminate a quiet transaction, a receiver that hears 200ms of silence after a received message sends a single lightweight `TYPE_ACK` back to the sender.
* **Explicit Data Nonce:** Each Data dart carries a fresh 12-byte random GCM nonce in its extension area. The nonce is *transmitted* rather than implicitly derived: with a 7-byte cleartext header and no sender identity on the wire, an implicit IV cannot be made unique across concurrent senders in a shared conversation (reusing an IV under the same key is catastrophic for GCM). NACK and SYNC packets still use the legacy implicit derivation (see §4 for the caveat).
* **End-to-End Encryption (group keys):** All payloads are encrypted and authenticated with AES-256-GCM under a **per-conversation group key that the server never sees**. The first member to join a room (the *creator*) generates the key; every other member receives it as a **member-to-member `KEY_SHARE`** — each share ECDH-encrypted to that specific member and relayed opaquely by the server. The server only ever learns the public membership roster, never any key material.
* **Forward secrecy (key rotation):** group keys carry an **epoch** (2 bytes in the Data header). The creator rotates the key on a timer (`DART_REKEY_SECONDS`) and when a member leaves, so a compromised key only exposes its own epoch; old epochs are retained for a short window to decrypt in-flight traffic, then pruned. This is epoch-rotation forward secrecy, not a per-message ratchet.
* **Fallback:** NACK/SYNC/optimistic-timer probes provide recovery over UDP. A **TCP fallback transport** is implemented in all three servers (TypeScript, Go, Rust): clients can switch to a reliable TCP connection (port = UDP port + 1, 9001) using the same 2-byte big-endian length framing. QUIC is not implemented.

## 3. Packet Formats

### 3.1 Data Dart (Type 0x01)
Used for normal messages.
* **1 byte:** Type + Flags (0x01 = Data Dart)
* **2 bytes:** Conversation ID
* **3 bytes:** Sequence number (per-sender, big-endian)
* **1 byte:** Extension length (always 18 for Data darts)
* **12 bytes:** GCM nonce (extension payload; included in the authenticated AAD)
* **2 bytes:** Group-key epoch (extension payload; selects the decryption key)
* **4 bytes:** Dictionary fingerprint = first 4 bytes of SHA-256 of the windowed per-sender dictionary (extension payload; included in the AAD)
* **Variable:** Encrypted payload, plaintext layout = `[2-byte senderId][deflate(message)]`
* **16 bytes:** Authentication tag (AES-GCM)

The 7-byte header plus the extension form the AEAD associated data. The sender identity is *not* in the cleartext header; it is recovered from the decrypted payload (and bound by the auth tag).

### 3.2 NACK / Repair Request (Type 0x02)
Sent by the receiver when a sequence number is skipped.
* **1 byte:** Type (0x02 = NACK)
* **2 bytes:** Conversation ID
* **2 bytes:** Sender ID
* **12 bytes:** GCM nonce (fresh random nonce per packet)
* **Variable:** Compact list of missing sequence numbers (encrypted)
* **16 bytes:** Authentication tag

### 3.3 Sparse Cumulative State (Type 0x03)
Sent rarely to resynchronize state, or sent as a probe by the sender if a message remains unconfirmed.
* **1 byte:** Type (0x03 = State Sync)
* **2 bytes:** Conversation ID
* **2 bytes:** Sender ID
* **12 bytes:** GCM nonce (fresh random nonce per packet)
* **3 bytes:** Highest contiguous sequence number (encrypted)
* **16 bytes:** Authentication tag

### 3.4 Key Exchange Request (Type 0x04)
Sent by a client to request access to a conversation room. It publishes the member's public key; the server records it and replies with a membership roster. **The server never generates or holds a key.**
* **1 byte:** Type (0x04 = Key Req)
* **2 bytes:** Conversation ID
* **2 bytes:** Sender ID
* **16 bytes:** Request nonce (random)
* **65 bytes:** ECDH Public Key (prime256v1 uncompressed)

### 3.5 Key Share (Type 0x08) and Member Info (Type 0x09)
* **0x08 KEY_SHARE** (member → member, relayed opaquely by the server): `type(1) | convId(2) | senderId(2) | targetId(2) | epoch(2) | nonce(12)` (all AAD) + GCM ciphertext of the 32-byte group key, encrypted under a transport key derived from ECDH between the sharing member and the target member. The target decrypts with its own private key; the server cannot.
* **0x09 MEMBER_INFO** (server → member): the server embeds its long-term public key, and encrypts the roster `[creator(1)][count(2)][{senderId(2), pubKey(65)}…]` under a transport key derived from ECDH between the server and that member. A client that pins the server's fingerprint can authenticate the roster. Sent to every member whenever membership changes.

### 3.6 Dictionary Reset (Type 0x06) and Hybrid ACK (Type 0x07)
Both control frames are authenticated with the current group key (GCM, empty payload), so outsiders can no longer forge them:
* **0x06 Dict Reset:** `type(1) | convId(2) | senderId(2) | targetId(2) | nonce(12)` (all AAD) + 16-byte tag. Used to force peers to flush their per-sender compression dictionaries after a permanently lost packet.
* **0x07 Hybrid ACK:** `type(1) | convId(2) | senderId(2) | targetId(2) | seq(3) | nonce(12)` (all AAD) + 16-byte tag. Sent after 200ms of silence to confirm delivery. The routing fields keep their fixed offsets, so the relay server still routes ACKs without decrypting them.

## 4. Security
* **End-to-End Encryption:** the per-conversation group key is generated by the room creator and distributed member-to-member via `KEY_SHARE`. The relay server is **blind**: it only tracks public membership and relays opaque ciphertexts, so it cannot read message content.
* **Forward secrecy (rotation):** the creator rotates the group key (new epoch) on a timer and when a member leaves; old epochs are retained briefly then pruned. A leaked key only exposes its own epoch. This is not a per-message ratchet.
* **Server Authentication (key pinning):** the server uses a long-term ECDH key persisted in `dart_server.key` (override with `DART_SERVER_KEY_FILE`). Clients can pin its SHA-256 fingerprint (`DART_SERVER_FINGERPRINT` / `SERVER_FINGERPRINT`); on joining, the client verifies the server's public key embedded in `MEMBER_INFO` matches the pin and aborts on mismatch, so an active man-in-the-middle cannot substitute its own key or inject roster entries.
* **Encryption:** All payloads (Data, NACK, SYNC, ACK, Dict Reset, Key Share, Member Info) are encrypted and authenticated with AES-256-GCM using a fresh random nonce per packet, so no nonce is ever reused under the same key.
* **Known limitations (do not ship as-is):**
  * **No per-message ratchet.** Forward secrecy is epoch-based; the creator's long-term key is used to encrypt every epoch's key shares (a compromise of a member's long-term key compromises the epochs it was in).
  * **Pinning is not PKI.** Fingerprint pinning relies on the operator distributing the fingerprint out-of-band; there are no certificates or certificate authorities.
  * **Metadata leaks.** Conversation ID, sequence numbers and control-flow signalling travel in cleartext; the server knows who talks to whom in which room.
  * **Insider forgery of control frames.** Control frames (ACK, Dict Reset, NACK, SYNC) are authenticated with the shared group key, so an *outsider* cannot forge them, but any *group member* (who holds the key) still can.
  * **Creator dependency.** If the room creator leaves, the room keeps working (other members share the key with newcomers), but only the creator rotates keys.
* The Authentication Tag ensures integrity and authenticity of the encrypted payloads, mitigating spoofing and tampering.

## 5. State Machine & Reliability
1. **Sender:** Fires a Data Dart with sequence `N`. Starts a probe timer.
2. **Receiver:** Receives `N`. If `N` == `Highest_Received + 1`, update `Highest_Received`. Do nothing (Silence).
3. **Receiver (Loss):** Receives `N+2`. Realizes `N+1` is missing. Sends a NACK for `N+1`.
4. **Sender (NACK):** Receives a NACK for `N+1`. Retransmits `N+1` re-compressed against the current dictionary.
5. **Termination:** After 200ms of silence, the receiver sends one hybrid ACK so the sender stops probing.

## 6. Group Chat
Group chats use a server-assisted model:
1. Sender sends one Dart to the server.
2. Server fans it out to all group members.
3. Members stay silent on success.
4. If a member misses a packet, they send a NACK to the server.
5. The server repairs from its cache, or forwards the NACK to the originating sender if it doesn't have the packet cached.

The server learns each peer's sender identity from its control packets (Key Req, NACK, SYNC, ACK); Data darts carry no cleartext sender ID, so a peer must complete key exchange before it can send Data.
