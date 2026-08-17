# Dart Protocol Specification

## 1. Overview
Dart is an experimental chat protocol designed for low latency and minimal bandwidth. It uses a UDP-first approach where **silence is success**. Unlike TCP or traditional protocols that require positive ACKs for every packet, a Dart receiver stays silent when a message is received correctly and in order, and only speaks when it detects a gap (loss) or needs to terminate a quiet transaction.

**Status:** This is a working prototype. The wire format below matches the current implementations (TypeScript, Go, Rust) and has been verified to interoperate across all three. It is **not** a finalized, audited specification.

## 2. Core Principles
* **UDP First:** Darts are sent over UDP for the lowest possible latency.
* **Silence = Success:** Successful, in-order reception generates zero return traffic.
* **Negative Acknowledgements (NACK):** The receiver only responds if a sequence number is skipped (detecting loss) or a packet fails authentication.
* **Delta Compression:** Payloads are delta-compressed against a *bounded window* (last 200 messages) of the *per-sender* history of the conversation (acting as a zlib dictionary). Because only the same sender's stream is used and the window is deterministic, both sides build identical dictionaries as long as that stream arrives in order. Each Data dart carries a 4-byte SHA-256 fingerprint of the dictionary in its header, so a lost-message desync is detected before inflation and recovered in a single step. The bounded window also lets clients prune older history (bounded memory).
* **Hybrid Cumulative ACK:** To terminate a quiet transaction, a receiver that hears 200ms of silence after a received message sends a single lightweight `TYPE_ACK` back to the sender. This is not a per-packet ACK.
* **Explicit nonces:** Every GCM-protected frame carries a fresh 12-byte random nonce. An implicit IV cannot be made unique across concurrent senders (reusing an IV under the same key is catastrophic for GCM).
* **End-to-End Encryption (group keys):** Control frames are authenticated with AES-256-GCM under a **per-conversation group key that the server never sees**. The first member to join a room (the *creator*) generates the key; every other member receives it as a **member-to-member `KEY_SHARE`** — each share ECDH-encrypted to that specific member and relayed opaquely by the server. The server only ever learns the public membership roster, never any key material.
* **Per-message ratchet + epoch rotation:** Data payloads are encrypted with a **per-message key** derived from the sender's one-way ratchet chain (see §4), not the group key. Group keys and ratchet chains carry an **epoch**. The creator rotates on a timer (`DART_REKEY_SECONDS`) and when a member leaves; on rotation every member regenerates its chain. If the creator leaves, the server elects the smallest remaining senderId as successor, who rotates immediately.
* **Fallback:** NACK/SYNC/optimistic-timer probes provide recovery over UDP. A **TCP fallback transport** is implemented in all three servers (TypeScript, Go, Rust): clients can switch to a reliable TCP connection (port = UDP port + 1, 9001) using the same 2-byte big-endian length framing. QUIC is not implemented.

## 3. Packet Formats

### 3.1 Data Dart (Type 0x01)
Used for normal messages. The payload is encrypted with a **per-message key**
derived from the sender's one-way ratchet chain (see §4), not the group key.
* **1 byte:** Type + Flags (0x01 = Data Dart)
* **2 bytes:** Conversation ID
* **3 bytes:** Sequence number (per-sender, big-endian; ordering/recovery only)
* **1 byte:** Extension length (always 24 for Data darts)
* **2 bytes:** Sender ID (cleartext extension; selects the sender's ratchet chain before decrypting)
* **12 bytes:** GCM nonce (extension payload; included in the authenticated AAD)
* **2 bytes:** Ratchet-chain epoch (extension payload; selects the chain generation)
* **4 bytes:** Dictionary fingerprint = first 4 bytes of SHA-256 of the windowed per-sender dictionary (extension payload; included in the AAD)
* **4 bytes:** Message index (monotonic per-sender per-epoch; positions the ratchet chain)
* **Variable:** Encrypted payload, plaintext layout = `[deflate(message)]`
* **16 bytes:** Authentication tag (AES-GCM)

The 7-byte header plus the 24-byte extension form the AEAD associated data. The
sender identity is in the cleartext extension so the receiver can select the
sender's chain before decrypting; the message index + chain derive the unique
per-message key.

The relay server **does not use** the cleartext sender ID on Data darts to
attribute identity. It learns a transport peer's senderId from that peer's
control packets (Key Req, NACK, SYNC, ACK) during join, then caches Data by
that learned identity. A peer must complete key exchange before it can send Data.

### 3.2 NACK / Repair Request (Type 0x02)
Sent by a receiver when a sequence number in another member's stream is skipped.
`senderId` identifies the member who detected the gap (the signer); `targetId`
is the member whose stream has the gap.

Missing sequence numbers travel in **cleartext**. They are routing metadata, not
message content: Data darts already expose `seq` on the wire, and a blind relay
must read the gap list to repair from its cache without holding the group key.
Integrity still comes from the group-key GCM tag (members verify) and the
per-sender HMAC (the target member verifies).
* **1 byte:** Type (0x02 = NACK)
* **2 bytes:** Conversation ID
* **2 bytes:** Sender ID (the signer)
* **2 bytes:** Target ID (the member whose stream has the gap)
* **12 bytes:** GCM nonce (fresh random nonce per packet)
* **2 bytes:** Count of missing sequence numbers
* **3 × count bytes:** Missing sequence numbers (24-bit, big-endian)
* **16 bytes:** Authentication tag (AES-GCM over empty plaintext; the whole prefix is AAD)
* **32 bytes:** Per-sender HMAC over the whole frame (see §4)

### 3.3 Sparse Cumulative State (Type 0x03)
Sent rarely to resynchronize state, or sent as a probe by the sender if a message remains unconfirmed.
* **1 byte:** Type (0x03 = State Sync)
* **2 bytes:** Conversation ID
* **2 bytes:** Sender ID
* **12 bytes:** GCM nonce (fresh random nonce per packet)
* **3 bytes:** Highest contiguous sequence number (encrypted)
* **16 bytes:** Authentication tag
* **32 bytes:** Per-sender HMAC over the whole frame (see §4)

### 3.4 Key Exchange Request (Type 0x04)
Sent by a client to request access to a conversation room. It publishes the member's public key; the server records it and replies with a membership roster. **The server never generates or holds a group key.**

`senderId` is chosen by the client. Registration is **last-writer-wins**: a
reconnect with a fresh ECDH keypair overwrites the old binding (UDP peers have
no close event, so a stale binding would otherwise lock a member out forever).
Each KeyReq makes the server re-broadcast the roster, which is how members
refresh stale pubkeys — clients re-send their KeyReq a few times after joining
so a lost roster update is never permanent.
* **1 byte:** Type (0x04 = Key Req)
* **2 bytes:** Conversation ID
* **2 bytes:** Sender ID
* **16 bytes:** Request nonce (random)
* **65 bytes:** ECDH Public Key (prime256v1 uncompressed)

### 3.5 Key Share (Type 0x08), Chain Share (Type 0x0A) and Member Info (Type 0x09)
* **0x08 KEY_SHARE** (member → member, relayed opaquely by the server): `type(1) | convId(2) | senderId(2) | targetId(2) | epoch(2) | nonce(12)` (all AAD) + GCM ciphertext of the 32-byte **group key** (used to authenticate control frames), encrypted under a transport key derived from ECDH between the sharing member and the target member.
* **0x0A CHAIN_SHARE** (member → member, relayed opaquely by the server): same 21-byte header as KEY_SHARE + GCM ciphertext of the sender's ratchet-chain state `[chainKey(32)][index(4)]`. A member distributes its chain so peers can decrypt its messages. At join the **current** state is shared (future messages only, preserving forward secrecy); when a peer NACKs the sender's stream, the sender re-shares the epoch's **seed state (index 0)** so a receiver that lost the original share can still decrypt the backlog. Re-sent with short retries because it goes over UDP.
* **0x09 MEMBER_INFO** (server → member): the server embeds its long-term public key, and encrypts the roster `[creator(1)][count(2)][{senderId(2), pubKey(65)}…]` under a transport key derived from ECDH between the server and that member. A client that pins the server's fingerprint can authenticate the roster. Sent to every member whenever membership changes; members also re-send their KeyReq after joining, which triggers a fresh roster broadcast, so a roster update lost to UDP is never permanent.

### 3.6 Dictionary Reset (Type 0x06) and Hybrid ACK (Type 0x07)
Both control frames are GCM-authenticated with the current group key AND carry a
32-byte per-sender HMAC (see §4) — Dict Reset / SYNC are keyed to the relay
server (which verifies them before relaying); ACK / NACK are keyed to the target
member (verified by that member). So a group member can no longer forge another
member's control frames:
* **0x06 Dict Reset:** `type(1) | convId(2) | senderId(2) | targetId(2) | nonce(12)` (all AAD) + 16-byte tag + 32-byte per-sender HMAC. Used to force peers to flush their per-sender compression dictionaries after a permanently lost packet.
* **0x07 Hybrid ACK:** `type(1) | convId(2) | senderId(2) | targetId(2) | seq(3) | nonce(12)` (all AAD) + 16-byte tag + 32-byte per-sender HMAC. Sent after 200ms of silence to confirm delivery. The routing fields keep their fixed offsets, so the relay server still routes ACKs without decrypting them.

## 4. Security
* **End-to-End Encryption:** the per-conversation group key is generated by the room creator and distributed member-to-member via `KEY_SHARE`. The relay server is **blind**: it only tracks public membership and relays opaque ciphertexts, so it cannot read message content. It *can* read routing metadata, including NACK gap lists (see §3.2).
* **Per-message ratchet (sender keys):** data payloads are encrypted with a **per-message key** derived from the sender's one-way ratchet chain:
  `messageKey(i) = HMAC(chainKey_i, "DartMsgKey" || i)`, `chainKey_{i+1} = HMAC(chainKey_i, "DartChainKey")`. Each member generates its own chain per epoch and distributes the CURRENT state via `CHAIN_SHARE` (a fresh peer receives no history). A compromised **message key** decrypts only that one message; a compromised **chain state** reveals future but not past messages in that epoch. On re-key (epoch change) every member regenerates and re-distributes its chain. Residual: a member's long-term key is used to encrypt its chain shares, so a long-term compromise exposes the epochs that member was in.
* **Server Authentication (key pinning):** the server uses a long-term ECDH key persisted in `dart_server.key` (override with `DART_SERVER_KEY_FILE`). Clients can pin its SHA-256 fingerprint (`DART_SERVER_FINGERPRINT` / `SERVER_FINGERPRINT`); on joining, the client verifies the server's public key embedded in `MEMBER_INFO` matches the pin and aborts on mismatch, so an active man-in-the-middle cannot substitute its own key or inject roster entries.
* **Encryption:** All payloads (Data, NACK, SYNC, ACK, Dict Reset, Key Share, Member Info) are GCM-authenticated with AES-256-GCM using a fresh random nonce per packet. Data uses the per-message ratchet key; control frames use the group key; key/chain shares and member info use an ECDH-derived transport key.
* **Per-sender control-frame authentication:** the group-key GCM only proves "some group member" sent a control frame. To attribute it to a specific member, each control frame additionally carries a 32-byte HMAC-SHA256 keyed with `SHA-256(ECDH(senderPriv, peerPub))` — a pairwise key only the sender and the intended peer can derive. Directed frames (ACK, NACK) are keyed to their **target member** and verified by that member; broadcast frames (SYNC, Dict Reset) are keyed to the **relay server**, which verifies them before relaying. A group member therefore cannot forge another member's ACK / NACK / SYNC / Dict-Reset. Residual: SYNC / Dict-Reset verification is centralized in the server (members trust its relay), and there is no anti-replay watermark.
* **Known limitations (do not ship as-is):**
  * **Long-term key compromise.** A member's long-term ECDH key is used to encrypt its `CHAIN_SHARE`s, so a compromise of a member's long-term key exposes the epochs (chain seeds) that member was in.
  * **Pinning is not PKI.** Fingerprint pinning relies on the operator distributing the fingerprint out-of-band; there are no certificates or certificate authorities.
  * **No room access control.** Knowing a 16-bit conversation ID is enough to send `KEY_REQ`. Pinning authenticates the *server*, not members. `senderId` is client-chosen and registration is **last-writer-wins** (§3.4): a member reconnecting with a fresh keypair overwrites their own old roster entry — required for UDP reconnects, since there is no close event to expire a binding — but it also means an offline member's id can be claimed by a newcomer.
  * **Metadata leaks.** Conversation ID, sequence numbers, NACK gap lists and control-flow signalling travel in cleartext; the server knows who talks to whom in which room.
  * **No anti-replay watermark on control frames.** Control frames are per-sender authenticated (see §4) so a group member can't forge another member's frames, but a captured frame can be replayed (a replayed ACK/NACK/SYNC/Dict-Reset merely causes a re-transmit or history reset, as before).
  * **Successor election is server-driven.** When the creator leaves, the server elects the smallest remaining senderId as successor (broadcast via the roster); members trust the server's roster, consistent with the server tracking membership.
* The Authentication Tag ensures integrity and authenticity of the encrypted payloads, mitigating spoofing and tampering.

## 5. State Machine & Reliability
1. **Sender:** Fires a Data Dart with sequence `N`. Starts a probe timer.
2. **Receiver:** Receives `N`. If `N` == `Highest_Received + 1`, update `Highest_Received`. Do nothing (Silence).
3. **Receiver (Loss):** Receives `N+2`. Realizes `N+1` is missing. Sends a NACK for `N+1`.
4. **Relay:** Reads the cleartext gap list. If the missing dart is in the sliding-window cache, it repairs from RAM. It **always** also relays the member-signed NACK to the target (original sender) — the sender must see the NACK to re-share its ratchet-chain seed when the receiver lost that share, and to retransmit if the cache missed.
5. **Sender (NACK):** Receives a NACK for `N+1`. Retransmits `N+1` re-compressed against the current dictionary, but preserves the message's **original ratchet epoch** on the wire and reuses its cached per-message key. It also re-shares its chain seed so the receiver can decrypt the retransmitted backlog.
6. **Receiver persistence:** The receiver keeps re-NACKing an outstanding gap on a short timer until it closes, and the sender keeps re-probing (SYNC) while its latest message stays unacknowledged — a lost repair round can therefore never stall the conversation silently.
7. **Termination:** After 200ms of silence, the receiver sends one hybrid ACK so the sender stops probing.

## 6. Group Chat
Group chats use a server-assisted model:
1. Sender sends one Dart to the server.
2. Server fans it out to all group members.
3. Members stay silent on success.
4. If a member misses a packet, they send a NACK to the server.
5. The server repairs from its cache AND forwards the NACK to the originating sender, so the sender can retransmit and re-share its chain seed.
