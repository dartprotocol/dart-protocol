# 🎯 Dart Protocol

[![License: ISC](https://img.shields.io/badge/license-ISC-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-7-3178c6?logo=typescript&logoColor=white)](src/)
[![Go](https://img.shields.io/badge/Go-1.15-00add8?logo=go&logoColor=white)](go/)
[![Rust](https://img.shields.io/badge/Rust-1.97-dea584?logo=rust&logoColor=white)](rust/)

An experimental messaging protocol built around a **Hybrid "Silence = Success" Architecture**: it minimizes network chatter by avoiding per-packet positive ACKs, encrypts every message **end-to-end** with member-generated group keys, and keeps the relay server **blind** to message content — implemented byte-for-byte identically in **TypeScript, Go and Rust**.

> **Experimental.** The wire format matches the current TypeScript, Go and Rust implementations (verified interoperable in all combinations), but the security model has known limitations — see [Security Model](#-security-model), [Known Limitations](#-known-limitations) and [SECURITY.md](SECURITY.md). Do not deploy as-is.

## 🎯 Scope: What Dart Provides (and What It Doesn't)

Dart is an experimental **transport & framing protocol** for low-latency group
messaging. It is a building block for an application, not an application
framework.

**Dart handles:**
- Binary packet framing and reliability (NACK repair, hybrid ACKs, sequence
  tracking) over UDP, with a TCP fallback and a WebSocket bridge for browsers.
- End-to-end payload encryption via per-message ratchet keys, plus group-key
  authentication of control frames.
- A canonical wire format implemented byte-for-byte in TypeScript, Go and Rust.

**Dart does not handle — by design. These belong to the application:**
- **User identity & authentication.** `senderId` is a protocol handle chosen by
  the client; mapping it to real usernames, accounts, or sessions is the
  application's job.
- **Room access control & authorization.** The 16-bit `convId` is a routing
  identifier, not a permission system. Applications should gate room access
  before allowing a client to send a `KEY_REQ`.
- **Rate limiting, spam filtering, or abuse prevention.**
- **Public-key infrastructure.** Server identity is verified via fingerprint
  pinning; applications needing real certificates/PKI must layer it on top.

**Boundaries the wire format itself imposes (see [PROTOCOL.md](PROTOCOL.md)):**
- **16-bit `convId`** is both short and guessable — a small room-ID space that
  application-level gates should treat as public.
- **`senderId` binding is last-writer-wins** — a fresh UDP socket can reclaim an
  offline member's id, so application identity should not rely on `senderId`
  persisting across reconnects.
- **Routing metadata is cleartext** — `convId`, `seq`, `senderId`, and NACK gap
  lists are visible; the server knows who talks to whom in which room. Hiding
  this requires a different topology (mesh/P2P/mix network) and is out of scope.

Because applying security at the application boundary is delegable but the wire
constraints above are not, treat this as a **transport layer**: build your own
authentication and access control in front of it, and do not deploy it as-is
for sensitive traffic.
## 📁 Repository Layout

```
├── src/            TypeScript codec + clients (CLI, Web, Electron, sim) + server
├── go/             Go codec, native client and server
├── rust/           Rust codec, native client and server
├── public/         The project's website + WebSocket web client (demo)
├── bench_endtoend.js   Real end-to-end benchmark (all servers × all clients)
├── PROTOCOL.md     Wire-format specification
└── README.md
```

## 🧠 Core Philosophy
Traditional protocols (like TCP or standard reliable UDP) rely on positive-ACKs for every packet. In a group chat of 10 people, a single message can trigger 10 Data packets and 10 ACK packets.

Dart turns this around: during active communication, **Silence = Success**. Clients track sequence numbers. If sequence `4` arrives after sequence `2`, the receiver detects the gap and fires a NACK for `3`. If no gap is detected, no ACKs are sent.

To protect the "Final Message" in a burst from hanging in silence, Dart adds a **Hybrid Cumulative ACK**. When a receiver gets a message and then hears silence for 200ms, it fires a *single* lightweight `TYPE_ACK` back to the sender. This cleanly terminates the transaction with almost zero overhead.

## 📦 Packet Types
Dart uses a compact binary framing format. The canonical layout is in [PROTOCOL.md](PROTOCOL.md).
- **`TYPE_DATA` (0x01):** 7-byte header (`type | convId | seq | extLen`) + 24-byte cleartext extension (`senderId | nonce | epoch | dictFp | idx`) + deflate(message) encrypted under the sender's **per-message ratchet key**. `senderId` is in the extension so the receiver can select the right chain before decrypting. Retransmissions retain the original message `epoch` and cached message key rather than using the sender's newer current epoch.
- **`TYPE_NACK` (0x02):** Sent by a receiver who detects a sequence gap. Missing sequence numbers are **cleartext** so a blind relay can repair from cache without the group key; GCM + per-sender HMAC still authenticate the frame.
- **`TYPE_SYNC` (0x03):** A sparse probe sent by a sender (e.g., at 300ms) to ensure their last message wasn't silently dropped.
- **`TYPE_KEY_REQ` (0x04):** Publishes the member's public key when joining a room. Registration is last-writer-wins (a restart with a fresh keypair re-binds the `senderId`); the server re-broadcasts the roster on every KeyReq, and clients re-send their KeyReq after joining so a lost roster update is never permanent.
- **`TYPE_KEY_SHARE` (0x08), `TYPE_CHAIN_SHARE` (0x0A) & `TYPE_MEMBER_INFO` (0x09):** member-to-member group-key delivery, per-sender ratchet-chain delivery (both ECDH-encrypted, relayed opaquely), and the server-authenticated membership roster.
- **`TYPE_DICT_RESET` (0x06):** An emergency signal sent when a packet is permanently lost (>4 seconds), forcing clients to gracefully flush their compression dictionaries and recover.
- **`TYPE_ACK` (0x07):** The hybrid cumulative positive-ACK sent after 200ms of silence — not a per-packet ACK.

Delta compression uses the **per-sender** history as the zlib dictionary — a bounded window (last 200 messages) of the same sender's stream, so the sender and every receiver build identical dictionaries as long as that stream arrives in order. Every Data dart carries a 4-byte SHA-256 **dictionary fingerprint**, so a desync from lost history is detected before inflation and recovered in one step. Clients prune history older than the window, so memory stays bounded regardless of how long a room runs.

## 🔒 Security Model
* **End-to-End Encryption:** the per-conversation group key is generated by the room **creator** and shared **member-to-member** via `KEY_SHARE`, each share ECDH-encrypted to a specific member. The server is **blind** — it relays opaque ciphertexts and never holds a key, so it cannot read message content.
* **Per-message ratchet + forward secrecy:** data is encrypted with a **per-message key** derived from each sender's one-way ratchet chain — a compromised message key decrypts only that one message, and a compromised chain state reveals *future* but not *past* messages. Chains are shared member-to-member via `CHAIN_SHARE` and regenerated per **epoch**; the creator rotates on a timer (`DART_REKEY_SECONDS`) and when a member leaves. If the creator leaves, the server elects the smallest remaining senderId as successor, who rotates immediately.
* **Encryption & Integrity:** Data is encrypted with AES-256-GCM under the per-message ratchet key. Control frames use the current epoch's group key. Every GCM call uses a fresh random nonce and a 16-byte authentication tag.
* **Server authentication (key pinning):** the server persists its long-term ECDH key and prints its SHA-256 fingerprint at startup. Clients pin it via `DART_SERVER_FINGERPRINT` (or `SERVER_FINGERPRINT` in `web-app.ts`) and abort if the roster's server key doesn't match — blocking MITM key substitution.
* **Known gaps:** pinning is not a public PKI (fingerprints are distributed out-of-band), conversation IDs / sequence numbers leak in cleartext, and SYNC/Dict-Reset verification is centralized in the server. Control frames are per-sender authenticated (ACK/NACK verified by the target member, SYNC/Dict-Reset by the relay server), so a group member can no longer forge another member's frames. See [Known Limitations](#-known-limitations).

## 🌐 Dual-Transport Architecture
Dart is implemented across two distinct native transport layers that interoperate seamlessly:

1. **Native UDP Client (`cli.ts` & Electron GUI)**
   * Binds directly to Node.js `dgram` and sends raw binary Dart datagrams to the server on Port 9000.
   * Provides the minimum possible overhead, bypassing the OS TCP stack.

2. **Browser Client (`web-app.ts`)**
   * Polyfills ECDH and AES-GCM crypto using the native Web Crypto API.
   * Wraps the raw binary Dart packets in a WebSocket frame over Port 9002.

The Node, Go and Rust servers bridge the two transports. They relay opaque ciphertexts and never hold a group key, so the message content is end-to-end encrypted between members.

All three servers also expose a **TCP fallback** transport on port 9001 (UDP port + 1) with 2-byte big-endian length framing. Clients switch to it via `DART_TCP_FALLBACK=host:port`, giving reliable delivery for high-loss or NAT-traversal situations.

## 📊 Efficiency Measurements (Reproducible)
We run a 10,000-message discrete-event simulation comparing Dart vs. a standard Positive-ACK baseline under 50ms latency.

**This is a synthetic model, not a live-network measurement.** Every packet is an assumed fixed 43-byte payload; the model does not simulate real loss bursts or jitter. It is fully deterministic and seeded for reproducibility.

```bash
npm run benchmark
# or, to vary parameters:
MSGS=5000 LATENCY=25 SEED=7 npm run benchmark
```

Current output (seed 12345, 10,000 messages, 50ms one-way latency):

**1:1 Topology (Happy Path):**
*   **Dart UDP:** 20,000 packets (860 KB)
*   **Baseline:** 30,000 packets (930 KB)
*   *Dart uses ~33% fewer packets in active 1:1 bursts.*

**1:3 Group Topology (Happy Path):**
*   **Dart UDP:** 40,000 packets (1.72 MB)
*   **Baseline:** 70,000 packets (2.02 MB)
*   *Dart uses ~43% fewer packets by aggregating ACKs and eliminating O(N²) fan-out.*

**High Packet Loss (30% Loss in 1:3 Group):**
*   **Dart UDP:** ~60,000 packets (~2.2 MB)
*   **Baseline:** ~99,000 packets (~3.1 MB)
*   *Dart roughly halves overall network load under heavy simulated loss.*

The earlier README numbers (e.g. exactly 76,912 packets) were not reproducible and have been replaced by the seeded, scriptable model above.

### End-to-End Measurements (real clients + servers, many users)

`npm run bench:endtoend` runs the protocol end-to-end with real clients and servers — the TypeScript server scales to 100 in-process users, and the Go/Rust servers run as separate processes — then compares measured wire traffic against a positive-ACK baseline model (each message costs `1 + (K−1) fan-out + (K−1) ACKs = 2K−1` packets, inflated by `1/(1−L)` for loss `L`).

| Scenario | Users | Msgs | Packets/message | Gain vs +ACK | Delivery |
|---|---|---|---|---|---|
| 1:1 fan-out (TS) | 2 | 100 | 2.02 | **32.7%** | 100% |
| Group fan-out (TS) | 10 | 100 | 11.0 | **42.1%** | 100% |
| Group fan-out (TS) | 100 | 100 | 115.5 | **42.0%** | 100% |
| All-to-all chat (TS) | 10 | 200 | 10.95 | **42.4%** | 100% |
| All-to-all, staggered (TS) | 50 | 1000 | 87.0 | 12.1% | 99.7% |
| **10% loss** (TS) | 10 | 100 | 11.95 | **43.4%** | 100% |
| **30% loss** (TS) | 10 | 100 | 13.45 | **50.4%** | 99.4% |
| Go server (TS clients) | 20 | 100 | 20.38 | **47.7%** | 100% |
| Rust server (TS clients) | 20 | 100 | 22.12 | **43.3%** | 100% |
| Cross-language (Go + Rust native clients receive) | 4 | 50 | — | — | Go **100%**, Rust **100%** |

**Honest takeaways:**
- Steady-state, Dart sends **~33–48% fewer packets** than a positive-ACK chat, converging toward the theoretical ~50% ceiling as the group grows (Dart sends 0 ACKs per message; the baseline sends K−1).
- **The gain grows with loss** (43% at 10% → 50% at 30%): a NACK-only model costs less than ACK + retransmit once the link degrades.
- **Delivery is ~100%** at 0–10% loss and 99.4% at 30% loss (the residual is the 4s permanent-loss timer racing the test window).
- **Known stress limit:** a *synchronized* all-to-all burst with 50 senders saturates the single-threaded client receive path (each client gets ~49 streams simultaneously → UDP socket overflow). The realistic staggered pattern recovers to 99.5% delivery. This is a client-throughput limit, not a steady-state protocol failure.
- **Benchmark-driven bug found:** the end-to-end run exposed a Rust client defect — it awaited its deferred ACK task inline, blocking the receive loop ~200ms per message and overflowing the socket buffer under load (delivery dropped to ~40%). Fixed by running the task concurrently; delivery returned to 100%.
- **Join is O(N²):** the server-blind membership protocol fans the roster + key shares to every member on each join (N=100 → ~137 packets/user, ~2s). Amortized over a long-lived room, but it is the largest structural overhead vs. a server-issued-key design.

## 🚧 Known Limitations
1. **Large File Transfers:** The protocol assumes small, single-packet chat payloads. It does not natively support binary chunking or media transfers.
2. **Per-message ratchet:** handled — data is encrypted with per-message keys from each sender's one-way ratchet chain; a compromised message key decrypts only that one message, and a compromised chain state reveals future (not past) messages in that epoch (chain compromise is additionally bounded by epoch rotation). The server itself is blind and sees no key material.
3. **Pinning is not a public PKI:** fingerprints are distributed out-of-band (no certificates/CAs).
4. **Cleartext metadata:** conversation IDs, sequence numbers and control signalling are visible on the wire; the server knows who talks to whom in which room.
5. **Control-frame per-sender auth:** handled — ACK/NACK carry an ECDH-derived per-sender HMAC the target member verifies, and SYNC/Dict-Reset are keyed to the relay server which verifies them before relaying (so no group member can forge another member's control frames). Residuals: SYNC/Dict-Reset verification is centralized in the server, and there is no anti-replay watermark.
6. **24-bit sequence wrap:** handled — ordering/dedup/window state lives in the modular 24-bit sequence space, so the counter wraps cleanly at 16.7M instead of breaking delivery (nonces are random, so there is no crypto impact).
7. **Creator dependency:** handled — if the room creator leaves, the server elects a successor (the smallest remaining senderId), who takes over key rotation immediately on takeover.

## 🗺️ Roadmap / TODO
Ordered roughly by impact vs. effort.

### Security depth
- [x] **Per-message ratchet (sender keys)** — each sender owns a one-way per-message ratchet chain shared member-to-member via `CHAIN_SHARE`; a compromised message key decrypts only that one message, and a compromised chain state reveals future but not past messages. (Residual: a member's long-term key is used to encrypt its chain shares, so a long-term compromise exposes the epochs that member was in.)
- [ ] **Real PKI instead of fingerprint pinning** — certificates / Web PKI so first-contact trust doesn't rely on out-of-band fingerprint distribution.
- [x] **Resist insider control-frame forgery** — ACK/NACK are authenticated with an ECDH-derived per-sender HMAC verified by the target member; SYNC/Dict-Reset are keyed to the relay server, which verifies them before relaying. (Residual: SYNC/Dict-Reset verification is centralized in the server; no anti-replay watermark.)
- [x] **Remove the creator dependency** — when the creator leaves, the server elects the smallest remaining senderId as successor, and the successor rotates the key immediately on takeover, so re-keying (and forward secrecy) survives the creator leaving.

### Architecture (needs a different topology)
- [ ] **Hide routing metadata** (convId/seq/who-talks-to-whom) — impossible in the current star topology; requires a P2P mesh (server = rendezvous only) or onion/mix routing. See the "different topology" note below.

### Engineering
- [x] **Go + Rust unit tests** — `go/core/codec_test.go` (14 tests) and `rust/src/core/codec.rs` tests (14 tests) cover codec round-trips for every frame plus cross-language golden wire vectors (fixed nonces) generated from the TS reference; the ratchet-chain helpers are locked to byte-identical vectors across all three implementations. (`go test ./core/`, `cargo test`.)
- [x] **24-bit seq wrap handling** — ordering/dedup/window state now lives in the modular 24-bit sequence space, so the counter wraps cleanly across the 16.7M boundary (verified by a wrap-boundary integration test).
- [ ] **De-duplicate `web-app.ts` / `electron-gui.ts`** — the two clients are near-identical copies.
- [ ] **Browser WebTransport (V2)** — replace the TCP/WebSocket bridge with QUIC datagrams so the browser gets true UDP semantics (see `public/v2.html`).

### On "a different topology"
The current design is a **star** (all clients → server), so the server must read convId/seq/senderId to route, cache, and repair. That metadata can never be hidden in this topology. Hiding it means moving to a **mesh/P2P** (server as rendezvous only, per-pair random room tokens) or an **onion/mix network**. The per-message ratchet does *not* need a topology change — it's a key-derivation redesign that works over the current star.

## 🚀 How to Run the Demo

```bash
git clone https://github.com/<YOUR_USER>/<REPO>.git
cd <REPO>
npm install
npm run build     # compiles TypeScript + builds the browser bundle
```

**1. Compile and Start the Server (Go Native):**
```bash
cd go/server && go build . && ./server
```

**2. Chat from the Browser (WebSocket):**
Open `http://localhost:9002` and type a Room ID.

**3. Chat from the Terminal (Node.js UDP):**
Open a new terminal window and run:
```bash
node src/cli.js
```

**4. Chat from the Terminal (Go Native UDP):**
A fully idiomatic Go port is available in the `go/` directory. It uses Go's `compress/flate` dictionary mode and native `crypto/aes` to interoperate with the Node clients.
```bash
cd go
go build -o dart-cli
./dart-cli
```

**5. Chat from the Terminal (Rust Native UDP):**
A clean, idiomatic Rust port using Tokio is available in the `rust/` directory. It uses `flate2` and `aes-gcm`.
```bash
cd rust
cargo build --release
./target/release/client
```

**6. Chat from the Native Desktop GUI (Electron + UDP):**
Open a new terminal window and run:
```bash
npx electron electron-main.js
```

Join the same Room ID on any client, and you can chat instantly across all transports (Node, Go, Rust, Browser, Electron).

**Security note:** the server prints its fingerprint at startup. Pin it on every
client (`DART_SERVER_FINGERPRINT=<fingerprint>`, or `SERVER_FINGERPRINT` in
`public/web-app.ts`'s compiled bundle) so an attacker can't substitute their own
server key. Optionally set `DART_REKEY_SECONDS` to tune group-key rotation, and
`DART_TCP_FALLBACK=host:9001` to use the reliable TCP fallback transport.

## 🧪 Tests & Benchmarks

```bash
npm test                 # TypeScript integration suite (server + sim clients)
npm run benchmark        # reproducible synthetic efficiency model
npm run bench:endtoend   # real end-to-end benchmark (all servers × all clients)
cd go && go build ./...  # Go build check
cd rust && cargo build   # Rust build check
```

## ⚖️ License

[ISC](LICENSE) — free to use, modify and distribute.
