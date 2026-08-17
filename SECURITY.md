# Security Policy

Dart is an **experimental** protocol. It is not audited and should not be used
for production or high-value traffic.

## Reporting a Vulnerability

Please **do not open a public issue** for security vulnerabilities. Instead,
email the maintainers (or open a private advisory on GitHub). Please include:

- The affected component (TypeScript / Go / Rust, client / server / codec).
- A minimal reproduction if possible.
- The impact and your suggested fix, if you have one.

We aim to acknowledge reports within 5 business days.

## Known Limitations (not yet fixed)

See also the [Roadmap](README.md#-roadmap--todo) in the README.

- **Per-message ratchet (sender keys).** Data is encrypted with a per-message
  key derived from each sender's one-way ratchet chain: a compromised message
  key decrypts only that one message, and a compromised chain state reveals
  future (not past) messages in that epoch. Chains are distributed
  member-to-member via `CHAIN_SHARE`, relayed opaquely by the server. Residual:
  a member's long-term key is used to encrypt its chain shares, so a long-term
  compromise exposes the epochs that member participated in.
- **Pinning is not a public PKI.** Server authentication relies on out-of-band
  fingerprint distribution (`DART_SERVER_FINGERPRINT`); there are no
  certificates or certificate authorities.
- **No room access control.** Knowing a 16-bit conversation ID is enough to
  send `KEY_REQ`. Pinning authenticates the server, not members. `senderId` is
  client-chosen and registration is **last-writer-wins**: a member
  reconnecting with a fresh ECDH keypair overwrites their old roster entry
  (required for UDP reconnects — there is no close event to expire a binding)
  — which also means an offline member's id can be claimed by a newcomer.
- **Routing metadata is cleartext.** Conversation IDs, sequence numbers, NACK
  gap lists and control signalling are visible on the wire; the server knows
  who talks to whom in which room (content is end-to-end encrypted, the server
  is blind to it). The gap list is deliberately readable so the relay can
  repair from cache without holding a group key.
- **Control frames are per-sender authenticated.** ACK / NACK carry an
  ECDH-derived per-sender HMAC verified by the target member (a group member
  cannot forge another member's ACK or NACK); SYNC / Dict-Reset are keyed to
  the relay server, which verifies them before relaying. Residuals: members
  trust the server's verification of SYNC / Dict-Reset (they cannot verify
  those themselves), and there is no anti-replay watermark (a replayed frame is
  re-verified but only causes a re-transmit / history reset, same as before).
- **No cryptographic audit.** The protocol and implementations have not been
  formally reviewed.

## Recommended posture

- Always set `DART_SERVER_FINGERPRINT` on clients before connecting.
- Keep `dart_server.key` secret and out of version control (it is gitignored).
- Rotate the server key periodically; clients must re-pin the new fingerprint.
