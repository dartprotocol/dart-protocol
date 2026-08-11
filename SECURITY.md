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

- **No per-message ratchet.** Forward secrecy is epoch-rotation based; a
  member's long-term key compromise exposes the epochs it participated in.
- **Pinning is not a public PKI.** Server authentication relies on out-of-band
  fingerprint distribution (`DART_SERVER_FINGERPRINT`); there are no
  certificates or certificate authorities.
- **Routing metadata is cleartext.** Conversation IDs, sequence numbers and
  control signalling are visible on the wire; the server knows who talks to
  whom in which room (content is end-to-end encrypted, the server is blind to
  it).
- **Insider control-frame forgery.** Group members holding the group key can
  forge ACK / NACK / SYNC / Dict-Reset frames.
- **24-bit sequence wrap** after ~16.7M messages per sender (nonces are random,
  so there is no cryptographic impact).
- **No cryptographic audit.** The protocol and implementations have not been
  formally reviewed.

## Recommended posture

- Always set `DART_SERVER_FINGERPRINT` on clients before connecting.
- Keep `dart_server.key` secret and out of version control (it is gitignored).
- Rotate the server key periodically; clients must re-pin the new fingerprint.
