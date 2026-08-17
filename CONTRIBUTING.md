# Contributing to Dart Protocol

Thanks for your interest! This is an experimental research project — issues,
bug reports, benchmarks and pull requests are all welcome.

## Getting started

```bash
npm install                 # TypeScript toolchain
cd go && go build ./...     # Go codec + server + client
cd rust && cargo build      # Rust codec + server + client
```

## Protocol changes

Dart has **three interoperable implementations** (TypeScript, Go, Rust) that
must stay byte-compatible on the wire. Any change to the packet format must be
made in all three codecs and verified with the interop tests:

```bash
npm test                    # TypeScript integration suite
npm run bench:endtoend      # real clients/servers, many users
```

## Guidelines

- Keep the three languages in sync — a format change in one breaks the others.
- Never introduce a zero-key fallback, fixed IV/nonce reuse, or a
  server-held conversation key.
- Add or update the `check_sync.go` / `rust/src/bin/check_sync.rs` /
  `test_sync.js` cross-language format checks when the SYNC frame changes.
- Update `PROTOCOL.md` as a **present-tense spec** of the current wire format,
  not a changelog of previous drafts. Recite the whole file after a format
  change; do not patch one section and leave a contradicting paragraph in
  another. Then update `README.md` and `SECURITY.md` to match.
- `public/PROTOCOL.md`, `public/README.md` and `public/SECURITY.md` are
  pointers to the root files — do not fork a second copy of the spec.
- Follow the existing code style in the file you are editing.

## Code of conduct

Be respectful. This is a small experimental project; focus on the code, not
the person.
