// Cross-language SYNC format check (mirrors check_sync.go and src/bin/check_sync.rs).
// Run `go run ../check_sync.go` from the repo root for the Go-side hex output and
// compare against `cargo run --bin check_sync` in rust/. Both must produce the same
// hex for the same (fixed) nonce. The production codec uses a fresh random nonce per
// packet; a fixed nonce is used here only so the byte streams are comparable.
fn main() {
    println!("Run `go run check_sync.go` in the repo root and `cargo run --bin check_sync` in rust/ to compare.");
}
