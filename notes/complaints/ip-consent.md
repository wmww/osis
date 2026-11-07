# ip-consent
- The brief said "tier-2 networking once (`cargo test-net`)": bare `cargo test-net` runs no `#[ignore]` test, so the P2P/QUIC tier-2 tests did not run (11 min of other work). The real check is notes/coordination.md's `cargo test-net -- --ignored driver:: runtime:: quic relay lan` (30 s); briefs should quote that form.
