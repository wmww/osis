# ip-consent
- The brief said "tier-2 networking once (`cargo test-net`)": bare `cargo test-net` runs no `#[ignore]` test, so the P2P/QUIC tier-2 tests did not run (11 min of other work). The real check is notes/coordination.md's `cargo test-net -- --ignored driver:: runtime:: quic relay lan` (30 s); briefs should quote that form.
- Review: `osis` `sources::thin_client_over_quic` (tier 2, direct_sync off, untouched here) failed once ("not reached: down", 60 s) while the tier-2 run built beside other load; passed 3/3 alone and on the next full run. Flaky under load.
