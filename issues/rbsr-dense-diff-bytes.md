# Range reconciliation sends about the whole ID list at 1% difference
> Summary: Reconciling 10^6 blob IDs with 10^4 differences takes 3 round trips (within the bound) but sends 35 MB up and 5 MB down, more than the 32 MB of the plain ID list: once differences are denser than about 1 per 250 IDs, every range of the last split level mismatches and its 16 subranges all go as mode 1 ID lists, matching ones included.
> Tags: performance, sync, proto

Repro: `cargo test --release -p osis-proto --lib million_blob_rounds -- --ignored --nocapture` (236 request messages, 1.3 s CPU).

Rounds meet spec/requirements.md (logarithmic). Bytes are O(n) whenever the difference is dense, which is the common case after a long offline period on a busy label. Cheaper options (spec/wire.md §11.3 change, owner sign-off): split mismatched ranges below the list threshold into fingerprints again instead of lists, or send lists only for ranges at most `LIST_MAX` and fingerprint the rest; or a smaller split fan-out near the leaves. Not needed for correctness.
