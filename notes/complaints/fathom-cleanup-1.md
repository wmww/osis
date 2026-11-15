# fathom-cleanup-1
- The `#[deprecated]` probe on osis-sync found one unused item: its tests/it reaches nearly every pub item, so test-only and internal-only uses dominate (317 of 440 items test-only). Infallible `Result`s and forwarding wrappers were the yield; no tool finds either (a body regex flags every delegating call and every trait impl).
- A test fake's methods pin a trait's `Result` signatures: an infallible ground call needs the trait, the live impl and every fake changed together.
