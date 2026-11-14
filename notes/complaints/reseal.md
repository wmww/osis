# reseal
- The brief carried two rules for fresh encryptions that disagree: "each section under the epoch it was written under" (SECURITY bullet, which the code then built as a per-commit epoch table) and "`Engine::seal` with held sections, wrap from `wrap_secret`" (the contract, spec/crypto.md §5). Followed the spec; the table is gone.
- No sync World test makes a fresh encryption from held blobs (logging again, a deposit): `Live::fresh`'s collection of held blobs is checked only through the facade's `HeldBlob` contract; a mutation passing none fails no osis-sync test.
