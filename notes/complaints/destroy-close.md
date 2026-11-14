# destroy-close
- `VerifyingKey::from_bytes` rejects small-order points, so a "zero keys" sentinel step cannot be parsed: the closing step marks itself by a zero `step_key` and `claims_hash` instead. Worth knowing before designing any other sentinel key on the wire.
- (review) The destruction tests' `three()` world costs about 2.5 s each (most of every test there): the release-reads-absent test and the forgotten test are one test so the end-to-end close adds only its run past `ROLE_KEEP` and `TOMBSTONE_LIFETIME`.
