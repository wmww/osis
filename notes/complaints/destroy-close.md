# destroy-close
- `VerifyingKey::from_bytes` rejects small-order points, so a "zero keys" sentinel step cannot be parsed: the closing step marks itself by a zero `step_key` and `claims_hash` instead. Worth knowing before designing any other sentinel key on the wire.
- `destruction::a_released_things_sync_id_empties_and_is_forgotten` takes about 5 s (world run past `ROLE_KEEP` and `TOMBSTONE_LIFETIME`), at the edge of the default-test budget.
