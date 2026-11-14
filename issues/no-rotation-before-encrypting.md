# Nothing rotates or finalizes before a content write is encrypted
> Summary: A reader whose grant's `until` passed reads what is written after: the writer node encrypts the next write under the old read epoch with no finalize and no rotation, because nothing on the write/seal path calls `ensure_rotated` (spec/crypto.md §4 encrypt under covering epoch, spec/permissions.md §3 required rotation, §2 finalize before encrypting).
> Priority: critical
> Tags: security, engine, sync

## Reproducer
osis-sync `flows::repro_a_passed_until_rotates_before_the_next_encryption_spec_crypto_4` (ignored): node 0 grants node 1's account read on t with `until` a minute ahead; node 1 reads; two minutes on node 0 writes again: node 0's roster no longer lists node 1's account, its read epoch is unchanged, and node 1 reads the new value.

## Cause
`Engine::ensure_rotated` (finalize due edges, rotations due, blocked roles) says "labeling calls it before wrapping, stamping or boxing under the actor". In production only the edge flows call it (`flows/edges.rs`, `flows/signing.rs`); neither `Engine::commit` nor sync's `seal_body` (read module, own entries) nor the facade's `Engine::seal` does. The old node sync made that call; the rebuild dropped it. Wire it where every encryption under an actor passes (the facade's seal, or the commit path), with the commits it writes logged as any own commit, and refuse to seal under a role still blocked.
