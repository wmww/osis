# Sequence runs amplify input size
> Summary: A run `[Dot, n, [], [], [], []]` of about 8 bytes creates up to 2^16 element records (bare anchors are legitimate in snapshots, spec/crdt.md §3.2), so a 16 MiB delta can ask for ~10^11 records and exhaust memory. No spec limit bounds the records a delta may create; options: a format constant for records per delta (or per decoded byte), or charging bare-anchor runs against a budget the node sets per aspect.
> Tags: crdt, security

- Where: `crates/osis-crdt/src/seq_wire.rs` `decode_elems` allocates `n` records per run; paging (§8) multiplies the reachable input.
- Legitimate sizes: a reset text keeps one bare-anchor run per former run (notes/crdt.md, Text size: ~6,000 runs for the automerge trace), so a cap far above real states is enough.
- Authenticated malicious writers are out of scope (notes/crdt.md, Owner decisions), but a decoder that can be made to OOM by ~10 bytes per 2^16 records is a robustness gap; a limit is a spec change (owner call).
