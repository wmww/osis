# Snapshot runs amplify input size
> Summary: A snapshot run `[Dot, n, [], [], [], []]` of about 8 bytes creates up to 2^16 bare-anchor records, so a small snapshot can exhaust memory. Writer and import deltas are bounded (bare runs rejected, `MAX_DELTA_BARE` content-less elements per delta, spec/crdt.md §3.3 rule 7); snapshots cannot be, since honest bare-anchor states exceed any fixed bound. Fix: store uniform bare and flag-only runs as range records in state (implementation only, no spec change).
> Tags: crdt, security

Repro: no test yet: decode a sequence snapshot holding one `[Dot, 65535, [], [], [], []]` run.

- Where: `crates/osis-crdt/src/seq_wire.rs` `decode_elems` allocates `n` records per run; `seq.rs` keeps one `SeqElem` per dot.
- With range records, decode allocates per run, not per element; join, prune and linearization must split a range when a write lands inside it (a bare range places at END by dot, so it stays one node until something anchors into it).
- Legitimate sizes: a reset text keeps one bare-anchor run per former run (notes/crdt.md, Text size: ~6,000 runs for the automerge trace).
