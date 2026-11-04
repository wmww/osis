# A removed map entry of text or list keeps its key in snapshots
> Summary: A removal resets every record of the dot, but a text or list value's bare anchors stay (spec/crdt.md §5.7), and they stay in the keyed record, which repeats the key. Snapshots carry it (spec/crdt.md §5.6 says a key never outlives its entry's content). Honest flow, no concurrency needed: any `map<k, text>` or `map<k, struct{text}>` entry removed. The sweep (spec/sync.md §7) cannot reach it: no reset takes anchors.
> Tags: security, crdt

Repro: osis-node `waits::removed_text_entry_key_goes_repro_spec_crdt_5_6` (ignored). Predates the sweep.

Simplest rule to try: a keyed record left with no write moves its fragment (anchors) into the dot's key-erased record, as value-less erasure does (spec/crdt.md §4.7). Check that it is a lattice: `prune_dot` runs after any join, and a nested write arriving later recreates the keyed record, so it depends on `lattice_laws` holding with the key-erased record's anchors joined into reads.

Parked: branch `crdt-leftovers` on devbox (local only, not merged), its review says neither commit is ready. Commit 1 leaves a state difference by arrival order, against spec/requirements.md Deterministic (reads alike, digests and snapshot bytes not; `seq_compact` seed 7410006), needing a call by Tess or the sweep at compaction. `issues/list-mark-lost-on-fall.md` is commit 2's gap. See those issues and notes/complaints on that branch.
