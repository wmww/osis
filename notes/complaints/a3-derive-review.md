# a3-derive-review
> Summary: Mishaps met reviewing A3 brief 3 (the evidence derivation's leaves and duty).

- A `cargo test ... | grep` probe run in the foreground passed 120 s while building and moved to the background; probes that build go to a log file from the start.
- Three of the worker's new indexes had no default test that shrinks them (an addendum forgotten, a late witness, a lowering leaving a rebuilt set): `check` compares from scratch, but only on steps some test takes. Planting "never removed" per index found them in one batch.
