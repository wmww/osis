# Joint-model differential mismatch at OSIS_PERM_SEED=1303000
> Summary: `differential::joint_model_agrees_large` fails at OSIS_PERM_SEED=1303000 (shard seed 0x4005efee1da, sample 4383): on a shrunk 4-write history the model drops write w0 (n1's second removal of A1 on A0) and perm applies it. Unexamined: which side is wrong.
> Tags: perm, tests

Found by the snapshot-receipts branch's oracle run (it changes no perm or model code). Replay: `OSIS_PERM_SEED=1303000 cargo test --workspace --test it -- --ignored differential::joint_model_agrees_large`.

Shrunk trace (nodes n0, n1; A0 owned by n0, A1 owned by n1; genesis: n1 Admin on A0, A1 Admin on A0):
- w3: t=1 n1 (id 3) sets A1 on A0 := None, received by n0
- w0: t=1 n1 (id 4) sets A1 on A0 := None, received by n0
- w2: t=2 n1 (id 1) sets n1 on A0 := None (self-removal), received by n0
- w1: t=3 n0 (id 2) sets A1 on A0 := None, received by n1

Model: w0 applied false, dropped true; perm: applied true, dropped false. Both removals at t=1 are of A1's edge, one of which A1 (owned by n1) itself held admin through: likely around a write that removes the author's own path (self-removal vs explicit demotion, notes/permissions.md) with a commit-ID tie at equal `t`.
