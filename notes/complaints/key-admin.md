# Complaints: key-admin
> Summary: Mishaps met making the key hop an ordinary edge (roles-model, spec, notes).

- A chained background run (`tools/heavy cargo ... ; tools/heavy cargo ...`) rebuilds at each step, so an edit to the model while an earlier step runs reaches the later steps: the whole chain had to be stopped and rerun before fixing an oracle. A search binary copied once per chain would let edits go on.
- roles-model's `tiny` oracles (`key audited`, `illegit gains`) restate W3's needs and "held its right" by hand; three rounds of 100,000 to 1,000,000 worlds went to bringing a new oracle in line with the walk's least-need and judged-once clauses, which no hand world states.
- `World::list_write` keeps its name on this branch though it means "an edge write on a key hop": osis-perm's `paths/mod.rs` calls it and core/perm was off limits until A1 lands.
- A Bash call mixing `cargo test`, `rm` of scratch logs and `cp -r` into the scratchpad was auto-denied whole; split calls passed.
