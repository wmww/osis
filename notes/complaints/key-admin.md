# Complaints: key-admin
> Summary: Mishaps met making the key hop an ordinary edge (roles-model, spec, notes).

- A chained background run (`tools/heavy cargo ... ; tools/heavy cargo ...`) rebuilds at each step, so an edit to the model while an earlier step runs reaches the later steps: the whole chain had to be stopped and rerun before fixing an oracle. A search binary copied once per chain would let edits go on.
- roles-model's `tiny` oracles (`key audited`, `illegit gains`) restate W3's needs and "held its right" by hand; three rounds of 100,000 to 1,000,000 worlds went to bringing a new oracle in line with the walk's least-need and judged-once clauses, which no hand world states.
- The brief expected osis-perm's walk to hold a key hop read as always listed; the walk that landed keeps no edge for it at all (it comes with A4), so "make the walk match" was a build of its own, not an edit.
- A Bash call mixing `cargo test`, `rm` of scratch logs and `cp -r` into the scratchpad was auto-denied whole; split calls passed.
