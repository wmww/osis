# reach-fix
- Queued `tools/heavy cargo test` runs in one background chain each build at their own invocation, so editing the crate while an earlier one holds the lock changes what the later ones run: hold edits until the last has built.
- A generator that draws from its rng for a new option shifts every seed: a seed a reviewer filed against main no longer reproduces. Draw new dimensions only behind an option that is off for the old worlds (`Wide::mint`).
- The family slice tests are sized by step: a new `Shape` dimension multiplies their cost unless every default step is scaled with it.
