# review-speed-3
- Replaying a seeded failure without a branch's fix: a wip commit reversing the one file (`git show C -- F | git apply -R`) and a single-crate run took 35 s; no `tools/bin-at` build of main was needed since the property only exists on the branch.
- A coverage tally gated on `seeds.overridden` is never checked by the gate (it always offsets): easy to miss when reading "checked on the default seeds".
