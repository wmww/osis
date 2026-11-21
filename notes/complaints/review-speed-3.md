# review-speed-3
- Replaying a seeded failure without a branch's fix: a wip commit reversing the one file (`git show C -- F | git apply -R`) and a single-crate run took 35 s; no `tools/bin-at` build of main was needed since the property only exists on the branch.
- A coverage tally gated on `seeds.overridden` is never checked by the gate (it always offsets): easy to miss when reading "checked on the default seeds".
- The branch's own offset check missed `honest_values_*_plain` sizing values by the raw seed: the gate's offset (about 4e11) asked for 44 TB and aborted the whole engine lib properties binary, so every engine property after it went unrun. A converted loop's seed must index nothing but an RNG or a modulus.
