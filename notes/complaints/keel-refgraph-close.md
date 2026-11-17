# keel-refgraph-close
- An ignored repro (osis-sync `tickets::repro_a_crash_after_accepting_*`) pointed its `#[ignore]` at the plan issue's Status while the bug was long fixed; it passed as soon as run. Ignored repros citing a plan issue go stale silently; tools/policy.py could check that an `#[ignore = "issues/X.md"]` names an existing file.
- Test comments carried the plan's property codes (`refgraph R4`, `S1`): codes into a plan doc dangle once it closes. Cite spec sections instead.
