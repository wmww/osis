# eph-unify-3b
- `cargo test --workspace` stops at the first failing test binary unless `--no-fail-fast`: the first tier-1 run hid every crate after osis-node (18 of 35 result lines). Worth saying in notes/build.md's command forms.
- Tier 1 took 11 min wall at load 42 (other agents' runs); about 4.5 min at load ~20.
- `ephemeral::host_cap_compaction_frees_it_spec_sync_5` is tuned to the byte: a commit-size change (here about 150 bytes less per commit) moved it into a configuration where the last upload stays refused forever; finding that took a lane dump (`ephemeral_dump`), which is the right tool and worth naming in the test.
- Reviewer: verifying a retuned cap needed main's binary with a probe test; `tools/bin-at` takes a rev, so the probe went in via a plumbing commit (`git read-tree`/`apply --cached`/`commit-tree`) on a throwaway branch. A `bin-at --patch FILE` would save that.
