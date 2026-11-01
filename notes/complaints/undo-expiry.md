# undo-expiry
> Summary: The brief's crdt per-branch command runs `budget_*` timing tests in dev.

- The brief's `OSIS_CRDT_SEED=148013 cargo test -p osis-crdt -- --include-ignored --skip repro_` also runs `tests_seq_ops::budget_big_text_spec_6` in dev, which was still going after 30 min. With `--skip budget --skip bench:: --skip scale::` added (as the whole-set tier-2 form in notes/build.md has), the set takes 9 s. The periodic-check command in notes/coordination.md has the same gap.
