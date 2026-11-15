# full-cost
- `tools/mutate.py` on a value computed twice (here the owed set, read in two expressions) reports "none" for a mutation that cannot change behaviour; mutate the shared binding instead.
- Store caps are not durable: a store test reopening the store must set them again, else every refused entry "fits" after the restart and the test fails far from the cause.
- The three destruction::*_spec_commits_5 failures (engine role_sigs index check) are still on the base.
