# Random ephemeral reverts leave two nodes reading differently
> Summary: with only writes, creations and reverts, 8 of 200 seeds end with a writer and an admin reading an ephemeral aspect differently, and some reverts fail with "commit-level write off the delta stamp"; same seeds on main's revert code, so not from the rights check. Not traced.
> Tags: ephemeral, crdt, tests

Repro: `OSIS_EPH_START=0 OSIS_EPH_SEEDS=200 cargo test -p osis-node --test it -- --ignored --exact ephemeral::repro_ephemeral_revert_diverges`: seeds 5, 6, 26, 42, 59, 75, 100, 181.

Seen on seed 5 (no demotion): b creates a thing at step 12 and writes it at step 28, then a revert of an older change fails with `Delta(Malformed("commit-level write off the delta stamp"))`; a keeps the value of step 12, b reads step 28's. 18 such errors over the 200 seeds. Whether the failed revert causes the lost write is not known.

Related, also unchanged by the rights check: after a revert deletes an ephemeral thing, the node that reverted reads it unknown while the other still read its old value (seed 5, step 5), though spec/crdt.md §4.6 says the undo resets its state. The repro's `alike` compare covers it. Check whether the reset is meant to travel.
