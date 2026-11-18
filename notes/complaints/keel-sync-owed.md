# keel-sync-owed
- tools/mutate.py batches wrap each OLD as an expression; one OLD that is not (`= stranded {`) fails the one build and every row reads "does not build": a 2-minute relink lost. Check each OLD is an expression before batching.
- Several libtest name filters go after `--` (`cargo test -p x --test it -- a b`); before it cargo refuses the second.
- A world test's marginal cost is easy to underrate: one more `run` after a re-accept on the siblings fixture costs about 2.7 G instructions, half the task's budget. Measure with `tools/icount BIN -q <name>` before and after.
- "Stamped under S" does not show a sealed fire was promoted: a writer that applied the fire logs a fresh encryption of its own. In place is the filler wrap no read secret of the thing opens.
