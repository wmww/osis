# Complaints: order-seeds
> Summary: order-seeds (the order harness's "applied: model false, node true" seeds): the brief's lead named the walk while the cause was the apply wait; 50 order seeds overran one `heavy` hold under load; a single-seed replay of a passing Settled seed exits 101 on a coverage floor; an issue said to hold a shrunk script held none.

- The brief read the failures as an edge-write status disagreement in the walk (osis-perm `paths` against roles-model). The failing check is `applied differs`, which compares whether a commit applied or waits (held-model `unreached` against `apply::thing_wait`), not `roles.0` statuses: printing the check's name beside its text ("applied differs: ...") would have said so. About an hour went to the walk's notes first.
- The brief said the 5-step shrunk script was in the issue; the issue held none (the shrink was rerun: 270 s of hold).
- `OSIS_ORDER_SEED=777000000046` (Settled) passes its checks and still exits 101: `Seen::floors` fails a one-seed run ("held-model judged no list element reset"). A seed replay should skip floors that need more seeds than it ran, or say "0 failing" as its result.
- 50 order seeds in one hold: 5,956 CPU-s and 744 s of wall at load 32, over the `heavy` limit (5,060 CPU-s, 598 s). 40 fit.
- Engine default tests (`cargo test -p osis-engine`) took 270 to 530 s of wall per run while other agents' holds ran; five runs were needed to restate tests the rule change reached.
- A rule change in `apply` reached nine default tests that built hostile commits along paths nobody granted and expected them held invalid; they had to be read one by one. A helper for "a hostile commit along a path whose edges are held" would keep such tests on the rule they mean to test.
