# A covered drop then a purge that falls loses a live write the read oracle keeps
> Summary: `order::held_set_decides_plain` seed 7310 (Settled) fails once the judged nodes run node-sync's covered drops: after its sync exchange a node reads `t:reg.0` as absent where the node keeping every body reads "also". The node dropped the write's body (#18) under a snapshot carrying it (#20), which it later holds as a leftover (its copy stripped for a purge); the keep-everything node holds #20 whole and #18 too. Likely spec/commits.md §5 Covered, Limit (a purge that falls after a covered drop restores nothing beyond the cover's copies), which the read oracle does not model; not yet confirmed. Listed in tools/known_failures.txt.
> Priority: normal
> Tags: tests, node, retention

## Repro
`OSIS_ORDER_SEED=7310 OSIS_ORDER_LEN=60 tools/heavy cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain`, order #1 (newest first), "now, after the sync exchange". `OSIS_ORDER_DUMP=1` shows #18 `dropped {1} Cover by [#20]`, #20 `stripped {0} valued {0}` at the node, both whole at the keep-everything node; purge request #26 (peer 0, `purge.0` on the same thing) is the candidate.

## To decide
- Confirm the sequence: #18 dropped under #20, then #26 names #18 (its value held value-less, #20's copy stripped), then #26 falls (its author demoted).
- If so, spec/permissions.md §6 ("A body no node holds stays gone; the delta then reads as never received") and §5 Covered, Limit disagree on whether the node counts #18 missing again (and fetches it) once its only cover carries it value-less. Either the engine marks such a part missing (`retention::uncover` when a cover's copy is stripped), or the limit stands and the read oracle needs an excuse computed from the history (a purge naming a body that falls), not from the node.
