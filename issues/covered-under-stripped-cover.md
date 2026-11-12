# A body missing again after a fallen purge drops as covered under a cover holding it value-less
> Summary: Data loss. After a purge request falls, the delta it named is missing again (spec/permissions.md §6: never received, fetched again), but a held snapshot whose copy of it the purge stripped (a valued leftover, the copy value-less) still "covers" it: `snapshot::covered_join` says covered for any body not held (`!held` → `Some(true)`), so node-sync's covered pass (`CoverPass::drop_covered`) drops the missing part and the node never fetches it again. The write is live and valid, other nodes and hosts hold it, and this node reads it absent for good. `order::held_set_decides_plain` seed 7310 (listed in tools/known_failures.txt).
> Priority: critical
> Tags: engine, retention, node-sync, security

## Confirmed sequence
Shrunk seed 7310, order #1 (every commit reversed, so the thing's commits wait for its creation and apply in one cascade at `#6`): `#9` (peer 0, `t:reg.0` = "g") and `#14` (peer 2's snapshot carrying it); purge `#16` names `#9`. In the cascade the purge stands for a while (`#14` stripped), then falls (role commits), leaving `#9`'s `t:reg.0` part missing (to be fetched again) and `#14` a valued leftover with `#9`'s value value-less. The next covered pass drops `#9` "Cover by #14"; no purge stands, the state reads nothing, the keep-everything node reads "g". Any order where the purge applies before its fall arrives does the same; nothing in it is specific to the cascade.

Not spec/commits.md §5 Covered, Limit: that is a body dropped before the purge, whose cover's copies the purge then strips. Here the body drops after the fall, under a copy that no longer holds its value: joining the body into the cover would change it (spec/crdt.md §4.7 Join: value-less copies yield to the valued one), so it is not covered.

## Direction
- `covered_join`: a body not held is covered only where the cover holds its writes as the body would give them; a cover holding them value-less while no purge or expiry holds them so (the expiring-delta check above it is the same shape) covers nothing. Check `retention::uncover`: a cover stripped for a purge leaves the bodies it covered uncovered (missing again) when the purge falls, so the dropped-before case's Limit is the only loss.
- Check whether node-sync deletes such a body at hosts as covered (spreading the loss).
- Oracle gap: `held::compare` leaves a missing part's covered drop unjudged ("covered drops unjudged"); held-model could judge it (a body not held, its cover's copy value-less, no purge standing: kept).

## Repro
`OSIS_ORDER_SEED=7310 OSIS_ORDER_LEN=60 tools/heavy cargo test -p osis-node --test it -- --ignored --exact order::held_set_decides_plain` (`OSIS_ORDER_SHRINK=1` gives the 22-commit history; `OSIS_ORDER_DUMP=1` shows `#9 dropped {0} Cover by [#14]`, `#14 stripped {0} valued {0}`).
