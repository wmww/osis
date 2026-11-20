# custody model: a node drops a taken revocation
> Summary: roles-model `custody::tests::random_worlds_hold_large` at OSIS_ROLES_START=647344785567 (2,000 worlds) fails its `flip` check once: "node T at 17 dropped a taken revocation [10, 4] -> [10, 21]". The model's own search, no engine involved; fails on main's binary.
> Priority: low
> Tags: tests, roles-model

Replay: `OSIS_ROLES_START=647344785567 cargo test -p roles-model --lib -- --ignored --exact custody::tests::random_worlds_hold_large` (about 15 s wall). The world prints with the failure: removals by A and C forking, X acting as Z taking A's removal of 4, A answering after settle. The same check fails in the engine differential at another seed (issues/custody-differential-failures.md, 357482902476): either the rule lets a taken revocation be replaced or the check reads the set where it may rightly change. notes/redesign-plan.md A4 deletes the custody machinery; look before then only if custody code changes.
