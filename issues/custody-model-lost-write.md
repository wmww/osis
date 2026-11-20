# custody model: a node settles without a write
> Summary: roles-model `custody::tests::random_worlds_hold_large` at OSIS_CUSTODY_START=OSIS_ROLES_START=567669682357 (2,000 worlds) fails its `writes` check twice: "node A settled without C's write 54 on t". The model's own search, no engine involved; fails on main's binary (d22b49086).
> Priority: low
> Tags: tests, roles-model

Replay: `OSIS_CUSTODY_START=567669682357 OSIS_ROLES_START=567669682357 cargo test -p roles-model --lib -- --ignored --exact custody::tests::random_worlds_hold_large` (about 12 s wall); the world prints with the failure (A's removal of 3, a T rotation sealing it, C's write on t). A second check of the same search besides issues/custody-model-flip.md's `flip`. notes/redesign-plan.md A4 deletes the custody machinery; look before then only if custody code changes.
