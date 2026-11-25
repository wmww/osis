# Replaced `keys.0`, `secrets.0` and `sync.0` bodies are never dropped
> Summary: spec/commits.md §2 and §5 Fixed retention let an admin compaction-snapshot `keys.0` and `secrets.0` (only `roles.0` and `signers.0` are never snapshotted), and keep a replaced role-class body `ROLE_KEEP`; but the engine writes no role-class snapshot (`retention::snapshot::compacted` false for every role-class aspect, `compact.rs` `compactable` skipping fixed retention, Own replaces content only), so every replaced body of these aspects stays at every holder for good, growing with rotations and grants.
> Priority: normal
> Tags: retention, engine, keys

Property: every drop that is not expiry or purge is a cover, and a body past its keep bounds drops under one (spec/commits.md §5); notes/growth.md counted these bodies "Bounded" on that rule.

Minimal world: an admin rotates T's read role N times; each rotation's `secrets.0` and `keys.0` bodies are replaced by the next and kept at every holder of T (and in every unit carrying T's key part) for good. Likewise each grant's boxes once re-boxed.

Where: `retention/snapshot.rs` `compacted` (`!is_role_class`), `retention/compact.rs` `compactable` (`fixed_purge_by(a).is_none()`), `retention/purge.rs` re-snapshots by `compacted`; `ROLE_KEEP` (`retention/history.rs`) only delays a drop no cover makes.

Options:
1. Build it: an admin compacts `keys.0`, `secrets.0` and `sync.0` past `ROLE_KEEP` (admin-only snapshots, spec/permissions.md §5.2; a `secrets.0` snapshot's records rule, spec/crypto.md §4; `sync.0` steps' chain from genesis, spec/sync-ids.md, must stay verifiable, so maybe `sync.0` stays whole).
2. State it: these bodies grow with rotations (spec/commits.md Fixed retention, notes/growth.md as a row with its growth).
