# A shared key used from two devices in one instant can defeat a re-snapshot's audit
> Summary: If one key (a recovery key, or an admin-level link key) is used from two devices at the same instant to remove a member and add it back, a later roster snapshot forgets the removal, and writes the removal had cancelled come back for nodes that compacted. Fixing it needs a format change (the commit ID in ledger keys).
> Tags: permissions, security

Ledger keys are (`ts`, node) (spec/permissions.md §6; the `tenure` type is fixed by `vectors/schema/core.vec`, frozen under FC-2). The walk orders same-key commits by commit ID: C1 removes m (audits, drops m's earlier edge writes below the thing), C2 re-grants m. The produced ledger ends m's tenure at (ts, k) with C1's frontier and the roster edge starts at (ts, k); `ledger_writes` sees the roster edge in force at that key, so the replay's end value equals the start and audits nothing. Pinned by `crates/osis-perm/tests/roster.rs` `same_ts_demote_regrant_not_replayed_spec_permissions_6`; the random neutrality runs skip such histories.

Fix: carry the commit ID (or a per-key sequence) in ledger keys and roster `since`, at the next frozen-vector bump. Until then, the client should not stamp two membership commits of one node at one ts (HLC already prevents it on one device; two devices sharing a key are the only source).
