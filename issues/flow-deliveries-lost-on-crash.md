# A crash loses a flow's certificate copies and waiting placements
> Summary: a flow's `Done` lives in memory until `carry_out`, and node-sync's `deferred` certificate copies (waiting for a rotation) are memory only. A crash before `carry_out` loses `First`/`Certificate`/`Removal` certificate copies under other groups' labels, `Direct` deliveries and the `first` upload priority; a crash any time loses `deferred` copies. Nothing recomputes them.
> Tags: node-sync, security

## Notes
- From reading (self-removal-crash branch): `take_done` (`sync/deliver.rs`) is the only caller placing `Delivery::Removal` and `First`/`Certificate` chains (`place_chain`, `place_aspects`); `deferred` is filled by `place_certificate_in` and drained by the next pass of that group (`pass/mod.rs`). `state.add_direct` and `note_unsent` are durable, but only once `take_done` ran (inbox deliveries are safe: `note_unsent` runs in the commit's transaction).
- Recovered after a crash: the commit's bodies under its own labels (the next pass uploads every own commit; the self-removal crash test checks this), and own deposits (`deliveries_survive_a_crash_before_carry_out_spec_sync_5`).
- Lost: a removal's copies under the labels of groups holding the target (spec/permissions.md §3: those readers must see it), a grantee device's certificate copy under its home label, the pairing channel's commits, and "before any other upload" ordering.
- Fix direction: record pending placements durably in the commit's transaction (like `note_unsent`), or derive them at start from stored role commits; same for `deferred` (store, or re-derive per group at its next pass).
- Test: each delivery kind, crash before `carry_out` (and with a deferred copy, crash after), restart, settle; the copies are at the hosts.
