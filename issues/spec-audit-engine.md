# Spec audit 2: undo, un-merge, validity and retention where code and spec part
> Summary: Code bugs and open decisions from part 2 of the spec audit (crdt §4.6-§4.8, permissions §5.1 steps 3-4, commits §4-§5): undo's "in effect" judged per aspect, a malformed header frontier read as none, carrier-only snapshots kept as covers, dead node-form role overlap code, list presence after expiry, smaller undo gaps.
> Tags: spec, engine, crdt, permissions

Spec-side wording was fixed on branch spec-audit-2. Part 1: issues/spec-audit-crdt.md, spec-audit-validity.md.

## Code bugs (spec is right)
- **Undo "in effect" only sees the undone aspect's commits.** spec/crdt.md §4.6: a commit is in effect while no undo commit in effect undoes it (a whole-commit property). `engine/src/undo/mod.rs` `chain_judge` builds `undoers` from `ix.by_aspect` of the aspect alone. X touches A and B; its undo U writes only B (the register rule wrote nothing on A); on A, X still reads in effect, so a later step-back on A is refused where the spec allows it (same for redo). Take undoers from every held header whose `undoes` names the commit. Interop (reads differ).
- **Malformed header frontier treated as no frontier.** `engine/src/apply/validity.rs` `header_frontier` returns `None` when field 12 does not decode (`.ok()?`), so the commit applies as a demotion with no frontier (every audited write drops); the same failure in a roster snapshot's linked ledger frontier is bad input (~:335). spec/wire.md §4 field 12 now says bad input. Reject in `Header::validate` or at apply.
- **Carrier-only snapshots recorded as covers.** spec/commits.md §5: a carrier-only snapshot covers none. `retention/mod.rs` `drop_part_as` fills `Dropped::covered_by` from `covered()`, which never checks `carrier_only`; `uncover` then counts it as a carrier, so a body whose real cover turned invalid does not count as never received (spec/permissions.md §5.2). Node-sync already skips carriers when choosing drops. Filter them out of `covered_by`. Rare.
- **Dead node-form role overlap code.** `commit/src/validate.rs` rejects node-form role and roster-snapshot commits (spec/commits.md §4), but perm still voids `roles.0` node-form overlaps (`perm/src/walk.rs` `gather`, `Input::ranges`, `voided`, `Dots::Node`) and `validity.rs` `dots_of` builds node-form dots. Remove.

## Decisions
- **List presence after expiry.** `crdt/src/seq.rs` `creation_counts` counts a list creation while its content fragment is non-empty, which value-less writes keep it (`strip_values`): a list whose only elements expired reads `[]`, not absent. spec/crdt.md §4.3/§4.7 say value-less writes do not count toward `written` and call list creations value-carrying. crdt-model agrees with the code. Pick one and say it in §4.3.
- **Demotions within one commit.** All edge writes of a commit are judged against the state before it (`walk.rs` `Pass::commit`), but each demotion and the "reaches the holder just before R" check (`change`) see the commit's earlier writes applied. spec/permissions.md §5.1 step 4 does not say which; matters only for the multi-removal shape. Say "before that write, the commit's earlier edge writes applied, in header order" or make it before the commit.
- **Undo in a `Slots` position.** `crdt/src/ops.rs` `present_slot` judges "still the current winner" inside the register slot even when another slot is read; the undo's register write then resets newer writes in every slot. spec/crdt.md §4.6/§7 do not say which slot.
- **Root register "absent before" failing**: the undo writes nothing (`crdt/src/undo.rs` register arm); §4.6 has no rule for it. Write it down.
- **"Outermost absent" below a map entry or list element**: `undo.rs` restarts the path at the entry's value (map arm, seq `nested`), so the rule can fire inside where an outer absent position already failed it. Probably unreachable; confirm with a test, then match the spec.

## Code quality
- `perm/src/scope.rs` `demotion_scope` takes "before" as the current edge with `until` stripped, not the edge as restored (values taken by self-removal, a demoter's kept standing): frontiers can cover less than the walk audits. Allowed (only over-covering is forbidden) but loses writes needlessly.
- `undo/mod.rs:97` doc ("`Some(0)` for one gone") is wrong for durable data (`write_expiry` returns `None` for an unknown commit).
- `retention/mod.rs` `covered()` checks frontier reach for node form only (`by_frontier`), not session form; session commits are memory-only, so likely unreachable. Confirm or add.

## Not audited
Death re-dating after a validity flip or un-merge (`retention/deaths.rs` `rejudge_deaths`, `replay_all`) and "a drop is final"; purge mechanics beyond `known_purged`; epoch-start rounds (§6); undo of ephemeral creations (`unmake_ephemeral`); crdt-model undo vs engine undo line by line.
