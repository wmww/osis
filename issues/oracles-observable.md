# Oracles test what users observe
> Summary: Tess: stop iterating against tests that test too much. Most order/held/parts oracle excuses hide held-body and death-date differences users never see. Plan below, folded into the retention steps (issues/retention-modes.md).
> Priority: normal
> Tags: tests

Rules: an excuse is computed from the history, never from the node under test; exchange between nodes runs through real sync, not harness-chosen re-gives.

3. **With retention step 2**: order `check_orders` becomes P1 reads and rosters equal the keep-everything node holding the same commits (excuse only for a part that may have waited at its expiry, `order::waited_at_expiry`, or a purge that fell, both history-derived); P2 after a sync exchange (and a writer's repair for flagged aspects) reads equal; P3 nothing purged/expired readable (`value_past_end`); P4 reopen equals rebuild. Drop `states` (optionally a probe continuation instead), `pending`, `parted`, `plain_state`, `alike_repaired`'s skip, `purge_flips`, `refetched`, and with death dating the drop_flips family, `bound_kept_now`, `body_past_bound`, `carried`, and `expired_pending` (node-flagged, used by `bound_kept_now` only).
4. **With retention step 0**: held-model compare keeps applied, validity, reads, forbidden values, kept-until-T presence; drops held-vs-dropped for convenient bodies and its timing excuses.
6. **With retention step 5 (H3)**: `history()` only within kept history; undo availability (`ContentGone`), `commits()`, `changed()`, `Change.origin` documented best-effort and never compared across nodes.
7. **Low**: `withheld_departures` as one content-level rule ("a holder can always share what it holds") instead of `invalid_raise`, `regranted`, `sharers`.
Leave alone: walks, perm differentials, `keep.rs`, `value_past_end`, `walk_sides`, `random_window`'s cap refusal.
