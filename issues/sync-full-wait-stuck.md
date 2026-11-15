# A full node's wait for room can last forever
> Summary: A node keeping S unread that refused entries for room (code 12) waits for room to grow, then pulls S anew and sends `full` false (spec/sync-streams.md §4 Full); its sources' places already passed the refused entries. The wait is kept only in memory (`Streams::room`, core/sync/src/streams/mod.rs:205) and judged on S's own usage, so a restart, or a refusal by the store-wide cap (`Env::room` `total_bytes`) followed by an entry leaving another sync ID, never ends it: the refused entries never arrive, and each peer's durable full flag for this node (record row `FULL`, streams/known.rs:93) stays true for good, so readers keep counting it full (deletes there skip the carrier check, read/judge.rs:589 `src.full`; status names it among those not taking S).
> Priority: critical
> Tags: sync

A missing end. Room growth is the one pull-anew trigger outside the durable `N/` mark (dropped copy, raise to read and head move all go through `Store::anew_feed`; `Streams::room_grew` calls `pull_anew` directly).

Fix idea: keep the full state durably per S (an `N/` mark kind, or a row with S's usage and the cap kind it hit), judge growth on the room of the cap that refused (S's own, or the store's total; durable and ephemeral apart, as the spec's "of that entry's kind" says), and route the pull anew through the mark so a restart reads it back like the other triggers; the next connection to each told peer sends `full` false once room grew. Clear the state with a shred of S (`forget_shredded` leaves `room`, so a shredded S's zero usage runs `pull_anew` on an S no longer held).

Repros (fast, streams it, `Pair`):
- Restart: `full_told_then_room_again_spec_sync_streams_4` with `p.b.restart_all(seed)` after the Full assert, before the drop: expect the Pull from the start, a not seeing b full, the other entry taken.
- Store-wide cap: b keeps K1 and K2 unread, `total_bytes` 4000, no per-ID cap; a stamps one 3000-byte entry under each; b takes x1, refuses x2 (12); drop x1 at b, run: expect a Pull joining `(K2, None)` and x2 held.

Related, low: a head move while S's copy is dropped (`N/` empty mark, `set_unheld(true)`) runs `pull_anew` everywhere and clears the mark while S is still dropped; a crash before unread's `set_unheld(false)` rebuilds `unheld` without S, and the dropped entries are never fetched again. `pull_anew` should keep the empty mark while S is in `unheld`.
