# A full node forgets its refusals at a restart
> Summary: A node keeping S unread that refused entries for room (code 12) keeps what it refused, and the bytes S used then, only in memory (`Streams::room`, core/sync/src/streams/mod.rs:205); its sources' places already passed those entries. After a restart, room growing triggers no pull anew and no `full` false (spec/sync-streams.md §4 Full), so the refused entries never arrive there, and each peer's durable full flag for it (record row `FULL`, streams/known.rs:93) stays true for good, so readers keep counting it full: deletes there skip the carrier check (read/judge.rs:589 `src.full`) and status names it among those not taking S.
> Priority: normal
> Tags: sync

Room growth is the one pull-anew trigger outside the durable `N/` mark (dropped copy, raise to read and head move all go through `Store::anew_feed`; `Streams::room_grew` calls `pull_anew` directly).

Fix idea: keep the full state durably per S (its bytes at the last refusal) and route room growth through the `N/` mark, so a restart reads it back like the other triggers; the next connection to each told peer then sends `full` false once room grew.

Repro (fast, streams it): node K keeps S unread with a tiny cap; a reader serves three entries, K refuses one for room and tells `full`; restart K; delete an entry at K so room grows; settle. Expected: K holds the refused entry and the reader's record of K is not full. Today: neither.
