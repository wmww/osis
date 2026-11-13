# A waiting snapshot's carried copies judged by the held snapshots' bound
> Summary: Two judgments answer "may this snapshot carry a value of a write now value-less": held snapshots keep a per-source counter bound (`snapshot::Carried`, `carried_meets`), waiting ones decode their part again whenever the aspect's value-less list changes (`pending::strip_carried_waiting`, memo `Core::waiting_carries`). Giving a waiting snapshot the same bound, taken once when stored, would make it one judgment and drop the memo.
> Priority: low
> Tags: engine

Current shape:
- Held: `Carried` (per source, least and greatest counter of a write the held body holds valued) is noted with the snapshot (`apply::note_carried`, in `Indexes::snapshots`); an expiry strips the state in place only where no held bound `meets` the expiring writes. O(sources) per question, no decode.
- Waiting: `strip_carried_waiting` asks `carried` (decode the part, strip by the list, compare) through the memo `waiting_carries`, keyed (commit, aspect index) and read against the aspect's value-less list and the commit's pending entry. It decodes the part when stored, at the first look after, whenever the list changes (any purge or expiry on the aspect), and at every look while the part cannot be read.

The change: compute the waiting part's `Carried` once when it is first read (the decode `carried` does), keep it with the pending entry (in memory, as the memo is; rebuilt at open with the first look), and decode again only when `meets(list)` says the bound may hold a listed write. The bound is a hull, so `meets` true still needs the decode; false needs nothing. `waiting_carries` goes, and both kinds of snapshot answer through `Carried::meets`.

Gain: fewer decodes on an aspect whose list changes often while a snapshot waits (each purge or expiry there re-decodes), and one concept instead of two. Not a correctness issue.

Risk: a waiting part that cannot be read yet (page away, parked) has no bound; it must stay "unknown, judge at each look" so `Err` from `carried` keeps its handling.
