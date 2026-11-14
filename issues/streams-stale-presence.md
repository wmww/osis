# A whole listing not marked trimmed leaves stale presence
> Summary: spec/sync-streams.md §4 Applying lets only a listing from the start marked `trimmed` replace what a requester holds as present at a source. A whole reply to a cursor that names no position (a restored or copied source store) is not trimmed, so an entry the source lost with no deletion event stays `known` there; a node keeping S unread may then count its own entry held at a source that lacks it and leave S (spec/sync-set.md §3).
> Priority: normal
> Tags: sync

The code follows the spec (core/sync/src/streams/pull.rs `apply`, SN_infer). A from-the-start listing read to its end is the source's live set (spec/sync-streams.md §3 Node log), so replacing presence on every whole listing (each member it covers) would close this; it changes a spec rule, so it waits for a decision. The requester's own store is never touched either way (NetStream SN_infer_lit, SN_infer_knew).
