# A listing proves presence, not deletion
> Summary: issues/net-reconnect.md inferred "not listed means deleted" for any from-the-start reply. A reader's entries are not all at any peer, so this drops writes nobody deleted. The model finds it at first contact (core/test/tla/net, SN_infer_lit, SN_infer_knew). Rule: a listing never deletes.
> Priority: normal
> Tags: sync, node, proto, spec

A from-the-start reply (first contact, a join with no cursor, a cursor below the horizon) listed the peer's live entries, and the requester treated anything it held and did not see listed as deleted there. Between readers this is wrong: a node's own write that has not reached this peer is not listed, and neither is anything the peer never received. The model drops a write at first contact (`SN_infer_lit`, NoWriteLost). spec/sync.md §6's narrower form, "an entry the client knew present there", also fails: a peer restored from an older state lists less than the requester knew (`SN_infer_knew`).

It also breaks retention's principle: every drop that is not expiry or purge is a right holder's covering snapshot; an inference from absence is neither.

## Rule
A listing proves only what is present. A deletion reaches a node as a log event, within `TOMBSTONE_LIFETIME`; past that a stale entry stays and retention judges it (a covering snapshot, expiry, purge), and a re-listed stale entry is only bytes. "Holds no deleted entry after a long absence" is not a property any more; the model checks what replaces it (`CaughtUpHolds`, modulo entries deleted somewhere).

issues/net-reconnect.md states this. spec/sync.md §6's "was deleted there" goes with job 6.
