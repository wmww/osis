# A logged entry holding a purged delta is never dropped by read
> Summary: read judges bodies per (S, commit) and drops own entries only when the body's verdict is must-not-hold or covered and dropped; a purge removes the purged part from the body (`sync_bodies` lists the rest, or a lasting header), so `read_facts` never says `Purged` and the entry whose blob still holds the purged delta stays logged and served.
> Priority: critical
> Tags: security, sync

- spec/sync-judgement.md §1: a delta the node dropped makes the blob holding it must-not-hold for it; §2 must-not-hold: purged. Must-not-hold is a property of a held blob (an entry), not only of the body S needs now.
- Seen in review of sync-integrate-1: own write on a thing with its own secrets, then a purge request naming it: `sync_bodies(c)[s]` becomes a header-only lasting body, `read_facts(s, c).must_not` is `None`, and `Live::own(s, c)` still lists the entry whose blob holds the purged part, so read's `body` neither drops it nor logs the rewrite.
- Direction: read judges each own entry of the commit against the body (an entry whose blob holds a part the node dropped or purged is must-not-hold: dropped, its rewrite logged as a fresh encryption of the remaining body, spec/sync-ids.md §1 Several blobs of one commit); the engine's `blob_parts(b)` against `Meta::dropped` gives it. `MustNot::Purged` then has no use as a body verdict and goes.
- Read is gated off (`read::live::READY`), so no node runs this yet; it must be settled before the gate opens.
