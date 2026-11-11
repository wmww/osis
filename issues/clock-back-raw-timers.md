# A clock gone back stalls what counts in wall ms
> Summary: after the wall clock jumps back by D, session pings and stall checks (`next_ping`, `c.timer`), `settle_at`, the peer wait and `Refused` back-offs wait up to D more.
> Priority: low
> Tags: node-sync, proto

A quiet label's own bound is kept (notes/node-sync-work-sets.md Idle labels). A session whose ping waits for the clock also learns no new clock sample and finds no dead connection until then.

Fix if it matters: compare each deadline against now plus its longest wait (a deadline further off than that: the clock went back), as `Work::resync_due` does. D is rare and small on a synced machine; the cost is a stale node for D.
