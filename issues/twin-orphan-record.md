# A crash inside a Twin step leaves an orphan record that holds waits
> Summary: `Opens::dropped` (the loser of a Twin exchange) is in memory until the step's `flush`, so a crash inside that step leaves the loser's record in the store: never resumed (the peer dropped its copy), its members make `wait_for` wait on that peer until `RECORD_BUDGET` evicts it. Accepted today as rare, which is a carve-out by rarity: fix it by rule.
> Priority: normal
> Tags: sync, opens

What a user sees: after a crash at the wrong moment, a leave, a self-removal's drop or a timed loss on S waits on that peer far longer than the rule says (until the record is evicted by budget, which an idle node may never reach). notes/principles.md, How often is not whether: the rate of the crash says nothing about whether this may stay wrong.

Where: core/sync/src/opens/mod.rs `settle_pair`, `flush`; notes/sync-opens.md One connection per pair.

Directions (none chosen):
- Make the drop durable with whatever else the Twin step writes, so a crash keeps both or neither (a crash before it re-runs the Twin exchange at the next crossed connection, which already finds twins).
- Or judge a kept record no peer resume can name any more as gone at start (needs a fact that tells it; the peer's Resume list does not include it, but absence from one Resume says nothing in general).

Test: a crash (`DiskFault::Crash`) at each durable write of a Twin step, then a leave of S: S stops after the pass in flight, as with no Twin.
