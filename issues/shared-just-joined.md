# "No peer shares S" is wrong for a sync ID just joined
> Summary: leave/unsync, self-removal and life (heard out or alone) act at once when `Opens::shared(S)` is false (no connection has S open, no kept record holds S); a sync ID that joined the sync set since this node last met S's other holders is in no record yet, so those duties act as if alone. Proposed one rule: who to wait for = the peers the rosters say may hold S, each counted until its record acknowledged S's current credentials with S not a member, or its record goes.
> Priority: normal
> Tags: sync

`wait_synced` judges by the rosters (`Engine::others_hold`, spec/sync-status.md §3) for this reason. The duties without a caller's timeout still read `Opens::shared` (core/sync/src/leave.rs `judge`, status `removal_done` via `Ground::shared`, `Status::heard_out_or_alone` for life and read's forget).

## The window and its harm
S joins (an accept, a redeem, a thing moved into a synced group) while every other holder is away or not yet met. Until a connection agrees on S, no record holds S.
- Leave: accept, write, unsync, all before any connection: the pass is vacuous (no source, no record), so the copy goes with its own writes sent nowhere. Loss, but only of writes whose thing's content travels under S alone (a thing whose key home this node still syncs carries its parts there too, and nothing is lost: probed with a thing granted out and moved between per-node synced groups).
- Self-removal: accept then leave before any connection: `removal_done` at once, then S is lost and shredded; the removal reaches no other account, which keeps this account as a holder (and keeps boxing new epochs to it). No data loss; a silent leave.
- Life (heard out or alone): a release judged with nothing under S heard; needs a stale copy of a retainer held from elsewhere, so hard to reach, but a wrong release spreads to every node. Forgetting a destroyed thing's S early only leaks entries at peers.

## Proposed rule (one value, two bounds)
- Who may hold S: the rosters (J of a peer's actors, `Engine::judge_peer`; own nodes syncing S's thing; the granters of S kept unread). Same as `others_hold`, per peer.
- A duty waits for such a peer while it has S open, or its kept record holds S, or its kept record has not acknowledged S's current credentials (`acked_pos < changed_at(S)`: not yet told S). It stops counting once its record acknowledged with S not a member (it does not hold S: a grantee who never accepts blocks nothing), or its record is evicted (`RECORD_BUDGET`). A holder never met (no record) is not waited for: no known peer could take it. Single-device accounts: no roster holder, act at once.
- `wait_synced` counts every roster holder, record or not (the caller's timeout bounds it): a redeemer's first contact has no record before its dial completes.
- Cost: needs records indexed by `acked_pos` (records unacked for S by range) and `peers` stamps written for the sync IDs whose `changed_at` an ack passes (what the next filter additions iterate anyway). Opens work, not contained in a review.
