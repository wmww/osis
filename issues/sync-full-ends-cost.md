# Full ends cost a listing at every source
> Summary: Each stream sign that S's refused entries may be gone (spec/sync-streams.md §4 Full: a deletion of an entry not held here, a listing from the start not asked by a pull anew) ends full and pulls S from the start at every source, refetching every still-refused body; at a full S with churn or record-less peers that is a relisting per deletion or per connection, from every source, and an unproven peer drives it for all of them.
> Priority: normal
> Tags: sync

The node keeps no memory per refused entry, so any sign ends full for S as a whole and the pull anew must go to every source (a source whose place passed a refused entry would never show it again otherwise; ending full while pulling anew only at the source that showed the sign leaves full false with refused entries unfetched elsewhere).

Costs, k sources, n entries of S:
- Steady state of a cap that is simply too small: most new entries are refused, so most deletions name an entry not held, and each deletion seen outside a listing ends full: one listing of n from each of k sources plus the refused bodies again, per deletion (or per listing time, whichever is slower). Work is not in proportion to what changed.
- A record-less peer lists S whole at each connection: that listing ends full, then the pull anew lists S at that peer a second time and at the k-1 others once.
- Hostile: an unproven peer sharing S sends Deleted of made-up IDs or reconnects record-less: each costs every honest source a listing of S. The fill and flow control bound the rate (a trigger while S is not full does nothing, and S is full again only after a refusal), not the amplification factor k.

Direction (not small): attribute room refusals per source, like the `t` told-head rows (one per (source, S): "this place passed an entry refused for room"), set at every holder whose place settles the refused entry; a sign from source A drops only A's mark and pulls anew at A (a listing from the start at A needs no second listing: it re-shows A's set and re-marks); S is full while some mark stands, with room growth and expiry still ending it everywhere. Record-less marks live with the connection, which lists whole next time anyway. This bounds a peer's cost to its own stream but keeps the per-deletion relisting at that source; removing that needs per-entry refusal memory (rejected as unbounded) or a weaker full (a stated limit: full may outlive a refused entry deleted while a record source stays connected).
