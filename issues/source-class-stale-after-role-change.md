# A source's class is frozen at its open: wrong between stores, stale after this node's role changes
> Summary: a member's class (store or reader) is fixed by the credential that opened it, so two stores class each other Reader, and a node going from keeping S unread to reading S (or back) keeps the old class past reconnects and restarts: it never deposits, deletes or logs again at a store, and its peers treat it as a store.
> Priority: normal
> Tags: sync, opens, read

Repro (World, `history::world(0, 3)`): `New(0)`, `Grant(0,0,1,Syncs)`, `Grant(0,0,2,Syncs)`, `Run` x3, then `Grant(0,0,2,Reads)`, `Run`. `w.status(i)[s].sources[..].src.class`:
- while 1 and 2 both keep S unread, each classes the other Reader;
- after node 2 reads S, node 2 still classes store node 1 Reader, and node 0 still classes node 2 Store;
- unchanged after `Cut(1,2)` and after restarting node 2 (the record keeps the member with its class).

Causes:
- `opens::cred::source_class`: a sync proof tested here (this side keeps S unread, the peer showed a sync proof) gives Reader, yet a store shows one too. Which side's Hit opens S decides the class: arrival-order dependence.
- spec/sync-opens.md §6 re-judges a member at each change of what this node holds, but only to end it. A member that stays (J reader or sync holder, or its credential still admissible) keeps its class. `Known::kept` (KEPT row) is written only at a join, from that class.

Effects: `read` (`views`, `kept_at`) owes a store judged Reader nothing (no deposit, Delete or logging again); `inbox` targets, `register` and `status::readers` read the same class.

Fix direction (decide in opens, spec/sync-opens.md §4/§6): the class says whether the peer keeps S unread now, judged on what this node holds now. Where J decides it (sync holder: store; reader: reader) the class follows J at every re-judge. Otherwise it follows a credential only one class can use. A class moving at a re-judge closes and re-tests the member (or rejoins it so `Op::Kept` is written), on both sides. Test: the repro above, plus a deposit reaching node 1 from node 2 after the role change.
