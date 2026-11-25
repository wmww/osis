# A sync holder never learns a thing became public
> Summary: An account holding X at sync only (its nodes keep X unread) never learns the public was granted read on X: no node reading its account holds X's public piece to log there, and X's own entries are sealed under epochs it lacks. The designed rule (the store takes its head's open public entry box and reads X) is modelled; its build loops, because opens judge such a node by its proven sync role while it reads by the public.
> Priority: normal
> Tags: sync, engine

Repro: osis-sync `differential::repro_a_sync_holder_reads_a_thing_made_public` (node 1's account holds thing 0 at sync and strongs it; node 0 makes it public and writes; node 1 keeps it unread). The full-size differential's class "node N reads thing N unlike the reference, its value none where the reference's roster lists the public" (issues/differential-full-size-classes.md).

The redeemer's half (a node reading X by the public alone never heard its removal) is fixed: the lapsed read secrets (spec/sync-opens.md §4, §6; notes/public-and-cards-brief.md, Who hears).

**Design, modelled** (held-model `closure::public_epochs` `Heard`, the `store` clause; control: it off): a node keeping S unread whose head lists S's public entry takes the head's public entry box (open form: every party's, spec/sync-ids.md §3), as a public link's redeemer takes it from an answer; holding a read secret it syncs S read, takes the public's grant and its role follows. No fan-out: readers already register the step at every store.

**Build finding** (the reason it is not in): built as an engine call taking the head's box from the store's settle, the grant direction passes the repro, but after the public's removal the node loops:
- J at every source judges it a sync holder (its proven role) while it declares a reader; the pair churns (node 1 and its source exchanging ~80 KB per round, past the storm cap), so no complete pass of S ends;
- its lost-access drop of the public's read secrets is due but waits for that complete pass (`lost_passed`), so it stays reading with stale secrets;
- its store's head, frozen while it read (a reader refuses Registers), still lists the public when it goes back to unread: it takes the box again (guarded by skipping a head its recorded path has passed).
The open question is J: whether the public's grant counts in J (every party may hold S while the public reads it: J reader), and how a store keeps its head moving then (walk state exists only for store credentials or J sync holder, spec/sync-opens.md §4).

**Oracle**: the differential's reference counts the public's read everywhere (`closure::World::public`). Two further cases it reads that the spec does not give:
- a strong held, with nothing of X held by any node reading the unit, before X is made public (full-size seed 9): no node knows X's sync ID (sync IDs do not derive from tids), so nothing can tell it; redeeming a link is the way in. The reference needs carriers for public pieces, `(t, x)` counted only where a node reading `t` holds X (as `entry::Net::logged` does for bridges and stubs).
- carriage outlives its carrier: public pieces logged under T while a node held X stay required while a strong reaches X, so a node whose own role on X went keeps reading X by the public (seeds 128, 167, 198 under a least-fixpoint carrier rule). Carriers in the reference must accumulate over the history, not be recomputed at the end.

Seen on main in osis-sync `differential::histories_hold_their_closure_plain` (seed 65054997954: node 1 keeps thing 0 unread at sync, value none, where the reference's roster lists the public at read; tools/known_failures.txt).
