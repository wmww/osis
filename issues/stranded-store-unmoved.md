# A store registered a step past its keys is never moved on
> Summary: a node keeping S unread whose head is a step its held sync secrets do not derive (stranded) takes nothing, so it never shows the role commits a reader waits for before registering the next step: it stays at that head for good. Seen as a sync holder granted after the thing's epochs moved on, registered only the genesis step.
> Priority: normal
> Tags: sync

Repro: osis-sync `differential::repro_a_store_granted_past_genesis_is_moved` (thing 0 public, its epochs moved on, then node 1's account given sync: node 1 holds only the newest sync epoch, is registered the genesis step, and waits there; it never reaches the step listing the public and keeps thing 0 unread).

The two rules meet head on:
- spec/sync-ids.md §6 Steps: a reader registers each recorded step after the source's step "only once that source's stream showed it holding the role commits of S's actor the step's epochs depend on" (at once only toward a departed peer).
- spec/sync-judgement.md §6 Stops: a store whose head's sync key no held secret derives takes nothing while its head stays there; it shows the sync keys of its secrets no step of its path bears, "so a reader holding one registers its path onward".

A stranded store can hold no role commit, so the first rule never lets the second happen. The departed carve-out already registers at once; the same holds for any stranded store (it holds nothing for the step to depend on). A reader opened at such a store by a sync key deeper than its head knows it is stranded there. Without the public, the same history leaves node 1's store with no head at all (nothing registered), which the differential does not flag: check whether such a store syncs anything.
