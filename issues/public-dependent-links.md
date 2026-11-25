# A public link to a dependent thing never redeems
> Summary: Redeeming a public link to a dependent D of a public thing X stays pending for good: the followed link names D with X's sync ID, which D owns no `sync.0` of, so the sync set never reads it. Once it redeems, the redeemer reads D with nothing of X held: it needs X's sync ID for the public's piece (X's role entries, opened by the public entry) to follow X's rotations and the public's removal.
> Priority: normal
> Tags: sync, engine

Seen: osis-sync script `New(0), NewIn(0, 0), Give(0, 0, Holder::Public, Reads), Run, Redeem(1, 1), Run` leaves the redeem `Pending` (node 1 reads nothing of thing 1; the reference agrees only because no strong was written). `Engine::thing_sync_now` reads a followed link's sync ID only where the followed thing owns it (`owned_sync_ids(t)`), and a dependent owns none.

Once fixed, the redeemer's account carries D by the public's grant on X (spec/sync-set.md §2 T's keys open) but holds X only as public pieces under its account, logged by nobody else (Carriers): no reader of the account holds X's rotations or the removal. The rule the lapsed read secrets give a reader of X (spec/sync-opens.md §6) would serve such a node too if it synced X's sync ID for role entries while it reads a dependent of X by the public (as a holder held for keys syncs a holder's); model it with held-model `closure::public_epochs` (`to_dep`, `Heard`).
