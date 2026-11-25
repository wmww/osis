# A stub at sync no node can log
> Summary: Sync differential `histories_hold_their_closure_plain` seed 188729745532: the model keeps a thing unread at an account holding sync on it only through a holder it does not read, by the stub its read unit carries (spec/sync-set.md §2 Stub; held-model `stubs_at_sync`); no node reading that unit holds the stub's parts, so none logs it (§2 Carriers) and the engine never enters the thing. The model's stubs have no carrier rule. Fails before the cards change too.
> Priority: normal
> Tags: sync, tests

Shrunk (`OSIS_SYNC_SHRINK=1`):
```
New(1), // thing 0
New(2), // thing 1
Strong(2, Some(1), 0),
New(1), // thing 2
Give(1, 2, Holder::Node(0), Syncs),
Give(1, 0, Holder::Thing(2), Syncs),
```
Nodes 0 and 2 act for account A0, node 1 for A1. A0 reads thing 1 (its dependent), whose strong reaches thing 0; A0 holds sync on thing 0 only through thing 2 (A0 sync on thing 2, thing 2 sync on thing 0). The model (`Rule::SPEC`, `stubs_at_sync`) has A0's unit carry thing 0's stub, so A0's nodes keep thing 0 unread. The stub (thing 2's edge piece on thing 0) is under A0's sync ID only as a node reading A0 that holds it logs it there (spec/sync-set.md §2 Carriers, spec/sync-judgement.md §1): A0's nodes hold nothing of thing 0 (thing 2 is no thing they read, so its key part brings them nothing, and holding for keys needs a read secret of thing 2); node 1 holds it but does not read A0. The grant was written by a writer of thing 2, so it fires nowhere; a fire at thing 2's inbox would be sealed to its read key anyway. The engine enters nothing, as the spec's carriage says.

Not the cards change: the seed fails the same at a40f1792c (before it).

To decide: either the model gets a carrier rule for stubs (as `bridged` is for dependents of other things: a stub of X under T only where a node reading T holds X's pieces otherwise), which breaks held-model's "by role" property in such worlds (a requirements-level promise: a strong in a read unit to a thing its thing holds sync on is held), or the spec gives A0's nodes a way to the piece (e.g. holders held for keys at sync, a sync-only holder's key part read by role entries).
