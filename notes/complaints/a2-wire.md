# Complaints: a2-wire
> Summary: Workflow snags met wiring the evidence derivation to the engine's held set.

- A hand-delivered reader engine silently keeps nothing it cannot read: a body it holds no key for reads as "not held" (`body_valid` None), with no pending reason. The test had to grant the readers read on D first; a reason or a diagnostic would have saved a probe round.
- `LocalPeer::pass_end` is private, so a test delivering by hand has to call `settle_needs` and `reexamine` itself to let the node closure take in a record it was just handed.
- A delta writing into a map entry an earlier commit created reads as nothing alone (`Fragment::read`), so reading `sync.0` steps by `read()` finds none in a step-issuing commit; the first version of the adapter did, and only a hand test showed it.
