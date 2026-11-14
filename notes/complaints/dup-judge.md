# dup-judge
> Summary: workflow snags met on the dup-judge branch.

- `LocalPeer::deliver` takes the engine's redeliver set itself (`Peer::wake`), so a facade test checking what `take_redeliver` names must ingest and `reexamine` by hand.
- The sync world harness has no way to place a hostile peer's forged entry in a store, so the store-level forgery scenario has no world test; the rule is tested at the engine rows and the pure judgement.
