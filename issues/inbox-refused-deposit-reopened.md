# A refused deposit is opened again at every judge
> Summary: inbox `held::judge` opens a peer's deposit (`deposit_commit` → `Engine::open_entry`) each time it is judged; a sealed fire refused there (`ingest_sealed_fire`: applied invalid, or a part waiting) runs its whole ingest and rollback again every time, hundreds of times in one differential history.
> Priority: normal
> Tags: sync, engine

**Seen**: one 11-step differential history (3 nodes; node 1 holding a ticket fire it judges invalid) opened three refused sealed fires 142, 178 and 197 times, each a decrypt, decode and a rolled-back transaction. Bounded: the judge runs when its inputs move, but its inputs move with most engine changes, so the work grows with the node's activity times the refused deposits held, not with anything about the deposit: a peer leaving many refused fires makes every engine move here cost one ingest each (notes/principles.md, work in proportion to change). `deposit_commit`'s doc says a peer's deposit is opened once; a refused one is not.

**Direction**: the refusal is a function of the fire and the held set; keep the verdict (or the commit ID) of an opened deposit and judge again only when what the refusal read moves (the fire's thing's roles, its chain's records, the blobs its part waits for), as other verdicts do (notes/principles.md, Fast by construction).
