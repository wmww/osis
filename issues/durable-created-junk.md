# Junk in a durable `/created`
> Summary: A durable commit's `/created` part is valid whoever wrote it (validity.rs `part`) and is checked only by its read (a record hashing to the tid), so any label member can add losing junk writes to any thing's `/created`, kept forever (retention `nobody`) and joined into its state; an honest `snapshot(t, "/created")` would copy it. The ephemeral check (`is_minted`) does not fit as is: two nodes persisting one ephemeral thing each carry a minting of it, so an honest state holds several.
> Tags: security, engine

- Shape: a writer delta or a compaction snapshot with `/created` = the record (winning) plus losing writes of anything; carried_records (apply/mod.rs) and note_created (apply/atomic.rs) read only the winner.
- Repetition by honest nodes: none automatic today (`/created` is never dropped, so `snapshot_first` never compacts it; `Engine::snapshot` carries one aspect and no `/created`, though spec/commits.md §2 says snapshots carry `/created` of what they cover). Cost is the forever-kept commit itself.
- Option: per commit, each `/created` part is exactly one write setting the record (any source; a snapshot's: a join of such writes, at most one per carried commit?), else bad input; refuse explicit snapshots of `/created` (never needed: kept forever).
