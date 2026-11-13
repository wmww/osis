# Ephemeral data: differences from durable still to remove
> Summary: Places where ephemeral data still differs from durable without following from "held in memory" (notes/ephemeral.md Principle): a delete's ephemeral state stays at other holders, presence at a peer that cannot read is relearned per connection, and an extra guard on deleting bodies outside the closure. Each has a plan below.
> Priority: normal
> Tags: ephemeral, engine, sync

## Delete
- Today (spec/sync.md §9 Sending, Delete; notes/ephemeral.md Deletion): `delete(T)` drops T's ephemeral state at the deleter only (`retention::memory::drop_things`); other holders keep it until they restart or it expires. Durable resets reach every holder.
- Decision: a delete leaves no ephemeral state of T at any holder, as its durable resets leave none (concurrent writes it did not see survive, as durable ones do).
- Why a reset commit alone does not do it: bodies are placed under labels whose closure holds their things now (`commit_bodies_under`), and the delete takes T out of every closure. The durable delete commit still reaches holders through its part on the group; an ephemeral reset commit has parts on T only, so it goes nowhere.
- Plan:
  1. Holders rule (memory reason: caps are per label, so state of a thing in no synced closure is under no cap; durable holders keep their copies. notes/ephemeral.md Holders already says holders keep the state "until they stop syncing the label"): a node drops a thing's ephemeral state, its own writes included, when the thing leaves every closure the node syncs. Judged only for things the node had inside a settled closure (the `State::memory_in_closure` guard: after a start the closure is what has arrived so far). Forgets locally without deleting at hosts (a new `MemoryDrop` kind; host entries go by the existing outside-closure deletes). A thing coming back into a closure is fetched again (the label reconciled). This also closes notes/ephemeral.md Open: a node that stops syncing a label or loses read access keeps that label's ephemeral state until restart.
  2. Where T stays in a closure the deleter could not take it out of, the delete's own durable commit carries it: a node applying a delete of T drops T's ephemeral state stamped before the delete, its own writes included (a later ephemeral write survives, as a durable one stamped after a reset does). One write stays one commit (Tess: a `Write` is never two commits); no ephemeral reset commit is written, and undo needs nothing ephemeral (what it dropped predates the delete). A delete therefore always writes its durable commit, even when T holds no durable content (its group removals give it one in practice; with none, the commit is the resets of T's ephemeral aspects' durable counterparts or an empty role part, whichever is simplest to build).
- Tests: after a delete, every holder reads no ephemeral state of T, its own writes included; a thing removed from its only group and added back reads its ephemeral state again from the holders and hosts that kept it; a restarted node's partial closure drops nothing.

## Presence at a host
- Today (spec/sync.md §9 Held at a peer that cannot read L, §10 Stream): a node relearns which memory entries such a peer holds on every connection, from each join's listing of its live ephemeral entries.
- Only a peer restart loses them; a reconnect to the same running peer does not.
- Plan: list them again only after the peer restarted.

## Unplaced bodies
- Today (`State::memory_in_closure`, spec/sync.md §9 As durable bodies): a node deletes a memory body outside the closure only if it judged or placed it inside since it started. Durable deletes once it holds the body and its view is settled.
- The stated reason (a restarted node's closure is what has arrived so far, deleting while a placement is on its way storms) holds for durable bodies too: closures are durable data. Either the guard belongs to both classes, or `settled` suffices for both. Effect today: a body only restarted nodes had placed stays at the host until the host restarts.
