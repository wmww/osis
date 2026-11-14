# A registrar holding no write secret registers a step before the store holds its write rotation
> Summary: `Engine::step_needs` at a node that is no writer of S's thing leaves out the rotation of a newer write epoch (it holds no write epochs), so inbox's register sends the step to a store keeping S unread before that store holds the rotation; the store, on the new head, refuses the rotation's entry stamped under the parent (code 9) and takes it only as a reader's deposit.
> Priority: normal
> Tags: sync, inbox, engine

spec/sync-ids.md §6 Steps: a node registers each step "only once that source's stream showed it holding the role commits of the thing's actor the step's epochs depend on (the rotations of the epochs it registers and of those they supersede)". Seen in `keep::a_head_move_restamps_own_entries_and_readers_deposit_nothing_spec_sync_judgement_3` (node 0 rotates t's write secret boxed to itself alone; node 2, a reader, registers the step at node 1): node 2's `step_needs` of the new step lists an older rotation but not the write rotation, node 1 reaches the new head, refuses the write rotation's entry (stamped under the parent, as it must be, spec/sync-judgement.md §3 Own store) and node 2 deposits a fresh encryption of it.

Cost: one deposit per write rotation per store per head move registered by a non-writer; the store holds the rotation only deposited until a writer promotes it.

Fix shape (unchecked): `step_needs` reads the rotations behind each key the step registers from the role history every reader holds rather than from the epochs it holds; or a registrar that cannot name them leaves the step to a writer. Engine side: Fathom's.
