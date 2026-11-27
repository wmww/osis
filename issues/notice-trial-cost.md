# Notices cost a receiver trial decapsulations, unasked and unbounded
> Summary: A Notice message is taken under any sync ID from any peer, and opening one tries every read epoch of every holder of the sync ID's things and of every thing on the node's own chains (once per thing), so a peer sending junk notices makes the receiver do unbounded KEM work.
> Priority: normal
> Tags: security, sync, engine

`Msg::Notice` is taken "whatever is shared" (core/sync/src/opens/mod.rs `push`; spec/wire.md §11.2 Notice). `Engine::take_notice` (core/engine/src/sync/notices.rs) calls `open_notice` once per thing of S and once more with none; each runs `notice_key_held` (core/engine/src/flows/inbox.rs), a decapsulation per held read epoch of each key holder of that thing and of each thing on `own_chains`, recomputed each time. The box names no holder (its AD does), so a junk notice costs the most. Nothing counts these against a budget.

Who controls it: any connected peer, with no credential, any number of times per connection.

Fix (proposed): name the holder and its epoch in the Notice message (the sender already judged the receiving peer proves the holder or reads through it, so it tells the receiver nothing new; the connection is encrypted), so one notice costs one decapsulation; take one only under a sync ID the receiver holds or follows (the two cases notices are sent in: a member being ended, a member opened by role), and at most once per (connection, notice content). A count test at n and 10n holders.
