# Unbounded writes leave no per-write data
> Summary: First target built: a writer's own whole replaces cover its older commits and nodes forget them (spec/commits.md §5 Own replaces, Forgetting; `growth::single_writer_replace_grows_nothing`, flat with writes and with idle time). Left: receipts for commits covered by another writer, forgetting compaction snapshots, keep-previous for snapshot chains, automatic client compaction.
> Priority: normal
> Tags: engine, perm, spec

## Rule
- A removal lists what came after the removed writer's newest snapshot and names that snapshot. A node forgets a commit, ID included, once the author's own cover (snapshot or whole replaces) covers it and no write of it is live; role, creation, lasting, purge-carrying and snapshot commits stay.
- Commits covered only by another writer's snapshot keep a receipt (ID, author, actor, thing, aspect, receive time; about 50 B).
- Clients compact their own writes automatically. Own means same author: an account's devices are one author, since a reader cannot tell them apart.

## Built
One small aspect, whole replaces, no membership change: stored bytes do not grow with the writes (node, reader, host; test in core/node/tests/it/growth.rs). A plain whole replace is its own cover, no compaction step: any later own whole replace held valid here covers (`Indexes::own_replaces` by thing, aspect, author; a function of what is held), once two such exist; a commit with several parts goes only whole (a reader cannot rewrite its blob to relay the rest); forgetting runs on events (`State::forget_due`), not scans (spec/commits.md §5 Own replaces). Work per write is flat at n and 10n with three writers (`growth::own_cover_work_per_write_is_flat`). The writer's previous replace stays until the next lands; `roles-model` `forget.rs` (`OWN_PREV`, `previous_snapshot_bounds_the_loss`, search `forget-prev`) confirms a cover that reached a node before the removal's `ts` keeps what it carries; two late covers in a row lose what only they carried.

## Left
- Receipts for commits another writer's cover covers (rule above, about 50 B); commits covered only by another writer stay whole.
- Forgetting compaction snapshots, and the keep-previous rule for snapshot chains (an own snapshot still drops under the next at once).
- Clients compact their own writes automatically: nothing runs compaction for non-replace writes.
- A commit with a part no own replace covers (a second aspect, a path write) stays whole for good, and is judged again on each later write of its covered aspects (`left.wait`): work per write grows with such commits held.
- A reader keeps bodies a snapshot covers: it lacks the purge right (spec/commits.md §5 Principle says it drops them; only own replaces do today).

## Accepted (Tess)
Permission changes over inconsistent connections cannot all work out; this is one more minor concession, like dropping a removed node's commits it synced to nobody.
- A snapshot that reaches a node before the removal naming none of it, and counts for nothing after: the writes only it carried are gone (`roles-model` `forget.rs`, late snapshot).
- A snapshot standing only on an addendum that later falls.
- A `required^.0` rule that invalidates both covers after a commit was forgotten: the honest write is lost, the writer still authorised. Existing snapshots already have this weakness; not built around (needs Tess only if the requirement should be stronger).
- At account level, a hostile device's snapshot can claim a sibling's edit without its value.

## To check when building
- A snapshot rewrites the whole field, so a very large field needs a snapshot that links existing pages (none allowed today).
- spec/requirements.md states the visible guarantee and the best-effort goals, in user terms, never naming snapshots; wording goes to Tess.
- The model: `roles-model` `forget.rs`, `forget_account.rs`.
