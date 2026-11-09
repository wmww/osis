# Unbounded writes leave no per-write data
> Summary: Decided (Tess): a writer's own snapshot stands in for its older commits, and nodes forget those commits outright, so writes without kept history pile up nothing. Accepted cost: a removal racing a writer's snapshot can lose what that snapshot carried. Queue after account signing step 6 and expiry step 6.
> Priority: normal
> Tags: engine, perm, spec

## Rule
- A removal lists what came after the removed writer's newest snapshot and names that snapshot. A node forgets a commit, ID included, once the author's own snapshot covers it and no write of it is live; the kinds that stay are as today (role, creation, lasting, purge-carrying).
- Commits covered only by another writer's snapshot keep a receipt (ID, author, actor, thing, aspect, receive time; about 50 B).
- Clients compact their own writes automatically. Own means same author: an account's devices are one author, since a reader cannot tell them apart.

## First target (Tess)
One small aspect on one thing, replaced whole each time, no membership changes: stored bytes do not grow with the number of writes. Test first: bytes at n and 10n writes, flat. A whole replace covers the writer's earlier writes by itself, so check it needs no separate compaction step. Wider cases (many writers, uncooperative writers, combinations) may carry justified wrinkles.

## Accepted (Tess)
Permission changes over inconsistent connections cannot all work out; this is one more minor concession, like dropping a removed node's commits it synced to nobody.
- A snapshot that reaches a node before the removal naming none of it, and counts for nothing after: the writes only it carried are gone (`roles-model` `forget.rs`, late snapshot).
- A snapshot standing only on an addendum that later falls.
- At account level, a hostile device's snapshot can claim a sibling's edit without its value.

## To check when building
- Bound the loss: keep the writer's previous snapshot until the next one lands, so a late snapshot falls back to it and costs at most one compaction interval. Not modelled yet: add it to `forget.rs` first.
- A snapshot rewrites the whole field, so a very large field needs a snapshot that links existing pages (none allowed today).
- `Receipt` is rewritten on every insert (O(n) per write): make it append segments.
- spec/requirements.md states the visible guarantee and the best-effort goals, in user terms, never naming snapshots; wording goes to Tess.
- Spec: spec/commits.md §5 ("never headers"), spec/permissions.md lists; notes/growth.md rows 1, 3.
- The model is on branch `zero-growth`.
