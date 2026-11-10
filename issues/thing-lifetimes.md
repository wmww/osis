# Thing lifetimes by reference
> Summary: Design: a thing may list its retainers (`retainers^.0`, admin-only); it lives while a listed retainer that is itself alive references it, up to a standalone thing; anything else is dropped for good, cycles included. Dropping is an ordinary end written by a node that may end the thing and judges it unreachable from what it holds; a node that cannot judge leaks, never deletes. One node-local reference index serves the judgment and backlinks. Rules, costs, the model and its result, questions for Tess, build steps.
> Priority: normal
> Tags: tess-call, data-model, api, permissions, sync, engine

**Blocked on Tess** (Questions 1-4). Nothing is built but the model. Not to be implemented before her go-ahead.

## Principle
A thing's lifetime is decided by whoever may end it. Listing retainers is their standing instruction to end the thing once none of them keeps it; a node carries the instruction out only with the right to end the thing and only on what it holds, so a node that cannot see enough leaks and never deletes. Nothing here is a validity rule: no write is valid or invalid because of a list or a reference.

## Words
- **Standalone**: a thing with no `retainers^.0`. Lives until ended explicitly or by expiry.
- **Referenced**: a thing with `retainers^.0`. **Retainer** of X: a thing X lists there (not the retained copy of spec/permissions.md §3, which a removed holder keeps).
- **Reference**: a tid (CBOR tag 1616) in a thing's data. One from a retainer counts for lifetime; every other reference is plain data and may dangle.
- **Dropped**: ended (spec/commits.md §5 Ending) because it was judged unreachable.

## Rules
### The list
- `retainers^.0` (Tess's name `retainers`; `^` is the admin-only marker, spec/data-model.md §2), core schema, `set<tid>`, ordinary retention (`admin`). Absent: standalone. Present: referenced, also when empty (an empty list is unreachable).
- Concurrent writes merge as any set; a removal of the aspect against a concurrent add resolves as any reset does. A list that does not read as `set<tid>` cannot be judged: the thing is kept.
- Admin-only is needed, not a preference: nodes end a thing on what its list says, so writing the list is as strong as ending the thing. A list any writer could write would let every writer of any thing, standalone ones included, have it ended for good.

### What a reference is
- R **references** X when X's tid occurs in R's **kept history** (issues/thing-history.md: the valid held writes live in R's state, and the replaced bodies still in history), in a durable aspect other than `created.0`, the role-class aspects and `retainers^.0`. So `group.0` counts (a thing may live by its group), and a durable signal's fire counts while it is in history (a chat message keeps its attachment). (Question 2: current values only is the alternative.)
- Not references: a value-less write (expired, purged); an invalid write; ephemeral data (it may be lost by accident, and a drop is final); a tid inside a chunked set element or map key (links are not followed); a tid spelled in text (`osis://...` in a string). The excluded aspects say who has authority over R and what R hangs on, not what R points to.
- Found without a schema: any tag-1616 value at any depth of the inline canonical value, map keys, set elements and unknown tags' content included.

### The judgment
Judged from what the node holds, per thing, as one of three:
- A thing is **known** when the node holds a live `created.0` of it and may read it. It is **ended** when the node holds what shows it ended (spec/commits.md §5). Anything else is **unknown**: never held, not readable (access lost, a retained copy), or ended with nothing kept.
- **Kept**: the least set holding every known standalone thing, and every known thing X with a listed retainer R that is unknown, or is kept and references X.
- **Unreachable**: known and not kept. So: its last referencing retainer stopped referencing it, every listed retainer ended, or it sits on a cycle no standalone thing reaches.
- An unknown retainer keeps: the index holds no rows of a thing the node cannot read, and that absence is never read as "does not reference". Losing access to a retainer, a member's removal and a forgotten thing all make it unknown.
- So that an ended retainer is known ended: a held thing listing an ended thing is a dependent of it (spec/commits.md §5 Ending): the node keeps the ended thing's record and value-less creation while it holds such a thing. Nothing travels for it.
- Nodes holding the same data and trust sets judge alike. A node holding fewer things judges unreachable only what a node holding more would (model).

### The drop
- A node that holds X, holds the right to end it (the purge right over every `created.0` delta of X it holds, spec/permissions.md §6: its admins by default, or what the creation's purgeable-by says), and judges X unreachable, ends it: an ordinary end, authored by the node's account, one commit naming every thing it drops in that run.
- **When**: once it has heard out (spec/permissions.md §2, `SyncEngine::heard`) every label it tracks whose closure holds X or a retainer the judgment read; a thing under no label is judged at once. A commit's parts apply together, but commits arrive in any order: without this a node that receives "R1 no longer references X" before the earlier "R2 references X" drops a live thing (model). Offline, nothing is dropped; it stays until the node is heard out.
- The end is valid like any purge request. Receivers do not check that X was unreachable: they cannot.
- **Final**: an ended thing stays ended. A reference or list written without knowing of the end, before or after it, dangles and reads as gone; a write to X is a write to an ended thing. Two nodes may each write the end; duplicates are harmless.
- **Cascade**: what X kept alive is judged when X is judged unreachable, whether or not this node may end X, and dropped the same way by whoever may end it.
- A node without the right over an unreachable thing remembers it (`pending`) and ends it if it gains the right. A node that never holds enough leaks it.
- No other node deletes anything: readers, plain writers and nodes that cannot read the data act only on the end when it arrives.

### Disputes, validity
- Lists and references are read under the node's trust set, like every value. A drop written on one side of a dispute over a retainer is an ordinary end of X and stands on both sides if X itself is not disputed. Limit, stated: a dispute over a retainer can drop what only the other side reads as referenced.
- A reference whose write turns invalid (its author demoted with a frontier that omits it) stops counting; a drop it caused stands when the write counts again.

## Index and backlinks
- One local, rebuildable index of references in held readable data: rows `(target, source thing, AK)` with a count, per class: live durable, live ephemeral, history. `retainers^.0` values are indexed like any value, which gives "who lists X" (they are not references for lifetime).
- Kept in the transaction that changes the state or the history: apply, un-merge, expiry, purge, a body leaving history, ending, forgetting. A row never outlives the data it came from (spec/commits.md §5 Dropping a body).
- **Backlinks** read the live classes: `db.backlinks(tid)`: the things, with the aspect, whose current values reference the tid, as the acting actor may read them; paged, and live through the same listener rules as `on_change` (initial delivery, then each change, local ones included, after the commit is durable). Shape per the queries pass (notes/api.md Queries); a reference is found only in data this node holds and may read, in history never, and a group listing the thing is a backlink like any other (the direct group index is this index filtered to `group.0`).

## API (notes/api-design.md)
No new call, error or type for lifetimes: the list is an aspect.
- `osis::RETAINERS`, a typed key of `set<tid>`. Create referenced, in one commit: `let x = w.create()?; w.at(x, RETAINERS).set(&[r])?; w.group(r).add(x)?` (or any write putting `x` in `r`). Add: insert. Move: insert the new, remove the old, and change both references, in one `Write`. Make standalone: `w.at(x, RETAINERS).remove()`. Drop now: `w.end(x)`.
- `Permission { needs: Admin }` as for any admin-only aspect.
- `Invalid` at commit when a write's own change of a thing's `retainers^.0` leaves it unreachable as this node judges it (created with a list and no reference, moved under a thing that does not reference it): caught before it silently vanishes. Not judged when a listed retainer is unknown.
- A dropped thing reads as any ended thing: absent. No call reads "alive".
- One commit per structural change is what makes part-received data safe; the API gives no way to write a move as two commits by accident beyond writing two `Write`s.

## Interactions
- **History** (issues/thing-history.md): a removed reference counts while its body is in the retainer's history, so undo within the window finds the thing, and what leaves history releases what it referenced. With no history set, a removal releases at once. Dropping X ends X's own history with it.
- **`delete(R)`** resets R's content and memberships: R references nothing live, so what it kept is released as its history leaves. **`delete(X)`** removes X's memberships, so a thing living by its group is dropped once that leaves the group's history.
- **Purge** of the write holding a reference releases at once ("delete for everyone" on a message drops its attachment).
- **Expiry**: an expiring write's reference counts until T. A thing referenced by an expiring thing should be created in the same expiring commit: then every node drops both at T with nobody online. Otherwise it waits for a node that may end it and held the retainer when it expired. Limit: a thing that reaches such a node only after its expired retainer left nothing behind is unknown-referred there and leaks.
- **Ending**: `end(R)` on a standalone root drops everything only it kept. Things whose first admin is a dropped thing live on as today (authority is not lifetime).
- **Removal, lost access**: never a reason to drop (unknown keeps). A removed member's node forgets what it lost; the others judge as before.
- **Hosts and nodes that cannot read**: do nothing; the end deletes blobs as any ending does.
- **Sync**: a reference syncs nothing. A node that holds R but not X sees a dangling tid; one that holds X but not R keeps X.

## Cost
- Index per write: O(tids that entered or left the state), read from what apply already changes; a reset of a collection costs the tids under it, once (paid for by their insertion). A rebuild (validity flip, purge) costs what the rebuild costs today plus the aspect's tids.
- Judgment: a search up the lists through referencing retainers, stopping at the first standalone or unknown thing. A single-retainer thing whose reference goes is judged in O(1). A thing with another referencing retainer costs the walk up that chain: O(depth). A failed search visits only unreachable things, each of which is then dropped or pending. No cache of liveness: the only kept state is the work list (things a change touched, judged when heard out) and `pending`.
  - Limit: on a thing with several referencing retainers at the bottom of a deep chain, each change of its support costs the chain's depth. If a measured budget is missed: a support forest with a dynamic-tree ancestor test, O(log n).
- A change queues: the things whose references from the written thing changed; the thing whose list changed; the listers of a thing that ended, became known or unknown; the pending things of a gained right. Model: one unreference under a root of n children judges 2 things at n = 10 and n = 100.
- Dropping n things: one end commit with n `purge.0` parts, and per thing what any ending by purge leaves for good (notes/growth.md row 5, about 450 B). Short-lived things should expire instead: an expiry leaves nothing.
- Growth rows to add: the index (per live or in-history reference, about 50-70 B, local, rebuildable); the work list and `pending` (per unreachable thing not yet ended here); an ended retainer's record kept while a held thing lists it.

## Problems, stated
1. **A writer who is not an admin cannot create a referenced thing** under a shared first admin (`create_with_admin`): the list needs admin. Same for `retention^.0` (issues/thing-history.md): per-thing settings are an admin's. Question 3.
2. **Partial views leak** (by choice): a thing readable where its retainers are not is never judged there. Requiring one sharing context would need a validity rule across things that role changes break anyway. The API path that avoids it is the usage rule already in spec/requirements.md Generality (share a set through one actor): create the thing under the retainer's actor.
3. **Offline nodes drop nothing**, so an unreferenced thing is still found by a search there until the node syncs. An app that means "delete this now" calls `end`.
4. **Disputes** can drop across sides (Rules, Disputes).
5. Rejected: a delete right for writers of a listed retainer (Question 1); the list writable by writers (above); the creating commit writing the list without admin (any writer can write a commit carrying a copy of `created.0`, so it equals a writer-writable list); the list writable by "whoever may end" judged per held creation delta (held copies of a creation can differ in purgeable-by, so validity would depend on which copies a node holds); a liveness cache per thing (state to keep right under every arrival order for a cost only deep multi-retainer chains pay); deriving cascades locally without ends (a node without the right deletes only at expiry); treating a not-held retainer as dead (wrong deletes at every partial holder).

## Model
`core/test/held-model/src/lifetimes.rs`, `tests/it/spec_lifetimes.rs` (9 tests, pass, 1 s):
- over every view of 3 things (unknown, ended, or known with any list and references, itself included): the walk up judges exactly as the least-fixpoint rule; with everything held, kept is what a walk down from the standalone things reaches;
- making any thing unknown never adds a drop (a node missing things, or losing access, drops only what the whole view drops);
- cycles drop unless a standalone thing reaches them, two concurrent rewrites closing one included; self-listing and an empty list drop; an ended retainer drops, an unknown one keeps;
- a move written as one commit is safe in every subset of commits a node may hold; as two commits, the removal held without the earlier addition drops a live thing (why a node hears out first);
- an end held is final against any later list or reference;
- 4000 random runs of 14 changes over 5 things (lists, references, ends, lost and learned things, rights gained and lost): judging only what each change touches ends exactly what a from-scratch judgment says the node may end, and `pending` is exactly the rest (two seeded mutations of the propagation fail it);
- cost: counted at n and 10n.

Not modelled: what a reference reads (history windows, validity), hearing out, the end's own validity and spread (ordinary purge rules), disputes.

## Requirements wording (Tess's sign-off)
Data model, after "References may dangle":
> A thing may name the things whose references keep it alive. Once none of them, alive itself, references it, it is dropped for good, with whatever only it kept alive, cycles included. Limit: it is dropped only by a node that may end it and holds what shows it is unreferenced; until then, and where no such node exists, it stays. Limit: a drop decided without a reference written concurrently, or not yet received, stands.

## Questions for Tess
1. **Who may write the drop.** Recommended, and the default: no new right; the nodes that may already end the thing (its admins, or whoever its creation's purgeable-by names, `writer` included) do it. The outline's alternative, a delete right for writers of a listed retainer: an end of X would be judged by R's roles, so a node holding X without R could not judge it and R's role history would have to travel under X's labels; those writers hold no delete keys for X at hosts; and it is a grant outside roles. Its gain is small: where one actor shares R and X, `writer` on the creation gives the same people the right.
2. **Does a reference in kept history count?** Recommended, default: yes. A thing lives as long as undo or the retainer's history could show the reference; with no history set, as today's outline (current value only). It is what lets a chat message (a signal: no current value) keep an attachment, and what keeps undo of "remove the image" from restoring a dead link. Cost: history rows in the index, and drops that happen when a window passes. Alternative: current values only; undo then restores a dangling reference, signals keep nothing alive.
3. **Writers creating referenced things in a shared space.** Default: accept; only admins of a thing set its list (and its history setting). Alternative if members who only write must create them: an initial list in the creation record (fixed at creation, needs no authority, cannot be turned on an existing thing), which `retainers^.0` overrides; cost: a record format change and two places to read.
4. **Requirements wording** above, and that partial views leak rather than requiring one sharing context.

## Steps
Each one worker and one reviewer, in order. Steps 1-2 are useful alone (backlinks) and wait on nothing; 5 needs issues/thing-history.md steps 3 and 5.
1. **Reference index** (engine). Rows and counts for live durable and ephemeral values, kept on apply, un-merge, rebuild, expiry, purge, ending, forgetting. Tests (through `internals`, then step 2's API): rows follow the value in any arrival order; a validity flip, an expiry and a purge remove them; lost access leaves none; a path write into a map of n and 10n entries changes O(written tids) rows and reads no other entry; notes/growth.md row.
2. **Backlinks API.** `db.backlinks` and its listener per notes/api-design.md and the queries shape; CLI `backlinks`. Tests: a note linking a note shows and stops showing, locally and after sync; only what the acting actor may read; ephemeral references show; paged at n and 10n.
3. **List and judgment** (engine, no writes). `retainers^.0` in the core schema; known/ended/unknown; the walk; the work list and `pending`; the ended-retainer dependent clause. Tests: lockstep with held-model `unreachable` and `Node` over generated worlds and changes; losing access to a retainer never yields unreachable; judged counts at n and 10n.
4. **The drop** (node-sync, osis). Trigger when heard out; batched ends; gained rights; `RETAINERS`, the commit-time `Invalid`; spec (data-model §9 and a lifetimes section, commits §5 Ending), notes/api.md. Tests (observable, several nodes): unreferencing drops at every node; a one-commit move keeps; a subtree and a cycle drop; a node without the right keeps it until an admin's node syncs; a node missing a retainer, and a removed member's node, drop nothing; a two-commit move part-received drops nothing before the pass ends; a concurrent re-reference dangles; an expired retainer.
5. **References in history** (Question 2). History rows by body, released as bodies leave; signals. Tests: undo inside the window finds the thing, outside it does not; purging a message drops its attachment; a window passing costs the references that leave.
6. **Notes and bookkeeping.** notes/lifetimes.md (principle, rules, limits), notes/growth.md, notes/api.md, requirements wording as signed off; kit, app and chat adoption is app-layer work.
