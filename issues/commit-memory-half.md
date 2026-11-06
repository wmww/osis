# A write that makes two commits, and writes refused for mixing
> Summary: For Tess. Four kinds of `Write::commit` (or revert) still make a durable commit plus a memory commit under one `ts`, which a peer may hold one without the other; seven mixes are refused (`Invalid`) though a user may not expect it. The wire has no commit of two storage classes. A rule at every receiver ("`group.0~` lists drafts only") removes two of the four without a wire change; `delete` and some reverts remain. What to decide, with a recommendation.
> Tags: engine, sync, spec, tess-call

## For Tess
**Still two commits** (durable, then memory, same `ts`; engine `Engine::write`, `revert_batch`):
1. `delete(t)` of a thing with ephemeral state: the durable resets, then its ephemeral aspects' resets and its `group.0~` entries.
2. Saving a draft that is an ephemeral member of groups (or any durable write on a durable thing still in a `group.0~`): the durable `group.0` adds, then the `group.0~` removals.
3. A durable `w.group(g).remove(m)` of a member also listed in `g`'s `group.0~`: the durable removal, then the `group.0~` one.
4. `revert`/`undo`/`redo` of a write that made two, and the undo of a save (the thing a draft again here: durable undo, then its ephemeral memberships restored).

**Refused though a user may not expect it** (`Invalid`/`Clash`, nothing applies; the app writes two commits itself): durable and ephemeral writes in one `Write` (a title and a cursor); plain and expiring ephemeral writes; a signal beside any other write; deltas wanting different expiries; saving a draft whose ephemeral membership expires (spec/data-model.md §8); a `delete` of a thing whose aspects or groups fall under different `required.0^` rules; an ephemeral delta larger than a blob.

**Why**: on the wire a commit has one storage class (below), and the two halves are stored differently: durable in logs and stores, memory only in memory. Effects today: with the durable half alone, a deleted thing's ephemeral values or a stale `group.0~` entry show until the memory half arrives or the holders restart (mild); with the memory half alone (the two are separate blobs), a saved draft is briefly in none of its groups at that peer (cases 2 and 4), until the durable half arrives.

**Decide**:
- (a) Cases 2 and 3: adopt the receiver rule "`group.0~` lists drafts only" (below). Then neither makes a memory commit. Needs a call on `MembershipNotSaved` (a saving node that may not write the group): the membership is lost (recommended: an ephemeral membership is already lossy), or the save is refused (one more surprising refusal).
- (b) Case 1: keep two commits, documented (recommended for now: nothing reads a deleted thing's ephemeral side after it left its groups), or a durable floor (below: one commit, a new core aspect).
- (c) Case 4: with (a), the undo of a save keeps the memberships durable (one commit; recommended), and only reverts of case 1 stay two.
- (d) The refusals: keep. Each is a write the wire cannot carry as one commit; splitting them quietly is what Tess ruled out.

Recommendation: (a) with the membership lost, (b) two commits, (c) memberships stay durable, (d) keep. Then the only split is `delete` of a thing with ephemeral state and its revert.

## Why the wire cannot carry it now
- spec/commits.md §2: an AK with `~` in a durable commit, or without `~` in an ephemeral one, is a bad part dropped alone; "a commit spanning several kinds is invalid". The marker is in the header (spec/wire.md §4), the class in the blob prefix (spec/sync.md §1, §3): one commit is one blob per label, held in logs and stores or in memory only (spec/sync.md §4, §9). Durable is commit form with retention and pages; ephemeral is session form, retention `writer`, no pages, records beside each part.
- One commit of both classes needs a class per part in the header, and either one blob whose durable entry holds the memory parts (hosts keep it in their logs: no longer ephemeral) or two blobs under one ID applied only together (a durable commit then waits on a memory blob a restarted host lost; letting it apply alone is today's split). Plus a durable commit whose memory parts are forgotten at restart while its header stays, and two `dot` forms in one header. No small version exists.

## Derived at every receiver
**"`group.0~` lists drafts only"** (cases 2, 3): an entry of a `group.0~` naming a thing whose `created.0` the node holds reads as nothing, and the node may forget it (a durable thing never becomes a draft, so it never reads again). The saving commit already carries the durable adds where the saver may write the group; a durable removal leaves nothing in `group.0~` to remove. Converges as the saving commit arrives (it goes under the group's labels: the thing is in the group's closure). Costs: spec/data-model.md §8 read rule and the "join of held parts" invariant for this one aspect; the membership index (`Indexes::eph_members`, `groups.0`, closures, spec/sync.md §3) filters by held records; the `MembershipNotSaved` call above; the undo of a save cannot restore ephemeral memberships (they would read as nothing), hence (c).

A stamp rule ("an entry reads as nothing where `group.0` has a later write on that member") was weighed and does not work for case 3: a set's tombstone keeps the dot and reset stamp, not the value (spec/crdt.md §5.5), so a node that got `group.0` as a snapshot after the removal cannot tell which member it removed.

**Not derivable: `delete`** (case 1). A delete is not on the wire: it is resets of every aspect the deleter holds and its group removals (notes/api.md Writes; spec/crdt.md §4.6 for undoing a creation), which a receiver cannot tell from "this commit clears these aspects". The ephemeral resets are per observed dot, which only the deleter knows. Ways to one commit:
- **Durable floor**: a new core durable aspect, say `ephemeral_floor.0` (a register of a `ts`), written by `delete` in its durable commit; every node reads the thing's ephemeral writes stamped at or below it as nothing and may forget them. Undoing the delete restores the floor in its one durable commit (values come back where still held). Costs: a core aspect and a cross-class read rule; a floor drops concurrent unseen ephemeral writes stamped earlier too (what a delete means anyway).
- **Refuse**: `delete` of a thing with ephemeral state is `Invalid` until the app removes that state in a commit of its own. Every app deleting a thing with a cursor writes two commits by hand, and one that does not know of `group.0~` cannot.

## Left
- spec/requirements.md (Atomic, line "A commit is never split") conflicts with the four cases, and its Limit lists only expiry and `nobody` mixes, not durable beside ephemeral or signal: left for Tess with this call (a requirements change).
- `core/osis/src/lib.rs` "One write, one commit" still says a `Write` is one commit, whole at every node; it needs this exception.
