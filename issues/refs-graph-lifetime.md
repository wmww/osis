# One reference graph for sync, storage and lifetime
> Summary: Tess's speculative design, to iterate on before building: every reference is strong or weak (a flag in the data); a thing with a sync ID syncs everything its current state reaches by strong references (any aspect, not only `group.0`); each node keeps exactly what its root group reaches the same way, so release is unsync and is local. Removes retainers, release requests and default filing. Her order: finish sync, cleanup, iterate this design, then build.
> Priority: normal
> Tags: engine, sync, data-model, tess-call

Only the Decided section is decided. The rest records her design, what it implies under today's permissions and sync specs, and the questions it leaves. Storage side: issues/storage-follows-groups.md.

## Decided (Tess)
- **No default strength.** Every reference states strong or weak: in the encoding (two tags, no bare tid as a value), in the API (no `Tid` into a value) and in schemas. `group.0` entries carry the flag like any field.
- **Words.** A **tid** is a thing's ID and is never a value. A **strong** and a **weak** are the two kinds of reference; each holds a tid and is built from one. **Ref** (reference) means either kind. Schema types: `strong`, `weak`, and `ref` (either, the writer picks per value); the type `tid` goes.
- **Rust.** `Strong`, `Weak`, and `Ref` (the enum of both). `Tid` converts into `Strong` and into `Weak` with `.into()` (so a write to a typed field takes a tid and the schema's strength; a `ref` field makes the writer choose), and each converts back. A read that returns a reference can also return its `Tid` (generic on the return type).
- **Schemas bind the local writer only**, as all types do (spec/versioning.md §5): a peer may write either strength anywhere it may write, and every node syncs and holds by the flag in the data, never by a schema.
- **A strong and a weak to one tid are different values.** A set may hold both, a map may have both as keys; the target is held when any strong to it is in current state. No rule bars strong map keys: schemas type keys.
- **A strong keeps its target whatever the size of the value holding it** (issues/refs-in-chunked-elements.md).
- **`osis://` links in text** become weak references: issues/text-links-as-references.md (independent of this work).

## Terms
Defined, changed or removed by this design; used only in these meanings below.
- **Reference** (ref): a strong or a weak inside a thing's current durable value. Whether `created.0` and the role-class aspects stay outside the index, as today (notes/engine-refs.md), is open question 12.
- **Strong reference** (new): a reference flagged strong in the data. Makes its target part of the referrer's sync closure and keeps it alive at nodes that reach the referrer.
- **Weak reference** (new): a reference flagged weak. Points only: syncs nothing, keeps nothing alive. A target the node does not hold is an error at read.
- **Current state**: a thing's valid held writes that carry values (no history, no value-less, invalid, ephemeral or signal writes). Unchanged from what lifetimes and garbage collection read today.
- **Sync closure** (changed; today "closure" of a group, spec/sync-set.md §2): of a thing with a sync ID, everything reachable from it through strong references in current state, plus key homes as today (open question 4). Clashes with today's closure, which follows `group.0` subgroups and items only.
- **Root group** (new): the one group per node that its holding is computed from. Itself held unconditionally; the only thing nothing references.
- **Node group** (new): a node's root group. A thing reached from it only through things without sync IDs is **local** to the node.
- **Account group** (new): a group every node of the account reaches strongly from its node group. A thing reached from it is **synced** to all the account's nodes. Replaces the synced group G_N and `synced^.0` (spec/sync-set.md §1), see open question 2.
- **Held set** (new): what a node's root group reaches by strong references. The node keeps exactly this (filtered by what it may hold, as the sync set filters today).
- **Release** (changed): a thing leaving a node's held set, and that node dropping it, as unsyncing does today (spec/sync-set.md §3 Unsyncing). Local, needs no right, writes nothing, not prompt. Today it means a release request that destroys the thing at every node.
- **Unsync**: the same as release. One word should go (open question 9).
- **Retainer**, **retainer set**, `retainers^.0`, **standalone**, **referenced thing** (removed): no per-thing list of what keeps it.
- **Release request**, `released.0` (removed): no commit asks other nodes to drop a thing.
- **Group**, `group.0` (changed): a group is any thing with a `group.0`, which is only a convenient default container of references (strong by default, open question 1). No longer "the unit of sync" (spec/requirements.md Terms): the unit is a thing with a sync ID and its sync closure. Items and subgroups lose their distinction for sync (open question 3).
- **Filing** (removed, spec/sync-set.md §1): creating a thing that no strong reference reaches after the commit is an error, never a silent add to home.
- **Destroyed** (scope changed): only by purge or expiry of the creation. A released thing is not destroyed: it is absent at this node and may live elsewhere. spec/requirements.md Terms says destroyed includes released.
- **Deletion kinds** (Tess): **expiry** is prompt, guaranteed, zero growth, set at creation; **purge** is prompt, guaranteed, leaves a tombstone, any time; **release** is not prompt, zero growth, any time.

## The design
- Every reference is strong or weak, recorded per reference in the value. Strength is dynamic data: two writes of the same field may differ.
- A thing with a sync ID (its own secrets) syncs its sync closure: what its current state reaches by strong references, wherever in any aspect they sit. `group.0` is one place to put them, not special to sync.
- Weak references point at a thing without making readers sync it. Reading a weak reference whose target is not held is an error.
- Each node has one root group, its node group. A thing is held while the node group reaches it by strong references in current state; once it does not, the node releases it. A thing a node can no longer reach is not its concern even if other nodes hold it through groups this node cannot see.
- Making a thing: the creating transaction must leave it strongly referenced from something already reachable, or the write is refused. A local thing is one put in the node group (or a group under it); a synced one in the account group (or under it); a temporary one in a group that is later released, taking it along.
- Only current state counts, as garbage collection does today: history never keeps anything.
- Cycles are handled by reachability: a cycle no root reaches is released whole.
- Purge and expiry are unchanged: prompt, guaranteed, destroy the thing everywhere.

## Why
- One mechanism for sync, storage and lifetime: today's sync closure (`group.0`), retainer lists with their reference rule, release requests and filing are three answers to "what keeps this here".
- Removes the corner cases of release by request: who may release, the heard-out wait before judging, request expiry and forgetting, evidence kept for dependents of a released thing, a stale copy coming back and being released again, re-minting a released thing (notes/lifetimes.md Limits and problems). Release that writes nothing has none.
- Creation semantics are explicit: where a thing lives is what its creator put it in, never a default.
- Matches the storage principle (issues/storage-follows-groups.md): a node's storage is attributable to the groups it reaches, and dropping every group drops it to zero.
- Data model and API keep their shape: a reference is still a tid in a value, references may dangle, and `group.0` stays the default for apps that do not care.

## Permissions and actors (worked from spec/permissions.md, spec/sync-set.md, spec/sync-judgement.md)
- **Who may add a strong reference**: any writer of the aspect holding it; an admin-only (`^`) aspect's, its admins only. This is no new power: a writer of a thing already pulls any thing into its readers' sync today by writing `group.0` on it. The surface widens from `group.0` to every writable field.
- **Strong references to things the referrer's readers cannot read**: a commit goes under S only where S's actor may read a part of it on a thing of the closure (spec/sync-judgement.md §1). So S carries no ciphertext for them: a plain thing whose key home S's actor cannot read never goes under S, and a thing with its own sync ID syncs at a reader only where that reader holds its read or sync secret, else it is `Unsyncable` there (a diagnostic, as today). No storage cost lands on readers who cannot read the target. Privacy of IDs: the tid is visible to every reader of the referrer, strong or weak, as today.
- **Things with their own secrets** in a sync closure sync under their own sync ID at each node that holds their secret, as a group's subgroup with secrets does today; their closure is their own. The sync closure of S stops at them for what goes under S (the reader actor rule, spec/sync-judgement.md §1), and the held set walks on through them.
- **Readers judging different closures**: the closure is walked only through things the node reads (an unread thing is a leaf, spec/sync-set.md §2). Readers of S that read different subsets of what S reaches compute different closures and so different judgments of what goes under S. Today this happens only through unread subgroups; with references in any aspect it happens wherever S strongly references a thing some readers cannot read. Needs its own check against the judgement spec.
- **Sync-only holders (stores keeping S unread)** read no references, so they cannot walk: they keep exactly the sync IDs listed in their own root (as kept-unread things are leaves today) and what each carries as ciphertext, which includes plain things S's actor reads. A thing with its own sync ID strongly referenced from S is not served by such a store unless it is given that sync ID too (open question 6).
- **Grants and accepting**: an accepted share is a thing filed into a group the node reaches (strong reference from the account group or below), as the accept into a synced group is today (spec/sync-set.md §4). Invitations stay "things with a role not in the held set". Declining by filing elsewhere becomes filing into a group no root reaches, which releases it. `acted^.0` and `kept^.0` hold tids that must be weak (else they keep what was declined or closed).
- **Account group vs node group**: the account group is shared state of the account (readable by its nodes); the node group is per node. Per-node choices ("on every node", "nodes with room") become groups that a node's node group references. Whether a node group is readable by the account's other nodes matters to leaving: the wait rule asks whether another node of the account may hold S (spec/sync-set.md §3 Leaving), which today reads the other synced groups (open question 2).
- **Home**: D (home) must stay reached from every node group, as "Home stays under it" requires today (spec/sync-set.md §1); simplest is that the root implicitly references D, or that the account group is D's `group.0`.
- **Admin-only aspects** (`^`): strong references there are admin-written; the core's own (`synced^.0`, `acted^.0`, `kept^.0`) each need a fixed strength.
- **Authority is not reachability**: record chains, `roles.0` holders and signers are not references (role-class aspects are not indexed) and keep nothing. What a held thing needs of its authority chain travels as certificates (spec/permissions.md §4), as for a destroyed thing today; a thing whose first admin is not in the held set still verifies.
- **Disputes and validity**: strength and references are read under the node's trust set like any value. A reference whose write turns invalid stops counting, and the target is released where nothing else reaches it.

## Costs
- The reference index (`core/engine/src/engine/refs.rs`, notes/engine-refs.md) already keeps (target, source, AK) rows in the transaction that changes the state, at O(the write's reach). Strong edges are this index filtered by the flag: rows gain the strength (two counts, or strength in the key).
- A write on any indexed aspect may now move a sync closure and the held set, not only a `group.0` write. Each such change must reach the sync set as `group.0` changes do today.
- Adding a strong edge costs the newly reached subtree (as a `group.0` add does, spec/sync-set.md §2 Cost).
- Removing one is the hard case, as it is for the sync closure today: is the target still reached by another path? Options: from-scratch walk of the held set (today's bound for a `group.0` removal: O(closure)); a walk up the backlinks from the target to the root, stopping at the first path (what the lifetime judgment does today, O(depth) typical); a dynamic reachability structure if a measured budget is missed. Per Design principles (fast by construction) the from-scratch walk per removal is not acceptable as the steady path; the backward walk is the starting point.
- Two reachability questions share the index: each sync ID's sync closure (what goes under S, the same for all its readers given the same reads) and each node's held set (what the node keeps). They should be one memoized computation, not two walkers.
- No new durable state per thing: no lifetime work rows, `pending` or release evidence.

## What it removes or changes
Spec:
- spec/requirements.md Terms (group, destroyed) and Data model (the garbage-collection paragraph is Tess's wording, needing her sign-off: replaced by the reference graph rule).
- spec/commits.md §5 Lifetimes (whole), and in §5 Destruction the release request, "destroyed by release alone", forgetting at the request's expiry and needs through `retainers^.0`.
- spec/data-model.md §8 (`group.0` as a container; closure defined in sync), §9 `retainers^.0`, `released.0`, the filing line, and §5 (the tag or form carrying a weak reference).
- spec/sync-set.md §1 (synced group, `synced^.0`, Filing, Local stays local restated by reachability), §2 (closure by strong references in any aspect), §3 (release is Unsyncing), §4 (accept into a reached group).
- spec/wire.md (the release request's header rule), spec/permissions.md §6 if it names release, schema/core.osis.
Code:
- engine `retention/lifetimes.rs` and its `lw/`, `lh/`, `lp/` rows; release paths in `retention/destroy.rs` (`release_state`, `forget_released`, `Missing::Forgot` where only release uses it); release reading in purge (`Header::requests`), `osis_commit::retention::release_expires` and `destroying_request`'s release case; header validation of release commits.
- engine `refs.rs`: strength in rows; `RETAINERS` and `Reference::lists` go.
- osis: `Write::release`, `AspectWrite::retaining`, `core::RETAINERS`, the writer's lifetime checks (`require_kept`, `require_reference`, `check_lifetimes`); create's default filing replaced by the refusal.
- osis-sync: the `life` duty; the sync set walk (strong edges in any aspect); leave stays as the one drop path.
- held-model `lifetimes.rs` and `spec_lifetimes` (replaced by a reachability model: Design principles, model before building).
- notes/lifetimes.md, notes/engine-lifetimes.md, notes/deletion.md (release moves from destruction to unsync), notes/growth.md rows (release requests, lifetime work rows); issues/thing-lifetimes.md closes.
Migration: none (no backward compatibility before release, CLAUDE.md).

## Open questions
1. Encoding: which two CBOR tags (1616 is retired or becomes one of them).
2. (settled: Decided, schema types.)
3. Items vs subgroups: today an item is carried but its own `group.0` is not walked. Under strong references everything reached is walked. Keep both lists (and what does "item" mean then), or one set?
4. Key homes: today a thing is in the closure of its key home whether listed or not (spec/sync-set.md §2). Keep this as an implicit strong edge, or drop it now that creation must reference the thing?
5. Ephemeral aspects: may a strong reference there hold anything (memory, may be lost; today they are not references for lifetime)? Lean: no, durable current state only.
6. Stores: should a sync-only holder serve the things S reaches that have their own sync IDs, and how, given it cannot read S?
7. Node group readable by the account's other nodes (for the leave wait and dial peers), or local; how per-node organizing groups look.
8. Destruction evidence: with release no destruction, does "What is kept" (keeping a destroyed thing's evidence while a held thing references it) still need references, or only dependents?
9. One word for release and unsync, and the user-facing name.
10. Readers of S computing different sync closures (Permissions above): acceptable, or does the closure rule need a form every reader computes alike?
11. A writer forcing large storage on every reader by one strong reference: accepted as today with `group.0`, or bounded?
12. `created.0` and the role-class aspects hold tids (`creation.admin`, `creation.link`, `roles.0` keys) that are not indexed today because authority is not lifetime. As weaks they keep nothing by the general rule, so the exclusion is no longer needed for lifetime. Left: should backlinks list them? Check why they are unindexed beyond lifetime (`roles.0` reads through the role timeline, not as plain state) before keeping any exclusion.
13. Synthetic aspects typed by tid: `tid.0` (`tid`) and `groups.0` (`set<tid>`, derived: the groups that reach the thing through `group.0`, the inverse of the listing). With a tid no value they become weaks or stop being aspects (`groups_of` already serves the second). And with strong references in any aspect, is "the groups holding a thing" still the useful inverse, or is it backlinks by strong references?
14. Other roots: today's sync set also takes the shared-here set, a link being redeemed, a destroyed thing's sync IDs until emptied, and cuts paths through groups sourced at another node (spec/sync-set.md §2, §3, §5). Each becomes a strong reference from the root group or a stated root; "exactly what the root group reaches" does not hold until then.
15. The "not prompt" rule. Commits arrive in any order, so "no longer referenced" may be held before an earlier "referenced from elsewhere". Dropping locally is harmless; deleting the thing's blobs under a sync ID (Retag, spec/sync-judgement.md §1) is durable. What a node waits for before each needs stating; the lifetimes design waits to be heard out (notes/lifetimes.md Rules, When) and some form of that likely stays.
16. Removal cost. The backward walk from a target costs its fan-in when it is still held (one profile referenced by 10,000 messages). Candidate: each held thing records one path edge towards the root, so removing any other edge is O(1) and removing that one searches the target's other strong referrers. Model first.
17. notes/lifetimes.md (Limits and problems, stated: Rejected) rejected "every node releasing on its own judgment with no request": a partial-view node logs the thing again while right holders delete it, round for good. This design avoids most of it (release destroys nothing), but the loop returns wherever readers of S compute different closures (question 10): settle the two together.
