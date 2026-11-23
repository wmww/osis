# Evidence derivation
> Summary: Design and build state of `osis_engine::evidence` (A2 brief 2, notes/a2-spec/README.md Order of the code briefs): the copies a sync ID requires, derived from a node's held copies and the sync ID's unit by spec/permissions.md §4 under E1 (every edge write on a stated path's edges and on the edges a member writes) with delete-key steps; built unused beside `sync/certified.rs`; inputs, output, what re-derives what and its cost; keys-open travel as an indexed graph; the differential against held-model `Stage::E1` (0 disagreements), hand worlds and counts; carried demotions (A3 design); what the switch (brief 3) must know.

**Principle: a sync ID's evidence is a function of the copies the node holds and the sync ID's unit: the least set the spec's rules close over them. Nothing is placed once and remembered; a change re-derives exactly what it can move, and the incremental answer is the from-scratch answer by construction (same closure step, same seeds).**

## Input
Per held **copy** (commit ID, thing), held whole (a commit's edge writes on a thing are one `roles.0` delta, spec/crdt.md §2), its parts on that thing (`evidence::Part`), as the derivation's own structs (independent of header types):
- `kind`: content (anything with no edge write: content, purge requests, snapshots, `sync.0`) or an edge write (`Write`: its holder, and `gives_read`: read or above, any `until`, no self-removal, a step of the keys-open graph).
- `hops`: the edges of the path its commit states for that thing, key hop first; `None` while not known here (a split entry waiting to open: notes/path-form.md); `open_path` when it opens. A part with no known path brings no path edges.
- `dels`: the delete keys it lists at levels 1 and 3 for its thing's delete base (`Del`: base, level, key; spec/crypto.md §7). A key-actor base lists none here.
- `steps`: the steps a `sync.0` part records on its thing (`Step`: ID, parent, delete and write keys; spec/sync-ids.md §2).
- Per sync ID: its actor (whose role changes travel under it) and its unit's things (`join`, `leave`).
- **Record edges** (`add_record`): each (mint admin, thing it minted), standing for good: edges of the keys-open graph.
- `Config::keys_open`: Role changes travel's keys-open half on or off (off: writes naming the actor alone).

No validity, no order, no chained-ness: E1 takes every held write "whatever their validity or order", so the derivation needs no walk output at all.

## Output
`required(sid)`: every copy on a thing outside the unit in S's evidence, with one **reason** each (`Reason`: a write on an edge the set uses; a write naming a holder whose role changes travel under S; a write recording a step that places a listed key). Bodies (held copies on unit things) are S's sync unit blobs, not output. `from_scratch(sid)` the same from nothing. A copy is a whole (commit, thing), never keyed by commit alone (a role commit on two things is two copies). Records (members' creation records up their chains) are not output: brief 3 takes them from the bodies' and copies' paths.

## The rule (spec/permissions.md §4 under E1)
S's evidence is the least set of copies holding:
- **seeds**: the bodies' known path edges and listed delete keys (`atoms`, counted per body); each held copy with an edge write naming a holder in **open(S)** (Role changes travel).
- **closure**: an edge brings every held copy with an edge write on it; a delete key brings every held copy recording a step from its base's genesis to a step bearing the key (the parent chain of each bearing step, as far as held steps reach); a member copy (outside the unit) brings its parts' known path edges, the edge each of its edge writes sets, and the keys it lists.

"The edge each of its edge writes sets" is finding 9's clause: a removal applies only once the creations of the entries it resets are held (spec/permissions.md §2), and those creations are writes on the edges the commit writes. held-model's `CommitEdges::AllWrites` brings the edges of the commit's *other* parts; the two give the same members (a member's own edge's writes are already in: it entered by that edge, or as a travel seed whose edge's writes all name the same open holder).

Unjoined paths and junk (a non-admin's writes on a used edge) are copies under E1: the roster leak (P9) and junk copies (P10) of notes/a2-spec/README.md Open 2.

## Keys-open travel
Reachability over the **read graph**: an edge (holder → target) per held part giving read, and every record edge; multi-edges kept as their parts. An edge stays while a part setting it is held. **open(S)** is S's actor and everything reachable from it (held-model `World::opened`). With `keys_open` off, open(S) is the actor alone.

**The index.** Parts per edge, the record edges, the adjacency holder → target; per sync ID its open set and travel seeds; reverse thing → sync IDs whose open set holds it. No transitive relation is stored.

| change | keys-open work |
|---|---|
| a part giving read on a new edge (x, y) | per sync ID whose open set holds x and not y: walk what y opens beyond it, take the writes naming each newly opened holder: O(what it opens + its writes) |
| record edge added | as a new read edge |
| a write naming holder h | the sync IDs whose open set holds h take it |
| a read edge gone (forget) | sync IDs whose open set held both ends recompute open and seeds |

## Steps
Per (base, step ID) the held step and the copies recording it; per (base, level, key) the step IDs bearing it. A key's placement is walked inside the closure (`Item::Del`), memoized per closure (`dels`). A copy recording a step arriving or leaving closes again every sync ID placing a key of that base (`base_sids`): steps move only with rotations, a rare path paid at closure size. A body listing a key another body lists walks nothing (counted atom).

## Incremental
State per sync ID: `atoms` (per edge and per key, the bodies bringing it), its travel, and the closure (`members`, `edges`, `dels`). Global indexes: copies per thing, per edge written, per holder; the read graph; steps. Reverse: edge → sync IDs using it, copy → sync IDs holding it as member, thing → sync IDs whose unit holds it, open thing → sync IDs, base → sync IDs placing its keys.

Monotone changes extend the closure from what they add (`close`); a change that can shrink it (a forget, a body's last atom gone, a retag out, a step moved) marks the sync IDs it touches dirty, and each is closed again from its atoms and seeds (O(its closure), never O(its bodies)).

| change | cost |
|---|---|
| body appended on a path of k edges | k atom increments per sync ID whose unit holds its thing; an edge new to S closes from it |
| copy with an edge write on edge e | the sync IDs using e take it: O(those + what it brings); no body scan |
| path entry opens | its edges' atoms where a body; pushed into each closure holding it as member |
| body forgotten | its atoms out; S closes again only where it was the last on an edge or key; `forget_all` closes each sync ID once |
| thing joins or leaves S's unit (b bodies) | b bodies' atoms; S dirty if it held copies on the thing, or on leaving |
| from scratch for S | linear in bodies·k + closure |

Memory per sync ID: its used edges and keys, members and reasons, atom counts: O(edges and keys its bodies use + copies), not O(bodies).

The module is pure: it takes changes by call and does work in proportion to them. Brief 3 drives it from `memo::Feed`/`Effects` followers over the held set and the units; the derivation keeps no stamps.

## Carried demotions (design for A3: not built)
A removal reaches a thing other than its own by the evidence closure (wherever a node holds both it and a write on its edge it judges) and by **carried demotions** (spec/crypto.md §4): a keyset of M lists the explicit demotions below write or admin its rotator holds applied on M or below it, and is held only with those edge writes. At A3 the demotions a required keyset carries become a seed of the required set (notes/a3-spec/crypto.md; Open 8): one copy identity per (removal commit, thing) with the closure's, one blob per sync ID. held-model's `Rule::keysets` has it; the derivation does not (issues/engine-evidence-trails-model.md).

## What the switch (brief 3) must know
- The adapter gives each held copy every part of its commit on that thing: kind and holder from the `roles.0` entry, `gives_read` from the role (a self-removal gives none), hops from the stated path (split entries per `View::paths`, `open_path` when `apply::paths::refresh` opens one), `dels` from the header list's level-1 and level-3 keys for the thing's delete base, `steps` from the `sync.0` delta.
- Record edges: `add_record` for each creation record held.
- Accounts: Role changes travel's account clauses and the signing chain's rotations (spec/permissions.md §4, Interim) are not in the derivation: an account root's sync ID needs them as inputs, or waits for A4.
- A forget is the rare path (`retention::forgettable`); forget a compaction's bodies with one `forget_all`.
- The derivation keeps its own indexes; the engine's (`ix.held`) can feed or replace them.

## Left
- **The engine-level check**: a debug-only hook at the engine's drop, sampled, building `Evidence` from the engine's held commits per sync ID and asserting incremental equals from scratch and that a body whose required copies are held is judged by osis-perm `paths` over them as over everything. Needs the adapter above.
- **Finding 9's engine hand test**: X removes K and Q from A in one commit, K writes D through [A]; a reader engine given D's bodies and the required copies judges K's write as the full node, and one given them less X's grant to Q never applies the removal. Needs the adapter.
- **Steps under role compaction** (notes/a2-spec/README.md Open 4): a compaction snapshot carrying `sync.0` step entries is a copy recording them; the engine-level test owes a write listing an old step after `sync.0` is compacted.

## The differential
Against held-model `evidence` under `Stage::E1` (the drafted closure, pending on any write, keys-open travel on; `Rule::keysets` off), at every held set: per step of a world, for every node's held set and every sync ID's held entries, for every sync ID, the copies kept incrementally and from scratch against the model's required parts on things outside the unit, by (commit, thing). The model writes each part of a commit as an event of its own, so a held set can split a copy: no node holds such a set; it is stepped through and `check`ed, not compared. Story worlds with key-hop writes or foreign keys are skipped (the engine reads no key hop until A4).
- Plain property: every 291st family world, the story world of seed 0 under each of the six unit crossings.
- Large property: `the_derivation_agrees_with_the_model_large_spec_permissions_4` (full: every 17th family world, 1,500 random, 60 story seeds; the gate's a tenth).
- Hand worlds (`hand.rs`): each model hand test naming a rule or finding, with the copy the rule decides (f9 by the edge it writes, f11 and f13 the leaks E1 accepts, f14, f15 with junk copies counted, f23 a read hop bringing its writes, split, P4, f2); the derivation's own (a waiting path entry, a member's written edges, a removal evidence only where a body rests on its edge). Keys-open hand worlds (`travel.rs`): finding 19, OPEN 17 (records as read edges, with the control). The walk-level check (`walk.rs`): a reader holding D's bodies plus exactly the required copies judges every body of D as the writer under osis-perm `paths`, and less any one copy a verdict reads, not alike. Steps (`steps.rs`): genesis-to-key chains, siblings left out, either arrival order, forgets, a member listing a key.

## Counts (`counts.rs`, `steps.rs`, at n and 10n)
- A body appended on a path of k edges: k + 1 atoms, no closure work, the same at 10 and 100 held bodies.
- A role commit on an edge m bodies use: no body read, no closure again, at most 2 copies visited.
- A thing entering a unit with b bodies: b + 1 bodies read, 3b + 1 atoms.
- From scratch: one body read each; a sync ID keeps the same edges, atoms and copies at n and 10n.
- A write naming an actor: no earlier write naming it read.
- Keys-open travel: a read grant opens 3 walked at 10 and 100 other sync IDs.
- A body forgotten: 2 atoms and no close while another body uses its edges; the last on an edge one close of m visits (m = 10, 1,000); a compaction's 10 last bodies in one `forget_all`: one close.
- A body listing a placed key: no step walked, no close, at chains of 10 and 100 steps.
