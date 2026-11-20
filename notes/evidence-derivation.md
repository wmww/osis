# Evidence derivation
> Summary: Design and build state of A2 brief 2 (notes/a2-spec/README.md, Order of the code briefs): `osis_engine::evidence`, the set of certificate copies a sync ID requires, derived from a node's held commits and the sync ID's unit as notes/a2-spec/permissions.md §4 says (OPEN 10's proposal (iv)), built unused beside `sync/certified.rs`; inputs, output, what re-derives what and its cost, the differential against held-model `evidence::World::req`, mutations, counts, what brief 3 (the switch) must know.

**Principle: a sync ID's evidence is a function of the commits the node holds and the sync ID's unit: the least set the draft's rules close over them. Nothing is placed once and remembered; a change re-derives exactly what it can move, and the incremental answer is the from-scratch answer by construction (same closure step, same seeds).**

## Input
Plain facts per held **copy** (commit ID, thing): the commit's parts on that thing (`evidence::Part`), as the derivation's own structs (independent of header types, as osis-perm's walk input is):
- `pos`: the part's place in key order as a verdict reads it (draft §5.1 key for an edge-class part, the start of its `ts` for content: spec/permissions.md §5.2 Position); "ordered before" is `key(j) < pos(m)`.
- `hops`: the edges of the path the commit states for that thing, each marked record or not; `None` while the path is not known here (a split entry waiting to open: notes/path-form.md). A part with no known path brings nothing (finding 8); the entry opening is an update (`open_path`).
- the kind: content; an edge write (holder, whether it is a **grant** (sets a role above none: no self-removal, no finalize), a **removal** (gives below write at its `ts`, no finalize: A3's reach), whether it **gives write** or above (A3's reach), the remaining admin it names, the **creation** of the entry it resets as the reset names it (spec/permissions.md §2 Edge writes)); a vouch (the copy of the lowering it is keyed by).
- `chained` per edge-class part: whether it is a chained write (draft §4 Chained writes). An input, never computed here: the walk owns the rule (osis-perm `paths`' chained pass; held-model `World::chained` in the differential). It only grows with arrivals and may fall on a forget; the caller reports each flip (`set_chained`).
- Per sync ID: its actor (the holder whose grants travel under it) and its unit's things (`join`, `leave`).
- `Config::vouches`: vouch evidence on or off (the owner may drop role vouches: the derivation runs either way).

## Output
`required(sid)`: every copy on a thing outside the unit in S's evidence, with one **reason** each (`Reason`: a taken write on an edge the set uses, the creation a member's reset names, a vouch keyed by a member lowering, a write naming S's actor, a removal with its reach or a grant of that reach). Bodies (held copies on unit things) are S's sync unit blobs, not output. `from_scratch(sid)` the same from nothing. A copy is a whole (commit, thing): its edge-class parts on that thing travel together (finding 9's "apply together"), never a part alone and never keyed by commit alone (a role commit on two things is two copies).

## The rule (draft §4 with OPEN 10 (iv))
S's evidence is the least set of copies holding:
- **seeds**: the bodies (held copies on unit things); each held copy with a chained edge write naming S's actor as holder; **(A3)** each held chained removal of (h, t), t outside the unit, whose **reach** under S is held (chained write grants joining t to a unit thing), with that reach.
- **closure**, for each member m (body or copy):
  - each part of m whose path is **joined** (each non-record edge holds a held chained grant ordered before the part) brings its path's edges; an edge write brings its named remaining admin edge (joined or not);
  - an edge brings every held copy with a chained edge write on it;
  - an edge write brings the creation of the entry it resets, held;
  - (`vouches`) a member lowering brings every held chained vouch keyed by it on a thing some member is on.
A copy on a unit thing reached by the closure is a body already.

## Incremental
State per sync ID: `atoms` (per edge, the number of bodies bringing it: the bodies' own contribution), `seeds` (actor and reach copies), and the closure over those (`members`, `edges`, vouches waiting for a member on their thing). Global indexes over the held copies: chained writes per edge, chained grants per edge (ordered: the first one decides joined-ness), parts per resting edge ordered by `pos`, chained writes per holder, chained vouches per keyed copy, resetters per creation, held copies per thing; reverse: edge → sync IDs using it, copy → sync IDs holding it as a member, thing → sync IDs whose unit holds it, actor → sync ID. Joined-ness is per part, global (no sync ID in it).

Monotone changes extend the closure from what they add (one BFS step function, `close`); a change that can shrink it (a forget, a chained write falling, a part no longer joined, a retag) marks the sync IDs it touches dirty, and each dirty sync ID is closed again from its atoms and seeds (O(its closure), never O(its bodies)).

| change | what it does | cost |
|---|---|---|
| body appended on a path of k edges | k atom increments in each sync ID whose unit holds its thing; an edge new to S closes from it | O(k log) per such sync ID, independent of history |
| copy (role commit) arrives with a chained write on edge e | e → sync IDs; added to each and closed from it; a chained grant moving e's first grant earlier rechecks joined-ness of the parts resting on e ordered after it | O(sync IDs using e + what it brings + parts newly joined); no body scan |
| junk (an unchained edge write) arrives | indexed, its own joined-ness computed; nothing else | O(its parts' hops) |
| path entry opens (`open_path`) | the part's atoms added where it is a body | O(k) per sync ID |
| chained flips true | as the arrival of that part | as above |
| chained flips false, forget | sync IDs holding the copy as member, or whose atoms drop to zero, dirty; first grant moving later unjoins the resting parts in between | O(dirty closures + changed parts) |
| thing joins S's unit (b bodies) | b bodies' atoms; S dirty if it held copies on the thing | O(b·k + closure) |
| thing leaves | b bodies' atoms out; S dirty | O(b·k + closure) |
| **(A3)** reach | every chained removal or write grant arriving, falling or forgotten, and every retag, recomputes each sync ID's reach seeds from the held chained grants and removals | O(sync IDs × (grants + removals)): rare path, brute force; A3 indexes it |
| from scratch for S | every body on its unit's things, then seeds, then the closure | linear in bodies·k + closure |
Memory per sync ID: its used edges, its members and their reasons (the output), atom counts per used edge: O(edges its paths use + copies), not O(bodies). Global indexes: O(held parts · k), the size of holding the parts.

**The engine's memo machinery.** The module is pure: it takes changes by call (`add`, `forget`, `set_chained`, `open_path`, `join`, `leave`) and does work in proportion to them. Brief 3 drives it from `memo::Feed`/`Effects` followers over the held set, the units and the walk's chained flips, as `sync/certified.rs` follows `Indexes::chains_on` and `apply/paths.rs` follows `paths_unknown`; the derivation itself keeps no stamps.

## Seams
- **(A3) list leaves**: a leaf (R, t) is required while R is in the set and a body on t rests on R's edge: count bodies per (edge, thing) beside the per-edge atoms, and a leaf joins `required` keyed (R, t). Not built.
- Records (the members' creation records up their chains, record blobs) are not output: brief 3 takes them from the members' paths of `required`'s copies and of the bodies (spec, Logging evidence: record blobs stand).

## Built
- `core/engine/src/evidence.rs`: `Evidence` (the derivation, from scratch and incremental), unused by the engine.
- `core/engine/tests/it/evidence/`: the differential (`mod.rs`), hand worlds (`hand.rs`), count tests (`counts.rs`).

## The differential
Against held-model `evidence::World::req` under `Open10::Granted` with entry creations (`World::creations`), vouches counting and not. The adapter turns each model part into a `Part` (chained from `World::chained` over the held set, creation from `World::creation`, `pos` the model's key or `ts` start) and gives each held copy every part of its commit on that thing (the model writes a commit's parts as one event each; a copy is whole: an unheld part is unchained there). At every step of a world, for every node's held set and every sync ID's held entries (its one-sync-ID reader), for every sync ID: the derivation's copies kept incrementally (fed the step's new copies, chained flips, forgotten copies and retags) and from scratch against the model's required parts on things outside the unit, by (commit, thing).
- Default: every 97th family world (`the_derivation_agrees_with_the_model_on_a_family_slice_spec_permissions_4`, over 1,000 comparisons with copies), the story world of seed 0 under each of the six unit crossings.
- Properties: `the_derivation_agrees_with_the_model_plain_spec_permissions_4` (106 family, 20 random, 2 story seeds × 6 crossings × vouches: 150 worlds, about 26 CPU-s), `_large` (full: every 17th family world, 1,500 random, 60 story seeds; the gate's a tenth of the seeds and every 97th family world). 0 disagreements at both sizes.
- Hand worlds (`hand.rs`): each model hand test naming a rule or finding (f2, f9, f10, f11, f13, f14, f15 and OPEN 10's junk and admin counts, split, P4, the vouch switch) with the copy its rule decides; the other model hand worlds (f1, f3 to f6, f12, risk 3, P2, the addendum) as differentials; the derivation's own: a body whose path entry waits brings nothing until it opens, and a chained grant ordered after a write joins nothing.

## Counts (`counts.rs`, at n and 10n)
- A body appended on a path of k edges: k + 1 atoms, no closure work, no body but itself, the same at 10 and 100 held bodies.
- A role commit on an edge m bodies use: no body read, no closure again, at most 2 copies visited, the same at m = 10 and 100.
- Junk (an unchained grant by a non-admin) on a used edge: one recheck each, nothing else, no copy; a sync ID later taking the edge in reads the same at 3 and 30 junk grants.
- A thing entering a unit with b bodies: b + 1 bodies read, 3b + 1 atoms (b = 10, 100).
- From scratch: one body read each (11 and 101), closure visits the same; a sync ID keeps the same edges, atoms and copies at n and 10n.
