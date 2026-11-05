# held-model
> Summary: Brute-force executable spec of what a node holding a set of commits reads and keeps (apply and waits, validity with actors, invites and required retention, undo, purge, expiry, keep bounds); input format, input changes and how to call it.

Written from `spec/` alone, depending on no osis crate, so it is an independent reading to test the engine against. Every query recomputes from scratch (`evaluate` is a pure function of `Held`). AMBIGUITIES.md lists the choices the spec left; ASSUMPTIONS.md what is out of scope.

## Input (`src/types.rs`)
`Held { now, me, things, commits, own_state, dropped_valid }`:
- `now`: the node's corrected clock (wall ms). `me`: the node (needed for "may I drop this").
- Ids: things, actors and nodes share one `u32` space.
- `things`: every creation record the node knows, `Thing { id, owner }` with `Owner::Key` (a key actor: node, link key; owns itself), `Owner::Actor(a)` or `Owner::Ownerless { first_admin }`. A thing, author or owner not listed has an unknown record (it waits).
- `commits`: `Commit { id, author, actor, ts, expires, kind, parts, purge, frontier, undoes }`. The header is held; each `Part { thing, aspect, retention, body, stripped }` has `Body::Held(Delta)`, `Body::Missing`, `Body::Dropped` or `Body::Parked` (bytes it cannot interpret).
  - `actor`: the header actor (the author when acting for itself). `undoes`: the undone commit.
  - `kind`: `Content`; `Role` (each part a `Delta::Edge(EdgeWrite { holder, role, invite, until })` on `Aspect::ROLES`, `role` None removes, `until` wall ms, `until` 0 a removal saying keep); `Snapshot` (writes are copies under their original stamps).
  - `stripped`: owners whose values `act` stripped from the body (it holds its leftover).
  - Content and snapshot parts carry `Delta::Writes(Vec<Write>)`; a `Write` is a `Stamp { ts, dot: Dot { commit, ctr } }` and an `Op`: `Set`, `Reset`, `Create`, `SetIn`, `Remove`, `Insert`, `Delete`, `Undelete` (its char a copy owned by the element's creator), `Anchor`. Value fields are `Option`: `None` is held value-less. A `required.0^` part carries `Delta::Required(Vec<Rule { prefix, retention, expiry }>)` on `Aspect::REQUIRED` with `Retention::FIXED`.
  - `Aspect { name, kind, admin_only }`: `kind` is Register, Map or Text; `admin_only` is the `^` marker.
  - `Retention { by, least_abs, least_rel, most_abs, most_zero }`; `purge: Vec<PurgeItem>` (a commit's delta on an aspect, a whole aspect, or an author on an aspect); `frontier` on demotions.
- `Body::Missing`: never received or counting so; `Body::Dropped`: dropped here for its keep bounds or as covered (never received too, but its commit applied: it counts as a held part that does not wait, AMBIGUITIES.md 40).
- `own_state`: writes the state holds that no held body does (live writes of bodies dropped at keep at most).
- `dropped_valid`: snapshot parts this node dropped while valid (`act` fills it); one held again and judged invalid takes back what it gave (spec/permissions.md §5.2).

## Output (`src/model.rs`, `evaluate(&Held) -> Outcome`)
- `parked`, `applied`, `valid` (per part of an applied commit; role parts: whether the edge write applied), `purged` (part to request).
- `reads` per `(thing, aspect)`: `Read::{Absent, Reg, Map, Text}`; `states`: canonical writes.
- `at_most`: each held body's keep-at-most bound where keep bounds decide its fate (the node drops it no earlier and by then; 0: at the kill); `deadlines`: every clock value after `now` at which the output may change with the held set unchanged.
- `fates` per held or parked body: `Keep(why)`, `Leftover(why)` (strip values), `MayDrop(why)` (covered), `MustDrop(why)` (keep at most from its bound, a purged snapshot, `Gone`: a waiting part past its expiry or an unjoinable body expired or purged, which counts as never received), `NeverReceived`; `keep_in_state`: the live writes a keep-at-most drop leaves in the state; `deaths`: first and last death.
- `valueless`: deltas held value-less (expired, purged); `forbidden`: every value of theirs still held, with where (body or own state). An engine holding the same set must hold none of them once it has acted.

`act(&Held, &Outcome, may)` carries out the forced fates (and one optional drop) and returns the next held set; `timeline(&Held)` the settled role timeline; `undo::undo(&Held, target, id, ts, author)` the undo commit node `me` writes (spec/crdt.md §4.6); `gen::history(seed, n)` builds a random history, `gen::shuffle` reorders one.

## Input changes
For adapters written against the previous input (one change per line):
- Apply follows spec/commits.md §4 as of whole-commits step 3: no atomic apply, no "counts as held" clauses; feed a part the node does not hold as `Body::Missing`, and `Body::Dropped` only for a body the node itself dropped (its commit applied).
- `Held` gained `dropped_valid`.
- Output: `at_most` and `deadlines`; a waiting part of an applied commit that a request names is `Leftover(PendingPurged)`, not in `purged`.
- `roles::Possible` is gone (only the deleted clauses used it).

## Properties (`tests/it/props.rs`)
- The output is a function of the held set (any order of commits, writes, own state). The histories include undos (written by `undo::undo`), invites, `until`, self-removals, finalizes, link redemptions, acting for a person, `required.0^`, parked parts and unknown records.
- Forced fates change no read and leave no forbidden value; each optional drop changes no read.
- A commit arriving after the node acted on the rest reads as if held from the start, except on aspects with a keep-at-most bound or expiry (spec/requirements.md, Deterministic limits); about 1 seed in 1000 differs there.
- The output is constant between `now` and its first deadline.

## Adapter use
osis-node `tests/it/held.rs` maps what a node holds into `Held` and compares applied commits, validity, reads, fates, keep-at-most drop times and `forbidden` (scope and normalizations in its module doc); the order harness runs it on every node it judges under `Cfg::model` (`order::arrival_order_purge_*`, `held_model_agrees_*`, `arrival_order_exhaustive_large_*`). Run this crate's properties with more seeds by raising `SEEDS` locally (3000 pass).
