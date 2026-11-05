# held-model
> Summary: Brute-force executable spec of what a node holding a set of commits reads and keeps (atomic apply, validity, purge, expiry, keep bounds); input format and how to call it.

Written from `spec/` alone, depending on no osis crate, so it is an independent reading to test the engine against. Every query recomputes from scratch (`evaluate` is a pure function of `Held`). AMBIGUITIES.md lists the choices the spec left; ASSUMPTIONS.md what is out of scope.

## Input (`src/types.rs`)
`Held { now, me, things, commits, own_state }`:
- `now`: the node's corrected clock (wall ms). `me`: the node (needed for "may I drop this").
- `things`: `Thing { id, owner }`; the owner node has admin by owner chain.
- `commits`: `Commit { id, author, ts, expires, kind, parts, purge, frontier }`. The header is held; each `Part { thing, aspect, retention, body }` has `Body::Held(Delta)`, `Body::Missing` or `Body::Dropped`.
  - `kind`: `Content`; `Role` (each part a `Delta::Edge(EdgeWrite { holder, role })` on `Aspect::ROLES`, `role` None removes); `Snapshot` (writes are copies under their original stamps).
  - `stripped`: owners whose values `act` stripped from the body (it holds its leftover).
  - Content and snapshot parts carry `Delta::Writes(Vec<Write>)`; a `Write` is a `Stamp { ts, dot: Dot { commit, ctr } }` and an `Op`: `Set`, `Reset`, `Create`, `SetIn`, `Remove`, `Insert`, `Delete`, `Anchor`. Value fields are `Option`: `None` is held value-less.
  - `Aspect { name, kind, admin_only }`: `kind` is Register, Map or Text; `admin_only` is the `^` marker.
  - `Retention { by, least_abs, least_rel, most_abs, most_zero }`; `purge: Vec<PurgeItem>` (a commit's delta on an aspect, a whole aspect, or an author on an aspect); `frontier` on demotions.
- `own_state`: writes the state holds that no held body does (live writes of bodies dropped at keep at most).

## Output (`src/model.rs`, `evaluate(&Held) -> Outcome`)
- `parked`, `applied`, `valid` (per part of an applied commit), `purged` (part to request).
- `reads` per `(thing, aspect)`: `Read::{Absent, Reg, Map, Text}`; `states`: canonical writes.
- `fates` per held body: `Keep(why)`, `Leftover(why)` (strip values), `MayDrop(why)` (covered), `MustDrop(why)` (keep at most from its bound, a purged snapshot), `NeverReceived`; `keep_in_state`: the live writes a keep-at-most drop leaves in the state; `deaths`: first and last death.
- `valueless`: deltas held value-less (expired, purged); `forbidden`: every value of theirs still held, with where (body or own state). An engine holding the same set must hold none of them once it has acted.

`act(&Held, &Outcome, may)` carries out the forced fates (and one optional drop) and returns the next held set; `gen::history(seed, n)` builds a random history, `gen::shuffle` reorders one.

## Properties (`tests/it/props.rs`)
- The output is a function of the held set (any order of commits, writes, own state).
- Forced fates change no read and leave no forbidden value; each optional drop changes no read.
- A commit arriving after the node acted on the rest reads as if held from the start, except on aspects with a keep-at-most bound or expiry (spec/requirements.md, Deterministic limits); about 1 seed in 1000 differs there.

## Adapter use
osis-node `tests/it/held.rs` maps what a node holds into `Held` and compares applied commits, validity, reads, fates and `forbidden` (scope and normalizations in its module doc); the order harness runs it on every node it judges under `Cfg::model` (`order::arrival_order_purge_*`, `held_model_agrees_*`, `arrival_order_exhaustive_large_*`). Run this crate's properties with more seeds by raising `SEEDS` locally (3000 pass).
