# held-model
> Summary: Brute-force executable spec of what a node holding a set of commits reads and keeps (apply and waits, validity with actors, invites and required retention, undo, purge, expiry, history modes, signals); input format, input changes and how to call it.

Written from `spec/` alone, depending on no osis crate, so it is an independent reading to test the engine against. Every query recomputes from scratch (`evaluate` is a pure function of `Held`). AMBIGUITIES.md lists the choices the spec left; ASSUMPTIONS.md what is out of scope.

## Input (`src/types.rs`)
`Held { now, me, things, commits }`:
- `now`: the node's corrected clock (wall ms). `me`: the node (needed for "may I drop this").
- Ids: things, actors and nodes share one `u32` space.
- `things`: every creation record the node knows, `Thing { id, link }` with `RecordLink::Key` (a key actor: node, link key, recovery key; admin of itself) or `RecordLink::Admin(a)` (its first admin). A thing, author or first admin not listed has an unknown record (it waits).
- `commits`: `Commit { id, author, actor, ts, expires, kind, parts, purge, frontier, undoes }`. The header is held; each `Part { thing, aspect, retention, body, stripped }` has `Body::Held(Delta)`, `Body::Missing`, `Body::Dropped` or `Body::Parked` (bytes it cannot interpret).
  - `actor`: the header actor (the author when acting for itself). `undoes`: the undone commit.
  - `kind`: `Content`; `Role` (each part a `Delta::Edge(EdgeWrite { holder, role, invite, until })` on `Aspect::ROLES`, `role` None removes, `until` wall ms, `until` 0 a removal saying retain); `Snapshot` (writes are copies under their original stamps).
  - `stripped`: the commits whose values `act` stripped from the body (it holds its leftover).
  - Content and snapshot parts carry `Delta::Writes(Vec<Write>)`; a `Write` is a `Stamp { ts, dot: Dot { commit, ctr } }` and an `Op`: `Set`, `Reset`, `Create`, `SetIn`, `Remove`, `Insert`, `Delete`, `Undelete` (its char its own value). Value fields are `Option`: `None` is held value-less. A `required^.0` part carries `Delta::Required(Vec<Rule { aspect, retention, expiry }>)` on `Aspect::REQUIRED` with `Retention::FIXED`. An `addenda.0` part carries `Delta::Addenda(Vec<(removal, listed commits)>)` on `Aspect::ADDENDA` (entries of a held body; a stripped one lists nothing).
  - `Aspect { name, kind, admin_only, signal }`: `kind` is Register, Map or Text; `admin_only` is the `^` marker; `signal` the `~` marker (parts carry one root `Set`, retention keeps history, never in a snapshot).
  - `Retention { by, history }`: `History::None` (gone once replaced; `writer`) or `History::Keep { until, after }` (kept at least until wall ms `until` and/or `after` ms past the earliest valid replacing write the compactor holds, the later; both 0 convenient, `until` `FOREVER` kept for good); `purge: Vec<PurgeItem>` (a commit's delta on an aspect, a whole aspect, or an author on an aspect); `frontier` on demotions.
- `Body::Missing`: never received or counting so; `Body::Dropped(by)`: dropped here as covered by snapshot commit `by`'s part on the aspect: it contributes nothing while the cover stands (valid, held or itself dropped covered) and is never received once it does not (`Outcome::uncovered`); its commit applied when it was held, so it counts as a held part that does not wait (AMBIGUITIES.md 40).

## Output (`src/model.rs`, `evaluate(&Held) -> Outcome`)
- `parked`, `applied`, `valid` (per part of an applied commit; role parts: whether the edge write applied), `purged` (part to request).
- `reads` per `(thing, aspect)`: `Read::{Absent, Reg, Map, Text}`; `states`: canonical writes.
- `fates` per held or parked body: `Keep(why)` (`Until`: before its absolute keep-at-least or a purge request's floor at every node, or within D of the earliest replacing write the node holds; `Plain`: uncovered, or covered by no snapshot holding the right), `Leftover(why)` (strip values), `MayDrop(Covered)` (convenient, or past T: a valid snapshot whose commit holds the purge right over the body covers it), `MustDrop(why)` (`Covered` under purge-on-replace, at every node; `Gone`: a waiting part past its expiry or an unjoinable body expired or purged, which counts as never received; `PastBound`: a signal body, whole or leftover, past its keep bound), `NeverReceived`.
- Signals: nothing of a signal aspect joins (read `Absent`, empty state); a valid content body on one is replaced at its own `ts`, so `history()` shows its write until its keep bound (`signal_kept`) unless purged.
- `replaced`: held valid bodies holding a write the canonical state does not, with `replaced_at`: the wall ms of the earliest valid replacing write held (by its signed `ts`); `history`: per aspect the replaced writes of kept bodies whose keep-at-least still holds here (`history()`, a function of the held set); `owed`: replaced purge-on-replace bodies no valid right-holding snapshot covers while `me` holds the right (the cover `me` owes in the replacing transaction, `cover`); `uncovered`: dropped bodies whose cover (or purge) fell, to be fetched again.
- `deadlines`: every clock value after `now` at which the output may change with the held set unchanged (unparking, expiry, keep-until).
- `valueless`: deltas held value-less (expired, purged); `forbidden`: every value of theirs still held, with the body. An engine holding the same set must hold none of them once it has acted.

`act(&Held, &Outcome, may)` carries out the forced fates (strips, drops, makes the uncovered and never received missing, and one optional drop) and returns the next held set; `cover(&Held, &Outcome, thing, aspect, id, ts)` the covering snapshot `me` writes from its whole state (retention by `snapshot_retention`: purge-on-replace when it carries a purge-on-replace write, else `writer` kept for the longest D among the carried writes' own deltas); `timeline(&Held)` the settled role timeline; `undo::undo(&Held, target, id, ts, author)` the undo commit node `me` writes (spec/crdt.md §4.6); `gen::history(seed, n)` builds a random history (writers cover what they owe most of the time), `gen::shuffle` reorders one.

## Input changes
For adapters written against the previous input (one change per line):
- Retention is `{ by, history }` (history modes); keep bounds, `own_state`, `dropped_valid`, `at_most`, `deaths` and `keep_in_state` are gone: every drop is as covered (`Body::Dropped(by)`), purge or expiry, and the state is the join of the held bodies.
- Apply follows spec/commits.md §4 as of whole-commits step 3: no atomic apply, no "counts as held" clauses; feed a part the node does not hold as `Body::Missing`, and `Body::Dropped(by)` only for a body the node itself dropped as covered (its commit applied).
- A waiting part of an applied commit that a request names is `Leftover(PendingPurged)`, not in `purged`.

## Properties (`tests/it/props.rs`)
`settle` carries out the forced fates, writes the covers `me` owes, and (given the full history) fetches again what `uncovered` or `NeverReceived` names.
- The output is a function of the held set (any order of commits and writes). The histories include every history mode, undos (written by `undo::undo`), invites, `until`, self-removals, finalizes, link redemptions, acting for an account, `required^.0`, parked parts and unknown records.
- Forced fates change no read (but a waiting part gone at its expiry or purge, which can make its commit apply) and leave no forbidden value; each optional drop changes no read.
- Once a right holder has settled, it holds no replaced purge-on-replace body (but as an expired or purged leftover, or before a purge request's floor), no body is dropped before its absolute keep-at-least but by purge, and `history()` shows no body the node may drop.
- A commit arriving after the node acted on the rest, and the same commits arriving one at a time in any order with the node acting as they come, read as one held from the start, once bodies whose cover or purge fell are fetched again; aspects where a part went at its expiry while waiting excepted (spec/requirements.md, Deterministic limits). 2400 seeds pass.
- A signal's `history()` reads alike in both convergence properties above.
- The output is constant between `now` and its first deadline.

## Adapter use
osis-node `tests/it/held.rs` maps what a node holds into `Held` (its history modes: purge on replace is `PurgeOnReplace`, keep history is keep-at-least, none given convenient) and compares applied commits, validity, reads, fates, bodies dropped, state writes no held body carries, covers owed and `forbidden` (scope and normalizations in its module doc); `order::held_set_decides` runs it on every node it judges (`Cfg::model`; also `held_model_agrees_*`), as the reference independent of the engine. Run this crate's properties with more seeds by raising `SEEDS` locally.
