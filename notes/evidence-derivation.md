# Evidence derivation
> Summary: `osis_engine::evidence` as built: the copies a sync ID requires, derived from a node's held copies and the sync ID's unit by spec/permissions.md §4 under E1 (every edge write on a stated path's edges and on the edges a member writes) with delete-key steps; the engine keeps one fed per commit (`evidence::kept`), read by `sync/certified.rs`; the engine's input and check (`evidence::held`), engine hand tests; inputs, output, what re-derives what and its cost; the differential against held-model `Stage::E1` (0 disagreements), hand worlds and counts; carried demotions, added beside it.

**Principle: a sync ID's evidence is a function of the copies the node holds and the sync ID's unit: the least set the spec's rules close over them. Nothing is logged once and remembered; a change re-derives exactly what it can move, and the incremental answer is the from-scratch answer by construction (same closure step, same seeds).**

## Input
Per held **copy** (commit ID, thing), held whole (a commit's edge writes on a thing are one `roles.0` delta, spec/crdt.md §2), its parts on that thing (`evidence::Part`), as the derivation's own structs (independent of header types):
- `kind`: content (anything with no edge write: content, purge requests, snapshots, `sync.0`) or an edge write (`Write`: its holder, and `gives_read`: read or above, any `until`, no self-removal, applied in the walk here).
- `hops`: the edges of the path its commit states for that thing, key hop first (a hop's holder is a thing or a key: the derivation is generic over its holder type, `evidence::Holds`); `None` while not known here (a split entry waiting to open: notes/path-form.md); `open_path` when it opens. A part with no known path brings no path edges.
- `dels`: the delete keys it lists at levels 1 and 3 for its thing's delete base (`Del`: base, level, key; spec/crypto.md §7).
- `steps`: the steps a `sync.0` part records on its thing (`Step`: ID, parent, delete and write keys; spec/sync-ids.md §2).
- Per sync ID: its actor and its unit's things (`join`, `leave`).

No validity, no order: E1 takes every held write "whatever their validity or order", so the derivation reads no walk output itself. The one verdict in its input is `gives_read`: an invalid or pending write giving read opens no keys. A copy re-derives when its writes' standing moves (`copy_parts` reads the walk, stamped).

## Output
`required(sid)`: every copy on a thing outside the unit in S's evidence, with one **reason** each (`Reason`: a write on an edge the set uses; a write recording a step that places a listed key). `stepped(sid)`: the members recording a step that places a listed key, whatever reason each entered by (a copy keeps one reason, so a member entering by an edge and also recording such a step is told apart only here): those whose `sync.0` part S's cut holds; `closure_of` returns them beside its members, seeds included. Bodies (held copies on unit things) are S's sync unit blobs, not output. `from_scratch(sid)` the same from nothing. A copy is a whole (commit, thing), never keyed by commit alone (a role commit on two things is two copies). Records (members' creation records up their record chains) are not output: `sync_ids/certs.rs` takes them from the bodies' and copies' paths.

## The rule (spec/permissions.md §4 under E1)
S's evidence is the least set of copies holding:
- **seeds**: the bodies' known path edges and listed delete keys (`atoms`, counted per body).
- **closure**: an edge brings every held copy with an edge write on it; a delete key brings every held copy recording a step from its base's genesis to a step bearing the key (the parent chain of each bearing step, as far as held steps reach); a member copy (outside the unit) brings its parts' known path edges, the edge each of its edge writes sets, and the keys it lists.

"The edge each of its edge writes sets" is finding 9's clause: a removal applies only once the creations of the entries it resets are held (spec/permissions.md §2), and those creations are writes on the edges the commit writes. held-model's `Rule::commit_edges` brings the edges of the commit's *other* parts; the two give the same members (a member's own edge's writes are already in: it entered by that edge, or as a travel seed whose edge's writes all name the same open holder).

Unjoined paths and junk (a non-admin's writes on a used edge) are copies under E1: the roster leak and junk copies of notes/a2-spec/README.md Open 2.

## Steps
Per (base, step ID) the held step and the copies recording it; per (base, level, key) the step IDs bearing it. A key's placement is walked inside the closure (`Item::Del`), memoized per closure (`dels`). A copy recording a step arriving or leaving closes again every sync ID placing a key of that base (`base_sids`): steps move only with rotations, a rare path paid at closure size. A body listing a key another body lists walks nothing (counted atom).

## Incremental
State per sync ID: `atoms` (per edge and per key, the bodies bringing it) and the closure (`members`, `edges`, `dels`). Global indexes: copies per thing, per edge written, per holder; steps. Reverse: edge → sync IDs using it, copy → sync IDs holding it as member, thing → sync IDs whose unit holds it, base → sync IDs placing its keys.

Monotone changes extend the closure from what they add (`close`); a change that can shrink it (a forget, a body's last atom gone, a retag out, a step moved) marks the sync IDs it touches dirty, and each is closed again from its atoms and seeds (O(its closure), never O(its bodies)).

| change | cost |
|---|---|
| body appended on a path of k edges | k atom increments per sync ID whose unit holds its thing; an edge new to S closes from it |
| copy with an edge write on edge e | the sync IDs using e take it: O(those + what it brings); no body scan |
| path entry opens | its edges' atoms where a body; pushed into each closure holding it as member |
| body forgotten | its atoms out; S closes again only where it was the last on an edge or key; `forget_all` closes each sync ID once |
| thing joins or leaves S's unit (b bodies) | b bodies' atoms; S dirty if it held copies on the thing, or on leaving |
| a sync ID taken back (`remove_sid`) | its unit, open set and closure leave the reverse indexes: O(those) |
| from scratch for S | linear in bodies·k + closure |

Memory per sync ID: its used edges and keys, members and reasons, atom counts: O(edges and keys its bodies use + copies), not O(bodies).

The module takes changes by call and does work in proportion to them. Its lookups are stamped (`Ix::stamps`, one key per `Row`: a copy's parts, the copies on an edge, the steps bearing a key, a held step, a sync ID's closure; any other read is of the whole), so a value derived from it (`osis_base::memo`: a read thing's certificates) is due exactly when a row it read was written. A sync ID's row is written where its closure moved (`extend` adding an edge or member, `reclose` ending on another closure), never by a body that only counts an atom.

## Carried demotions
A removal reaches a thing other than its own by the evidence closure (wherever a node holds both it and a write on its edge it judges) and by **carried demotions** (spec/crypto.md §4): a keyset of M lists the explicit demotions below write or admin its rotator holds applied on M or below it, and is held only with those edge writes. `sync_ids/certs.rs` adds the `roles.0` parts of the demotions a placed keyset carries (`carried_demotions`) beside the derivation's output; the derivation does not seed its closure with them, as held-model's `Rule::keysets` does (issues/engine-evidence-trails-model.md; notes/a3-spec/README.md Open 8 makes them a seed).

## The engine's input (`evidence::held`)
`held::copies` reads every commit in `ix.commits` (any validity) into copies, from the index and the held `sync.0` bodies, nothing kept:
- Per aspect on a thing one part; a `roles.0` aspect one part per edge write its commit makes there (`ix.held.edge_commit`: kind, holder, `gives_read` from the edge, no self-removal), hops by `osis_perm::paths::hops` along the role commit's one path; every other aspect and each purge item a content part, hops from `validity::stated` (`None` while a split entry is unopened). An unresolved removal (no ops) is one content part.
- `dels`: the aspect's header keys at levels 1 and 3, each for the thing up the record chain whose steps bear it.
- `steps`: each step entry whose step a held `sync.0` body writes, walked in the fragment (a step joins the sync ID entry its genesis made, so a read of the delta alone shows none); snapshots included, which is how a role compaction keeps steps evidence (Open 4: a carried entry keeps its recording write's stamp).
- Records: `held::mint`, every held record naming a mint admin.
- Header keys are step keys (`Core::listed_step`), so step evidence places them on engine data; a key's base is the thing up the record chain whose held steps bear it (`Core::key_base`), else the thing's delete base.

**The check** (`Engine::check_evidence`, tests; run by the order harness's `node_checks` and `evidence::engine`): per thing t with a held part, as a sync ID whose unit is t alone, the derivation built with the copies in reverse order and units last agrees with the one built units first, `check` holds (incremental = from scratch), and a reader holding t's parts plus exactly the required copies judges every part on t (content validity, edge write status) under osis-perm `Paths::evaluate` of the engine's readings (`validity::reading`, empty trust) as the node holding everything. This is the engine side of the joint property; a full engine-to-held-model `Stage::E1` adapter would test the derivation the plain differential already compares, so it is not built. Withholding the copies fails it on the role-paths world.

## The kept derivation (`evidence::kept`)
The engine keeps one derivation (`Core::evidence`, `Engine::kept_evidence`): every held commit's copies, every held record's mint admin, each read thing (`SyncRows::read`) as a sync ID with itself as actor and its sync unit. Each input is followed per key by a `memo::Effects` (a held commit's `copy_parts`, a thing's mint admin, whether a thing is read, whether a read thing's unit holds a thing), wanted from the containers' feeds (`ix.commits`, `Held::records_feed`, `SyncRows::read`, `Closure::member_feed`), so an ask settles the keys whose reads were written since the last and gives each difference to the derivation (`add`, `forget_all`, `add_record`, `remove_record`, `add_sid`, `remove_sid`, `join`, `leave`). A rollback moves the stamps it undoes, so the keys it touched settle again.
- A commit's copies change without the commit: a record up one of its things' chains arriving, its role commit reading resolving, its split entry opening, its `sync.0` body arriving. `copy_parts` reads each through a stamped container, so the commit is due by itself; nothing names these cases.
- `sync/certified.rs` follows each read thing's certificates by what deriving them read (`Effects<Tid, Certs>`; `sync_certificates`: `required`, `edges`, and `closure_of` for mintings, frozen history and current keys, each a stamped read of the derivation's rows, beside the engine's indexes), so a follow derives the certificates of the things whose inputs moved and writes their rows' differences (`Certified::put`). A certificate is its seeds closed over records: each record's contribution (the records up its chain, its mintings with their evidence: `Engine::record_certificates`) is a memo per record (`Core::record_certs`), merged per follow, so a make derives the new record's alone; the merge and the rows' diff stay O(the certificate), set operations only. A memo answer read through `Engine::certificates`' copy is the kept derivation's (no closure reads a sync ID); one derived on the copy reads the copy's stamps, which move when it drops. The follow is counted (`certified: follows`, `certificates: record contributions derived`; osis `making::making_a_dependent_thing_costs_what_it_changed_*` flat at 80 and 400 things). The asks outside a follow read the derivation as it stands (`evidence_now`); `Engine::certificates` of a thing not read adds it as a sync ID on a copy.
- A copy of the engine copies the derivation (`kept::Own`): its stamps are the copy's, as the copy's followers' reads are (`osis_base::copying`). Shared by `Arc` between a world and its copy, the copy's first change cloned it outside the copy and its followers kept reading the stamps of a table nothing wrote.
- Oracles: `Engine::kept_differs` (the kept copies, records, sync IDs and each sync ID's required copies and edges against `held::derive` over the same inputs, and the derivation's own `check`) and `certified_differs` (each read thing's followed certificates against `sync_certificates` anew, the rows against those written from nothing), run by `check_evidence` and, in debug builds, at the 1st, 2nd, 4th, ... follow of each engine.
- Counts: one more write on a granted thing reads that commit's copies and takes one body, at the writer and a reader, after 10 and 100 held writes (`evidence::engine::a_write_costs_the_kept_derivation_what_it_moved_at_n_and_10n`); a write on one of 3 or of 30 read things derives the same things' certificates, at most 2 (`a_write_in_one_of_n_read_things_costs_the_certificate_follow_the_same_at_n_and_10n`).
- Records ride beside evidence (a reader needs the creation records of the things on the paths); carried demotions are added by `sync_ids/certs.rs`, not derived here.
- Every copy a certificate carries is cut (`Cut`, `Engine::cut_parts`: spec/permissions.md §4 Copies) and closed over the derivation (`add_closure`, each closure copy cut to evidence), whatever put it there: required copies, stubs, frozen history, and each holder's public key record (`public_key_record_into`: its current `keys.0` commits, whose listed keys' steps a reader needs to judge them; the mint admin's among them).

## Engine hand tests (`evidence/engine.rs`)
- Finding 9: X removes K and Q from A in one commit; K wrote D through [A] before (listed) and after. D's evidence holds the removal and both creations; a reader engine handed D's bodies, A's record and exactly the required copies judges both writes as X; one handed them less X's grant to Q holds the removal unresolved and takes K's later write as valid.
- Open 4: after G issues steps and compacts `sync.0`, the snapshot records every step, its entry keeps the recording write's `ts`, and with the recording writes forgotten it alone places a dependent's listed key (`Reason::Step`).

## The differential
Against held-model `evidence` under `Rule::fixed` (the spec's closure with chain stubs, notes/stub-rewrite.md Model findings; `Rule::keysets` off), at every held set: per step of a world, for every node's held set and every sync ID's held entries, for every sync ID, the copies kept incrementally and from scratch against the model's required parts on things outside the unit, by (commit, thing); each held set's `gives_read` is the model's own judgement over it (`World::reads_valid`), as the engine feeds its walk's. The model writes each part of a commit as an event of its own, so a held set can split a copy: no node holds such a set; it is stepped through and `check`ed, not compared. Story worlds with key-hop writes or foreign keys are skipped.
- Plain property: every 291st family world, the story world of seed 0 under each of the six unit crossings.
- Large property: `the_derivation_agrees_with_the_model_large_spec_permissions_4` (full: every 17th family world, 1,500 random, 60 story seeds; the gate's a tenth).
- Hand worlds (`hand.rs`): each model hand test naming a rule or finding, with the copy the rule decides (f9 by the edge it writes, f11 and f13 the leaks E1 accepts, f14, f15 with junk copies counted, f23 a read hop bringing its writes, split, P4, f2); the derivation's own (a waiting path entry, a member's written edges, a removal evidence only where a body rests on its edge). The walk-level check (`walk.rs`): a reader holding D's bodies plus exactly the required copies judges every body of D as the writer under osis-perm `paths`, and less any one copy a verdict reads, not alike. Steps (`steps.rs`): genesis-to-key chains, siblings left out, either arrival order, forgets, a member listing a key.

## Counts (`counts.rs`, `steps.rs`, at n and 10n)
- A body appended on a path of k edges: k + 1 atoms, no closure work, the same at 10 and 100 held bodies.
- A role commit on an edge m bodies use: no body read, no closure again, at most 2 copies visited.
- A thing entering a unit with b bodies: b + 1 bodies read, 3b + 1 atoms.
- From scratch: one body read each; a sync ID keeps the same edges, atoms and copies at n and 10n.
- A write naming an actor: no earlier write naming it read.
- A body forgotten: 2 atoms and no close while another body uses its edges; the last on an edge one close of m visits (m = 10, 1,000); a compaction's 10 last bodies in one `forget_all`: one close.
- A body listing a placed key: no step walked, no close, at chains of 10 and 100 steps.
