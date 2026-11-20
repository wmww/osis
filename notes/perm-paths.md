# osis-perm: the walk along stated paths
> Summary: Design and build state of osis-perm's walk along stated paths (A1 step 3a, `osis_perm::paths`): its one rule, input and output, the event log that makes from-scratch evaluation and incremental update one definition, cost shapes and their count tests, what the differential against roles-model `paths` compares and at what size it passes, the draft-spec corrections it forced, and what steps 3b and 7 owe.

**Principle: a part's right rests on the edges of the one path it states, read in key order, and a lowering is judged once, at the first pass that reaches it holding its right.** Every rule of notes/a1-spec/permissions.md §5.1 follows from it: what a part needs of each edge (admin, an invite grant's invite, a finalize's write), what a lowering puts in question (the parts resting on its edge whose need it no longer meets), when it is void (its drops would take what its own path rests on, or its remaining admin), the last-admin rule (one named edge, read in the pass), seeds (a trusted write's drops read before the walk). Nothing searches for another path.

## Input
Plain structs (`paths::Commit`, `Part`, `PartKind`, `EdgeWrite`), independent of the header's types, so the header's renames do not reach them; step 2 writes the adapter from held role commits.
- `Commit`: commit ID, `ts`, signer, its edge-class parts. `Part`: the thing written (`on`), the stated path [A1..Ak], and an edge write (holder, value as `types::Edge` or a removal, frontier or none, remaining-admin holder, adminless mark) or a vouch.
- `remains` and the mark are per part, not per commit: the header carries one of each per commit (the adapter copies it to each part); roles-model gives each part its own, and per part covers both.
- Records: thing to mint admin, given at construction (descent reads them); a changed record set means a new `Paths`.
- Trust set: `WriteId`s (commit ID, part index in the commit's input order).
- A finalize is not flagged: it is a removal of another holder's grant with no frontier that is not a self-removal (spec/permissions.md §2 Finalize), read off the part.
- Order within a commit (§5.1 step 1): by thing written, then `roles.0` before `vouches.0`, then the part setting an edge of the commit's own path last (a self-removal of the path's last thing, or the final record edge of a descent), then holder tid. Assumed: the header orders its aspects by thing then AK; step 2 checks this against the header.

## Output
- Per part: `Status` (applied, applied as an invite grant, void, dropped, unapplied: held, judged by nothing or skipped).
- Per edge: its history in the settled walk (key, value per applied write), the value just before any key (point query), the final values (`until` counted removed) and invites.
- Trusted writes the settled walk does not apply (void, seeds lost).
- The dispute set (`Candidates::Explicit`): read over what applies and the final roles; step 3b widens it with content validity.
- `Changed` from each update: the parts whose status changed and, per edge, the earliest key from which its history changed. The engine reacts only to that.

## One definition: the walk as an event log
The walk is a run of passes over the held parts in key order; D and the verdicts carry from pass to pass. The implementation keeps:
- the pass state (per edge: value, edge as restored in role and invite, history; per part: applied, applied as invite) with an undo entry per applied part, so the state can be rolled back to any key;
- an **event log**: each verdict given (the lowering's key, its drops) in the order the walk gave it.
A pass that ends at a lowering whose drops join D does not restart from the start: it rolls the state back to the commit of the earliest drop and continues, since every part before that point replays unchanged (D and the verdicts changed only after it).

Adding commits whose earliest part is at key p (no trust set): the log is cut at the first event given at a key ≥ p; every event from there on is forgotten (its verdict and drops cleared), and the state is rolled back to the earliest of p, those events' keys and their drops' keys; the walk continues from there. Why that equals the from-scratch walk: every event before the cut was given by a pass that had walked only parts before p, so the from-scratch walk over the larger set gives the same events in the same order, and its pass state at the rollback point is the state the kept events give. From scratch is the same call with the log cut at the start. No cache, no fallback, one code path; debug builds may compare.

With a non-empty trust set the walk is evaluated from scratch on every change (seeds read every held part before each trusted write, and the redo for a void trusted write starts over). Components are not split yet: one walk holds every thing.

## Cost shapes
- A part appended at the end of key order: its own steps only: a point query per hop (an edge value read), plus, for a lowering that falls, the parts resting on its edge (its candidates: the index `resting` per edge) and its void check.
- A void check (`keeps`) reads back along the setters of its path, each grant's own path in turn, memoized per check: k void lowerings at the end of a chain of k grants cost k² setters read (finding 17; accepted, Open 2). Iterative, never recursive (an adversary's chain is unbounded).
- A backdated part, or a lowering applying with drops: the walk from the earliest affected key: every part after it is walked again, over every thing (no components yet).
- From scratch: one step per part per pass, passes = 1 + restarts; each restart walks from its earliest drop.
- Disputes: one from-scratch walk per candidate (Open 3 (a)).

## Built
- `core/perm/src/paths/` (`mod.rs` the input and output types, `walk.rs` the walk): every rule of draft §1 Path (hops, descent, the last edge), §2 (edge writes, self-removal by path end, finalize, invite grants), §1 The last admin (`remains`, the mark, the remaining admin kept past the drops), §5.1 steps 1 to 5 (order within a commit, passes, verdicts, drops, `keeps` as an explicit stack, the restart from the earliest drop), Trust set (seeds by need, the redo for a void trusted write), disputes (`Candidates::Explicit`, over what applies and the final roles), vouches walked as edge-class parts (entries unread), several edge writes per commit (a repeated holder makes the commit bad input). Incremental `add` and from scratch by the one event-log path above; `Changed` from a journal of first values kept while an update runs. No unsafe, no new dependency, no indexing that can panic (`Tab`).

## The differential
`core/perm/tests/it/paths/` against roles-model `paths` under `Rules::fixed` with `Vouch::Off` (the first walk: vouches walked, entries unread). Per node view (held set, the frontier leaves it sees, its trust set) it compares every edge-class part's status, every edge's history (the applied writes in key order), the final roles and invites (every edge the walk set, as the model's `roles`), the void trusted writes, and the dispute set (the model's `disputes_by` with what applies and the roles; content validity is step 3b's).
- Hand worlds (`hand.rs`): a counterpart of each rule-naming model hand test, same names, at the views the model's test reads; two of the walk's own (`an_ended_value_restores_its_role`, `keeps_passes_over_a_fallen_finalize`) where no model test reached a rule.
- Default: `tiny_worlds_agree` (150 worlds of each of the six `tiny` kinds, disputes compared), `story_worlds_agree` (36 story worlds at every node, disputes in 6), `incremental::incremental_equals_from_scratch` (200 worlds of each kind, commits added one at a time in a shuffled order: each `Changed` equals the difference of the readings, the end equals from scratch).
- Properties: `paths_tiny_agree_large` (160,000 worlds), `paths_story_agree_large` (8,000 story worlds at every node), `paths_incremental_agrees_large` (60,000 worlds). All 0 disagreements at full size (`OSIS_FULL=1`), about 60, 130 and 40 CPU-s; the gate runs a tenth: about 25 CPU-s together.

## Mutations
Each control of the model that reaches edge-class parts, taken by the walk as a source edit, fails the default tests, each by its named hand world: `-no-void`, `-exempt`, `-audit-applied`, `-admin-falls`, `-own-drops`, `-remains-unkept`, `-leave`, `-invite-role`, `-any-edge`, `-timed`, `-last-any`, `-all-candidates`, `-seeds-all`, `-refuse-shapes`. So do rules with no control: the verdict's raise check (finding 27), no drop or seed reaching its own commit, the own-path part last, a finalize's role, an invite grant's need as an invite, a self-removal only lowering, the edge as restored disregarding `until`, `keeps` passing over a fallen finalize. Not applicable here: `-once`, `-listed`, `-key-order` (writing policy: step 5), `-own-vouch` (vouch counting: 3b).

## Counts (`counts.rs`, at n = 100 and 1000)
- A part appended at the end: 1 step, 1 pass, nothing audited (a grant, a write along two hops, a removal of an edge nothing rests on).
- A backdated part: n + 1 steps (the walk from it on), also on a thing the history never touches: no components yet.
- A lowering applying with drops: 1 restart, from its earliest drop (the parts after it walked again, never those before); audited = the parts resting on its edge.
- A void lowering at the end of a chain of k grants: its check reads about k setters (k = 10 and 100: tenfold); k of them about k² (finding 17, accepted).
- From scratch: one step per part.

## Where the walk departs from the model
- A finalize is a shape on the wire (a frontier-less removal of another holder's grant that is no self-removal); the model flags it. A frontier-less removal of a holder's own grant by a path ending at it is therefore a self-removal and applies; the model, reading its flag, judges it a finalize (`a_finalize_ends_an_ended_grant_and_an_invite_follows_it` pins the walk's reading). No generator makes such a write.
- A self-removal lowers in every component the spec names: role, invite, `until` and `floor` (`types::lowers`); the model compares role and `until`, and reads a removal as role none with no `until`, so its self-removal removing a timed grant raises the `until` and applies nowhere, where the spec's removal always lowers. Its generators make neither case (0 disagreements at full size).

## Draft spec corrections
- notes/a1-spec/permissions.md §5.1 step 4: the writes `keeps` passes over when their own `keeps` fails are grants and finalizes (the model reads any write that is neither lowering-shaped nor a self-removal so; a finalize is neither).

## What step 3b needs from it
- Content validity reads the settled walk's histories (role before a key: `role_before`) and its cuts: an applied explicit lowering on an edge of the path taking it, as restored, from the role needed to below. The edge as restored just before each applied explicit write is in its undo entry; expose it with the history.
- Vouches' second walk: `listed` reads a lowering's frontier; the counting entries join it there (`Walk::listed`), and the first walk is this walk.

## What step 7 owes
- Components: a backdated part or a restart walks only its component (things joined by a part's thing, holder, signer, path, named holder and record chains); today any backdated part walks every later part over every thing (`counts::a_backdated_part_walks_again_what_follows_it` asserts n + 1 for a thing the history never touches; with components it is 1).
- Trusted walks incremental (today every change under a non-empty trust set is a walk from scratch, and each redo for a void trusted write another); disputes walked per component, not over every thing (Open 3).
