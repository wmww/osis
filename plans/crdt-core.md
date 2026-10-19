# CRDT core: framework, non-sequence encodings, wire, join, diff, snapshots
> Summary: Implement spec/crdt.md in `osis-crdt` except sequences (plans/crdt-seq.md): stamps and dots, the fragment model, register/bag/struct/enum/set/map, join/prune/presence, the wire grammar with every §3.3 rejection, slots and embeddings, value-less writes and expiry stripping, un-merge, structural diff with a `View`, snapshot deltas with frontiers and paging. Differential-tested against models/crdt from the first commit.
> Tags: crdt, tests

Crate: `osis-crdt`. Depends on: osis-core. Dev-depends on: models/crdt. Unblocks: crdt-seq, commit, node-core.
Spec: spec/crdt.md §1–§5.6, §7–§9; spec/commits.md §4 (atomic apply expectations), §5 (death tracking). Notes: notes/crdt.md (design reasons, implementation hints, what the model does not check). Spec trumps this plan.

## Deliverables
- Types: `Source` (Node/Commit/Derived), `Dot`, `Ts`, `Stamp` with the §2.2 total order; `CounterRange`; interning of sources so a state does not repeat 15/32-byte sources per write (the model stores them in full; the implementation may not).
- `Fragment` enum with every encoding including `Seq` (its state struct per §5.7 declared here; its join/read/ops/encode land in plans/crdt-seq.md and return `Error::Unsupported` until then, never panic) and `Slots`.
- Join, prune (effective reset, `>=` survival, tombstones, emptiness), presence (`written`, explicit `W`), read to `osis_core::Value`, per encoding §5.1–§5.6.
- Join reports a **change summary**: paths whose read may have changed and the writes that **died** (§4.8) with the superseding `ts`, so node-core can fire listeners and track retention per body without re-reading everything.
- Wire: encode/decode `Delta` and `Snapshot` (§3.2) byte-identically with the model; the `Sources`/`Commits` tables and bare forms (§3.3 rule 1); every rule 7 rejection, including those the model is lenient on (run maximality is seq's, nested register resets, Slots reset equality, own-counter range checks §2.3, foreign stamps in a non-snapshot delta). Decoder bounded (sizes from `format`).
- Ops producing deltas (§4.5, §5.x): set/replace/remove_aspect, set_field, set_case, add/remove/replace for sets, put/remove for maps (lowest live dot rule), inc/set for bags, with counter consumption exactly per §2.3 and the net-effect rule (omitted elements, anchor rewriting hooks for seq).
- Undo per §4.6 for these encodings (needs an undo buffer of pre-reset values: define the `UndoBuffer` trait node-core fills).
- Un-merge (§4.6): `unmerge(bodies, residues, author) -> State` as the join of held bodies minus the author's writes; an in-place fast path only where the spec permits (creations, flags, resets, elements), with a test that both agree.
- Value-less writes and expiry (§4.7): `strip(delta_or_state, range)`; join of valued and value-less copies; snapshots carry expiring deltas value-less.
- Slots and embeddings (§7): pointwise join, register embedding into bag/struct/enum/set/map (text embedding is seq's), chosen-member read, one reset per position.
- Structural diff (§9) for these encodings with the `View` trait (identity view for untyped writes); opaque elements never touched; defaults never materialized (the `View` reports a field's declared default).
- Value-to-value diff for the API's `edit(base, new)` (notes/api.md Writes): `diff_values(base, new, view) -> Vec<PathOp>` over struct fields, enum cases, map keys, set elements and bag values (exact by id/key/value, no state needed), with sequence positions delegated to crdt-seq; the ops then resolve against the current state like any path op.
- Snapshots and paging (§8): `Frontiers`, received-range bookkeeping input; paging of any fragment, delta or snapshot: an element array above `PAGE_TARGET` is split at content-defined boundaries (osis-core chunker, 16/64/256 KiB) into pages written through `PageSink` (returns `Link`s) and read through `PageSource`; canonical (mandatory above, forbidden below); two-level link pages.
- Performance posture: state structures sized for maps with many entries (BTreeMap by dot; local `key -> live dots` index); no O(state) work for a small delta beyond the touched elements; paged states live in the store (plans/store.md), so expose join over a page at a time.

## Steps
- [ ] Types, order, interning; `Fragment` skeleton with all variants; wire grammar types. Commit this skeleton early and record "skeleton merged" in Progress: plans/crdt-seq.md starts from it.
- [ ] Register, struct, enum, set, map, bags: join/prune/presence/read; differential tests against models/crdt (random op sequences from the model's generator; equal reads, equal canonical bytes, equal under random delivery orders and duplication).
- [ ] Wire encode/decode + rule 7; every rejection a negative test; the model's lenient cases covered here.
- [ ] Ops, counter consumption, net effect; undo; diff with View.
- [ ] Slots/embeddings, value-less/expiry, un-merge; snapshots, frontiers, paging through PageSink/PageSource (in-memory impl for tests).
- [ ] Join laws proptests (commutative, associative, idempotent; across encodings); benches (join of a 10^5-entry map delta, read, encode) with criterion.

## Tests
Everything in notes/crdt.md "Reference model" plus the listed additions: own-counter range checks, strict rule 7, value-less embedding, bootstrap-from-snapshot-then-edit convergence, paging (every page within bounds, pages re-join to the state, equal states give equal pages). Tier 1 runs at small sizes; tier 2 (`#[ignore]`) at large.

## Done when
Every encoding but seq round-trips, joins and reads identically to the model under the differential suite; the crate has no `Unsupported` paths except seq; notes/crdt.md gains an "Implementation" section (structures, interning, change summary). Delete this plan when crdt-seq is also done, folding both into notes/crdt.md.

## Progress
