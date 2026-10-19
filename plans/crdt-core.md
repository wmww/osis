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
- Un-merge (§4.6): `unmerge(bodies, residues, author) -> State` as the join of held bodies minus the author's writes (the current state counts as a held snapshot); an in-place fast path only where the spec permits (creations, flags, resets, elements), with a test that both agree.
- Value-less writes and expiry (§4.7): `strip(delta_or_state, range)`; join of valued and value-less copies; snapshots carry expiring deltas value-less.
- Slots and embeddings (§7): pointwise join, register embedding into bag/struct/enum/set/map (text embedding is seq's), chosen-member read, one reset per position.
- Structural diff (§9) for these encodings with the `View` trait (an `any` position takes the value kind's encoding, §3.1) (identity view for untyped writes); opaque elements never touched; defaults never materialized (the `View` reports a field's declared default).
- Value-to-value diff for the API's `edit(base, new)` (notes/api.md Writes): `diff_values(base, new, view) -> Vec<PathOp>` over struct fields, enum cases, map keys, set elements and bag values (exact by id/key/value, no state needed), with sequence positions delegated to crdt-seq; the ops then resolve against the current state like any path op.
- Snapshots and paging (§8): `Frontiers`, received-range bookkeeping input; paging of any fragment, delta or snapshot: an element array above `PAGE_TARGET` is split at content-defined boundaries (osis-core chunker, 16/64/256 KiB) into pages written through `PageSink` (returns `Link`s) and read through `PageSource`; canonical (mandatory above, forbidden below); two-level link pages.
- Performance posture: state structures sized for maps with many entries (BTreeMap by dot; local `key -> live dots` index); no O(state) work for a small delta beyond the touched elements; paged states live in the store (plans/store.md), so expose join over a page at a time.

## Steps
- [x] Types, order, interning; `Fragment` skeleton with all variants; wire grammar types. Commit this skeleton early and record "skeleton merged" in Progress: plans/crdt-seq.md starts from it.
- [x] Register, struct, enum, set, map, bags: join/prune/presence/read; differential tests against models/crdt (random op sequences from the model's generator; equal reads, equal canonical bytes, equal under random delivery orders and duplication).
- [x] Wire encode/decode + rule 7; every rejection a negative test; the model's lenient cases covered here.
- [x] Ops, counter consumption, net effect; undo; diff with View.
- [x] Slots/embeddings, value-less/expiry, un-merge; snapshots, frontiers, paging through PageSink/PageSource (in-memory impl for tests).
- [x] Join laws proptests (commutative, associative, idempotent; across encodings); benches (join of a 10^5-entry map delta, read, encode) with criterion.

## Tests
Everything in notes/crdt.md "Reference model" plus the listed additions: own-counter range checks, strict rule 7, value-less embedding, bootstrap-from-snapshot-then-edit convergence, paging (every page within bounds, pages re-join to the state, equal states give equal pages). Tier 1 runs at small sizes; tier 2 (`#[ignore]`) at large.

## Done when
Every encoding but seq round-trips, joins and reads identically to the model under the differential suite; the crate has no `Unsupported` paths except seq; notes/crdt.md gains an "Implementation" section (structures, interning, change summary). Delete this plan when crdt-seq is also done, folding both into notes/crdt.md.

## Progress
- Step 1 (skeleton merged): `Source` (Arc-interned) / `Dot` / `Stamp` / `CounterRange`, `Fragment` with all variants, `Seq` types and hooks in `seq.rs`, `View`, `PageSink`/`PageSource`, `Writer`, `Changes`, wire `Enc`/`Dec` tables; spec edit §3.3 rule 2 (own commit-form source sorts first).
- Step 2: delta-driven `join_into`/`prune`, presence, read, slots and embeddings, change summary; differential lockstep vs the model (tid/enum tags aligned to 1616/1617). Found and fixed (spec, model, impl) order-dependent nested slots; map key index still to do (ops step).
- Step 3: `encode_delta`/`decode_delta`/`encode_snapshot`/`decode_snapshot`; decode checks grammar, §2.3 ranges and claims, rule 7, then re-encodes and requires the input bytes (one check for every canonical rule). Byte-identical with the model in node and commit form; model sorts own commit-form source first and its generator no longer emits nested register resets.
- Step 4: `create`/`replace`/`remove`/`diff` (View-guided, write-for-write equal to the model's), `PathOp` ops through `Batch` (net effect: later op overrides, created-and-removed omitted with a `W` keeping the collection present), `undo` with `UndoBuffer` (pre-commit state implements it), `diff_values`. Spec clarification §5.6/§9 (diff against the key's merged read). Known: undo restores values, not absence (a collection emptied by undo stays present; no undo of a lone `W`). Map key index not yet built (ops scan entries).
- Step 5: `strip` (equal to the model; laws), `remove_author`/`unmerge`/`unmerge_in_place`, `Received` frontiers, bootstrap-then-edit convergence, paging through `PageSink`/`PageSource` with `PageParams` (bounds, two levels, third-level refusal, equal states equal pages, canonical rejections, format size; 10^5 at tier 2). Fixed an O(state) `is_empty` on every join.
- Step 6: join laws within and across encodings; the 10^5-map budget is a tier-2 timing test (`budget_big_map_spec_4_1`: create 53 ms, join 43 ms, read 132 ms, encode 224 ms / 31 pages, decode 276 ms, one-entry join 0.3 µs, release) instead of criterion (a heavy dev-dependency compiled by every `cargo test`). Open: issues/crdt-path-op-cost.md. Plan stays until crdt-seq is done.
- Review fixes: §2.2 Derived dots order right after the write they embed (spec, model, `Dot` order); `Slots` re-embedded on every prune; map diff writes stored keys (each stored key a view merges); bag redo; page expansion limits (each page once, link-list target, fan-out, nesting across pages); un-merge fast path also refuses an author `W`.
