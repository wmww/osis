# CRDT sequences: text and list, linearization, moves, diff
> Summary: Implement spec/crdt.md §5.7 and §6 in `osis-crdt` on top of the crdt-core skeleton: runs, creation and anchors, top-2 positions, deleted flags and element resets, bare anchors, linearization with cycle breaking, move, insert/delete/undelete, text and list diff (Myers, LCS with in-order pairing), register-to-text embedding with Derived sources, run canonicalization, snapshot emission, and the size budget from notes/crdt.md.
> Tags: crdt, tests

Crate: `osis-crdt` (modules `seq`, `linearize`, `seq_wire`, `seq_diff`). Depends on: crdt-core skeleton merged. Unblocks: node-core text/list support, api text sessions.
Spec: spec/crdt.md §3.2 (Run grammar), §3.3 rules 2–3, 5, 7; §4.3 (presence for sequences), §4.7 (text elements, Derived records), §5.7, §6, §7 (text embedding), §9 (list and text diff). Notes: notes/crdt.md (worked examples, text size table, implementation hints). Spec trumps this plan.

## Deliverables
- Element state per §5.7 (`created`, content, `pos` top-2, text `deleted` LWW / list `R_elem`), record-never-dropped rule, bare anchors, Derived records that go with their last write.
- Join (union by dot, first-seen creation/content, top-2 of union, max flag/reset, fragment join for lists), prune, presence (value-less creations do not count), read (linearization → string or list of reads).
- Linearization §6: children greatest-first, DFS, hidden subtrees for unknown anchors, Derived anchors absent → bare anchor at END, cycle breaking by demoting the smallest-stamp edge to its next candidate (cur → prev → END), END ordering by dot. Implementation: incremental cache (re-place touched subtrees; recompute an SCC on cycles) with a test that it equals the whole-state algorithm on random states.
- Ops: insert (creation run), delete (flag/element reset per maximal dot run), undelete with content, move (roots, pred, outside in reverse visual order, root chaining), cut/paste composition, list element nested ops, replace, remove_aspect; counter consumption and the net-effect anchor rewriting (§4.5).
- Wire: runs (maximal, ≤ 2^16, uniformity rules), segments, Content rules, PosW/FlagW ordering, bare-anchor emission in snapshots only, rule 7 rejections for runs; byte-identical with the model.
- Undo (§4.6, §5.7): text flag, list element reset, undelete, re-insert, position write back if still `cur`.
- Embedding register → text (§7) with Derived dots; anchors to Derived dots through `Sources`.
- Diff (§9): text Myers over chars (no move detection); list: opaque elements set aside, LCS by deep view equality, in-order pairing of unmatched, recursion, leftovers delete/insert.
- Sequence part of the API's `edit(base, new)` (notes/api.md): diff `base` against `new` (Myers/LCS as above), then rebase the resulting index edits onto the current sequence by matching `base` to the current read (LCS); an edit whose base position is unmatched lands after the nearest matched predecessor. Property: when current equals base the result equals the structural diff; with concurrent remote edits, remote content outside the edited ranges survives. The text session reuses the same rebase for remote merges.
- Bench: port `models/crdt/src/bin/text_bench.rs` to an osis-bench bench over the implementation; assert the ratios of notes/crdt.md (≤ 3.5x at 100 edits/commit, ≤ 7x at 10) as a tier-2 size-budget test.

## Steps
- [x] State, join, read with whole-state linearization; differential tests vs models/crdt text and list (random ops, random delivery, duplication).
- [x] Wire runs + rule 7; worked examples of notes/crdt.md as named tests.
- [x] Ops incl. move and cut/paste; undo; embedding; list nested ops (test: list delete vs concurrent nested write resurrects the element, spec/crdt.md §5.7).
- [ ] Diff; random undelete test; incremental linearization cache with equivalence test; bench and budget.

## Tests
notes/crdt.md worked examples (typing, concurrent inserts, move with concurrent insert, several roots, concurrent moves, cycle, reset against newer insert, displaced insert, delete vs move, unknown anchor) as named tests citing the example; the model's props for seq; large-text proptest at tier 2.

## Done when
Differential suite green for text and list; budgets met or an issue filed with measurements; notes/crdt.md updated. Delete together with plans/crdt-core.md.

## Progress
