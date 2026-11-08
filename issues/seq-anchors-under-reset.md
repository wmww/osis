# Sequence anchors pile up under whole-value resets
> Summary: A list or text that is replaced whole keeps a bare anchor for every element it ever had, forever, so an aspect replaced often grows without bound. The anchors only serve an insert concurrent with the replace; a reset could drop them if an insert can tell that its anchor is older than a reset. Needs a semantics choice, a model, then the build.
> Priority: normal
> Tags: crdt, tess-call

## Now
- A reset drops writes but never sequence element records (spec/crdt.md §4.2 Prune, §5.7). A record left with no write is a **bare anchor**: not read, placed at END (§6.2 step 3), emitted in snapshots.
- So `replace` and `remove_aspect` (§5.7) leave every old element as a bare anchor, also inside struct fields, map entries and list elements under a reset of theirs. Overwriting a list- or text-holding value n times keeps every element of all n values. A struct with one list field overwritten 20 and 200 times measured 7.4K and 53.8K of in-memory state; a run-compressed snapshot keeps about a byte per run (notes/growth.md).
- Why (notes/crdt.md, "Sequence records are never pruned"): an insert concurrent with the reset and stamped above it survives ("a newer write never loses to an older removal") and anchors on an old element. An element whose anchor is not in the state is hidden until the anchor arrives (§6.1), because a missing anchor can't be told apart from one that hasn't arrived yet. The bare anchor answers "it existed", and the insert lands at END, after the new content.
- The anchor carries no position, only existence. And it is kept forever to answer a question that only arises while a concurrent insert can still arrive.

## Possible fix
Let a node tell "pruned" from "not arrived" without keeping the record: an element record under a reset `D` with no surviving write can go, if any write anchored on it can see that its anchor is older than `D`.
- An anchor names a dot, not a stamp (§3 `Anchor`, `PosW`), and a commit-source dot does not give its `ts`. So the anchoring write would carry its anchor's creation `ts` (or stamp). That is a wire change to creation runs and position writes, a few bytes per anchoring write.
- A write whose anchor is missing and whose anchor's `ts` is below an effective reset at the sequence, then **either**:
  - **(a)** goes to END: what a bare anchor gives today, so reads are unchanged;
  - **(b)** is dropped (hidden like a write into a non-live element, §1): it edited content that no longer exists. This changes behaviour; Tess's call. (b) also drops the insert's own record from the state on the next prune.
- Records of elements created at or after `D` stay as now. So does everything without a reset above it (deletes by flag, element resets inside a live list): the leak is the replace case.
- Check the other reasons records are kept: Emptiness counts records (§4.2, "or anchor survival would depend on arrival order"), map-entry bare structure in key-erased records (§5.6), the undo and un-merge rules that name records (§4.6), sibling keys of position writes (§5.7, `PosW`'s fourth field), `Derived` dots (§7), invalid-snapshot copies (§4.2 exceptions). Each must still converge with the record gone.

## How to go about it
1. **Decide (a) or (b)** with Tess: one question, with the trade-off in user terms.
2. **Model first**: extend core/test/crdt-model (independent oracle, never patched to match the implementation) with the new prune rule and the anchor `ts`. Check by exhaustive small instances, plus TLA if the arrival-order argument isn't obvious:
   - convergence: the same writes in any arrival order give the same read, with drops happening at different times at different nodes;
   - the chosen semantics for an insert concurrent with a replace, in both arrival orders (insert first, reset first);
   - nothing else changes: reads of histories with no reset above an anchor are identical to today's model;
   - growth: the state after n replaces of a k-element value holds O(k) records, not O(nk).
3. **Spec**: rewrite spec/crdt.md §4.2 (the "never removed by prune" rule and its exceptions), §5.7, §6.1 hidden elements, §3 wire for the anchor's `ts`; notes/crdt.md's rationale line; the notes/growth.md row.
4. **Build** in osis-crdt (prune, placement, the wire field), then any engine code that assumes records are grow-only.
5. **Test**:
   - small tier-1 reproducers for each property above, hand-readable;
   - a counting test: state size after n and 10n whole-value replaces of a list and a text is flat;
   - the per-branch oracles for sequences and paging (notes/testing.md: `seq_differential_large_spec_5_7`, `hostile_moves_join_time_spec_6`, `paging_large_spec_8`, `model_order_independent_spec_7_large`, the engine's `paged_apply_matches_whole_large_spec_crdt_8`) and the crdt model differentials (`tests_seq`, `tests_join`, `tests_decoder`);
   - the `seq_ops` fuzz target once, and every tier-2 oracle that uses crdt-model (the model changed).
