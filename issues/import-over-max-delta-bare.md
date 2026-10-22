# A move fails when the copy's shown elements need more than MAX_DELTA_BARE content-less ones
> Summary: An import carries only the sequence elements the importer's state shows and those they anchor at (spec/permissions.md §7), so deleted text and bare anchors nothing shown depends on stay behind. Left: a shown element whose anchor chain runs through more than `MAX_DELTA_BARE` (2^18) content-less elements in one origin (e.g. one char typed after 400k later-deleted ones, compacted) still needs them all, and `move_thing` fails ("more than MAX_DELTA_BARE elements without content").
> Tags: node, crdt, permissions

Repro: `crates/osis-node/tests/review.rs` `move_over_max_delta_bare_fails_spec_perm_7` (tier 2).

## Technical details
Options left: split one origin's import into several import commits (needs a rule for which elements go where and dot mapping per piece), or exempt imports from the bound (a small delta could then create many records). Re-anchoring the shown element at the nearest kept one was rejected (the copy's order could differ).
