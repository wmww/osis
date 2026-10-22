# A move fails when the copy's shown elements need more than MAX_DELTA_BARE content-less ones
> Summary: An import carries only the sequence elements the importer's state shows and those they anchor at, the latter without content (spec/permissions.md §7). Left: a shown element whose anchor chain runs through more than `MAX_DELTA_BARE` (2^18) hidden elements in one origin (e.g. one char typed after 400k later-deleted ones) still needs them all, content-less, and `move_thing` fails ("more than MAX_DELTA_BARE elements without content").
> Tags: node, crdt, permissions

Repro: `crates/osis-node/tests/review.rs` `move_over_max_delta_bare_fails_spec_perm_7` (tier 2).

## Technical details
- Kept-but-hidden elements lose their content in the import (no erased text in a copy), so they count against the bound even from an uncompacted origin whose typing carried the chars.
- The encoder (`Enc::note_bare`) enforces the bound for writer and import deltas alike (before, only receivers did, so an over-bound delta was accepted by its writer and refused everywhere else). So an undo of an insert of more than 2^18 characters (it writes deleted flags on all of them, no content) now fails locally instead of producing a delta receivers reject; the undo path does not split.
- Options left: split one origin's import into several import commits (needs a rule for which elements go where and dot mapping per piece), or exempt imports from the bound (a small delta could then create many records). Re-anchoring the shown element at the nearest kept one was rejected (the copy's order could differ).
