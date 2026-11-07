# `covered` walks the whole snapshot per body
> Summary: one `covered` check still costs about the snapshot's size, not the body's: 138 ms at 100k chars of text (was 309 ms, same box), so judging 1000 bodies once takes about 140 s. What is left is decoding the snapshot and walking its copies; pages name no positions, so a check cannot skip one.
> Priority: normal
> Tags: engine, performance

`deletion::covered_text_cost` (release, `OSIS_SCALE_BODIES`), 1000 bodies of 100 chars, one snapshot, 2 pieces per check.

Gone: `Fragment::part_at` kept a sequence whole, so a check joined and encoded all of it twice (now `Seq::footprint`, the records holding the body's dots; a law in `tests_laws` says a sequence's part judges as the whole, `part_at_a_sequence_is_the_deltas_records` counts); `copy_index` indexed every write of the piece (now `copy_index_in`, the body's ranges).

Left, of the 138 ms: about 46 ms in the piece callback (`copies` walks every element to pick the body's), the rest decoding and hashing the snapshot's pieces. `drop_covered` settles each pair once, but `must_hold` and `carried` judge bodies per pass.

Better: judge many bodies in one walk of the snapshot (`drop_covered`'s loop, a pass's bodies), O(snapshot + bodies) for the lot. Needs the callers batched, or positions on page links (a format change). A bound first needs a measured budget (notes/testing.md, Performance budgets).
