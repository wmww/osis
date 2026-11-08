# A text creation under a later undelete dates no death
> Summary: retention judges a text element's creation by the element's winning flag (`Fragment::winners`), so once an undelete (or a reset sparing a later creation) wins over the delete, the creation counts live and the inserting body is not dated at the delete; spec/crdt.md §4.8 has it dead from the earliest delete on. Kept longer, never lost.
> Priority: low
> Tags: retention, crdt

Seen as held-model's `keep-for-D dated later` tally (core/test/held-model/AMBIGUITIES.md item 27). Fixing it needs either the spec to say an undelete revives the creation, or deaths judged against more than the winners of the state (the delete is gone from it).
