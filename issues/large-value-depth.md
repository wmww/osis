# A large value near the depth limit is refused once chunked
> Summary: Found by reading. `chunk_ops` turns a large string or blob into a LINK before the batch's depth check (`out_of_profile`) and decoders' `check_value` count the link's own nesting (3 levels, 4 with delete keys), so an app value legal by spec/data-model.md §5 (64 levels) holding a value above `CHUNK_THRESHOLD` below depth 60 is refused at write. Rule to pick: a link counts as the value it reads as (0 for a string or blob), or the limit is stated on the stored form.
> Priority: low
> Tags: crdt, engine
