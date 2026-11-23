# move-writes
> Summary: slow spots met fixing a text move's placement writes.

- `scale::text_edits_are_flat` (by hand) takes about 7-9 minutes in a debug build (its ignore reason said most of a minute); one 800k-char setup alone is about 80 s, so a probe of one op at both sizes is the faster loop.
- Its store-bytes check is near its 2x bound for the undo (37.7 / 65.5 KB; 33.2 / 66.7 KB when a 600-char move ran before it): B-tree leaf luck, not the op, decides the margin.
