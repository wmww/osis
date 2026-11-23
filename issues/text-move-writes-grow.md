# A text move's pages written grow with the text
> Summary: in a paged text, a move of 4 chars in a new session writes 13 pages at 80k chars and 72 at 800k (osis-engine `scale::text_edits_are_flat`, by hand, with its move case put back), where an insert, a delete or an edit writes 4-6 at both; spec/requirements.md Scale wants O(change). Its loads are flat (at most 6 at 80k).
> Priority: low
> Tags: engine, performance

- Reproduce: drop the `"move"` skip in `scale::text_edits_are_flat` (it then fails `move: pages written: 13 at n, 72 at 10n`; about 6 minutes in a debug build). Store bytes were not read: the check stops at the first growing count.
- Start from which rows the move's commit rewrites at 800k that it does not at 80k (the placement's blocks between source and target, or the move's own bookkeeping), counted per table.
