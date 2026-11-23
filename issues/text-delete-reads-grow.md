# A text delete reads store rows in proportion to the text
> Summary: in a paged text, a delete, a text session's `Op::Edit` and an undo, each in a new session, read about 33 store rows (115 KB) at 80k chars and about 288 (1 MB) at 800k (osis-engine `scale::text_edits_are_flat`, by hand), where an insert or a move reads 7-25 (26-110 KB); their pages loaded and written stay flat. spec/requirements.md Scale wants O(change).
> Priority: normal
> Tags: engine, performance

- Seen in `Io` (`reads`, `read_bytes`) of each step's `measured`; `text_edits_are_flat` asserts pages loaded and written and store bytes written, not reads.
- Not traced. The ops that read whole are the ones removing chars of the big first commit (a delete, an edit replacing 2 chars, an undo of it): suspect the retention side of a removal (`deaths: a body`, held writes) reading that commit's body, not the placement. Start from the cost spans of the delete step at both sizes, by table.
- Every session also reads all of the placement's group rows (`held`, about one per 8,000 chars), a smaller part of the same growth.
