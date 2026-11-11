# lifetimes-2 complaints
> Summary: Footguns met building backlinks (step 2 of issues/thing-lifetimes.md).

- A dispatcher callback gets the node's own handle, not the subscribing one: a listener that re-reads must capture `limit` and `actor` and build its own `Reader` (as `answer_callback` does), or an acting (thin client) listener silently reads as the node.
- `w.delete(t)` of a thing whose durable aspects are all removed keeps its ephemeral values (and so their reference rows): the delete finds no content and writes nothing. Not investigated; the backlinks test avoids it.
- Adding a field to engine `Core` touches four places (the field, `clone`, the `rollback_classes` destructure, `blank_core`); the compiler finds all but `blank_core`.
