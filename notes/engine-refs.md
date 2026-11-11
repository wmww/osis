# Reference index
> Summary: The engine's local, rebuildable index of references in held readable data (`engine/refs.rs`): rows (target, source thing, AK) with a count, what counts as a reference, how every state change keeps the rows in its own transaction, costs and checks. Serves backlinks and the lifetime judgment (issues/thing-lifetimes.md).

## Principle
A row says exactly what the source's held state on that aspect holds: it changes in the transaction that changes the state and never outlives the value it came from.

## Rows
- Store index tables (rebuildable, dropped and refilled from every state by `index::write_all`): `node/refs to` (target ‖ source ‖ AK, empty) and `node/refs from` (source ‖ AK length ‖ AK ‖ target, the count as u64). A removed row is shredded. No in-memory copy: an open loads nothing; a read is a prefix scan (`Engine::references_to`, `references_from`, `refs::Reference`).
- Class by AK: an ephemeral (`+`) aspect's rows are memory rows, as its state is (live ephemeral), the rest durable. `retainers^.0` rows are kept like any (`Reference::lists`): who lists a target, not a reference for lifetime.
- Indexed: every aspect with a state but `created.0` and the role-class aspects (`refs::indexed`).
- Counted: every tid (`Value::Tid`, tag 1616) at any depth of a value the state holds as written (`Fragment::each_value`: register and slot values, set elements, list items, the keys of map records holding their creation), map keys, enum payloads and unknown tags' content included. Not counted: a value-less write (the state holds none), an invalid write (un-merged), a link's chunked content, a tid spelled in a string, text chars.

## Keeping it
- A join (`atomic::join_into_state`, the oracle's): the tids at the delta's reach (`Fragment::reach`, all a join can change) before and after, the difference noted (`refs::note`). O(the reach): a path write reads the entries it writes and replaces, no other.
- A paged reset joined page by page (`pages::join_reset`): the skeleton and each page it rewrites, before (as a load reads it) and after; laid out whole instead, as a whole write.
- A whole write (`Tx::set_state`: every rebuild, so validity flips, un-merges, expiry, purge, a part dropped, ending): the whole state against the stored rows (`refs::resync`). `Tx::write_state` is the same write without it, for a join's caller that noted its difference.
- A dropped aspect (ending, forgetting): its rows cleared before `drop_aspect`.
- Rollback: the store's savepoint, like any row.
- Check: `apply::check_rebuilt` (debug, end of transaction, sampled like the state check) asserts each checked aspect's rows equal its whole state's count (`refs::check`).

## Tests
osis `references::` (rows follow values; any arrival order; expiry and purge; a validity flip; lost access; a path write counted at n and 10n, a paged reset), engine `refs::tests`.
