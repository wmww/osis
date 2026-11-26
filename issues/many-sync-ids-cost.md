# What a node pays for holding many sync IDs
> Summary: Stage S1 of notes/redesign-plan.md. Every independent thing has a sync ID and a node holds one per independent thing it reaches, so work per sync ID held at a reconnect or a first sync grows with the wrong thing. An idle reconnect is flat (core/sync/tests/it/idle.rs) and a first sync fetches each blob once in a bounded number of round trips (first.rs). Left: opens' filter reload, fixed rows per input, step verifications and store rows per member at a first sync, the echo; three counting tests ignored since the sync rewrite.
> Priority: normal
> Tags: sync, engine, perf

Counts at n and 10n shared sync IDs: core/sync/tests/it/idle.rs (an idle reconnect's bytes, judgements, members moved, store rows) and first.rs (a first sync of a root with n members); the ignored `idle::probe_counts` prints every counter. `first::a_first_sync_of_n_sync_ids_takes_the_same_round_trips`, `idle::an_idle_reconnect_sends_reads_and_judges_the_same_at_10n` and `growth::a_head_move_relists_nothing_between_a_reader_and_a_store_at_n_and_10n` are ignored (notes/sync-rewrite-state.md, Ignored tests): recount once they run.

## Left
- **Opens' filter reload**: a record's peer filter is dropped while no connection holds it and read whole at its next take (`records::filter_values`, O(filter rows), a filter holding every shared S's credentials). Keeping it costs up to 2^22 entries per record in memory (notes/sync-opens.md, Durability): a decision, unless the filter is kept or tested without being read whole.
- **Fixed rows per input**: `Store::next_wake` scans one row of each of four time indexes and the log's next due at every handled input. A kept next wake (updated where a time row or the log's due is written) makes it O(1); a store change of its own.
- **First sync, per member**: about 22 step verifications (`verify: sync step`; a member's sync ID has one or two steps: who verifies them again per message is not established) and about 2,900 store rows read (read and streams most); whether any is per member squared needs a third size.
- **The echo**: both sides pull every shared member (spec/sync-streams.md §4 Stream), so a new reader lists back each entry it took; notes/slim-design.md C (no entry echoed to the peer it came from), a spec change.
- **The first reconnect after first contact** re-tests every credential and sends whole filters (spec/sync-opens.md §3): O(shared sync IDs) once per contact.
- **By design**: a member's keyset is fetched under the root's sync ID and again under its own (per-sync-ID copies, spec/sync-judgement.md §1); its size is A5's (cards). Certificate copies are logged under each member's sync ID at a grant (per (commit, thing), notes/evidence-derivation.md): recount.

## Still to count
- Making n at once (sharing a tag of n notes): a keys commit and a sealed secret per holder each, a genesis step each.
- Removing one reader from a thing holding roles on n others: each of the n rotates (spec/permissions.md §3 Required rotation): commits, bytes, steps per store, what each remaining holder fetches.
- A first sync through a node keeping the closure unread only; a first sync interrupted and resumed; start-up and the closure walk, each at n and 10n sync IDs.
