# Drop invalid bodies at once
> Summary: Plan (Tess: dropping and refetching is fine, the CRDT side in place): a body judged invalid drops at the end of the transaction that judged it, except the node's own commits (their author shows and resends rejected writes); one turning valid again (re-grant, late addendum) is refetched from any holder, lost when none has it, nodes agreeing. An invalid write contributes nothing to the state, so this fits the retention principle. Tried once on the addenda branch; what it needs is below. Today invalid bodies stay held (spec/permissions.md §6).
> Priority: normal
> Tags: engine, retention, permissions

In place: a sequence's order comes from valid writes only (spec/crdt.md §4.6, §6.1: an invalid delta's elements leave nothing; an anchor naming a dot with no record is a virtual anchor on END), so every read is a function of the valid writes held and an invalid body leaves nothing anything needs: it can drop outright, be refetched if it turns valid, and needs no leftover. Tests: osis-crdt `tests_seq::valid_order`, osis-node `validity::invalid_insert_leaves_no_trace_in_order_spec_crdt_6_1`.

1. **Drop**: `drop_due` filled where a part is judged invalid; dropped at the end of `Engine::run` after `answer_removals` (a witness lists what it held); skip role commits' parts, `addenda.0`, memory parts and own commits; a flip back makes the part missing and fetched.
2. **Tests**: about 30 assume invalid bodies are held (list in git history of this issue); rewrite each to what a user observes after a fetch; restate spec/permissions.md §6 ("nothing goes without a right") as the dropped-invalid rule.
