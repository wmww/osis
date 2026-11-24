# What a node holding many things still pays per write
> Summary: Making one dependent thing still grows with what the node holds (debug instructions per make: 34/42/47 M at 100/400/800 held): compaction weighing, the own-commits set handed to status whole, debug whole checks, and covered body drops. A 2000-thing commit costs about 17 M instructions per thing (debug).
> Priority: normal
> Tags: engine, sync, performance

Counted: osis `making::making_a_dependent_thing_costs_what_it_changed` (role lookups, timeline components moved, chain reach). What one thing stores and sends: notes/thing-cost.md. Measure with `tools/icount` and `tools/cpuprof` (per make: a run with 100 more makes less one without).
- **Compaction weighing** (`Engine::compactions`, `snapshot_cost`): the node root's aspects are weighed about once per 10 makes at 800 held without a snapshot following, each weighing encoding the whole state: O(held) at a rate falling slower than 1/held. Find why the estimate passes `FACTOR` times the last snapshot cost so soon after a weighing that declined.
- **Own commits as a whole set** (`Status::held_elsewhere`, engine `OwnCommits`): a sync ID's own commits are handed over as one `Arc<BTreeSet>` per change and status re-diffs it against every commit of every sync ID. Needs a change feed of own commits.
- **Debug whole checks** (`check_states`, `check_rebuilt`): O(state) per transaction by design.
- **Body drops and forgetting** (`shred_covered`, `forget_commits`): each streams its body and rewrites the pages it reaches; not yet traced to what grows.
- **Per thing of a big commit** (osis `commits::changes_on_as_many_things_spec_requirements_decentralization`): `write::framing_for` and `follow_certificates`.

Flat: paged state (a make writes one page; `scale::a_set_grown_one_element_a_write_writes_what_it_gained`). Rejected: keeping a session's decoded pages across transactions (saves none of the growth, needs a cache equal to the store under rollback).
