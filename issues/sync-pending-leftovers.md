# Pending leftovers: redelivery untested in sync, coarse reach wakes
> Summary: sync's reopen of a named commit's carriers has no end-to-end test; `rewrap`'s refusal of a per-sync-ID copy is unreached by tests; commits awaiting a reach, actor secrets or an epoch wake at every role change; a writer's stamped entries that never open stay while its key is the head's.
> Priority: low
> Tags: sync, engine, tests

- **Redelivery untested in sync**: `store::follow` opens every entry naming a blob of a commit `take_redeliver` names (`receive::junk_first_while_a_record_is_away_goes_once_it_comes_spec_commits_4` tests the engine side); the harness has no lie that sends a junk copy.
- `rewrap` refusing a per-sync-ID copy as a certificate of the same parts elsewhere has no test case that reaches it (no fixture found where both bodies hold the same parts).
- **Coarse wake**: `Wake::Moved` (reach, actor secrets, epoch) is woken by any change of the held role inputs, so k such pending commits (a peer's, within its budget) cost k examinations per role commit applied (spec/commits.md §4 Limits). Keying a reach by the edge targets on its path would need the walk to say which things it read.
- **Stamped entries that never open**: a reader keeps a writer's stamped entry that does not open (an epoch it may get later) uncharged while the stamp verifies under the head; `drop_unvouched` drops only carriers of pending commits and loose records at a head move, so a current writer's unopenable junk is bounded only by its writes until a delete-key holder or its removal.
