# A broken engine invariant on one commit stops the node, and spins it on reloads
> Summary: an engine `Corrupt` (or other local-class error) while applying a commit is lossless but a deterministic one stops the node for good: node-sync's step fails at every retry, and one in a re-examination round reloads the store in a loop with no pending commit of that round applying. No peer input is known to reach one (spec/commits.md §4: no local error from peer bytes); the failure mode for an engine bug stays: proposal below (set the faulting commit aside as locally unappliable). One encoder path left to check.
> Priority: normal
> Tags: engine, sync, security

What happens:
- Arrival: core/engine/src/sync/bodies.rs `open_entry_once` passes a local-class ingest error up (never `Opened::Bad`); core/sync/src/streams/pull.rs `take_body` takes nothing and the step fails at the next settle (`streams::an_owed_body_settles_only_once_taken_under_its_sync_id_spec_sync_streams_4`: refetched after a restart). Right for a transient store failure; for a logic invariant it repeats forever.
- Re-examination: `run_taken` (a `reexamine` round, `promote_loose`) failing sets `taken_failed`; the next transaction reloads as an open does and examines every pending commit (`Wake::Open`) in one round, so one commit whose examination errs rolls back the whole round again. `reload_owed` keeps `next_timer` at now: each tick reloads and fails. Arrivals not pending still apply, each after a whole reload. Read from the code, not built.

Tests: `LocalPeer::receive_with` panics on `Error::Corrupt`, so engine tests and the simulator fail at the receive that trips one.

## Peer-reachable local errors (audit of `Error::Corrupt` and local-class errors on apply, join, judge, purge, covers, ingest)
| site | what reaches it | peer-caused? |
|---|---|---|
| `retention/bounds.rs` `Killed::note` (every join: ingest, re-examination round, paged pieces, rebuild) | a dead write with no superseder held at the reach | Was, by forged copies (a snapshot carrying another's write under its stamp with another payload): a set element's write holding a reference in one copy and another value in the other (keyed by its reference), a value removal's copies naming other references, a register write and a reset of another encoding under one stamp, a delete copy of an undelete's flag. Closed: a write's identity is never its payload (spec/crdt.md §4.8), hiding is read from the joined state (`Fragment::hiders`); osis-crdt `tests_model::reach_holds_the_change` over every history incl. twins and hostile, osis-engine `retention::tests_forged`. A position write stamped with its element's dot has no wire form (both decoders refuse it). |
| `retention/bounds.rs` `judge_replaced_at` (tick, setting change, open, purge-on-replace) | a body's dead write with no superseder in another held body | Was, same classes (a copy swap read as a death; a removal held only by the judged body hiding the state's copy). Closed alike; any held body may hold the superseder. |
| `engine/refs.rs` reference and ticket counts below zero, `refs/kept.rs`, `tree_refs.rs` | a join's reach missing a value whose read it moves, so the index misses an increment and a later decrement goes below zero | Was: a value removal copy naming another reference showed elements of the first again outside the set's reach. Closed: a set's reach takes the references the state's records at the delta's dots name (`Set::at`), a paged set loads them (`Fragment::dot_values`); the reach law's read-values assertion runs over every history. |
| `apply/atomic.rs` "a verified delta failed to decode again" | decode-only reread of bytes this node checked | No: the checked and checking decoders give the same pieces for every accepted input (osis-crdt `tests_stream`). |
| crdt `Error::Mismatch` (local) from `codec` "fragment needs a third page level" | encoding a state the node stores or snapshots | To check: whether a joined state built from accepted peer deltas can need a third page level when the node pages it (the read-depth rule bounds nesting; not traced). |
| `flows/account.rs` "the account's open epoch" | sealing a box (a local write) | No (local action). |
| the rest (about 150 sites: index rows, records, pages, keys, counters this node wrote) | reading back the node's own store | No: store damage only. |

## Proposal: a faulting commit is set aside, the node goes on
Rule: a commit whose apply or examination fails with a local-class error that is not a store I/O error is **locally unappliable**: kept (its blob and record), not blamed on the peer (never `Opened::Bad`, never refused or forgotten), taken out of every round (other commits of the round apply as if it were pending on something never met), reported to the host as a node fault (an event and a status read: commit, aspect, error), and retried at the next open of a new build (and on an explicit host call); not on each tick.
What it needs:
- the error split: store I/O (transient: retry as now) vs logic (`Corrupt` raised on an invariant, crdt `Mismatch`); today both are `Corrupt`/local.
- a durable `unappliable` row per commit with the build that set it, read at open: a newer build clears them and the commits are examined again.
- `run_taken` examining commits one transaction each after a round fails (or bisecting the round), so the round's other commits apply; `reload_owed` dropped for logic faults.
- sync: an unappliable commit counts as received (cursors pass it) but its parts as missing for judging, so peers' copies are not fetched in a loop; held for retry.
- tests: a planted fault on one commit of a round (a test hook in the apply path) leaves the others applied, the node serving, the fault reported, and the commit applied after a reopen with the hook cleared.

Also owed (notes/sync-facade.md Pending): one small world per wait reason and waking event asserting `lost_wakes` empty; a box the reading-only budget refused, freed by room alone, has no wake until the next arrival or tick.
