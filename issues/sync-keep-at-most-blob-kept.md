# A keep-at-most drop leaves the blob at the node
> Summary: `Engine::tick` drops a replaced body at its keep-at-most bound (`drop_part`) without queuing an event (only expiries add to `changed`), so `SyncEngine::forget_dropped`, which runs on `Changed`/`Roster` events, does not run: the node keeps the dropped body's ciphertext and key until some later change. spec/commits.md §5 wants both gone at the bound.
> Tags: sync, node, retention, tests

- Seen in the simulator: `osis_sim::replay("keep_at_most", 6)` (seed 1, the tier-1 test, passes because a later write triggers the forget): an hour after the last overwrite, node 0 no longer holds the body (`holds_body` false) but still holds blob `e5ed..` of the replaced commit, entry `Commit { parts: [(0, 0)] }`; the server no longer has it.
- Fix: `tick` queues an event for keep-at-most drops too (or `SyncEngine` calls `forget_dropped` after every engine tick it drives).
