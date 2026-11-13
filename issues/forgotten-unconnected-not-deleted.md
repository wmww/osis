# Entries of commits forgotten while unconnected wait for a start
> Summary: A node that forgets a released thing while unconnected (its own ticks) knows entries of the commits it forgot, but once connected again no pass deletes them at the host until the node restarts: the start's judging of every entry finds them; the passes after reconnecting do not.
> Priority: normal
> Tags: node-sync, tests

- Reproducer: `destruction::a_destroyed_actors_secrets_go_with_the_last_entry_of_its_commits_*` (and `..._stay_for_a_commit_acting_for_it_*`) with `net.restart(b, 50)` removed: "b deleted them at the host" fails; the entries stay at the host and at b.
- Likely the drop's label marks (`memory_dropped`, `mark_labels`) are taken by passes run with no connection, so nothing judges those entries when a host is back. Until fixed, a destroyed thing's secrets held for them (`retention/destroy.rs::hold_secrets`) stay as long.
