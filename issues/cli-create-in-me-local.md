# `create` outside a synced group keeps data on one node, quietly
> Summary: `osis create ...` with no `--in`, or `--in me`, succeeds and prints the thing, but nothing synced lists it, so it never reaches the account's other nodes; with no `--in` nothing says so, and `--in me`'s `NotSynced` diagnostic is not printed by a one-shot CLI run (`diag --follow` against a daemon would show it).
> Priority: low
> Tags: cli

What users see: on node 1, `osis create note:title.0 '"x"'` (or `--in me`) prints a tid; on node 2 of the same account `osis get TID note:title.0` exits 3 (absent) forever. `--in home` was meant. Staying local is right (spec/requirements.md, Offline and network), and `create --in me` is still the right start for a new group (then `group sync`), so refusing either is wrong. Option: `create` prints a note on stderr when the new thing is in no synced group.
