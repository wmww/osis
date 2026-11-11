# `create --in me` keeps data on one node
> Summary: `osis create --in me ...` succeeds and prints the thing, but the account is no synced group, so the thing never reaches the account's other nodes; only a `NotSynced` diagnostic says so, which a one-shot CLI run does not print (`diag --follow` against a daemon would show it).
> Priority: low
> Tags: cli

What users see: on node 1, `osis create --in me note:title.0 '"x"'` prints a tid; on node 2 of the same account `osis get TID note:title.0` exits 3 (absent) forever. Nothing on the create's output says the thing stays local; `--in home` was meant. `--in me` is still the right start for a new group (`create --in me` then `group sync`), so refusing it is wrong. Options: `create` prints the diagnostic on stderr when the new thing is in no synced group, or `--in` defaults/aliases steer plain data to `home`.
