# member_churn: a label never opens at a host
> Summary: seen once in sim `member_churn` (node 2's connection to host 0 kept a group's label Testing, head None, synced false, at quiescence); no reproducer: the seed that showed it passes under the roster merger, whose run makes far fewer role commits. Not studied.
> Priority: low
> Tags: sync, sim, tests

- Seen: setup 313462591648 seed 313462591654, step 153, with merges by a merger read from the forks held (git history has that build); two `delete refused: code 1` diagnostics at step 29.
- Start at, given a reproducer: why the node never registers or opens that label there (a step refused for now and not registered again, or a head it never read).
