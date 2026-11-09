# kestrel-net-sim-peers
> Summary: workflow notes from building the sim peer links.

- A long python heredoc that edits sources cannot be in one Bash call with a build while the edit-build rule holds: pieces. Separate calls cost a round trip each.
- Reviewer: an exhaustive compare (all 100 NAT pairs against the packet machine, 0.1 s) found a wrong rule the table-of-15 had passed; the first draft's rule was derived from the same table it was checked against.
- A mutant of the packet machine that drops all same-NAT packets hangs the test forever (registration retries in `sched.run`); a mutant that only stops the direct path fails at once. Mutate the narrow thing.
