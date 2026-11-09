# kestrel-net-sim-peers
> Summary: workflow notes from building the sim peer links.

- A long python heredoc that edits sources cannot be in one Bash call with a build while the edit-build rule holds: pieces. Separate calls cost a round trip each.
- Reviewer: an exhaustive compare (all 100 NAT pairs against the packet machine, 0.1 s) found a wrong rule the table-of-15 had passed; the first draft's rule was derived from the same table it was checked against.
