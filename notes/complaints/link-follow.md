# link-follow
> Summary: workflow snags met on the link follow-time branch.

- A stray `cat > file` with no stdin in a compound command hung the Bash call until stopped (it read the tool's stdin): my slip, but the hang shows only as a timeout.
- (review) The redial timer (`REDIAL_MS` from each dial) lands on any deadline a whole number of 30 s from the dial, so a World test of a deadline's own wake must start the deadline off that grid (links' given-up test restarts 7 001 ms off it).
