# retention-no-snap
> Summary: the owner rule "no snapshot under keep at least plus keep at most" collides with keep-at-most carriers.

- The decision read literally (no snapshot at all) would leave no carrier for a body dropped live at its keep-at-most bound (deleted list or text elements stay live as anchors), so erased data would stay at servers. Specified instead as "carrier only": such a snapshot exists only as that carrier and drops nothing.
- Review: the must-hold half of carrier only (pass.rs `must_hold`) had no test that failed without it (own fresh bodies upload by another path); added a `verdicts` check.
