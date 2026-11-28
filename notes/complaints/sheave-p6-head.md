# sheave-p6-head
> Summary: workflow snags in the path-mark / differential classes job: scripts do not shrink, the harness waited one pass out at quiet, and a cherry-pick of a commit the gate had already rebased.

- `OSIS_SYNC_SHRINK=1` shrinks only `histories_hold_their_closure_plain`'s generated histories; a script replayed through `holds_on` (what issues/differential-full-size-classes.md says to replay) prints "OSIS_SYNC_SHRINK=1 shrinks it" and then does not. Seed 35's script was shrunk by hand, one-step-removed variants per round. Would have helped: `holds_on` shrinking its script under the variable, or the message not offering it.
- `World::run` waited out one complete pass at quiet; a pass begun during that wait ended the run with it under way, so the quiet checks judged a node mid-pass (seed 35's class, fixed). holding.rs tests call `w.advance(PASS_WAIT_MS); w.run()` by hand, likely the same gap worked around: worth checking whether they still need it.
- `tools/merge-branch gate` rebases the branch in place, so a SHA taken from it before the gate names a commit no branch holds afterwards; cherry-picking it elsewhere applied nothing. Take the branch name, not the SHA.
- A full-size-shaped script (three accounts, five nodes) takes about 25 s, past the few-seconds default; no smaller fixture (`siblings` with a pair) reproduced seed 35's shape in two tries.
