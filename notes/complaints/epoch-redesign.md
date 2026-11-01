# epoch-redesign complaints
> Summary: Footguns met while replacing settled chains with names.

- Two probe diffs from one review (scratchpad `forged-valid-claim-rv-*`) append at the same line of tests.rs, so `tools/bin-at --patch a --patch b` refuses the second; had to merge them into one hunk by hand. Reviewers: write one combined probe diff.
- `tools/bin-at` checks REV out in the worktree, so no edits while it builds (cost a wait).
- An end-to-end leak harness needs a precise ground truth: "the rotator held d's departure commit" was wrong twice (a later write re-raised d; a withheld removal of the demoter made a later re-raise valid at the observer). Record what the rotator's own view said too.
- The coordinator's periodic failures (forks_with_departures_settle_large 260189/260306/260366/260448) did not reproduce at item 189's commit or at main, alone or in a range: no way to tell what binary the periodic run used.
