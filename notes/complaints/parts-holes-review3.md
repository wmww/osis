# parts-holes review 3
- Local `main` was 5 commits behind `origin/main`, r1-repair among them, while the brief said main had moved: `git rebase main` said "up to date". Rebased on `origin/main`; the gate compares with local `main`, so its merge base is older than the branch's and it may cover more.
- The rebase replayed one spec paragraph's conflict in three commits, and each commit's merge had to be done by script.
- `git rebase` of a branch with four commits rewriting one long spec line: squash first next time.
- A `cp` of a test binary into a script, then `/usr/bin/time ... | grep` in a helper: one run reported exit 101 in 0.00 s with no output while the same command by hand passed. Unexplained; keep full logs of oracle runs.
- Rebasing onto r1-repair turned on a debug cross-check and hid a differential's expected difference behind it: seed 93101 needed reading twice. A harness comparing states needs r1's flagged-aspect rule whenever main gains one.
