# fathom-test-opt-12
> Summary: Workflow snags met while making compaction snapshots judge only what they newly cover.

- Brief said merge test-opt-11 (e3e051568) first; main then took it under other shas, so `git rebase origin/main` stopped on both carried commits and needed `--skip` twice. A brief could say "rebase onto main; skip carried commits already merged".
- The scale test's snapshot detector (`put_commit > 2`) went stale silently when create stopped filing (a plain new thing writes 1 commit, a snapshot step 2): count `compact: snapshots written` instead of inferring from store writes.
- A planted fault that flips a condition the wrong way (always-remove instead of never-remove) passed and looked like a coverage gap; check the fault does what its name says before reading the result.
