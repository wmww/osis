# sync-read
> Summary: Workflow mishaps met building the read module.

- The worktree the brief named (wt11) was claimed by another agent (sync-inbox) minutes after this one started; it switched the branch under this session. Claimed wt12 instead. Briefs should name a worktree only after `wt claim`, or tell the agent to claim its own.
- The brief pointed at core/sync/tests/it/harness/scripted.rs, which exists only on the unmerged sync-opens branch.
- The facade's per-commit facts (`BodyFacts`) cover a fraction of what spec/sync-judgement.md §2-§4 reads; read had to define its own seam (`read::Facts`) and list the rest as facade gaps.
- Review: the rebase onto sync-rebuild (with opens) conflicted in issues/sync-rewrite.md's Phase 4 line and tools/dead_pub_allow.txt's skeleton block: every module edits the same two lines. One item per line would merge cleanly.
- Review: the test fake's `exchange` drained the Deletes it handed to K, so `deletes() == 0` after an exchange checked nothing (nothing_emptied_before_told's first assert was vacuous). A count that a helper consumes is a trap; the fake now keeps what K took.
