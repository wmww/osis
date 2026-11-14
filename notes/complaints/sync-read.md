# sync-read
> Summary: Workflow mishaps met building the read module.

- The worktree the brief named (wt11) was claimed by another agent (sync-inbox) minutes after this one started; it switched the branch under this session. Claimed wt12 instead. Briefs should name a worktree only after `wt claim`, or tell the agent to claim its own.
- The brief pointed at core/sync/tests/it/harness/scripted.rs, which exists only on the unmerged sync-opens branch.
- The facade's per-commit facts (`BodyFacts`) cover a fraction of what spec/sync-judgement.md §2-§4 reads; read had to define its own seam (`read::Facts`) and list the rest as facade gaps.
