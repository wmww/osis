# sync-inputs
> Summary: workflow notes from harvesting the sync rewrite's inputs.

- The brief named a branch `deposit-authority` that exists nowhere (no local, remote or worktree branch, no commit naming it); harvested issues/deposit-promotes-without-write.md instead.
- The sync-only-chain issue is not on net-6b's tip (its fix deleted it); it is only readable at `56787564a^`. A brief citing a branch file should give the commit.
- Repointing ~300 references to 14 deleted issues needed a script; many pointed at section names that no longer exist anywhere, so section suffixes were dropped mechanically. Pointers into issues with section names rot fast.
