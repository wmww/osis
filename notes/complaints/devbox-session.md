# devbox coordinator session complaints
> Summary: footguns met coordinating the first two-box session over the osis channel: disk full from nine warm worktrees, a rebase chained into a gate, main moving under reviewed branches.

- Disk filled to 0 bytes at about 01:45 UTC with nine claimed worktrees (targets 3-9 GB each, about 54 GB) beside other projects' data; two gates died mid-compile. Freed by `cargo clean` in the three idle setup worktrees. `wt claim` should refuse or warn when free space is below a few builds' worth, and `wt release` should prune harder when the disk is tight.
- `git rebase main ... && tools/gate.sh` in one background command ran the gate on a conflicted tree (the rebase stopped on a conflict; `tail -1` succeeded). Check the rebase result before gating; never chain them.
- With two coordinators merging, main moved under four reviewed branches between gate and fast-forward (notes-only moves are fine; code moves cost a re-gate each: 128-195 s). A merge queue or "merge right after the gate, re-gate only when the diff overlaps" rule would cut this.
- `watch --count` and the store lock made the channel listener a kill/post/re-arm cycle per message (fixed by d1 for the count; the lock is the client-port work).
