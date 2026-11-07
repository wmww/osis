# retention-3 (worker)
- `Tx::state_at` clones the whole cached state for an unpaged aspect: a per-body judgment built on it cost 0.6 ms at 3000 set elements (O(state) per body). `Fragment::part_at` narrows first (`Tx::state_part_at`); `replace::replaced` still clones.
- `tools/bin-at` checks the worktree out at REV for the whole build: no edits in the worktree meanwhile (draft elsewhere).
- A release timing run at load 14 tripled one phase's fill time (7 s to 28 s) while another phase in the same run was normal: rerun before believing a slowdown.
