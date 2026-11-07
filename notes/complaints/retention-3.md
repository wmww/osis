# retention-3 (worker)
- `Tx::state_at` clones the whole cached state for an unpaged aspect: a per-body judgment built on it cost 0.6 ms at 3000 set elements (O(state) per body). `Fragment::part_at` narrows first (`Tx::state_part_at`); `replace::replaced` still clones.
- `tools/bin-at` checks the worktree out at REV for the whole build: no edits in the worktree meanwhile (draft elsewhere).
- A release timing run at load 14 tripled one phase's fill time (7 s to 28 s) while another phase in the same run was normal: rerun before believing a slowdown.
- Reviewer: `deaths_never_early_random_*` compares replaced_at on fewer bodies against the same code on all bodies, so a rule early everywhere passes it (a snapshot dated at a re-reported copy did); an independent per-write truth (held-model's replaced_at) would catch it.
