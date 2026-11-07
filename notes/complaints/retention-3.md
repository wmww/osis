# retention-3 (worker)
- `Tx::state_at` clones the whole cached state for an unpaged aspect: a per-body judgment built on it cost 0.6 ms at 3000 set elements (O(state) per body). `Fragment::part_at` narrows first (`Tx::state_part_at`); `replace::replaced` still clones.
- `tools/bin-at` checks the worktree out at REV for the whole build: no edits in the worktree meanwhile (draft elsewhere).
- A release timing run at load 14 tripled one phase's fill time (7 s to 28 s) while another phase in the same run was normal: rerun before believing a slowdown.
- Reviewer: `deaths_never_early_random_*` compares replaced_at on fewer bodies against the same code on all bodies, so a rule early everywhere passes it (a snapshot dated at a re-reported copy did); an independent per-write truth (held-model's replaced_at) would catch it.
- Reviewer 2: held-model scopes only registers, string maps and text (`held.rs` `IN`): the order harness's struct maps and sets never reach the model, so a kept-map op (35/36 on `t:keptmap.0`) was needed before any multi-write stamp met the model. Random kept histories alone did not produce the re-reported-copies shape in 60 seeds before the keptmap ops; a scripted history did.
- The order harness's `floors` treats any 60-step history as `broad` (all aspects reached): a new generator at 60 steps fails it for aspects it never draws.
