# keel-epochs-model
> Summary: mishaps rebuilding roles-model `epochs` on custody's chain.

- Swapping a source file to main's copy to compare (custody's `bounded` failure) while an earlier `tools/heavy` script was still queued made that script's later `cargo run`s rebuild with the swapped file: its control numbers were main's. Never edit sources while a queued script still has cargo invocations to come.
- `epochs_model_agrees_large` without `OSIS_FULL=1` runs a tenth of its stated size (`large_n`): easy to misread as the full run.
- custody's `random_worlds_hold_large` fails `bounded` once on main too (issues/retake-on-thief-merge.md), so the gate's custody property is red independently of this branch.
