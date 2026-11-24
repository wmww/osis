# terms-tla
- A TLC baseline run from the worktree reads the model files at each instance's start: editing a model while its module's baseline still runs mixes old and new files. Run the baseline from a `git archive` copy outside the worktree.
- `grep` on this box is ugrep: `grep -rc -i word` parses `-i`/`-t`/`-d` glued to the pattern as options. Use `rg`.
- issues/deprecated-terms.md names model identifiers in backticks, so each rename fails policy until the row is edited, though agents are told not to edit that file.
- `run.sh netstream` at one worker takes about an hour (S_* cfgs run millions of states each).
- Renaming a TLA+ identifier to a name of another length shifts a bullet list (`/\\` ... on the next line aligned under one after the name): the conjunct leaves the list and TLC finds a different model. Rotation's `FromHost` -> `FromStore` failed `TypeOK` in 6 states. Re-align continuation lines after every rename.
