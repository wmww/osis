# Complaints: mizzen-design-d1
> Summary: Workflow snags met writing stage D's paper half.

- Renumbering a design note's sections broke doc citations in model source comments (core/test/roles-model, held-model), which a notes-only job may not edit: the note kept its old numbers and took an unnumbered section instead. Code citing a note by section number pins the note's outline.
- roles-model's story gives its trusting nodes a fixed trust list (`Sim::removals`), so a failure that first-received sides would not show read as a design failure for weeks (issues/removed-key-backdated-drop.md). A model property stated "at trusting nodes" should say where the trust comes from.
- Testing a rule idea needed a throwaway edit of the model inside the worktree (kept as a patch in scratch, reverted before commit); the brief's "no code in the tree" and "probe a rule idea" pull against each other unless that is said.
