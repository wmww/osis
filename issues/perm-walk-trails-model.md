# osis-perm's walk trails roles-model `paths`
> Summary: roles-model `paths` is cut to notes/write-path-design.md (D2); osis-perm's `paths` walk is not until its rebuild, so its differentials against the model skip or switch off what the walk lacks, at the interim sites listed here.
> Priority: normal
> Tags: perm, tests

The walk is rebuilt from write-path §1 after D (notes/redesign-plan.md, osis-perm `paths`: rebuild the walk). Until then osis-perm's tests against roles-model carry these interim sites:
- **Owner keys**: `core/perm/tests/it/paths/mod.rs` `story_run` skips every story world with a list write or a commit signed by a key other than its signer's own (moves 54, 55), marked `// Interim (issues/perm-walk-trails-model.md)`. The walk has no list writes and reads no key hop.
- **The last-admin rule**: `core/perm/tests/it/paths/mod.rs` `input` marks every model write adminless (issues/last-admin-rule-in-perm-engine.md, which also holds the engine's site).

Replaced by: the rebuilt walk with owner keys; the skip goes and the story differential runs every world.
