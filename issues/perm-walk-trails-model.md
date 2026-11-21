# osis-perm's walk trails roles-model `paths`
> Summary: roles-model `paths` is cut to notes/write-path-design.md (D2); osis-perm's `paths` walk is not until its rebuild, so its differentials against the model skip or switch off what the walk lacks, at the interim sites listed here.
> Priority: normal
> Tags: perm, tests

The walk is rebuilt from write-path §1 after D (notes/redesign-plan.md, osis-perm `paths`: rebuild the walk). Until then osis-perm's tests against roles-model carry these interim sites:
- **Owner keys**: `core/perm/tests/it/paths/mod.rs` `story_run` skips every story world with a list write or a commit signed by a key other than its signer's own (moves 54, 55), marked `// Interim (issues/perm-walk-trails-model.md)`. The walk has no list writes and reads no key hop.
- **The last-admin rule**: `core/perm/tests/it/paths/mod.rs` `input` marks every model write adminless (issues/last-admin-rule-in-perm-engine.md, which also holds the engine's site).

- **Re-grant by right (C1/C2)**: the old walk counts a re-grant from each edge's first chained write; the model from the first write made by right (4444a80e1). `paths_story_agree_large` disagrees on such worlds (OSIS_PERM_SEED=3994064557: story world 2969410762, nodes 7 and 22, delta 30: model invalid, walk `Valid(Regranted)`; fails on main's binary), KNOWN in tools/known_failures.txt.

Replaced by: the rebuilt walk with owner keys; the skip goes and the story differential runs every world.
