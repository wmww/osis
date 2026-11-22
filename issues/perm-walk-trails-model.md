# osis-perm's walk trails roles-model `paths` on owner keys
> Summary: osis-perm's `paths` walk reads every commit's key hop as listed and takes no list writes until accounts are ordinary things (A4), so its story differential skips the worlds with owner-key moves and no differential writes a roster on a key-record thing.
> Priority: normal
> Tags: perm, tests

The walk follows roles-model `paths` rule for rule but for owner keys, which come with A4 (notes/redesign-plan.md; notes/perm-paths.md, The key hop). Interim sites in osis-perm's tests against the model:
- **Owner keys**: `core/perm/tests/it/paths/mod.rs` `story_run` skips every story world with a list write or a commit signed by a key other than its signer's own (moves 54, 55), marked `// Interim (issues/perm-walk-trails-model.md)`. The walk's input names no key: `paths::Commit` gains the owner key, `PartKind` a list write, and the walk a hop per (key, thing) read first on every path (content's hops with it: `content::Pair` names things only).
- **Rosters of key-record things**: the model takes edge and list writes on a thing whose record holds a key (O4, O5; `paths::tests` `a_thing_acting_as_itself_is_its_own_admin_under_every_trust_set`, `an_unlisted_key_makes_no_may_grant_grant`, `the_flow_holds_with_the_key_*`), the design past A4; spec/permissions.md §1 Interim and the walk apply none (perm `hand_content::an_edge_write_on_its_signer_is_bad_input`: refusing T's writes on itself refuses every edge write on T, since nothing else reaches T). No model generator writes one, so no differential skips; a generator that does needs a skip here until A4. Site: the doc of roles-model `paths::own_key`.

Replaced by: the walk with owner keys; the skip goes and the story differential runs every world.
