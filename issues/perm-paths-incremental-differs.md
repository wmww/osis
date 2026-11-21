# The unwired path walk's incremental and forget updates differ from a walk from scratch
> Summary: osis-perm `paths::incremental::paths_incremental_agrees_large` and `paths_forget_agrees_large` fail on some seeds (gate seed OSIS_PERM_SEED=328756246695, tiny world 330000184008, invites on, not detached, honest None and Lists): the incremental walk, and the walk updated after a forget, differ from `Paths` built from scratch. The same world fails `paths_components_agree_large` (issues/perm-components-unapplied-vs-dropped.md), likely one cause. Fails alike on main's binary.
> Priority: normal
> Tags: perm, tests

Replay: `OSIS_PERM_SEED=328756246695 cargo test -p osis-perm --test it -- --ignored --exact paths::incremental::paths_incremental_agrees_large` (and `paths_forget_agrees_large`): `world 330000184008 TinyMode { invites: true, detached: false, honest: None }: incremental and from scratch differ` (forget: `updated and from scratch differ`).

The walk (osis-perm `paths`) is built and unused, and is rebuilt as one walk per component with a checkpoint per restart point (notes/redesign-plan.md, osis-perm `paths`: rebuild the walk; stage A1). Not fixed in the old walk: the rebuild retires these harnesses' expectations along with it, and its tests must hold this world. Whoever takes it: diff the three readings of this world first (components, incremental, forget against single) to see whether one rule is wrong in all three.
