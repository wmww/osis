# The unwired path walk's by-component, incremental and forget readings differ from the single walk
> Summary: osis-perm `paths::incremental::paths_incremental_agrees_large` and `paths_forget_agrees_large` (gate seed OSIS_PERM_SEED=328756246695, tiny world 330000184008) and `paths::single::paths_components_agree_large` (OSIS_PERM_SEED=513418300552, tiny world 514673641167) fail on some seeds, all in invite worlds: the incremental walk, the walk updated after a forget and the walk by components differ from the walk from scratch. Likely one cause; left to the walk's rebuild (stage A1). Fails alike on main's binary.
> Priority: normal
> Tags: perm, tests

The walk (osis-perm `paths`) is built and unused, and is rebuilt as one walk per component with a checkpoint per restart point (notes/redesign-plan.md, osis-perm `paths`: rebuild the walk; stage A1). Not fixed in the old walk: the rebuild retires these harnesses' expectations along with it, and its tests must hold both worlds. Whoever takes it: diff the three readings (components, incremental, forget against single) to see whether one rule is wrong in all three.

**Incremental and forget.** Replay: `OSIS_PERM_SEED=328756246695 cargo test -p osis-perm --test it -- --ignored --exact paths::incremental::paths_incremental_agrees_large` (and `paths_forget_agrees_large`): `world 330000184008 TinyMode { invites: true, detached: false, honest: None }: incremental and from scratch differ` (forget: `updated and from scratch differ`); also under `honest: Lists`.

**By components.** On one shuffled arrival the walk by components leaves a part Unapplied that `Paths::single` reads Dropped. Replay: `run(514673641167, 1, alike)` in core/perm/tests/it/paths/single.rs (a temporary ignored test), on the branch and on `tools/bin-at origin/main` with that test patched in: both print, for tiny `invites: true, detached: false`, `honest: None` and `honest: Lists`:

```
  0: H ts 10: N6 := Write invite Write until 12
  1: N6 ts 9: Z := Write invite Write
  2: H ts 9: Z := Admin
  3: N6 ts 1 (commit 3): H := Write invite Write until 3 listing [1, 2]
  4: N6 ts 1 (commit 3): Z := Admin listing [0, 1]
  5: B ts 3 (commit 5): N5 := finalize
  6: B ts 3 (commit 5): N6 := finalize
  7: H ts 9: N6 := Write invite Write until 11 listing [1, 3, 4, 5]
  8: N5 ts 8: H := Read listing [1, 3, 6]
  ...
arrival [0, 3, 5, 4, 7, 1, 8, 2, 6]: statuses [(WriteId(commit 3, 0), Unapplied, Some(Dropped))]
```

From scratch both walks agree; only that arrival order differs. A split commit (3) of two edge parts on one thing, one with an `until` already past at a later grant's `ts`, finalizes in another commit (5). Not yet narrowed to which of the components' restarts misses the drop.
