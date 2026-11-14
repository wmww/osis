# Held-model and the node disagree on dropping a twice-undone text write as covered
> Summary: `order::held_set_decides_plain` at `OSIS_ORDER_START=1117` (PartsAway seed): in a clocked order a node drops an undone text write's body as covered while held-model says the settings held keep it live forever (`held-model differs: ... dropped as covered at T, live, the settings held keep it to u64::MAX`). Fails on main with the explicit history too; seeds reach it once aimed undos target commits a revert writes. Which side is wrong is not yet known.
> Priority: normal
> Tags: tests, node, retention

## Reproducer
Shrunk (seed 1117, `Cfg { away: true, ..}` as the replay line prints):
`vec![Aim(Typed { by: 2, t: 1, op: 11, k: 1, v: 0 }), Aim(Undo { by: 2, back: 1 }), Aim(Undo { by: 2, back: 1 }), Advance { who: None, ms: 5500918 }, Aim(Compact { by: 0, t: 0, op: 23 })]`
Fails in order #0 (as made) at an earlier clock, after all 16 ingests: commit #6 on `t:text.0`.

## Direction
Find whether the node's covered drop or held-model's live bound is wrong (spec/commits.md §5 keep-for-D, covered drops), fix that side, and add the shrunk history as a hand-written test.
