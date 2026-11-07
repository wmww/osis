# A winning differing copy drops the original without a keep-at-least window
> Summary: A valid writer's snapshot copying a co-writer's write with a greater payload covers the original body (spec/commits.md §5 Covered: the join leaves the snapshot unchanged) while the original never dies (a copy replacement is no supersession), so under a relative keep-at-least the original is compacted and deleted at hosts at once, where an overwrite would keep it D past its death. After the writer's removal it comes back only from a copy still held somewhere. Needs Tess's call between two plain rules.
> Tags: security, engine, crdt, retention

Found in review of the no-misstates branch. Not reproduced by a test; each step is in code or spec:
- Covered (spec/commits.md §5, `retention::snapshot::covered`): X's body joined into W's snapshot changes nothing when W's copy of X's write wins the copy order (validity.rs `snapshot_copy_covers_body_iff_its_copy_wins_*`). An honest compactor holding both carries W's copy too, so its snapshot covers X's body as well.
- No death: `osis_crdt::state::join_write` replaces an equal-stamp copy without `Changes::died`; spec/commits.md §5 dies only by a later write or expiry.
- Keep at least (spec/commits.md §5): "A body with no dead writes is past a relative bound", so compaction drops X's body and right holders delete it at hosts. An absolute bound (history-kept aspects) still protects it.

Against an overwrite by W under its own dot: X's write dies at W's `ts`, X's body is kept until that death plus D, history shows it, and W's removal within D (frontier not listing W's commits) brings it back from the held body. With the forged copy the same removal finds X's body gone everywhere unless some node still holds a copy (uncovering refetches, notes/engine-validity.md Uncovering), and history lost X's entry at once. Without a relative keep-at-least the two are equal (a dead body is covered by any later snapshot).

Plain rules, either closes it:
1. Covered also needs the snapshot to hold each live write of the body with the body's payload: a differing copy leaves it uncovered whichever wins. Keeps the verified original instead of acting on the claim; stores and reports nothing. Cost: a per-write comparison in `covered` (the walk the branch deleted, `copies_within`), and a forger can keep the victim's body held while its copy differs (storage of the victim's own write only).
2. A write whose copy loses the copy order dies, dated at the `ts` of the first valid snapshot holding the winning copy (no earlier than its body's): the forged copy then counts exactly as an overwrite at the snapshot's `ts`. Harder: deaths are keyed by stamp, which the winner shares, so a "dying" carrier must be told apart by payload in every encoding.

Recommendation: 1 (one comparison, no death bookkeeping; the keep-forever cost falls on the forger's victim's own write, bounded by it).
