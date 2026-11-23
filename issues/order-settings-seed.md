# The order harness judges a Settings history differently by what was held
> Summary: osis-engine `order::held_set_decides_plain` fails on main since the A1 switch (a4611a866) at `OSIS_ORDER_SEED=300644506442 OSIS_ORDER_LEN=60` (Settings family): one history judged differently by what was held. Not shrunk; cause not read. Could be the snapshot-carries gap (issues/snapshot-carries-unread.md) or another switch gap.
> Priority: normal
> Tags: engine, perm, tests

Replay: `OSIS_ORDER_SEED=300644506442 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (`OSIS_ORDER_SHRINK=1` shrinks it). Shrink first; check whether the carries fix closes it.

Also seed 610442177300 (Lists family), on main's binary (a4611a866), seen at the invite-leftovers gate. `held_set_decides_plain` now fails at a rate since the switch: every recent gate met a new seed. Shrink each with `OSIS_SHRINK_MATCH`; check them against the carries fix first.

Also seed 421200482733 (PartsAway), failing on main (466eb5afb).

Also seed 278997924631 (Addenda), failing on main (5fa1ed684) with "held-model differs: commit … applied: model false, node true" of a content commit minting a thing (`holds.0`, `created.0`, `t:reg.0` parts), not a role commit's `roles.0`: the same model-false/node-true shape on a different part; not yet read whether it shares the cause.
