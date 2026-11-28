# held_set_decides: a purge history judged differently by what was held
> Summary: osis-engine `order::held_set_decides_plain` fails on main at a gate seed (Purges emphasis): the node keeping every body ignores a purge by name whose right (a write grant) arrives after it; shrunk to four steps, not yet fixed.
> Priority: normal
> Tags: engine, tests

Shrunk (`OSIS_ORDER_SHRINK=1` from seed 851492042192, LEN 60) to four steps, failing at seed 0 too:
`Aim(SetGrant { by: 0, t: 5, holder: 2, role: Some(Write) })`, `Aim(Message { by: 2, t: 0, v: 8 })`, `Aim(Message { by: 2, t: 2, v: 5 })`, `Aim(PurgeNamed { by: 2, t: 2, of: 2, back: 0, v: 0 })`: on one thing, 0 grants 2 write (commit 25), 2 writes m8 (26) and m5 (27), then purges m5 by name (28, 29).
- `order_checks(&play(0, &h), order)` passes delivered as made and wholly reversed; it fails with the setup first and then 29, 28, 27, 26, 25 (the purge before its grant): the node keeping every body reads m5 (`want`), the judged node m8. Dropping 25 from that order passes.
- So the node keeping every body takes the purge as holding no right when it arrives before the grant, and does not judge it again once the grant arrives (spec/permissions.md §6 Judgment: the role timeline in any arrival order). The judged node, which drops bodies, reads it right. Start from how the keep-everything node re-judges a held purge request when a grant on its signer's path arrives.
- The hand test is the four steps above with that order, at seed 0 (about 15 s; a smaller setup than the order harness's 25-commit base would be better).
