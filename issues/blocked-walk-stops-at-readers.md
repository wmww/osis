# Blocked walk stops at actors the node may not rotate
> Summary: M holds a role on A, A on G. E leaves M. R may rotate G and only reads A and M (holds their epochs, knows E left): G's epoch is not blocked at R (`rotation::blocked_epoch` descends only through actors R may rotate), so R writes G content E opens through A's box to M at M's uncovered keyset, until M's and then A's rotators rotate (their next sync passes) and R sees G's box to A go stale.
> Tags: security, keys, engine

Found in review of alone-above. Pre-existing on main at every height; alone-above closed it only
along chains the writer may rotate. Model `NoLeakAbove` checks direct holder actors only
(`KeyAct(a)`), so `D0_above` does not see it.

Candidate rule (a rule change, not built): the uncovered clause descends through every epoch the
node holds, whoever may rotate it (stale, keyless stay rotators' only), and Seal leaves A out of G
when A's keyset reaches such an epoch. A's rotators find A's epoch blocked by its box to M and
rotate A in their next pass; then A is re-sealed. Costs another left-out window for A's members on
G (as in alone-above's self-removal case). Check in Depth0 with a three-level instance and
`NoLeakAbove` over `KClos(a)` before building.
