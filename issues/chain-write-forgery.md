# A removed admin can backdate a change to its remover's admin edge
> Summary: After admin A removes admin X, X can still write a backdated change to A's own admin edge (say, make it expire next week) and the change stands, because a removal never drops the writes behind its author's own admin edges, even ones the author never received. Fix: count those writes only through the removal's frontier.
> Tags: permissions, security

Repro: `models/tla/membership/MC_forge.cfg` (LateEdge fails; models/tla/membership/AMBIGUITIES.md M1). In osis-perm: n0 owns G; n1, n2 admins (received by all); n1 removes n2 at ts 8, having received nothing of n2's; n2 then writes n1's edge := admin `until` 9, stamped ts 6. The write stays applied (nothing dropped) and n1 has no role on G at the end.

Cause: spec/permissions.md §5.1 Frontier, "A's own chain writes and R itself always count", next to "a frontier MUST NOT cover what A had not received as of T". osis-perm (`walk.rs` `chain_writes`) counts the writes that set the admin edges on A's admin paths, whoever wrote them and whether A had them. X's backdated write on A's edge becomes such a write.

Fix options (spec change; walk.rs `audit` and the frontier the writer builds follow):
- (a) Drop the exemption: the demoter's frontier lists its chain writes (it holds them as chain certificates, so they are received). A forged one drops and A's edge reverts. Residue: if A's authority at T rested only on a chain write A had not received, it falls and R with it.
- (b) Exempt only chain writes that do not lower the edge they set (a forged raise only helps A).
Recommended: (a).
