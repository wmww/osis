# Permission model review: proposals awaiting owner
> Summary: The 2026-10-12 end-to-end review was done 2026-10-15 (agent); specs and corrections are in notes/permissions.md. This issue now lists only what needs the owner's call, plus one verification task. Close when each item is decided and its "proposal" mark in the note is resolved.
> Tags: security, permissions, sync, tests

All details in notes/permissions.md under the sections named.

Decisions needed (recommendation first):
1. **Hand-over is a revocation** (Hand-over as a revocation). Without it a handed-over thing's whole history is invalid under the receipt-time rule. Proposal: the hand-over commit carries the signer's frontier; hand over from an up-to-date node. Also: strip inherited admin edges of a handed-over actor; rotate its secrets and re-register label keys eagerly.
2. **No reference rewriting** (Resolution). Replaces the 2026-09-29 decision to rewrite old tids in data and markdown. Resolution is a read-time view; a fork is resolved by standing, then by a per-person `/follows` aspect (first seen by default). Reasons: a no-op register rewrite beats a concurrent real edit under LWW; concurrent text splices duplicate links; aliases are permanent anyway.
3. **Mutual admin removal**: earlier timestamp wins, not "both apply" (Model). Follows from judging membership writes by the receipt-time rule.
4. **Re-grant validates all** of the actor's writes, not only witnessed ones (Validity definition). Needed for lossless recovery from a stolen admin device's backdated mass revoke.
5. **Witnesses are writers and above**, never readers; attestations are a header-only commit kind, labeled like membership commits, never compacted away (Witnesses).
6. **Honest fork rule**: successors naming the same new owner resolve to the lowest record hash (Resolution).
7. Confirmations with no change: one role per actor covers acting and editing (core aspects are admin-gated anyway); nesting rotation cost accepted (wraps per direct member plus label re-registrations, no content); chat pattern limits accepted (app-level accepted-marker if a cutoff is wanted); label entitlement rule holds for all patterns, one cached check per (thing, label); per-role secrets hold, all epochs wrapped to members; key recovery not precluded (hand-over authorization is an extensible enum); rotate a key by handing over the key actor, not the person.

Verification before implementation:
- Model-check the membership timeline fixpoint (Validity definition, layer 1): generate small random histories of grants, revokes, hand-overs and receipts with skewed clocks; check the iteration terminates and that the stable result is unique and independent of iteration order. If a counterexample appears, the definition needs stratification or a different base.

Known accepted consequences recorded in notes/sync.md: a removed admin can win the label re-registration race at a blind node (hostile admin, out of scope; remedy is a new label); re-registration messages must be relayable by members.
