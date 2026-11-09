# Handoff to the next coordinator
> Summary: What is in flight and what comes next, for whoever coordinates after Fathom. Design principles and process live in notes/coordination.md; this note only holds state. Rewrite or delete once taken.

Read CLAUDE.md and notes/coordination.md first. Tess: opus only for every agent, no fable, until she says otherwise. Questions for Tess are issues tagged `tess-call`; priorities are on every issue. A second coordinator (Kestrel, Tess's other box) owns networking and docs cleanup; the split and protocol run over the dogfood channel (notes/dogfood.md).

## Large designs, in order
- **Rotation leak fix** (branch `half-valid`, not merged): keysets carry possession proofs, one verdict per rotation, keysets read as of the commit's key (Depth0 and Authority models). Blocked on the gate: an index rebuild disagrees on a derived epoch's establishment (`osis` test `sync::a_grant_on_a_group_owned_item_by_an_admin_grant`). Carries the rotation property test. Open beside it: issues/keys-depth0-removed-member-rotates.md, issues/rotation-settled-current-epochs-differ.md.
- **Test refactor** (notes/test-design.md): steps 1-8 and 10 done or in review (step 7 on `crdt-differential`); left: 5b (held-model values from crdt-model, issues/held-model-values-from-crdt-model.md), 9 (ephemeral, after connection-lived data), 11, 12. Open: issues/held-set-decides-full-size.md, issues/held-model-role-commit-scope.md.
- **Expiry and creation records** (notes/expiry-creation-design.md): steps 1-3 built. Left: the creation-record steps and step 4's osis-API examples. Open with it: issues/purge-author-order-452234901986.md (a purged write's leftover shadows an older value only where the body was held when the purge landed); decide in the leftover work: one leftover every node forms from what it holds, or fetchable leftovers.
- **Listener API** (notes/listener-design.md): steps 1-4 built. Left: 5 (path listeners), 6 (sessions follow every write), 7 (callers), 8 (node-state granularity, an app session with Tess).
- **Account signing** (issues/account-signing.md): steps 1 and 4 built. Step 2 open with Tess (covered commits: keep listing everything; per-session ranges studied with header forgetting). Next: 3 (spec), 5, 6.
- **Signal edits** (issues/signal-edits.md, tess-call): osis checks an edit claim (same author, original valid), removing chat's last shared rule.
- **Forgetting compacted headers** (notes/growth.md row 1): conflicts with removal lists naming commit IDs; study a per-session counter range for frontiers with it.
- Kestrel's: network rework (issues/net-rework.md), then data that lives while its keepers are connected (issues/connection-lived-data.md).

## Findings recorded only here
- Bounding rotation names (issues/rotation-names-grow.md): "chain coverage through supersedes" leaks (a TLA instance found it); a base-chain rule breaks when a base rotation turns invalid. Redo with the rotate-free principle (spec/crypto.md §4).
