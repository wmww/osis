# Handoff to the next coordinator
> Summary: What is in flight and what comes next, for whoever coordinates after Fathom. Design principles and process live in notes/coordination.md; this note only holds state. Rewrite or delete once taken.

Read CLAUDE.md and notes/coordination.md first. Tess: opus only for every agent, no fable, until she says otherwise. Questions for Tess are issues tagged `tess-call`; priorities are on every issue. Fathom is the lead coordinator (Tess); a second coordinator takes the areas the lead assigns (Kestrel had networking and docs cleanup); the split and protocol run over the dogfood channel (notes/dogfood.md).

## Focus (Tess)
Big features and refactors first; chase a bug only when it could threaten their viability. Don't rush to the goal API through shortcuts that later unravel it, but bring core to a settled, finalized state soon so the whole system can settle.

## Large designs, in order
- **Rotation leak fix**: merged (keysets carry possession proofs; one verdict per rotation; derived establishment computed from held commits). Open: issues/keys-depth0-removed-member-rotates.md, issues/history-entry-inputs-outlive-their-entry.md, issues/rotation-keyset-gone-before-its-boxes.md.
- **Test refactor** (notes/test-design.md): steps 1-8, 5b and 10 done or in review (step 7 on `crdt-differential`); left: 9 (ephemeral, after connection-lived data), 11, 12. Open: issues/held-set-decides-full-size.md, issues/held-model-role-commit-scope.md.
- **Expiry and creation records** (notes/expiry-creation-design.md): steps 1-3 built. Left: the creation-record steps and step 4's osis-API examples. Open with it: issues/purge-author-order-452234901986.md (a purged write's leftover shadows an older value only where the body was held when the purge landed); decide in the leftover work: one leftover every node forms from what it holds, or fetchable leftovers.
- **Listener API** (notes/listener-design.md): steps 1-4 built. Left: 5 (path listeners), 6 (sessions follow every write), 7 (callers), 8 (node-state granularity, an app session with Tess).
- **Account signing** (issues/account-signing.md): steps 1 and 4 built. Step 2 open with Tess (covered commits: keep listing everything; per-session ranges studied with header forgetting). Next: 3 (spec), 5, 6.
- **Settings** (issues/settings.md, decided with Tess): account and node settings as ordinary aspects on private things in home; the design to reach for whenever persistent settings are needed, and bespoke settings systems get cut over to it. Not urgent. Build after account signing step 6, which moves node data under D's home label: reconcile the two first.
- **Signal edits** (issues/signal-edits.md, tess-call): osis checks an edit claim (same author, original valid), removing chat's last shared rule.
- **Forgetting compacted headers** (notes/growth.md row 1): conflicts with removal lists naming commit IDs; study a per-session counter range for frontiers with it.
- Kestrel's: network rework (issues/net-rework.md), then data that lives while its keepers are connected (issues/connection-lived-data.md).

## Findings recorded only here
- Bounding rotation names (issues/rotation-names-grow.md): "chain coverage through supersedes" leaks (a TLA instance found it); a base-chain rule breaks when a base rotation turns invalid. Redo with the rotate-free principle (spec/crypto.md §4).

## Networking (Petrel's, devbox)
Kestrel's two branches are merged (net-repros: net-tests step 5; net-role-sync). Petrel owns networking in issues/net-rework.md's order: net-tests step 2 merged; honest-status step 1 and the shared-set + reconnect model in progress.
