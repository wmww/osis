# Handoff to the next coordinator
> Summary: What is in flight and what comes next, for whoever coordinates after Fathom. Design principles and process live in notes/coordination.md; this note only holds state. Rewrite or delete once taken.

Read CLAUDE.md and notes/coordination.md first. Tess: opus only for every agent, no fable, until she says otherwise. Questions for Tess are issues tagged `tess-call`; priorities are on every issue.

## Large designs, in order
- **Retention** (issues/retention-modes.md): steps 1-4 built (history modes on the wire; purge on replace is a covering snapshot; no death dating; state is exactly the join of held bodies; covered, expiry, purge and invalid drops). Left: step 5 (the history API shows only kept history, issues/history-verified-or-absent.md), the order-oracle redesign (notes/test-design.md step 4), the test refactor (notes/test-design.md).
- **Listener API and one commit model** (notes/listener-design.md): designed, four questions with Tess; build steps 1-7 after signal-fire merges (step 2 absorbs H3).
- **Chat library review** (after durable signals and the `chat:msg` rename land; Tess): libs/chat may be bloated or unnecessary. It was only meant as helpers for implementing chat correctly while chat was weird. Non-chat-specific parts worth keeping are designed into the osis API coherently (not copied in); convenience-only helpers go; chat that is still weird for historical reasons is made normal. Keep shared chat-specific code only for a real reason, and state it.
- **Expiry and creation records** (notes/expiry-creation-design.md): steps 1-3 built (branch `expiry-2` holds 2-3, with step 4's copy-expiry and sweep removals; not merged). A map record keeps only its writes its dot's records' join holds (spec/crdt.md §5.6, the map clause of §4.8), every reset of a dot reaches all its records, list creations and `W` carry values. Left of step 4: the osis-API examples. Open with it: issues/purge-author-order-452234901986.md (a purged write's leftover shadows an older value only where the body was held when the purge landed; a node that dropped it while invalid never gets the leftover). Decide in the expiry/purge leftover work: one leftover every node can form from what it holds (e.g. from the purge request and the header), or fetchable leftovers.
- **Account signing** (issues/account-signing.md): design decided and settled, eight-step build plan (models first); build next after retention.
- **Network rework** (issues/net-rework.md), then **data that lives while its keepers are connected** (issues/connection-lived-data.md), which replaces keep-alive and the ephemeral "Superseded commits" rule. The "host" concept is still being removed (issues/node-host-unify.md).
- **Forgetting compacted headers** (notes/growth.md row 1): closes most per-commit growth for small, frequently changed values.

## Findings recorded only here
- keys-tidy (branch gone): bounding rotation names (issues/rotation-names-grow.md): "chain coverage through supersedes" leaks (a TLA instance found it); a base-chain rule breaks when a base rotation turns invalid. Redo with the rotate-free principle (spec/crypto.md §4).
