# Handoff to the next coordinator
> Summary: What is in flight and what comes next, for whoever coordinates after Fathom. Design principles and process live in notes/coordination.md; this note only holds state. Rewrite or delete once taken.

Read CLAUDE.md and notes/coordination.md first. Tess: opus only for every agent, no fable, until she says otherwise. Questions for Tess are issues tagged `tess-call`; priorities are on every issue. Fathom is the lead coordinator (Tess); a second coordinator takes the areas the lead assigns; the split and protocol run over the dogfood channel (notes/dogfood.md).

## Focus (Tess)
Big features and refactors first; chase a bug only when it could threaten their viability. Don't rush to the goal API through shortcuts that later unravel it, but bring core to a settled, finalized state soon so the whole system can settle.

Signal edits: reuse the existing edit machinery rather than add a second mechanism; full-replace-only is fine (Tess), with API questions to settle. App re-rendering (listener step 8) goes ahead without a session with Tess.

## Large designs, in order
- **Rotation**: open issues/keys-depth0-removed-member-rotates.md.
- **Test design** (notes/test-design.md, Open work): the ephemeral property (after connection-lived data), the default-test slow tail, small items.
- **Account signing** (issues/account-signing.md): steps 1 and 4 built. Step 2 open with Tess (covered commits: keep listing everything; per-session ranges studied with header forgetting). Next: 3 (spec), 5, 6.
- **Settings** (issues/settings.md, decided with Tess): account and node settings as ordinary aspects on private things in home; the design to reach for whenever persistent settings are needed, and bespoke settings systems get cut over to it. Not urgent. Build after account signing step 6, which moves node data under D's home label: reconcile the two first.
- **Forgetting compacted headers** (notes/growth.md row 1): conflicts with removal lists naming commit IDs; study a per-session counter range for frontiers with it.
- Network rework (issues/sync-rewrite.md), then data that lives while its keepers are connected (issues/connection-lived-data.md).

## Findings recorded only here
- Bounding rotation names (issues/rotation-names-grow.md): "chain coverage through supersedes" leaks (a TLA instance found it); a base-chain rule breaks when a base rotation turns invalid. Redo with the rotate-free principle (spec/crypto.md §4).

## Networking
Order and state: issues/sync-rewrite.md; the build in progress is issues/sync-rewrite.md (one key, one store and serving path; step 3h2 under way). Step 10 of issues/net-shared-set.md (the epoch signature, account signing) decides when a proven account counts: check what main says before relying on "J counts key actors alone".
- Dogfood channel served from devbox (`~/osis-dogfood`, port 4040, transient units `osis-dogfood-host` (the node both Claudes sync through; `restart-host.sh`), `osis-dogfood-me`): a box stop stops them; restart per notes/dogfood.md with the same stores.
