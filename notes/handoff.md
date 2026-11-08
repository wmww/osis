# Handoff to the next coordinator
> Summary: What is in flight and what comes next, for whoever coordinates after Fathom. Design principles and process live in notes/coordination.md; this note only holds state. Rewrite or delete once taken.

Read CLAUDE.md and notes/coordination.md first. Questions for Tess are issues tagged `tess-call`; priorities are on every issue.

## Next watchdog pass
Tess asks it to judge whether the periodic checks deliver enough (which bugs did they find that per-branch oracles and reviews missed?) or should become a before-release run, and if kept, whether to run them alone on a quiet box: they use every core, so beside cargo-heavy agents they likely slow everything down, while agents mostly think and pack well together. For each bug they found, also name the subtle property behind it (notes/coordination.md, Testing: big random runs finding bugs is a design smell); those go to issues as design simplifications. Then update notes/coordination.md and delete this section.

## Large designs, in order
- **Retention** (issues/retention-modes.md): steps 1-4 built (history modes on the wire; purge on replace is a covering snapshot; no death dating; state is exactly the join of held bodies). Left: step 5 (the history API shows only kept history, issues/history-verified-or-absent.md), the order-oracle redesign (issues/oracles-observable.md item 3), dropping invalid bodies (issues/invalid-bodies-drop-at-once.md).
- **Expiry and creation records** (issues/expiry-knocks-out-commit.md, issues/creation-record-ordinary.md): study together; entries live while they hold content; no kept creation records, unknown-thing writes refetched.
- **Account signing** (issues/account-signing.md): designed and modelled (roles-model `epochs`), decisions recorded; build next after retention.
- **Network rework** (issues/net-rework.md), then **data that lives while its keepers are connected** (issues/connection-lived-data.md), which replaces keep-alive and the ephemeral "Superseded commits" rule. The "host" concept is still being removed (issues/node-host-unify.md).
- **Forgetting compacted headers** (notes/growth.md row 1): closes most per-commit growth for small, frequently changed values.

## Findings recorded only here
- keys-tidy (branch gone): bounding rotation names (issues/rotation-names-grow.md): "chain coverage through supersedes" leaks (a TLA instance found it); a base-chain rule breaks when a base rotation turns invalid. Redo with the rotate-free principle (spec/crypto.md §4).
