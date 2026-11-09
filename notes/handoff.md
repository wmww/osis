# Handoff to the next coordinator
> Summary: What is in flight and what comes next, for whoever coordinates after Fathom. Design principles and process live in notes/coordination.md; this note only holds state. Rewrite or delete once taken.

Read CLAUDE.md and notes/coordination.md first. Tess: opus only for every agent, no fable, until she says otherwise. Questions for Tess are issues tagged `tess-call`; priorities are on every issue. Fathom is the lead coordinator (Tess); a second coordinator takes the areas the lead assigns (Kestrel had networking and docs cleanup); the split and protocol run over the dogfood channel (notes/dogfood.md).

## Focus (Tess)
Big features and refactors first; chase a bug only when it could threaten their viability. Don't rush to the goal API through shortcuts that later unravel it, but bring core to a settled, finalized state soon so the whole system can settle.

Performance (Tess): core through kit to app must make the fast way the easy way: the most ergonomic way to build anything also gives it the right characteristics. There is no typical use, so nothing to tune for: everything reacts only to what it should, nothing is done twice, nothing scales with the wrong thing. Refactor as needed; don't profile and tweak hot paths.

Queued from Tess: remove everything called recovery (code, spec, cards, recovery keys), since it is a holdover and recovery is undesigned, once the switch to accounts merges; keep issues/recovery-redesign.md as the design question. Signal edits: study reusing the existing edit machinery before adding a second mechanism. App re-rendering (listener step 8) goes ahead without a session with Tess.

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
Issues/net-rework.md's order. Built on main: net-tests step 2; honest status step 1 (step 2 waits for Pull); `lan` in every build; shared-set steps 2-4 (`SyncEngine::proven`, J and credentials, records and `changed_at`) and the node log. Nothing in production reads J, credentials, records or the log yet.
- In flight: branch `net-beacons` (tip fe27c989a, on devbox only; shared-set step 5: beacons, Offer, Lost, first contact; peer connections open only through the shared set). Worker done, tier 1 and clippy clean; no review, gate or networking tier 2. Next: a fresh security reviewer (earlier steps' reviews each found a role- or relay-binding bug: ask that first). Its deviations from the design: Hits are keyed digests bound to side, listener key and challenges; new kinds `Shared` and `NoRecord`; a reader with no established epoch uses its newest secret; departed admits nothing (Covers not built); opposite dialers keep two connections until Pull; `Lost` goes at once until step 7. `port::a_wait_needs_no_pump...` failed once under load: check for a close-ordering race.
- After it: steps 6-9 of issues/net-shared-set.md, step 2 of issues/net-honest-status.md with Pull.
- Step 10 (the epoch signature, Fathom's account signing) decides when a proven account counts. Check what main says before relying on "J counts key actors alone".
- issues/leaving-not-confirmed-after-rotation.md needs a format change; offered to Fathom.
- Dogfood channel served from devbox (`~/osis-dogfood`, port 4040, transient units `osis-serving`, `osis-me`): a box stop ends them; restart per notes/dogfood.md with the same stores.
