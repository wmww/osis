# Handoff to the next coordinator
> Summary: What is in flight and what comes next after Capstan wound down (Fathom takes integration and sync). Design principles and process live in notes/coordination.md; this note only holds state. Rewrite or delete once taken.

Read CLAUDE.md and notes/coordination.md first. Opus for every agent; fable only when Tess says so for a job. Questions for Tess are issues tagged `tess-call`; priorities are on every issue. Coordinators talk over the dogfood channel (below) and the cross-session route.

## Focus (Tess)
Her target state: the sync rework on main; no extremely critical open issue and no open sync issue needing a major redesign; dogfood working; tests passing with fair coverage of the new code; no known n² blowups. Speed over a stable main: main may be briefly red if that reaches a working main sooner. Stopgaps stay simple and every site to remove later is marked in code: `// Interim (issues/<name>.md): replaced by <X>`. Never pin seeds of random tests: a bug gets a new hand-written minimal test (notes/coordination.md).

## State
- The sync rewrite is on main (notes/sync.md and the module notes; what is stubbed: issues/sync-unbuilt.md). issues/sync-rewrite.md holds the Phase 4/5 leftovers.
- One branch open: GitHub `capstan-leave-waits-lists` (tip b03d752a2; reviewed and approved): the sync half of the removal case of the "rotation drops a joiner's target" critical — a sync ID lost for want of thing lists waits for one more pass with a caught-up source, an unsync still ends it. It sits on Fathom's `fathom-joiner-target` 3ecfd08c4 (in its security review). Land both together once that review approves; delete the capstan branch after.
- Criticals left: the four account-fork issues (account-merge-storm, account-node-switch-back, account-removal-before-its-rotation, sibling-thing-epoch-listing-cycle) and removed-node learning; all wait on custody (Fathom: notes/account-forks-design.md). None reaches an honest single-device account.
- n² left: none known in the engine's sync readers or forgetting; forgetting still scans four small tables whole (issues/forget-whole-scans.md).

## Next, in order
1. Revoke and lowered-grant certificates (issues/sync-unbuilt.md, read): a node that only syncs S may keep accepting a revoked writer's later writes when the revoke travels under another sync ID.
2. Non-admin deletes by level keys (sync-unbuilt, read: `Act::Delete` signs with the head's delete key only; implementation, not protocol).
4. Designs for Tess to iterate: issues/refs-graph-lifetime.md (strong/weak references, root group, release by reachability), issues/storage-follows-groups.md (storage attributable to synced groups; purge tombstones leave with the last carrying group).
5. Test cost: issues/sync-test-cost.md, issues/tests-4x.md (no test-speed work for its own sake unless easy).

## Landing a branch (what the integrator did)
- In the branch's worktree: `git rebase origin/main` (never `reset --soft` onto a moved ref); check `git diff --stat origin/main...HEAD` shows only the branch's files.
- Tests of the crates touched (engine changes: `-p osis-engine -p osis-sync -p osis`; kit/app/API changes: also `cargo test -p osis-kit -p osis-app` and the GUI clippy), `cargo clippy --all-targets -- -D warnings`, `tools/policy.py` (" 0 violations"), `tools/spec_map.py --gaps --uncited`. Read the result lines before pushing: a push once went out red because the command didn't check them.
- Push main as a fast-forward (`git merge-base --is-ancestor origin/main HEAD`), never force. Several approved branches: stack them in one worktree, one combined check, one push; bisect only on a failure.
- tools/gate.sh only for large landings (it took 510 s wall on fastbox-0 at load 7); `~/osis-dogfood/holds.sh` before a push.

## Dogfood
Box fastbox-0 (this box), pin cc38ab39f, port 4044/udp. Units `osis-dogfood-host-cc38ab39f` (shared node, quic://45.77.211.216:4044, store ~/osis-dogfood/host-cc38ab39f) and `osis-capstan-cc38ab39f` (Capstan's member); `osis-apk-serve` serves the APK on :8099. Restart a stopped unit: `tools/dogfood-member.sh start host cc38ab39f` (or `start capstan cc38ab39f`) from a checkout at the pin. Address, link and chat tid are in ~/osis-dogfood/{HOST_ADDR,LINK,CHAT}.cc38ab39f (never commit them). A cut-over to a newer pin: notes/dogfood.md. Tess is not using dogfood.

## Findings recorded only here
- Bounding rotation names (issues/rotation-names-grow.md): "chain coverage through supersedes" leaks (a TLA instance found it); a base-chain rule breaks when a base rotation turns invalid. Redo with the rotate-free principle (spec/crypto.md §4).
