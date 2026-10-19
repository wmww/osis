# MVP meta plan: executing the implementation run with a team of agents
> Summary: How the toplevel agent runs every plan in plans/ to a working osis (CRDT, commits, crypto, permissions, storage, sync through blind servers, API, example apps) using opus sub-agents in worktrees for all coding, debugging and conflict resolution, fable only for hard problems; the ground rules (spec authority, change policy, complexity budget, targeted tests), the mechanics (spawn, merge, integrate, track, resume), the escalation ladder and failure criteria, and the order of work with what runs in parallel.
> Tags: tests, sync, crdt, permissions, crypto, storage, api

## 1. Goal
At the end osis works to spec: two or more devices of several people share typed data through untrusted servers and directly, merged by the CRDT, authorized by the membership rules, encrypted and shredded per the deletion rules, synced by labels with compaction, purge, expiry, rotation, re-seal, links and recovery cards, exposed through the `osis` API and proven by example apps and the simulator. Not a shippable consumer product: no GUI, no app store, no push wake-ups, no browser build, policies tuned roughly. A solid foundation with no large gaps; small gaps are issues.

## 2. Roles and models
- **Toplevel** (the agent running this plan; fable): plans the waves, spawns and merges, keeps notes/mvp-progress.md, reviews the permanent wire surface, resolves escalations, decides spec questions within the policy below, spins up extra agents when a problem needs it. Writes little code itself.
- **Opus sub-agents** (`model: "opus"`, `isolation: "worktree"`): every plan's implementation, debugging, test writing, merge-conflict resolution, integration passes, code reviews, notes updates. The default for all standard work.
- **Fable sub-agents** (`model: "fable"`): only for problems opus agents escalated or the toplevel judges hard: a design gap the spec leaves open, a rule that seems inconsistent, a convergence or security problem with no obvious fix, a cross-crate abstraction that must be redrawn. They produce a decision, a spec or notes edit, or a precise instruction for an opus agent; they do not take over the plan.
- **Fork agents** (`subagent_type: "fork"`): when the toplevel's own context is what the task needs (e.g. a merge decision that depends on the run's history). Rare.
- Nobody sets `effort` unless the owner asked.

## 3. Ground rules (put them in every sub-agent prompt)
- **Spec authority**: spec/ at the time of implementation trumps notes/ and plans/. A TBD is filled by plans/protocol-spec.md; filling it is not a spec change. A spec sentence that is wrong or unimplementable: minor clarification → edit it, record it under "Spec edits" in notes/mvp-progress.md, continue; significant or breaking (changes bytes already frozen in vectors, removes a property, changes a tension's call) → do not edit; write an issue tagged `owner-call` with the options and the recommended one, implement the most conservative reading that keeps the requirement, and continue elsewhere.
- **Requirements**: never weaken a spec/requirements.md item to fit code. If one cannot be met in a minor way after a real attempt, file an issue (`escalate`), note the gap, continue.
- **Complexity budget**: prefer removing a client-side convenience over adding a mechanism; no new wire fields or message kinds outside the spec; no new dependency without its line in notes/architecture.md; no new crate without a line in the crate map; abstractions in notes/architecture.md §2 are fixed unless an issue reopens them.
- **Code**: simple safe Rust; `#![forbid(unsafe_code)]`; no panics on data; error classes per notes/architecture.md §3; every test cites its spec section; seeded randomness only; no formatting tools; compact prose, comments, commit messages.
- **Tests, targeted**: iterate with `cargo test -p <crate>`; before committing run the crate plus its direct dependents; `cargo test --workspace` only at integration. Tier-2 tests are `#[ignore]`. Never add a test that sleeps or touches the network in tier 1.
- **Bookkeeping**: tick the plan's Steps as they land and append one line to its Progress per session; update the notes the plan names; create issues (with Summary and Tags) for nontrivial problems found; delete an issue only when its fix is merged; never record dates or estimates.
- **Git**: commit to the worktree branch with clear messages (ending with the attribution line the session gives); commit at least at every step boundary and before returning; never push, pull, rebase or rewrite history; never use bare `git stash`.
- **Return**: end with a report: what landed (commits), what is open, any escalation, any interface change other crates must know.

## 4. Mechanics
- **Integration branch**: the branch this plan runs on. Sub-agents work in worktrees (`Agent` with `isolation: "worktree"`) on their own branch; they never touch the integration branch.
- **Spawn prompt** (per plan): "Read notes/architecture.md, plans/<plan>.md and the spec sections it names; spec trumps the plan. Execute the plan's Steps in order, committing per step. Ground rules: <§3 verbatim>. When done or blocked, update Progress and return the report." Add the wave's known interface facts (what merged since the plan was written). Spawn independent plans of a wave in one message so they run concurrently.
- **Merge**: when an agent returns, an opus **integrator** agent (or the toplevel for trivial cases) merges the branch into the integration branch (`git merge --no-ff`), resolves conflicts (regenerating `Cargo.lock` by `git checkout --theirs Cargo.lock && cargo update -w --offline` or a fresh build; workspace `Cargo.toml` members are pre-registered so they rarely conflict), runs `cargo clippy --workspace -- -D warnings` and `cargo test --workspace`, fixes breakage caused by the merge (not the plan's own open steps), commits. A failing integration is never left on the branch: fix or revert the merge and re-spawn the plan agent with the failure.
- **Review before merge**: every plan branch gets a fresh opus reviewer (`/code-review`-style, medium) given the plan and spec sections: correctness against the spec, panics on data, missing tests, unjustified deps. Findings go back to the plan agent (SendMessage to continue it with context) or to the integrator if small. Branches touching the permanent wire surface (protocol-spec, osis-core CBOR and tid, commit header, blob prefix, label steps, vectors freeze) are additionally reviewed by the toplevel before merge.
- **Interface changes**: a plan that must change another crate's public API makes the smallest change, notes it in its report, and the integrator updates dependents; a disputed change becomes an issue and a fable or toplevel decision.
- **Progress file**: notes/mvp-progress.md, kept by the toplevel: one line per plan (not started / running (agent, branch) / review / merged at <sha> / blocked (issue)), the current wave, open escalations, spec edits made, owner-calls pending. This is the resumption point after any context loss. The toplevel re-reads it and `git log` before acting.
- **Resuming a plan**: when an agent stops with steps unticked (context exhausted, blocked then unblocked), spawn a fresh opus agent on the same plan; its Progress lines and the branch's commits are the hand-off. Merge partial branches when they are green and useful; do not keep long-lived branches.
- **Parallel load**: run every independent plan of a wave at once, but keep the integration branch moving: merge as soon as a branch is green rather than waiting for the wave. Downstream plans start when their gate is merged, not when the wave ends.
- **Communication between agents**: through merged code and notes only. An agent needing a fact from another plan reads the integration branch (ask the toplevel to merge first) rather than guessing.

## 5. Problems, escalation and failure
Ladder, applied by the toplevel to every blocker a report raises:
1. The plan agent tries alternatives inside the spec and its budget first, and says what it tried.
2. Re-spawn or continue the opus agent with a concrete hint, or spawn a second opus agent on the narrow problem (a failing differential case, a merge conflict, a flaky invariant) while the first continues.
3. A fable agent for a design-level problem: given the spec sections, the notes' rationale and the concrete failure; it returns a decision and, if needed, a minor spec or notes edit. Record it in notes/mvp-progress.md.
4. The toplevel spins up additional agents beyond this plan where the problem warrants (a missing model, a spike comparing two approaches, a review of an affected area). This plan is not a cage.
5. Owner-call issue when the fix would be a significant spec change, a requirement compromise beyond "minor", or a restructure of a fixed abstraction; implement the conservative reading meanwhile and keep every other plan moving.
Stop the run (report to the owner) only when no solution stays within the complexity budget, avoids a major restructure of the design, and keeps the requirements. Minor unmet requirements after a real attempt: issue + continue.
Watch for and act on: two agents reinventing the same helper (merge into the lower crate); test suites getting slow (move to tier 2, cut proptest cases); a crate pulling heavy deps (feature-gate); divergence between notes and code (fix notes in the same merge).

## 6. Pre-flight (before wave 0)
- Owner has reviewed the spec; re-read spec/ and `issues/` (owner-calls). An opus agent diffs every plan against the current spec and notes and fixes stale references; the toplevel skims the result. Create notes/mvp-progress.md.
- Confirm tooling: Rust stable toolchain, `cargo deny`, `cargo fuzz` (nightly) availability; record in notes/testing.md later.

## 7. Order of work
Gates are merges into the integration branch. "∥" = run concurrently. Models: all opus unless noted.

| wave | plans (∥ within a wave) | gate to start | notes |
|---|---|---|---|
| 0 | plans/workspace.md | pre-flight | serial; defines everything others code against. ∥ with it: plans/protocol-spec.md (opus drafts; toplevel reviews every layout before merge; it has no code dependency) and plans/tla-models.md (fully independent, low priority, runs as long as it needs; its ambiguity list goes to the toplevel as it lands). |
| 1 | plans/crypto.md ∥ plans/crdt-core.md ∥ plans/schema.md ∥ plans/perm.md ∥ plans/test-infra.md (vectors runner, fuzz skeleton, CI) | workspace merged | perm depends on core only; schema needs crdt's `View` trait, so crdt-core commits its skeleton first (its step 1) and schema starts on that merge. plans/store.md starts when crypto's AEAD + kdf step is merged. |
| 2 | plans/crdt-seq.md ∥ plans/commit.md ∥ plans/label.md ∥ plans/keys.md ∥ plans/proto.md | crdt-core skeleton (seq); crypto + protocol-spec (commit, label, keys, proto); perm for keys' rotation rights | If protocol-spec is late, commit/label/proto proceed with provisional layouts behind one module each and switch when it merges; vectors stay provisional until then. |
| 3 | plans/node-core.md ∥ plans/server.md ∥ plans/transport.md ∥ plans/large-values.md (library parts) | node-core: store, crdt, commit, perm, keys, schema; server: label, proto, store Backend, transport InProcess (its step 1); large-values: label, store | plans/sim.md phase A starts when node-core's module layout and writing path are merged. |
| 4 | plans/node-sync.md ∥ plans/membership-flows.md ∥ plans/api.md (first half) | node-core merged (plus server for node-sync tests) | node-sync and flows share `osis-node`: module ownership per plans/node-core.md; the integrator merges them often. large-values' node integration lands here. sim phase B after node-sync. |
| 5 | plans/apps-e2e.md ∥ plans/cli.md ∥ plans/p2p.md ∥ plans/sim.md phase C ∥ plans/api.md (second half, with the apps) | node-sync + flows merged | p2p is best effort (its plan says when to stop). cli's first steps need only api's first half; apps-e2e's localhost e2e waits for cli. |
| 6 | plans/hardening-signoff.md | everything merged | several opus agents in parallel inside it (reviews per subsystem), one integrator. |

Within every wave an **integration pass** (opus) runs after the last merge: workspace green, notes/architecture.md current, duplicated helpers merged down, tier-1 time measured, spec-to-test map regenerated, notes/mvp-progress.md updated. Then the next wave's spawn.

## 8. Reviews of the permanent wire surface
The toplevel personally reviews before merge: plans/protocol-spec.md output (every layout and constant; check the Padmé length-recovery rule, tag numbers against IANA, RBSR choice, link and card formats, first-contact invite), osis-core CBOR and tid, the commit header, blob prefix and framing, registration steps and claim sets, the vectors freeze. A frozen vector changes only with a `FORMAT_CHANGE` note and a toplevel decision.

## 9. Finish
hardening-signoff writes the report into notes/mvp-progress.md and notes/overview.md, deletes every completed plan (their durable content lives in notes/), and leaves issues/ as the list of what is open with tags. The toplevel's last message to the owner: what works, what deviates and why (tension or issue), open owner-calls, and suggested next plans. Do not push.
