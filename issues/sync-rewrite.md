# Sync rewrite: spec first, then all sync code and tests from scratch
> Summary: The plan that replaces the incremental network rework (the old plans net-rework and net-one-peer in issues/, deleted; read them in git at commit 3bc8bb668). Write the final sync design into spec/ (no interim states), model it, delete the sync code and its tests, rebuild both from the spec. Whole thing in about a day of agent time. For the coordinator that runs it.
> Priority: critical
> Tags: sync, node, spec, tests, net-rework

## Why (Tess, 2026-11-14)
The step-by-step port of the old host-based sync to the peer design (steps 3a … 6b, each split again and again) cost many times what the original system did: about 600 commits touched node sync since 2026-11-01, step 6b alone took 85 commits over seven agent passes and was still red. Causes: porting in place kept old and new models both working (interim states the later steps had to undo); design decisions surfaced mid-build; tests were tied to the old model (a separate test host type, about 300 call sites); long branches rebased against a fast main; and one seam the design never settled (a node that keeps a sync ID without reading it) surfaced as bug after bug (the cannot-read-audit note (at 1dcacb6b0)).

Tess's direction, which governs every choice below:
- **The spec is the product.** It must define something useful and implementable. Code and tests are disposable: agents can rebuild all of them from the spec, and may again when better models come.
- **Delete and rebuild freely**, code and tests alike. Our tests were thought up by agents, never grown from real users; rewriting them from the spec loses nothing we can trust. The constraint on tests is the time to run them, not the cost of writing them.
- **No users, no release:** no fixes to code that is being dropped, critical or not; no compatibility with old data or old wire formats.
- **Nothing blocks on Tess.** She checks in periodically. Decide by notes/coordination.md Design principles; a change to spec/requirements.md is the only thing to flag (it still needs her sign-off), and even then build the recommendation and tell her.
- **Pace:** all five phases in roughly 24 hours of wall time unless something goes wrong. Phases 0-2 are hours, not days.

## Words (check every new line against issues/deprecated-terms.md)
- No **label**, `LabelId`, `label.0`: the word is **sync ID** everywhere at once (spec, code, tests). Rename `label.0` in the new design (say `sync.0`) and its record shapes; decide the names in Phase 1 and list them in the deprecated-terms registry's "Removing takes" column as done.
- No **host**, **box**, **serving node**, **keeper**, **storage node**, **blind node**, or any kind of node named by what it can read. Whether a node reads data is a property of the pair (node, sync ID), never of the node. Write "a node that reads S" / "a node that keeps S unread".
- No **placed**/**placement** in the sync sense, no **upload**: use the registry's words (a node **logs** an entry in its own store; an entry is **held at** a peer; a peer **pulls**). "Placement" stays only for positions in a sequence (crdt).
- No **saved peer**, **label hosts**, **admission**, **keep list**; no **person** for the account actor; no **device** for a node.
- Not "two kinds of node". The design has one kind of node and, per sync ID, two ways a node holds it: **read** (it holds the read secret: full engine judgement) and **kept unread** (it holds only the sync secret: it keeps ciphertext, relays it, verifies signatures and its own grant and removal, and judges nothing else).

## Building it (Tess)
- Build in the right abstractions, e.g. for different network transports or ways of using them: sync never cares how a peer is reached.
- Efficiency is structural, designed in from the start, never profiling and shortcutting hot paths. Agents told to optimize used to add makeshift caches here and there; the real fix was a larger memoization system used everywhere. Each change does work in proportion to what changed.
- Tests: the trade-off is coverage against runtime, not against writing time (agents write tests cheaply; tests run on every change). Build the harness so the marginal test is cheap, which buys more coverage.
- Watch for architectural problems and antipatterns; fix them or record them for study. Nothing is right because it exists; a rule that stays has its reason documented.
- Improve, simplify, rewrite or restructure adjacent code and interfaces as you go, especially where that helps the new code: push good decisions out to the surrounding pieces; never pull in their questionable decisions or vestigial cruft.

## Scope
**Deleted (Phase 3):** `core/node/src/sync/` (about 30 files) and everything in `core/node` that only serves it; the stores and hub in `core/host` (rebuilt as the node's store per sync ID); the session and message layers of `core/proto` that the new design does not keep; the node test net (`core/node/tests/it/net`, its `Host` type and `add_host`), the node sync tests (about 85 files, 1,500 tests), the sync-shaped osis tests, and the sim's network model and scenarios (`core/test/sim/src/net`, `scenarios.rs`, `world.rs` keeper copies). Old sync TLA models stay only if Phase 1 reuses them.

**Kept:** osis-base, -crdt, -store, -commit, -crypto, -keys, -perm, -schema, -label's crypto parts (blob prefix, delete keys, steps' signatures; its sync-shaped parts are rewritten), the engine (minus its sync-only hooks, Phase 2), the osis API surface (its sync calls are reimplemented), app, kit, chat, CLI (their sync calls follow the API), transport (QUIC, relay, p2p; it is below sync).

**Fathom (the other coordinator)** keeps working on keys, rotation, perm and engine judgement. Tell them before Phase 3 which engine hooks go (Phase 2's list) so their branches avoid them. Their merges must not touch `core/node/src/sync` or `core/host` from Phase 0 on.

## Inputs to harvest (Phase 0)
Read these, fold every still-true decision into the Phase 1 spec, then delete them (the issue files) in Phase 0's commit; git keeps them. Harvested into notes/sync-rewrite-inputs.md; the deleted issue files are readable at commit a7dd2393c (`git show a7dd2393c:issues/<name>.md`):
- Old plans: net-one-peer at 3bc8bb668 (steps 3a-8, Interim states, decisions per step), net-rework at 3bc8bb668 (end state, target words, rules), net-6c-plan (reviewed plan for 6c with paste-ready spec text) and core/test/tla/net/NetOpen.tla (its model: side-bound open signatures, answers signed by the newest step's key only, the sync proof derived from the sync secret's seed).
- The unmerged net-6b branch (local branch `net-6b`, its notes synced-group and net-6b-left, its issue sync-only-chain): the synced group S (`synced^.0`), the sync set from S's closure, accepting grants, home under S, dropping after own writes are logged, the decision that a node keeping S unread judges its own grant without the account-epoch rule and stops only when its removal reaches it.
- The other net issues: net-connect.md, net-first-contact.md, net-honest-status.md, net-mesh-discovery.md, net-peer-key-superseded.md, net-reconnect.md, net-rename.md, net-role-sync.md, net-shared-set.md, net-static-hit-to-dialer.md, net-sync-structure.md, net-tests.md, reseal-to-hostless-inbox.md.
- the cannot-read-audit note (at 1dcacb6b0): the table of every judgement rule against a node keeping a sync ID unread, and its proposal (a node keeping S unread holds no engine state of what S carries, only a small sync record: sync IDs and sync secrets from boxes sealed to its own key). Its bugs: sync-demotion-drops-copy (old issue, at 1dcacb6b0), stranded-holder-unread (old issue, at 1dcacb6b0).
- Current spec text: spec/sync.md (all), spec/wire.md §5, §7-§11, spec/permissions.md §3-§5.5 (delivery parts), spec/data-model.md §8-§9, spec/requirements.md (Decentralization, privacy).
- Rules learned from tonight's bug fixes in node sync, each a scenario the new design must handle by construction or the new tests must cover. Get the list from `git log --since=2026-11-12 --format='%h %s' -- core/node/src/sync` plus their issues; at least: a lost Stream push re-read by sequence number (storm-489005); placed-again-once and its stand ending on a head move or a held cover's fall (log-liar, again-stand); a fresh blob per sync ID for a re-logged body (deposit-storm); readers depositing a must-hold body only they hold (eph-revert-reads); a later snapshot not held blocks "uncovered" (never-quiet); own tombstones lifted when a part counts missing again (eph-reverts-seeds); waiting for own role commits before re-logging (eph-seed8); keeping ephemeral records across a restart in place and lost access (eph-sim-unlisted, forget-lost-mem, forget-parts); a deleted entry in the node's own store needs no delete key (aged-covers); destroyed things' own sync IDs emptied only after their destroying request is held there (destroyed-label, release-loop branch, not merged); dial timeout (dial-bound); hub messages after a call's other outputs (no-host-chain); a store failure's restart in place. Write them into Phase 1's design or Phase 4's scenario list; delete each from the list only when one of those covers it.

## Phase 0: stop and clear (an hour)
1. Abandon and delete local branches: `net-6b*`, `net-3i*`, `net-6c-1` (merged), `net-6c-plan` (merged), `release-loop`, `header-only-bound`, `net-beacons`. Release their worktrees (`wt release` in each; check `git worktree list`). The release-loop told-before-emptying rule is an input above, not code to keep.
2. One harvest agent writes a note `sync-rewrite-inputs` in notes/: every decision and every bug-scenario from the inputs, one line each with its source, grouped by Phase 1 area. That note is Phase 1's checklist; it is deleted when Phase 1 merges.
3. Delete the old net issues listed above in the same commit, and repoint every pointer to them (notes, code comments, issues) to issues/sync-rewrite.md; `python3 tools/policy.py` must pass.
4. Post the plan and the freeze in the coordinator channel (Fathom): no edits to `core/node/src/sync`, `core/host`, `core/proto` session code or the sync tests by anyone until Phase 3 lands.

## Phase 1: the final spec (a few hours)
Rewrite spec/sync.md (and the sync parts of wire.md, permissions.md, data-model.md) as the end-state design. No interim states, no "until step N". Parallel design agents, one per area, plus one modeller and one reviewer; each area agent edits only its sections and lists open questions in the inputs note, the coordinator settles them by the Design principles.

Areas:
1. **What a node syncs:** the synced group S (`synced^.0`), sync set = S's closure filtered by what the node may hold; accepting grants; leaving; things the account lost.
2. **Sync IDs:** creation with a thing's own secrets, steps (a tree signed by parent delete keys), claim sets, sync key, sync proof (from the sync secret's seed), Register, the node's store per sync ID (entries, tombstones, caps).
3. **Connections and opens:** one open rule: each side opens S only with its own proof the peer may hold S (J judged by roles, a read secret shown on this connection, or a signature by the newest step's key bound to signer side and connection); never by who dialed. The shared set (intersection of what both sync), testing, Hit, Lost.
4. **The judgement per sync ID:** what a node holds, logs, deletes, deposits and promotes. One rule set, stated as must-hold / may-hold / must-not-hold over the commits under S, with covers, purges, expiry, destruction (destroying requests held under the thing's own sync ID before emptying it), and the bounded "logged again once" rule for disagreements. Two holdings: **read** (full judgement) and **kept unread** (keeps ciphertext; verifies stamps, signatures, delete keys; follows only its own grant and removal; no engine state of what S carries — the cannot-read-audit note (at 1dcacb6b0) proposal).
5. **Inbox, deposits, invites:** inbox sync ID, deposit seed, deposits by non-writers, promotion by writers (with the author's write checked at the writer), invites and their acceptance under S.
6. **Streams and flow control:** pulls, pushes with sequence numbers since the last PullReply, re-reading at the next reply after a gap, caps, full peers, stall and dial timeouts.
7. **Status:** what `status`, `wait_synced` and history completeness mean per sync ID.
8. **Hostile peers:** what each can do and the stated limits (a peer lying in its own log, refusing role entries, holding requests open).

Models (core/test/tla/net and new modules), via `tools/heavy`, sized per notes/test-properties.md (one-minute single-worker probe first; one instance per heavy call; under the hold limit; state under the worktree's `target/`):
- Opens: NetOpen.tla extended to the final rule (it already checks side binding, newest-step answers, the seed-derived proof).
- Hold/log/delete convergence per sync ID with two readers, one node keeping S unread and a hostile peer: no loop (each delete and re-log bounded), every reader reads alike at quiet, nothing a reader needs is deleted everywhere. Every rule in area 4 is in this model before code exists; tonight's storms were all loops a model shows.
- Destruction and emptying: the destroying request reaches every holder before the thing's own sync ID is emptied.

Exit: the reviewer checks the spec against spec/requirements.md and against the inputs note (every line covered or consciously dropped with a reason), the models pass with their negative controls failing for the stated reason, `tools/policy.py` and `tools/spec_map.py --gaps --uncited` pass (spec_map will report uncited rules until Phase 4; record that count). Merge.

## Phase 2: the engine boundary (an hour or two)
One agent writes a note `sync-boundary` in notes/: the interface between the engine and the new sync crate. What sync calls (ingest a commit or part, held parts and their bodies, judgement queries per sync ID, keys and secrets for a sync ID, the node's own grants and removals, timers) and what the engine emits (events, changed sync sets, commits to log). Then it lists every engine function that only the old node sync uses (`labels_read`, `labels_of`, emptying, `retake`'s sync side, `boxed_by`, `inbox_chain`, `keeper_due`, `destroyed_labeled`, `closure_whole`, `purge_resnapshots`' caller, and so on) and marks each keep / replace / delete. A node keeping S unread must need nothing from the engine about what S carries. Tell Fathom the list.

## Phase 3: delete and rebuild (most of the day)
1. **Delete** (one agent, one commit on a branch): the Scope list. The workspace must still build: stub the osis API's sync calls to return a "not built" error and mark the osis tests that need sync `#[ignore = "sync rewrite"]` in the same commit (they are rewritten in Phase 4, not kept as they are). Remove the engine hooks Phase 2 marked delete.
2. **Rebuild** in parallel, one owner agent per module, each against the spec and the boundary note, each in its own worktree off the deletion branch, with the module's spec-rule tests (Phase 4) written alongside:
   - wire and session (frames, Hello, relay, the messages the spec keeps);
   - opens and the shared set;
   - the node's store per sync ID (entries, tombstones, caps, deposits);
   - the judgement per sync ID for read sync IDs;
   - the judgement for sync IDs kept unread (small, its own module);
   - streams, flow control, pull/push sequence numbers;
   - inbox, steps and Register;
   - status;
   - the driver (connections, dials with timeout, timers, the one place outputs are applied: hub messages after a call's other outputs).
3. **Integrate:** one agent plugs the modules into the node and the osis API, removes the stubs, unignores and rewrites the osis tests that need sync.
4. Review each module (fresh reviewer, Briefs rules) and the integration; then one gate for the whole branch; then merge. Use a single integration branch the module branches merge into (local, not pushed), so main sees one fast-forward.

## Phase 4: tests from the spec (alongside Phase 3)
- Rules written in Phase 1 with no test until Phase 4 writes one (each is a Phase 4 spec-rule test; drop it from this line when its test lands): spec/commits.md §5 (unread delete margin), spec/permissions.md §3 (removal logged first), spec/sync-ids.md §2 (home sync id), spec/sync-set.md §1 (home under synced group); and these, whose tests went with the old sync's in Phase 3's deletion: spec/commits.md §2 (class from the key), spec/commits.md §5 (keep at least), spec/commits.md §5 (purge on replace cover), spec/commits.md §5 (purge on replace drop), spec/commits.md §5 (fire kept), spec/crypto.md §4 (encrypt under covering epoch), spec/permissions.md §3 (required rotation), spec/permissions.md §2 (tied edge removed), spec/permissions.md §4 (stranded), spec/permissions.md §7 (removed node's links), spec/permissions.md §7 (joiner's leave).
- **Scenarios from the old sync's issues** (each read with `git show 1dcacb6b0:issues/<name>.md`; drop a line when a test covers it):
  - unsettled-judgment-tests: a judgement staged while a fetch is out: a strict subset dropped as covered is not deleted by a node fetching the cover; a body killed by a write the holder lacks stays until its cover is there; a purged delta dropped as covered leaves at once without a carrier.
  - must-carry-liveness: deleter and holder judge a part's liveness differently (a later write only one holds): no delete and log-again loop past the bounded once.
  - chunk-of-forgotten-commit: a source showing a piece again after it was deleted through the freed set (a lost answer) gets it judged and deleted.
  - reader-copy-linked-blobs: a body whose only copies are at readers comes back with its linked chunk, tree-node and page blobs.
  - promote-covered-only-deposit: a deposit whose parts a held snapshot carries is not promoted.
  - host-takes-inline-before-owed: a node keeping S unread logs a removal before content announced after it, even when the content's bytes come inline first (spec/permissions.md §3).
  - refused-memory-entry-holds-label-unsettled: an ephemeral entry refused for the memory cap holds no deletion or repair judgement of S unsettled.
  - reopened-entries-at-readers: entries a covered drop's undo reopens are fetched again at a node whose only sources are readers.
  - relink-queue-lost-at-restart, suspect-repair-per-launch, pass-sources-restart: a restart forgets no chunk repair, writes no snapshot per launch for a report none can settle, and drops no source a removal's wait counts.
  - pulled-refusal-lost: a refusal of a pulled entry lost with its connection is learned again on reconnect.
  - doubted-head-exhausted: a doubted open head whose Behind walk finds no earlier credential still learns the peer's later head without a reconnect.
  - claimants-pending-grant: a node whose only word of its actor's new grant is a pending inbox commit claims with that actor.
  - stranded-holder-unread: a node holding a thing at sync only sends stranded reports, inbox chains and re-seals with no keyset it does not follow.
  - redeem-dropped-before-delivery: a `redeem` dropped, or a restart, before the join reaches the sharer's node still completes.
  - unsynced-label-rows-kept: a node that stops syncing S without forgetting its group serves or drops S's entries, never keeps them unserved.
  - listing-horizon-tests-isolation: a listing past the deletion horizon is checked with an entry the reader cannot judge (another node's card, a role certificate) deleted while it is away.
  - lan-replaces-relay-flaky: a LAN route replacing a relayed connection comes up at the first announcement, not its 30 s repeat.
  - clock-back-raw-timers: a wall clock gone back by D delays no ping, stall check, settle or back-off by D.
  - Counted at n and 10n: dropping F entries past a source's delete rate sends O(F) items in all (delete-resend-past-rate); a write killing one body under purge on replace judges O(1) entries (kill-judges-label-entries); a hostile contact's stamped inbox blobs up to the caps cost a change O(change) (inbox-full-walk-scale); one step flat in things held (sync-step-cost: 13 ms per Tick at 10^4 things); one connection's flood of inputs delays another source by a few reads (host-hub-stall; sources a transport cannot tell apart stay a stated limit).
  - no-server-audit: its 37-row feature table again, with only nodes that sometimes reach each other (no relay, no internet, no node at a fixed address).
  - Client port (once rebuilt): a client's `status()` shows the daemon's connections (status-over-port); tracking reads of `groups_of`, `role_on`, `holders`, `backlinks`, `profile_of` and `stream` follow a thing at a connected node (tracked-read-port).
- **One harness:** nodes driven deterministically; no special test node type; a node keeping S unread is an ordinary node granted sync; hostile peers are scripted nodes. Never drop a node's returned actions (the harness applies every action; an offline node answers its own dials with Down). Seeds, scripts and shrinking from the start (the order and ephemeral shrinkers in core/node/tests/it today show the shape: replayable scripts printed on failure, shrink to a fixpoint).
- **One fast test per spec rule**, named and cited per tools/spec_map.py conventions, default suite. Target: the whole sync suite runs in about a minute.
- **A reference-model differential** for convergence: random histories, every node reads alike at quiet and matches a simple model. It replaces the many seed-specific tests.
- **A small simulation set**: lost and duplicated messages, a peer lying in its own log, full peers, crashes and restarts in place, store failures. Each bug-scenario from the inputs note is one of these or a spec-rule test.
- **Scale by counting work** at n and 10n (messages, rows, bytes per change), never wall time: the sync-shaped checks the deletion removed are the rows of notes/test-scale.md, Checks to restore (drop a row when its test lands).
- Long runs (large seed counts) belong to release checks, not the gate.

## Phase 5: switch over (an hour or two)
The app, CLI and chat go through the osis API, which now runs the new sync; check them (`cargo test -p osis-kit -p osis-app -p osis-chat -p osis-cli`, GUI clippy). Rebuild the dogfood chat on the new build (notes/dogfood.md; old chat data does not carry over). Update notes (node-sync.md, peers.md, serving.md, synced-group.md and the rest that describe old sync) to describe the new code as present truth; delete notes that only described the old code. Delete this issue and the sync-rewrite-inputs note (if still there); update issues/deprecated-terms.md (rows for label, host, placed, admission, saved peer: done).

## How to run it (for the coordinator)
- Workflow rules still hold: CLAUDE.md, notes/coordination.md (Briefs, Test budget, reviews, gate). Up to 5 opus agents at once, reviewers included. Every brief names the agent's scratch dir and gate-log path inside it.
- Merges: claim a fresh worktree for each merge (`wt claim <name> origin/main`), push only through a script that refuses on an open hold, a stale base or a policy failure (the last coordinator's was in its scratchpad: check `~/osis-dogfood/holds.sh` before every push; post `hold:` and `merged:` lines with `~/osis-dogfood/post.sh`). Read the channel by sender, not by text (Fathom often starts a line with your name).
- Branch-local work (the deletion branch and the module branches) is not pushed; only main is.
- When a phase finishes, update this issue's phase status here, not in a new file.

## Status
- Phase 0: done.
- Phase 1: done. Spec: spec/sync.md (overview) and spec/sync-*.md, spec/sync-transport.md; models in core/test/tla/net (NetOpen, NetHold, NetDestroy, NetKeep) pass with every control failing for its reason.
- Phase 2: done: notes/sync-boundary.md (inventory and interface).
- Phase 3: deletion done on local integration branch `sync-rebuild` (never pushed). Building: crate foundation and harness (`sync-foundation`), wire messages (`sync-wire`). Waits on osis_base::memo::Effects from Fathom's memo worker.
- Phases 4-5: Phase 4 tests are written with each module; Phase 5's notes sweep is running on `sync-notes`.
