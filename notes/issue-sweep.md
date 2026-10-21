# Post-MVP issue sweep: state and how to resume
> Summary: The coordinator-driven sweep over the MVP's open issues: what merged to main, which agent branches are still unmerged (with their state), the issues left and why, and the resume procedure. Delete this note when every branch below is merged or discarded and its content folded into notes/mvp-progress.md.

## Method
Same as notes/mvp-progress.md "Method used by the run": a toplevel coordinator, one opus agent per issue group in its own worktree (`.claude/worktrees/agent-*`, branch `worktree-agent-*`, target dir `~/osis-targets/<branch>`), a fresh opus reviewer per branch (read-only), fixes sent back to the same agent, then the toplevel merges into main and runs `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace`. Pure design tradeoffs are not implemented; their issues are rewritten so the Summary and a "The decision (user terms)" section state what a user gains or loses per option, with technical detail kept below.

## Merged to main (each followed by a green clippy + workspace test run)
1. Sim sweep residues and the store pager test (`link_race` stall: certificate parts carried by any present blob count; `evil_server` 134: sim net stream-head ordering; pager test off-by-one). Issues deleted.
2. CRDT: snapshot runs as range records (allocation bounded), undo chains (spec/crdt.md §4.6, strong rule: every later non-undo commit of the aspect out of effect), tree reader bounds in spec/wire.md §6. Issues deleted.
3. Large values: lengths in tree nodes covered by the node hash (FC-4: `chunker/tree.vec`, `keys/seed.vec` refrozen), O(log n) seeks, uploads scoped to the body's own links (`Engine::body_links`), chunked list edits, lazy nodes fetch tree nodes before shredding. Issues deleted.
4. Security residues: reading-only secret candidates kept per epoch, bounded and checked against published keysets; invite grants write `/secrets` as puts at their own dots only (`Op::Put`, register positions only); owner-chain depth cap `MAX_OWNER_DEPTH` per delta; chunk repair after a purge-vs-reuse race (`Engine::relink`, backed off); hinted opens name their key actor; store files chmod'd on open. Issues deleted; residue filed as issues/reading-candidates-unknown-authors.md.
5. Roster snapshots one delta per edge (certificate copies carry only the chain's edges), label replacement completed (admin rotation, retirement, re-registration where lost), linked frontiers (durable, bounded by `MAX_LINKED_FRONTIERS`, bad input if unlisted), departures cache, key-actor re-seal fix. Issues deleted; issues/set-element-encoding.md filed.

6. Chat costs: certificates per label (another node's copy counts once its deltas are checked against the header and it is present at every server; others' fresh demotions left to their author 30 s after receipt), `revoke_joiner` single-commit flow, chat not a home item, `OSIS_TRACE_UPLOADS`; join 41 KB, removal 26 KB at 4 members.
7. API frictions: expiring placements, `core::group::ITEMS`, `now`/`owner_of`/`created`, `member_path`, link-joiner `demote` through `revoke_joiner`, `on_signal_in`, generic `write_with`, scoped server-list changes, text idle timer, path ops into absent map keys. Issue deleted; api-deferred rewritten.

8. Test gaps: spec-gap tests, hostile-server tests, sim adversaries (`equivocating_writer`, `tombstone_liar`), state-size invariant from honest servers' live entries, crdt decoder differential, stricter crdt model and codec (rule 7 items), server `TOO_LARGE` dead code removed.
9. CRDT: undo fixes (map-key re-add with the joined value; undo below a map key reads the join of live entries), struct/enum field-map paging (spec/crdt.md §8, wide structs no longer refused), list runs close at `CHUNK_MAX`, cached sequence placement (10^5-char text: build 18.9 s → 2.0 s, op 42 → 8.5 ms); issues/crdt-undo-absent-positions.md filed.
10. P2P: `Multi` transport under one driver, LAN loop with sealed signed announcements (FC-5: `sign/signatures.vec`, `kdf/purposes.vec`, `proto/messages.vec`), member-open proof kind 3 over ephemeral dials, stored `sync_policy { publish_reach }` defaulting to contacts-only groups, complete pass over peers (bounded), served-session eviction, announcement caches and candidate fallback; issues/p2p-followups.md filed.
11. osis-perm: tenure ledger audit-only entries make re-snapshots neutral (80k histories, no wire change), walk cost (role cache, audits by one backward search, undo log for restarts and late writes, incremental re-judge in the node): 10^4 writes 4.5 s → 0.5 s; issues/ledger-same-ts-commits.md filed; perm-eval-cost keeps open cost and late-write residues.

## Unmerged branches
- `worktree-agent-a9188d23cf53ba532` (node sync): in progress from main 9bcd188: the second-device joiner-removal liveness bug, concurrent upload duplicates, reading candidates from unknown authors, the remaining node-sync-gaps bullets.
- `worktree-agent-a4d5d86e39171e244` (node core): in progress from the CRDT merge: node-core-gaps and node-state-not-paged.
Both get a fresh review, a main merge, then merge to main with clippy + workspace tests + `tools/spec_map.py --check`.

## Issues left and their kind
- Reframed tradeoffs for the owner (no implementation planned): header-list-commitments, token-admin-secret, reseal-triggers, store-concurrent-readers; chat-costs keeps only the wire-format knobs (header once per commit, one KEM key per keyset, one sealed box per member) with savings in user terms; ledger-same-ts-commits (needs a format change); crdt-undo-absent-positions (spec choice).
- Being worked by the two branches above: node-sync-gaps, second-device-joiner-removal-loop, concurrent-upload-duplicates, reading-candidates-unknown-authors, node-core-gaps, node-state-not-paged.
- Still to assign: p2p-followups, perm-eval-cost remainder (persisted walk at open, late writes early in long histories), crdt-seq-linearization-cost remainder (batch ops copy the state, O(n) cache follow), api-deferred (queries are a design pass; the app layer is the owner's later work), tests-unbuilt remainder (10^4 sweep, membership-model refactors, TLA+ walk).

## Resume procedure
1. `git -C /home/ai/osis log --oneline -12`, `git branch`, `git worktree list`; read this note and `grep -h '^> Summary' issues/*.md`.
2. For each unmerged branch: read its last commits; spawn a fresh reviewer; have its agent (or a fresh one) merge main into the branch and test; then `git merge --no-ff` into main and run clippy, workspace tests and `python3 tools/spec_map.py --check` (regenerate the map when stale). Resolve notes/mvp-progress.md and notes/issue-sweep.md conflicts by taking main.
3. Then assign the remaining issue groups as new agents, about five compiling at once on a 16-core box with per-agent `CARGO_TARGET_DIR` and `CARGO_INCREMENTAL=0` (disk is the limit: keep one profile per agent).
