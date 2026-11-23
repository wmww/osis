# Handoff
> Summary: For the next coordinator (from Mizzen): what is in flight (branches, who owns what), what lands next, Tess's standing direction, and the open small items. Kept current as work moves.

## Tess's direction (standing)
- Stay focused and moving; simple and correct. Modify plans and process freely.
- A big change is one branch: delete the old code first, write the new, one review and gate at the end; no build-beside, scaffolding or spec-first jobs (notes/coordination.md, Rewriting an area). Main working is no value in itself; more than a little rebasing means something went wrong.
- Talk to her in plain words: no stage/brief/Open numbers.

## Primary: the sync rewrite (branch `mizzen-a2-switch`)
Sessions run out of room on it, so each session takes one piece and ends pushed with the sync-rewrite-state note (on the branch only) current: the successor starts there. The delete is done and the tree builds (tickets, accepting and chain certificates gone; certificates rebuilt from the evidence derivation each follow, Interim); 22 tests are ignored by the piece they wait for (`rg -n 'sync rewrite: ' core/`). Done since: holders' paths on role commits; takenness (a role counts only grants its holder takes: a write path stated to it, or a held `grant@~0` fire while its setting enables it); the key part carries no rotation (spec/permissions.md §4 Key part). Held for keys is built engine-side (holders read as ordinary sync IDs for now: the role-entries pull, own boxes and the osis-sync downward search are still owed), the node's own decisions read its taken role, and three fire bugs are fixed (grant fires that page, multi-rotation accounts, paged fire values). Ignored tests: 21. Held for keys is partly built: a third holding kind, the wire peer class (reader, store, keys), role-entries-only serving, role entries actually stamped as such. The downward search waits on Tess (below). The session now running: copies per (commit, thing) through osis-sync, fed per commit, leaving with their last body; then the delete-key check on. Behaviour change: the public role read returns the taken role. Then: held for keys; copies per (commit, thing) through osis-sync; the delete-key check on; acting after a complete pass.Then: fresh review, gate, land. Plan context: notes/redesign-plan.md A2 (How it is built), notes/a2-spec/README.md, notes/evidence-derivation.md, notes/delete-keys.md.
- Parallel jobs stay out of its files (certificates, tickets, evidence, sync logging).
- After it: a removal as evidence, accounts as ordinary things, public things and cards, core without accounts (notes/redesign-plan.md A3 to A6), each one branch, delete first; cut them to what is still needed before starting.

## In flight beside it
In-flight lines name issues in words, not paths: a branch that closes its issue would fail policy on this note.
- `mizzen-compact-seq` (worker): dead list/text records held compact in memory (decided A).
- `mizzen-purge-no-effect` (worker): a purged write has no effect on any read (Tess, decided).
- `mizzen-dating-redesign` (built and green; a fresh reviewer gates and lands it): every write on a kept aspect reads a big earlier body whole once per session; a position-based durable held-writes index, incremental dating, long runs split across pages. Its state section is in notes/engine-retention-dating.md.
- Gates count instructions per test binary (tools/test_cost.txt): NEW-COST fails, STALE-COST lowers its line in the landing.

## Safe parallel work queue (outside the rewrite)
- After the sync rewrite lands: the deprecated-terms rename pass ("edge" where a role grant is meant → grant, spec and code; issues/deprecated-terms.md).
- Workflow agent about half the time; one cleanup always.

## Small, waiting on Tess
- **Finding keys through groups you're not reading** (issue finding-the-paths-standing-read on branch `mizzen-a2-switch`): her decided design follows grants downward from the account, but nothing tells a node a group's grants except syncing that group, and a group's grants change, so the search becomes a standing sync of every group reached (it would sync granted things before anything references them, and keep released things' storage). Options: (1) grants travel as their own small entry kind under each group, so a node pulls only those, one stored per grant of each group it reaches (a requirements question: an unheld granted thing then costs its groups' grants); (2) search only when a reached thing can't be entered, stopping after one pass (blind to later grants); (3) the target's record rides with the evidence (fixes the common case, leaves deeper paths unfound). Coordinator's lean: 1, it is the decided design with its cost stated.
- **Replayed grant deliveries** (issue grant-fire-replay on branch `mizzen-a2-switch`): once a removed grant's last trace leaves a grantee's inbox (90 days past the removal), an old copy of the grant's delivery brings the grant back at that grantee's nodes (only there: the shared thing's own readers aren't fooled). Closing it means each grantee keeps one record per grant ever received from outside, for good, against the requirements' "no growth from churn". Coordinator's lean: keep it as history of the outside-grants setting, which she already said admins can cap or purge, so the cap bounds it and is the stated tradeoff. Asks: accept that reading (and the small requirements wording it needs), or accept the replay window.
- CLAUDE.md's GUI test command lacks `--no-fail-fast`; a smaller fixed setting for the KNOWN story search; the gate.checks CPU share raise (notes/time-limits.md).

## Parked
- `mizzen-snapshot-stream`: page-walking snapshot writer, unbounded memory on forged states; resume only with a per-source cursor (issues/durable-decode-bound.md).
- osprey box has no base unit in notes/time-limits.md: `tools/heavy tools/limits.py unit` before a gate runs there.

## Habits that saved time
- Gate and land with `tools/merge-branch gate NAME` (background, claudewait) and `tools/merge-branch land NAME`: claim, rebase, policy, gate, verify and clean-up in one checked tool (notes/gate.md).
- Gate commands: `mkdir` the log dir and set `L=` in their own step, never after an `&&` chain that can fail first (a missing dir or an unset `L` means the gate never ran). After `tools/land`, check main moved before deleting the local branch.
- Never `cd` into a worktree path by guess: `git worktree list`, then the path whose branch matches.
- Land only after `git merge-base --is-ancestor origin/main HEAD`; if main moved, test the crates both sides changed.
- A gate NEW failure: replay on main's binary (`tools/bin-at origin/main`); failing there → issue + rate line on main, then land.
- Name the claimed worktree explicitly; never a `cd` fallback.
- A model change runs its consumers' differentials before its gate.
