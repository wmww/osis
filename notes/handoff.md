# Handoff
> Summary: For the next coordinator (from Mizzen): what is in flight (branches, who owns what), what lands next, Tess's standing direction, and the open small items. Kept current as work moves.

## Tess's direction (standing)
- Stay focused and moving; simple and correct. Modify plans and process freely.
- A big change is one branch: delete the old code first, write the new, one review and gate at the end; no build-beside, scaffolding or spec-first jobs (notes/coordination.md, Rewriting an area). Main working is no value in itself; more than a little rebasing means something went wrong.
- Talk to her in plain words: no stage/brief/Open numbers.

## Primary: the sync rewrite (branch `mizzen-a2-switch`)
Sessions run out of room on it, so each session takes one piece and ends pushed with the sync-rewrite-state note (on the branch only) current: the successor starts there. The delete is done and the tree builds (tickets, accepting and chain certificates gone; certificates rebuilt from the evidence derivation each follow, Interim); 22 tests are ignored by the piece they wait for (`rg -n 'sync rewrite: ' core/`). Done since: holders' paths on role commits; takenness (a role counts only grants its holder takes: a write path stated to it, or a held `grant@~0` fire while its setting enables it); the key part carries no rotation (spec/permissions.md §4 Key part). Held for keys is built engine-side (holders read as ordinary sync IDs for now: the role-entries pull, own boxes and the osis-sync downward search are still owed), the node's own decisions read its taken role, and three fire bugs are fixed (grant fires that page, multi-rotation accounts, paged fire values). Ignored tests: 18. The held-grant rule is green (a thing's grants count where the node syncs it or holds an offer; a load-order bug in rebuilds and a never-handed-over wanted blob fixed along the way). The session now running: two seed-dependent tests, a harness check for commits stalled on blobs a source holds, the sync differential failure on main, then the per-commit derivation and the delete-key check. Behaviour change: the public role read returns the taken role. Then: held for keys; copies per (commit, thing) through osis-sync; the delete-key check on; acting after a complete pass.Then: fresh review, gate, land. Plan context: notes/redesign-plan.md A2 (How it is built), notes/a2-spec/README.md, notes/evidence-derivation.md, notes/delete-keys.md.
- Parallel jobs stay out of its files (certificates, tickets, evidence, sync logging).
- After it: a removal as evidence, accounts as ordinary things, public things and cards, core without accounts (notes/redesign-plan.md A3 to A6), each one branch, delete first; cut them to what is still needed before starting.

## In flight beside it
In-flight lines name issues in words, not paths: a branch that closes its issue would fail policy on this note.
- `mizzen-purge-no-effect` (worker, third session): a purged write has no effect on any read (Tess, decided); rule built and engine green but for expiry cost (waits on the dating redesign's index); osis history listing and some osis-sync tests left.
- Gates count instructions per test binary (tools/test_cost.txt): NEW-COST fails, STALE-COST lowers its line in the landing.

## Safe parallel work queue (outside the rewrite)
- After the sync rewrite lands: the deprecated-terms rename pass ("edge" where a role grant is meant → grant, spec and code; issues/deprecated-terms.md).
- Workflow agent about half the time; one cleanup always.

## Decided by Tess, for the sync rewrite
- **Grants belong to the thing granted** (replaces "paths found by following grants down; roles are the account's data"): a thing's grants sync with it; references find what a node cares about. Flow: outside grant signal → reference → ordinary sync → permissions, the signal carrying only what bootstraps the reference and sync (an offer, kept as the signal's setting keeps it, 90 days default for outside grants). No account grant list, no taken grants, no fire as proof, no kept-fires rules; keys are found from the synced thing up (holders its grants name, their grant data fetched, up to the node's own actors). This dissolves the replay and finding-the-paths questions.

## Small, waiting on Tess
- **How a holder's readers get a granted thing's sync ID and first box** (open; Tess thinks every option offered so far is wrong; talk later). Facts: a reference is a bare tid; the target's own sync ID gives no entry box to a reader-holder (only link keys get one); today the holder's key part (copies of the target's grant data logged under the holder's sync ID) is the only path, for things a holder made and things it was granted alike. Don't build changes to it until she has said what she wants.
- **Convergence clause** (requirements Decentralization): "at the latest once a writer of that data has synced with them" covered the purge divergence; check whether anything else needs it, then drop it?
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
