# Handoff
> Summary: For the next coordinator (from Mizzen): what is in flight (branches, who owns what), what lands next, Tess's standing direction, and the open small items. Kept current as work moves.

## Tess's direction (standing)
- Stay focused and moving; simple and correct. Modify plans and process freely.
- A big change is one branch: delete the old code first, write the new, one review and gate at the end; no build-beside, scaffolding or spec-first jobs (notes/coordination.md, Rewriting an area). Main working is no value in itself; more than a little rebasing means something went wrong.
- Talk to her in plain words: no stage/brief/Open numbers.

## Primary: the sync rewrite (branch `mizzen-a2-switch`)
Sessions run out of room on it, so each session takes one piece and ends pushed with the sync-rewrite-state note (on the branch only) current: the successor starts there. The delete is done and the tree builds (tickets, accepting and chain certificates gone; certificates rebuilt from the evidence derivation each follow, Interim); 22 tests are ignored by the piece they wait for (`rg -n 'sync rewrite: ' core/`). Done since: holders' paths on role commits; takenness (a role counts only grants its holder takes: a write path stated to it, or a held `grant@~0` fire while its setting enables it); the key part carries no rotation (spec/permissions.md §4 Key part). Held for keys is built engine-side (holders read as ordinary sync IDs for now: the role-entries pull, own boxes and the osis-sync downward search are still owed), the node's own decisions read its taken role, and three fire bugs are fixed (grant fires that page, multi-rotation accounts, paged fire values). Ignored tests are down to 76 (engine 17, other crates 59): three more engine faults fixed (own fires never written without sync, an opened fire not retaking boxes, a removal counted as beginning an edge), and a sealed fire ahead of the clock now waits for drift like any commit. The session now running takes the 59 outside the engine (grouped by cause, not symptom), then the engine's 17, then held for keys in osis-sync. Behaviour change: the public role read returns the taken role. Then: held for keys; copies per (commit, thing) through osis-sync; the delete-key check on; acting after a complete pass.Then: fresh review, gate, land. Plan context: notes/redesign-plan.md A2 (How it is built), notes/a2-spec/README.md, notes/evidence-derivation.md, notes/delete-keys.md.
- Parallel jobs stay out of its files (certificates, tickets, evidence, sync logging).
- After it: a removal as evidence, accounts as ordinary things, public things and cards, core without accounts (notes/redesign-plan.md A3 to A6), each one branch, delete first; cut them to what is still needed before starting.

## In flight beside it
In-flight lines name issues in words, not paths: a branch that closes its issue would fail policy on this note.
- `mizzen-chunked-refs` (worker): references inside chunked elements are not indexed (strong refs there keep nothing).
- `mizzen-dating-redesign` (worker, fable, may span sessions): every write on a kept aspect reads a big earlier body whole once per session; a position-based durable held-writes index, incremental dating, long runs split across pages. Its state section is in notes/engine-retention-dating.md.
- Gates count instructions per test binary (tools/test_cost.txt): NEW-COST fails, STALE-COST lowers its line in the landing.

## Safe parallel work queue (outside the rewrite)
- Workflow agent about half the time; one cleanup always.

## Small, waiting on Tess
- **Destruction and a late removal** (branch `mizzen-destruction-cut`, built and tested, not gated): a stolen direct-admin key can destroy a thing for good by a request backdated before its removal. The fix judges a destruction like any purge request (a later removal not listing it takes the right), which needs edit writes (`roles.0`) on a destroyed thing kept whatever their stamp; her rule "nobody writes a thing after its destruction" refused them. Without that, the result depends on arrival order. Honest nodes still refuse to write to a thing they hold destroyed; content after a destruction still reads as an unknown thing. Asks: accept the narrowed rule, then gate and land.
- **Purge and arrival order** (issues/order-purged-message-shown.md, options A and B in plain words there): today a purged write reads differently by whether a node held its body. Coordinator leans A (a purged write has no effect anywhere: deleting the newest message shows the previous one). Branch `mizzen-purged-shown` holds the diagnosis and a hand test; not landed. issues/purge-of-live-write-only-readers-hold.md is the same question for a request naming a live write.
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
