# Handoff
> Summary: For the next coordinator (from Mizzen): what is in flight (branches, who owns what), what lands next, Tess's standing direction, and the open small items. Kept current as work moves.

## Tess's direction (standing)
- Stay focused and moving; simple and correct. Modify plans and process freely.
- A big change is one branch: delete the old code first, write the new, one review and gate at the end; no build-beside, scaffolding or spec-first jobs (notes/coordination.md, Rewriting an area). Main working is no value in itself; more than a little rebasing means something went wrong.
- Talk to her in plain words: no stage/brief/Open numbers.

## Primary: the sync rewrite (branch `mizzen-a2-switch`)
Sessions run out of room on it, so each session takes one piece and ends pushed with the sync-rewrite-state note (on the branch only) current: the successor starts there. The delete is done and the tree builds (tickets, accepting and chain certificates gone; certificates rebuilt from the evidence derivation each follow, Interim); 22 tests are ignored by the piece they wait for (`rg -n 'sync rewrite: ' core/`). Done since: holders' paths on role commits (a sealed header field `holders`; firing only where no write path to the holder is stated); the branch is policy-clean. Pieces left, one per session: takenness and held for keys (running now, with a full workspace test run first and the key-part rotation question); copies per (commit, thing) through osis-sync; the delete-key check on; acting after a complete pass. Done on the branch: delete keys are step keys and their check is built (off until copies carry steps). Its job now, in order: delete chain certificates, the any-path search, `author_chain`, `current_keys` as evidence, tickets, `tickets.0`, key-change tickets, removal notices, accepting; then write logging and leaving by the evidence derivation (`evidence::`), turn the delete-key check on, held for keys over taken grants with the downward search, `grant@~0` and sealed copies, acting after a complete pass; spec moved alongside. Then: fresh review, gate, land. Plan context: notes/redesign-plan.md A2 (How it is built), notes/a2-spec/README.md, notes/evidence-derivation.md, notes/delete-keys.md.
- Parallel jobs stay out of its files (certificates, tickets, evidence, sync logging).
- After it: a removal as evidence, accounts as ordinary things, public things and cards, core without accounts (notes/redesign-plan.md A3 to A6), each one branch, delete first; cut them to what is still needed before starting.

## In flight beside it
- `mizzen-seq-runs` (worker): issues/seq-cold-edits-follow-gaps.md, the multi-op case.
- Gates count instructions per test binary (tools/test_cost.txt): NEW-COST fails, STALE-COST lowers its line in the landing.

## Safe parallel work queue (outside the rewrite)
- issues/text-move-writes-grow.md: engine pages / osis-crdt.
- issues/masked-backdated-lowerings.md: osis-perm walk.
- issues/held-model-until-no-deadline.md: cause never read.
- Workflow agent about half the time; one cleanup always.

## Small, waiting on Tess
- **Purge and arrival order** (issues/order-purged-message-shown.md, options A and B in plain words there): today a purged write reads differently by whether a node held its body. Coordinator leans A (a purged write has no effect anywhere: deleting the newest message shows the previous one). Branch `mizzen-purged-shown` holds the diagnosis and a hand test; not landed.
- CLAUDE.md's GUI test command lacks `--no-fail-fast`; a smaller fixed setting for the KNOWN story search; the gate.checks CPU share raise (notes/time-limits.md).

## Parked
- `mizzen-snapshot-stream`: page-walking snapshot writer, unbounded memory on forged states; resume only with a per-source cursor (issues/durable-decode-bound.md).
- osprey box has no base unit in notes/time-limits.md: `tools/heavy tools/limits.py unit` before a gate runs there.

## Habits that saved time
- Land only after `git merge-base --is-ancestor origin/main HEAD`; if main moved, test the crates both sides changed.
- A gate NEW failure: replay on main's binary (`tools/bin-at origin/main`); failing there → issue + rate line on main, then land.
- Name the claimed worktree explicitly; never a `cd` fallback.
- A model change runs its consumers' differentials before its gate.
