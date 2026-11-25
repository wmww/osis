# Handoff
> Summary: For the next coordinator: where main stands with the sync rewrite in it, the one ordered route from here (accounts as ordinary things, then what the rewrite still owes), what not to build on the way, what waits on Tess, and the open small items. Kept current as work moves.

## Tess's direction (standing)
- Stay focused and moving; simple and correct. Modify plans and process freely.
- How work is run: notes/coordination.md, Keep it simple. In short: work lands on main in the session that did it, main may be broken while a big change is in, delete and disable what is in the way, build the end state directly, one review and gate at the end. No kept branches, no maintained intermediate states.
- Talk to her in plain words: no stage/brief/Open numbers.

## State
- **Coordinator**: Spar. Agents run on main (no kept branches); security changes go through a branch, a reviewer and the gate.
- **Built on main, unreviewed as a whole**: the sync rewrite, accounts as ordinary things, public things, cards and the account library (osis-account, libs/account). The big review over them is done; its fix wave is nearly through (issues/differential-full-size-classes.md holds what the full-size differential still finds).

## The route (Tess)
Target: osis basically works, the big pieces in place, the architecture sensible and mostly settled; what is left is fixes, tweaks and verification. In order:
1. **The design changes in flight**: destroying a thing ends access through it, may-grant to the public, grant box records dropped, removal notices sealed to the removed party, steps' needs (their issues).
2. **Architectural slimming before dogfooding** (notes/priorities.md Slimmer things): it may churn the set of unknown issues, so it goes first. Philosophically sound changes that also work; usually less code.
3. **The final review and gate** over everything since the sync rewrite (notes/gate.md: a big change on main is gated from a fresh claim with `--base`), fixes on main.
4. **A light local dogfood pass** (chat between accounts, pairing, removing a node): testing finds problems; fix each at its level (mistake, architecture, or the model), never a workaround; where building it right is unclear, a design pass or a question for Tess. Many QA passes come later, before release.
5. Then known issues, more dogfooding, and simplification beside them.

Workflow and cleanup stay half the agents throughout (notes/coordination.md, Job mix).

## Old words and concepts
- issues/deprecated-terms.md lists what is still in the repo though deprecated, each with what removing it takes, and what is gone. Most of what remains goes with accounts.
- An old design the test models still carry, a design step and no clean-up: per-thing leaves of a removal's list (issues/models-read-list-leaves.md).
- A word met in git history or in a brief that the tree does not use is dead until the tree says otherwise: read notes/terms.md, never build on it.

## Not to build on the way
- **No grant list with the holder**, no taken or accepted grant, no fire kept as proof, no path a role commit states for its holders: each was built and removed (notes/holder-access-study.md; why not down from the account).
- **No fix sized by its label.** Three times a class of failing tests labelled with one cause had three or more; one probe line per failing test (what it holds, which fire or box was refused) sizes a job in a session's first minutes. A cause written in a note says whether it was probed or guessed.

## Waiting on Tess
Nothing.

## Parked
- Old branches on GitHub with nothing to land: `mizzen-a2-switch` (the sync rewrite before its last rebase; main has it) and `windlass-wiring-1` (a debug shadow of a walk since deleted). Delete them when Tess says.
- `mizzen-snapshot-stream`: page-walking snapshot writer, unbounded memory on forged states; resume only with a per-source cursor (issues/durable-decode-bound.md).
- The held-writes dating is about a quarter of the rotation and deep-departure properties' cost: product cost worth a design pass (notes/time-limits.md, Investigations).

## Habits that saved time
- Never `cd` into a worktree path by guess: `git worktree list`, then the path whose branch matches.
- A model change runs its consumers' differentials before it lands.
- This note names no code in backticks and no issue by path that a landing may delete: either fails policy here.
