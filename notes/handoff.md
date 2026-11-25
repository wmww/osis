# Handoff
> Summary: For the next coordinator: where main stands with the sync rewrite in it, the one ordered route from here (accounts as ordinary things, then what the rewrite still owes), what not to build on the way, what waits on Tess, and the open small items. Kept current as work moves.

## Tess's direction (standing)
- Stay focused and moving; simple and correct. Modify plans and process freely.
- How work is run: notes/coordination.md, Keep it simple. In short: work lands on main in the session that did it, main may be broken while a big change is in, delete and disable what is in the way, build the end state directly, one review and gate at the end. No kept branches, no maintained intermediate states.
- Talk to her in plain words: no stage/brief/Open numbers.

## State
- **Coordinator**: Spar. Agents run on main (no kept branches); security changes go through a branch, a reviewer and the gate.
- **The sync rewrite and accounts as ordinary things are on main**, unreviewed as a whole. Accounts: built through spec, delete, keys, making an account, pairing and removal, proofs, models (perm and sync side) and counting; state, ignores and what's left: notes/accounts-switch-brief.md. Accounts functions live in the osis-account library (libs/account).
- **Public things, cards and the library (A5 with A6 folded in)** are in progress on main: notes/public-and-cards-brief.md (order of work; pieces 1-2 done, piece 3 the public in perm/keys running).
- **The one review and gate** over the sync rewrite plus accounts come at the end of the public-and-cards stage, which rewrites the same machinery (Tess: structure first).

## The route
One list, in order; notes/redesign-plan.md holds the stages and their reasons.

1. **Public things, cards and the account library**: notes/public-and-cards-brief.md, pieces 3-8. Then the review and gate over everything since the sync rewrite.
2. **What the rewrite still owes**: notes/sync-rewrite-state.md (Next), issues/disputes-storage-under-f6.md.
3. **Then** a removal as evidence (what A2 did not already build) and clean-up. Cut each to what is still needed before starting.

Tess's direction (notes/priorities.md, Structure first): right shape first, fixes after; main need not work between pieces; tests rewritten slimmer, not ported; two agents on the primary line when their pieces don't collide.

## Old words and concepts
- issues/deprecated-terms.md lists what is still in the repo though deprecated, each with what removing it takes, and what is gone. Most of what remains goes with accounts.
- An old design the test models still carry, a design step and no clean-up: per-thing leaves of a removal's list (issues/models-read-list-leaves.md).
- A word met in git history or in a brief that the tree does not use is dead until the tree says otherwise: read notes/terms.md, never build on it.

## Not to build on the way
- **Nothing that accounts delete.** The account root, its key part, node cards, the signing chain, account epochs, custody and their tests go at step 1: an ignore or failure whose cause sits there is recorded and left (two of the ignored tests are in a test file on the delete list; the delete-key issue's account-epoch item goes the same way).
- **No grant list with the holder**, no taken or accepted grant, no fire kept as proof, no path a role commit states for its holders: each was built and removed (notes/holder-access-study.md; why not down from the account).
- **No fix sized by its label.** Three times a class of failing tests labelled with one cause had three or more; one probe line per failing test (what it holds, which fire or box was refused) sizes a job in a session's first minutes. A cause written in a note says whether it was probed or guessed.

## Waiting on Tess
Nothing. Her decisions from the last session are in notes/stubs.md, notes/principles.md (Deleting has no safe side) and the issues they touched.

## Parked
- Old branches on GitHub with nothing to land: `mizzen-a2-switch` (the sync rewrite before its last rebase; main has it) and `windlass-wiring-1` (a debug shadow of a walk since deleted). Delete them when Tess says.
- `mizzen-snapshot-stream`: page-walking snapshot writer, unbounded memory on forged states; resume only with a per-source cursor (issues/durable-decode-bound.md).
- The held-writes dating is about a quarter of the rotation and deep-departure properties' cost: product cost worth a design pass (notes/time-limits.md, Investigations).

## Habits that saved time
- Never `cd` into a worktree path by guess: `git worktree list`, then the path whose branch matches.
- A model change runs its consumers' differentials before it lands.
- This note names no code in backticks and no issue by path that a landing may delete: either fails policy here.
