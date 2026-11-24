# Handoff
> Summary: For the next coordinator: where main stands with the sync rewrite in it, the one ordered route from here (accounts as ordinary things, then what the rewrite still owes), what not to build on the way, what waits on Tess, and the open small items. Kept current as work moves.

## Tess's direction (standing)
- Stay focused and moving; simple and correct. Modify plans and process freely.
- How work is run: notes/coordination.md, Keep it simple. In short: work lands on main in the session that did it, main may be broken while a big change is in, delete and disable what is in the way, build the end state directly, one review and gate at the end. No kept branches, no maintained intermediate states.
- Talk to her in plain words: no stage/brief/Open numbers.

## State
- **Nothing is running.** No agent, no task in flight; the worktrees under `.worktrees/` hold old finished branches.
- **Main** builds, passes its default tests (3,849, none failing) and clippy, with the sync rewrite and the legacy clean-up in it. The seeds failing on it, unread: notes/priorities.md, Failing on main.
- **The sync rewrite is on main**, as it stood on its branch: unreviewed, ungated, no property or sim run on it.
  - 21 of its tests are ignored by cause (`rg -n 'sync rewrite: ' core/ libs/`); chat's join by a write link is one of them (fails at the redeem, "no holder answered", cause unknown).
  - Its account is notes/sync-rewrite-state.md: what the tree is, the ignores by cause, what is owed, and a list of rulings marked "For review".

## The route
One list, in order. It stands in for every other list of what is next (the order of the state note's Next, the order of code briefs in notes/a2-spec/README.md); notes/redesign-plan.md holds the stages and their reasons.

1. **Accounts as ordinary things** (Tess: next, delete first), on main directly, no branch. Builder's brief with the delete list, sizes and order of work: notes/accounts-switch-brief.md; stage A4 of the plan.
   - It builds on notes/stubs.md: Tess's decisions on grants, stubs, references in history and the inbox, with what the spec piece settles and what to model first. Also for the spec piece: home as the account itself or a dependent of it (the design note argues the first, the plan says the second: settle in the spec piece).
   - The key hop and the membership cases are modelled already (roles-model's paths; the walk reads the key hop as admin until this lands).
   - One piece a session, each ending pushed. The one review and gate come when accounts are in, over the rewrite and accounts together.
2. **What the rewrite still owes**, after accounts: notes/sync-rewrite-state.md (Next, and the ignored tests by cause), issues/delete-key-levels-unchecked.md (Left), issues/models-read-chained-sets.md.
3. **Then** what the plan has left: a removal as evidence (what A2 did not already build), public things and cards, core without accounts, clean-up. Cut each to what is still needed before starting.

Beside the route: the failing seeds (notes/priorities.md; each starts with a hand-written minimal reproducer, never the pinned seed: notes/principles.md); one cleanup always, a workflow job about half the time (the rewrite's ignores by cause: `tools/ignores.py`).

## Old words and concepts
- issues/deprecated-terms.md lists what is still in the repo though deprecated, each with what removing it takes, and what is gone. Most of what remains goes with accounts.
- Old designs the test models still carry, each a design step and no clean-up: the chained sets (issues/models-read-chained-sets.md) and per-thing leaves of a removal's list (issues/models-read-list-leaves.md).
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
