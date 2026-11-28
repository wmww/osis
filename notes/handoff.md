# Handoff
> Summary: For the next coordinator: where main stands (the stub rewrite and opening by claims in), the one ordered route from here (the alpha candidate, the structural items, a light dogfood pass, then known issues), what waits on Tess, old words, what not to build, and parked items. Kept current as work moves.

## Tess's direction (standing)
- Stay focused and moving; simple and correct. Modify plans and process freely.
- How work is run: notes/coordination.md, Keep it simple. In short: work lands on main in the session that did it, main may be broken while a big change is in, delete and disable what is in the way, build the end state directly, one review and gate at the end. No kept branches, no maintained intermediate states.
- Talk to her in plain words: no stage/brief/Open numbers.

## State
- **Coordinator**: Sheave, on the alpha candidate (notes/priorities.md, First). Agents run on main (no kept branches); every job is reviewed and gated as it lands (notes/coordination.md).
- **On main**: the stub rewrite (grants with the granted thing; signal → reference → sync → permissions; a node follows any stub: notes/stubs.md), sync IDs fixed at minting, opening by claims (claims in commits, one open rule, Head, claim pages: notes/sync-opens.md, notes/sync-access.md), the local part's log, one read path for the secrets index, cards as one entry per node, stream reports in one window; notices are gone. Slimming's built jobs are listed in notes/priorities.md item 4. The full-size differential fails 7 of 100 seeds, in classes (issues/differential-full-size-classes.md); every red on main is a line in tools/known_failures.txt with its issue (notes/priorities.md, Failing on main).

## Waiting on Tess
- Every tess-call issue, listed in notes/priorities.md, Parked on Tess; the model questions first.
- **Chain holders at sync**: a reader of a unit learns its own chain's holders of a thing it reaches at sync (notes/stub-rewrite.md, Decided). Sheave reads that as spec/requirements.md's "who granted it"; a strict reading of a sync holder learning no role grants wants her word.
- **Dispute sides end with the removal held**: spec/permissions.md §5.1, a recorded dispute side ends when the node no longer holds that removal commit, so releasing a thing returns its storage to a fresh node's and a node syncing it again judges the dispute afresh. Sheave reads "sides stick" as while the thing is held.
- issues/shared-things-refuse-readers-stranded-notices.md has its plan, for after the alpha.

## The route (Tess)
Target: osis basically works, the big pieces in place, the architecture sensible and mostly settled; what is left is fixes, tweaks and verification. In order:
1. **The alpha candidate** (notes/priorities.md, First: main red only with listed failures, the differential's classes, a dogfood smoke pass, one full gate). Record its hash here once reached: the point to back out to.
2. **The structural items** of notes/priorities.md, Core, in order: the stub rewrite's tail, dependent and independent things, reads never waiting on applies, slimming's remaining jobs (notes/slim-design.md).
3. **A light local dogfood pass** (chat between accounts, pairing, removing a node): testing finds problems; fix each at its level (mistake, architecture, or the model), never a workaround; where building it right is unclear, a design pass or a question for Tess. Many QA passes come later, before release.
4. Then known issues, more dogfooding, and simplification beside them.

Two agents on workflow and cleanup throughout (notes/coordination.md, Job mix): the last stretch drifted to all forward work; hold the split.

## Old words and concepts
- issues/deprecated-terms.md lists what is still in the repo though deprecated, each with what removing it takes, and what is gone.
- An old design the test models still carry, a design step and no clean-up: per-thing leaves of a removal's list (issues/models-read-list-leaves.md).
- A word met in git history or in a brief that the tree does not use is dead until the tree says otherwise: read notes/terms.md, never build on it.

## Not to build on the way
- **No grant list with the holder**, no taken or accepted grant, no fire kept as proof, no path a role commit states for its holders: each was built and removed (notes/stubs.md, Rejected).
- **No fix sized by its label.** Three times a class of failing tests labelled with one cause had three or more; one probe line per failing test (what it holds, which fire or box was refused) sizes a job in a session's first minutes. A cause written in a note says whether it was probed or guessed.

## Parked
- `windlass-wiring-1` on GitHub has nothing to land (a debug shadow of a walk since deleted). Delete it when Tess says.
- The held-writes dating is about a quarter of the rotation and deep-departure properties' cost: product cost worth a design pass (notes/time-limits.md, Investigations).

## Habits that saved time
- Never `cd` into a worktree path by guess: `git worktree list`, then the path whose branch matches.
- A model change runs its consumers' differentials before it lands.
- This note names no code in backticks and no issue by path that a landing may delete: either fails policy here.
