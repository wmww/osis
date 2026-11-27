# Handoff
> Summary: For the next coordinator: where main stands with the sync rewrite in it, the one ordered route from here (slimming, a light dogfood pass, then known issues), what not to build on the way, what waits on Tess, and the open small items. Kept current as work moves.

## Tess's direction (standing)
- Stay focused and moving; simple and correct. Modify plans and process freely.
- How work is run: notes/coordination.md, Keep it simple. In short: work lands on main in the session that did it, main may be broken while a big change is in, delete and disable what is in the way, build the end state directly, one review and gate at the end. No kept branches, no maintained intermediate states.
- Talk to her in plain words: no stage/brief/Open numbers.

## State
- **Coordinator**: Sheave, on the stub rewrite. Agents run on main (no kept branches); every job is reviewed and gated as it lands (notes/coordination.md).
- **Reviewed and gated**: everything on main, the final gate over the whole tree included. Slimming landed: no pull anew for a thing another node makes (attach left, issue attach-pulls-unit-anew), index rows repeating stored facts, one stored form per commit (~35% storage), a blob's bytes once per connection, memory per commit 128 → 70 KB (issue memory-per-commit). The full-size differential: 25 of 200 (issue differential-full-size-classes).
- **Pushed, awaiting review and gate**: `spar-slim-c2` (echo removed, anchored by a log cursor of the requester's own log; the NetStream TLA model passes with the anchor, its controls fail; return direction per dependent make 403 → 180 B). Streams only: nothing the stub rewrite touches, so it can be reviewed now.

## First: the stub rewrite (Tess: go-ahead)
Reference-driven stubs are on main (Tess's model: grants belong to the granted thing; signal → reference → sync → permissions; a grant nobody is told of is valid). Sync IDs are fixed at minting. Opening by entries is on main (notes/stubs.md, notes/sync-access.md, notes/sync-opens.md); the tests still failing since are issues/entries-open-failures.md, the full-size differential's classes issues/differential-full-size-classes.md. What else is decided and owed: notes/stub-rewrite.md. Sheave coordinates it.
- **Waiting on Tess**: the spec/requirements.md wording (stores may learn a padded holder count; "the grant's notice" → a grant signal; notes/stub-rewrite.md); issues/demoted-writer-deletes-at-stores.md (every Delete needs the current write key, recommended); issues/shared-things-refuse-readers-stranded-notices.md (let shared things take stranded notices, recommended).

## The route (Tess)
Target: osis basically works, the big pieces in place, the architecture sensible and mostly settled; what is left is fixes, tweaks and verification. In order:
1. **The stub rewrite above.**
2. **Architectural slimming** (notes/priorities.md Slimmer things; jobs in notes/slim-design.md): the rest in slim-design's order, after the stub rewrite where they touch it.
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

## Waiting on Tess
Every tess-call issue, listed in notes/priorities.md, Parked on Tess. The model questions come first: destroyed-holder-write-authority, destroyed-mint-admin-dependents, held-model-late-commit-read-lost, start-cost-grows-with-held.

## Parked
- `windlass-wiring-1` on GitHub has nothing to land (a debug shadow of a walk since deleted). Delete it when Tess says.
- The held-writes dating is about a quarter of the rotation and deep-departure properties' cost: product cost worth a design pass (notes/time-limits.md, Investigations).

## Habits that saved time
- Never `cd` into a worktree path by guess: `git worktree list`, then the path whose branch matches.
- A model change runs its consumers' differentials before it lands.
- This note names no code in backticks and no issue by path that a landing may delete: either fails policy here.
