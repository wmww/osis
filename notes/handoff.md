# Handoff
> Summary: For the next coordinator: where main stands with the sync rewrite in it, the one ordered route from here (slimming, a light dogfood pass, then known issues), what not to build on the way, what waits on Tess, and the open small items. Kept current as work moves.

## Tess's direction (standing)
- Stay focused and moving; simple and correct. Modify plans and process freely.
- How work is run: notes/coordination.md, Keep it simple. In short: work lands on main in the session that did it, main may be broken while a big change is in, delete and disable what is in the way, build the end state directly, one review and gate at the end. No kept branches, no maintained intermediate states.
- Talk to her in plain words: no stage/brief/Open numbers.

## State
- **Coordinator**: Spar, winding down at the end of its context; the next coordinator takes over. Agents run on main (no kept branches); every job is reviewed and gated as it lands (notes/coordination.md).
- **Reviewed and gated**: everything on main, the final gate over the whole tree included. Slimming landed: no pull anew for a thing another node makes (attach left, issue attach-pulls-unit-anew), index rows repeating stored facts, one stored form per commit (~35% storage), a blob's bytes once per connection, memory per commit 128 → 70 KB (issue memory-per-commit). The full-size differential: 25 of 200 (issue differential-full-size-classes).
- **Still running when Spar stopped** (let them finish; review each before it lands): echo removal anchored by a log cursor (`spar-slim-c2`), watchdog round 4, test optimizer round 6.
- **Pushed, held, not to review yet**: `spar-public-listing-role` (the public's listing role by its box, counted until the node's own `sync.0` records that head). It builds on the machinery below; judge it after the key-part decision.

## First: key parts contradict the model (Tess, stop and fix)
Tess stopped new work on this. **The model**: grants belong to the granted thing; a node finds what it cares about by references; the flow is signal → reference → sync → permissions. A holder's members need not learn what the holder holds; a member reaching X through H with no reference to X is correct. The bootstrap for syncing a referenced thing is its **stub in the referrer's sync unit**: whoever writes the reference normally syncs the target, so it (or any node syncing both) logs the stub there, and the unit's other readers sync the target from it. A bare reference with no stub is irregular and needs no support. Stubs are mainly for weak references (a strong reference brings the thing in whole; a stub only where the unit's keys do not open it), notes/stubs.md; Tess's decided design, partly built (weaks and fire stubs not built).
**The contradiction**: spec/permissions.md §4 Key part logs copies of every grant naming H (edge pieces) under H's own sync ID: a grant list on the holder, driven by grants, not references. Many rules sit on it: delivering edge pieces, held for keys fetching them, sync-alone holders and their removal by steps, stubs built from edge pieces, public pieces and following by the public entry, notices.
**How it came back**: key parts were built 2026-11-22 under the downward design Tess rejected the next day; the edge pieces were kept, renamed "a bootstrap for siblings"; the open question to Tess ("how a holder's readers get a granted thing's sync ID and first box") was closed in the handoff by the assumption that accounts as ordinary things would dissolve it, and the accounts brief never said to delete key parts; later fixes extended what the spec had. The coordinator explained the spec's shape to Tess as the design. Agents read the spec as truth: a principle the spec contradicts loses.
**What to do**: a design pass with Tess, no code first: list every use of edge pieces and key parts today, and for each the reference/stub/target-data/signal answer or the precise gap; then delete key parts' edge pieces whole and build reference-driven stubs (notes/stubs.md) in one rewrite (model first). Until then brief nothing that builds on key parts, edge pieces, held for keys fetching them, or public pieces. Judge every differential class and issue touching them after the rewrite, not before (chain-top-unseen-by-sync-holder dissolves under the model: no requirements change).

## The route (Tess)
Target: osis basically works, the big pieces in place, the architecture sensible and mostly settled; what is left is fixes, tweaks and verification. In order:
1. **The key-part fix above.**
2. **Architectural slimming** (notes/priorities.md Slimmer things; jobs in notes/slim-design.md): the rest in slim-design's order, after the key-part rewrite where they touch it.
3. **A light local dogfood pass** (chat between accounts, pairing, removing a node): testing finds problems; fix each at its level (mistake, architecture, or the model), never a workaround; where building it right is unclear, a design pass or a question for Tess. Many QA passes come later, before release.
4. Then known issues, more dogfooding, and simplification beside them.

Two agents on workflow and cleanup throughout (notes/coordination.md, Job mix): the last stretch drifted to all forward work; hold the split.

## Old words and concepts
- issues/deprecated-terms.md lists what is still in the repo though deprecated, each with what removing it takes, and what is gone.
- An old design the test models still carry, a design step and no clean-up: per-thing leaves of a removal's list (issues/models-read-list-leaves.md).
- A word met in git history or in a brief that the tree does not use is dead until the tree says otherwise: read notes/terms.md, never build on it.

## Not to build on the way
- **No grant list with the holder** (key parts' edge pieces are one, still in the spec: see First, above), no taken or accepted grant, no fire kept as proof, no path a role commit states for its holders: each was built and removed (notes/holder-access-study.md; why not down from the account).
- **No fix sized by its label.** Three times a class of failing tests labelled with one cause had three or more; one probe line per failing test (what it holds, which fire or box was refused) sizes a job in a session's first minutes. A cause written in a note says whether it was probed or guessed.

## Waiting on Tess
Every tess-call issue, listed in notes/priorities.md, Parked on Tess. The model questions come first: destroyed-holder-write-authority, destroyed-mint-admin-dependents, chain-top-unseen-by-sync-holder, held-model-late-commit-read-lost, start-cost-grows-with-held.

## Parked
- `windlass-wiring-1` on GitHub has nothing to land (a debug shadow of a walk since deleted). Delete it when Tess says.
- The held-writes dating is about a quarter of the rotation and deep-departure properties' cost: product cost worth a design pass (notes/time-limits.md, Investigations).

## Habits that saved time
- Never `cd` into a worktree path by guess: `git worktree list`, then the path whose branch matches.
- A model change runs its consumers' differentials before it lands.
- This note names no code in backticks and no issue by path that a landing may delete: either fails policy here.
