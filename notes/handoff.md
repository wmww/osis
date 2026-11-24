# Handoff
> Summary: For the next coordinator: where main stands with the sync rewrite in it, the one ordered route from here (accounts as ordinary things, then what the rewrite still owes), what not to build on the way, what waits on Tess, and the open small items. Kept current as work moves.

## Tess's direction (standing)
- Stay focused and moving; simple and correct. Modify plans and process freely.
- A big change is one line of work: delete the old code first, write the new, one review and gate at the end; no build-beside, scaffolding or spec-first jobs (notes/coordination.md, Rewriting an area). Main working is no value in itself; more than a little rebasing means something went wrong.
- Talk to her in plain words: no stage/brief/Open numbers.
- **No process spiral (Tess).** A large change bogs down in process, in problems of its intermediate states and in keeping branches rebased, and each of those breeds more of itself until nothing else happens. So: the primary work goes straight onto main, which may be broken for as long as it takes; nothing is fixed, tidied, reviewed or gated at a halfway point; a failure in an intermediate state is labelled and left unless it blocks the next piece. If a session is spending its time on anything but the change itself, stop and cut the thing demanding it.

## State
- **Nothing is running.** No agent, no task in flight; the worktrees under `.worktrees/` hold old finished branches.
- **Main** builds, passes its default tests (3,849, none failing) and clippy, with the sync rewrite and the legacy clean-up in it. Two seeds fail on it unread, each with its issue and rate line: a cold seq edit-then-move (issues/seq-cold-edit-move-placement.md) and a holder with key access lacking a box after rotations (issues/rotation-holder-lacks-box.md, security). The custody failures go with the account machinery.
- **The sync rewrite is on main**, as it stood on its branch: unreviewed, ungated, no property or sim run on it.
  - Built: a grant belongs to the thing granted (a node's role is by the grants of what it syncs or holds an offer of; a grant from outside arrives as an offer; holders are held for keys from the synced thing up, in engine and sync); a sync ID carries a commit's unit body and one certificate copy per thing outside the unit, read off the one evidence derivation; the delete-key check is on.
  - 21 of its tests are ignored by cause (`rg -n 'sync rewrite: ' core/ libs/`); chat's join by a write link is one of them (fails at the redeem, "no holder answered", cause unknown).
  - Its account is notes/sync-rewrite-state.md: what the tree is, the ignores by cause, what is owed, and a list of rulings marked "For review".

## The route
One list, in order. It stands in for every other list of what is next (the order of the state note's Next, the order of code briefs in notes/a2-spec/README.md); notes/redesign-plan.md holds the stages and their reasons.

1. **Accounts as ordinary things** (Tess: next, delete first), on main directly, no branch. Builder's brief with the delete list, sizes and order of work: notes/accounts-switch-brief.md; stage A4 of the plan.
   - It builds on notes/stubs.md: Tess's decisions on grants, stubs, references in history and the inbox, with what the spec piece settles and what to model first. Also for the spec piece: home as the account itself or a dependent of it (the design note argues the first, the plan says the second: settle in the spec piece).
   - The key hop and the membership cases are modelled already (roles-model's paths; the walk reads the key hop as admin until this lands).
   - One piece a session, each ending pushed. Main may be red: a test broken by the piece is ignored with the piece's label and left.
   - The one review and gate come when accounts are in, over the rewrite and accounts together.
2. **What the rewrite still owes**, after accounts (notes/sync-rewrite-state.md, Next): sealed copies in place of rotations delivered as grant fires; own boxes only for a holder held for keys; acting only after a complete pass; the offer cut to the bootstrap alone; the delete-key leftovers (issues/delete-key-levels-unchecked.md, Left); the ignores still standing, each probed for its own cause; the models' chained sets (issues/models-read-chained-sets.md); the citations of the two retired-machinery issues; the deprecated-terms rename.
3. **Then** what the plan has left: a removal as evidence (what A2 did not already build), public things and cards, core without accounts, clean-up. Cut each to what is still needed before starting.

Beside the route: the two failing seeds; one cleanup always, a workflow job about half the time (a tool that lists and runs the rewrite's ignores by name: three sessions wrote it in scratch).

## Old words and concepts
- issues/deprecated-terms.md lists what is still in the repo though deprecated, each with what removing it takes, and what is gone. Most of what remains goes with accounts.
- Old designs the test models still carry, each a design step and no clean-up: the chained sets (issues/models-read-chained-sets.md) and per-thing leaves of a removal's list (issues/models-read-list-leaves.md).
- A word met in git history or in a brief that the tree does not use is dead until the tree says otherwise: read notes/terms.md, never build on it.

## Not to build on the way
- **Nothing that accounts delete.** The account root, its key part, node cards, the signing chain, account epochs, custody and their tests go at step 1: an ignore or failure whose cause sits there is recorded and left (two of the ignored tests are in a test file on the delete list; the delete-key issue's account-epoch item goes the same way).
- **No grant list with the holder**, no taken or accepted grant, no fire kept as proof, no path a role commit states for its holders: each was built and removed (notes/holder-access-study.md; why not down from the account).
- **No fix sized by its label.** Three times a class of failing tests labelled with one cause had three or more; one probe line per failing test (what it holds, which fire or box was refused) sizes a job in a session's first minutes. A cause written in a note says whether it was probed or guessed.

## Waiting on Tess
1. CLAUDE.md's GUI test command lacks `--no-fail-fast`; a smaller fixed setting for the KNOWN story search; the gate.checks CPU share raise (notes/time-limits.md).

## Parked
- `mizzen-snapshot-stream`: page-walking snapshot writer, unbounded memory on forged states; resume only with a per-source cursor (issues/durable-decode-bound.md).
- osprey box has no base unit in notes/time-limits.md: `tools/heavy tools/limits.py unit` before a gate runs there.
- The held-writes dating is about a quarter of the rotation and deep-departure properties' cost: product cost worth a design pass (notes/time-limits.md, Investigations).

## Habits that saved time
- Gate and land with `tools/merge-branch gate NAME` (background, claudewait) and `tools/merge-branch land NAME`: claim, rebase, policy, gate, verify and clean-up in one checked tool (notes/gate.md).
- Gates count instructions per test binary (tools/test_cost.txt): NEW-COST fails, STALE-COST lowers its line in the landing.
- This note names issues a branch may close in words, not paths, and no code name in backticks: a branch that deletes either fails policy on this note.
- Gate commands: `mkdir` the log dir and set `L=` in their own step, never after an `&&` chain that can fail first (a missing dir or an unset `L` means the gate never ran). After `tools/land`, check main moved before deleting the local branch.
- Never `cd` into a worktree path by guess: `git worktree list`, then the path whose branch matches. Name the claimed worktree explicitly; never a `cd` fallback.
- Land only after `git merge-base --is-ancestor origin/main HEAD`; if main moved, test the crates both sides changed.
- A gate NEW failure: replay on main's binary (`tools/bin-at origin/main`); failing there → issue + rate line on main, then land.
- A model change runs its consumers' differentials before its gate.
