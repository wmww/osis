# Coordination
> Summary: How coordinators run the work: the model first, keep it simple (Tess: work lands on main in its session, main may be broken, delete and disable freely, build the end state directly), the job mix, working with Tess, how a job runs and lands, known failures, the test budget, briefs, rewriting an area, release checks, the standing jobs, several coordinators.

Design principles: notes/principles.md. Build and test mechanics: notes/build.md; the gate: notes/gate.md; time limits: notes/time-limits.md. Starting a session: read the handoff note (notes/, named handoff) when one exists, drain notes/complaints/ (Standing jobs, Watchdog), then work; a coordinator ending a session with work open rewrites the handoff.

## The model first (Tess)
The job is to understand osis's abstract model, as built out of osis's own concepts (things, references, roles, sync units, commits), and to make spec and code say it: not to build a database or an app that works in some superficially observable way. A passing test, a working demo or a closed issue shows nothing if the concept under it is wrong, and a design question answered by "what makes the tests pass" is answered wrongly. When a job turns into chasing symptoms, stop and ask what the model says (notes/principles.md, The model comes first); when the model does not say, that is the finding, and it goes to Tess.

## Keep it simple (Tess)
Large changes have repeatedly bogged down in process, in the problems of their intermediate states and in keeping branches rebased, each breeding more of itself until nothing else happens. Things need not happen in any particular way; they must happen without that.
- **Work lands on main, soon.** A worktree is a build directory, not a place work lives: commit, rebase on main, push (`tools/land`), in the session that did the work. No branch outlives its session, none is stacked on another, none is kept until it is green.
- **Main may be broken** for as long as a big change takes: nobody depends on it (dogfood runs a pinned build, notes/dogfood.md).
- **Delete and disable freely.** Old code goes first. A test the change breaks is deleted if it tests what is going, else ignored with a label naming the piece that brings it back, and left. Nothing of an intermediate state is fixed, tidied, reviewed or gated unless it blocks the next piece.
- **Build the end state directly.** What exists only to get from one state to the next (an adapter, a compatibility path, a second copy beside the first, a plan of stages each kept working) is not built. An end state that cannot be built directly is a design question for Tess, not a staging plan.
- **One review and one gate per big change, at its end.** Outside a big change in progress, every job is reviewed and gated (Tess): the default once the final gate over the sync rewrite and accounts is through (notes/handoff.md, The route).
- **When process costs more than the change, cut the process.** A check, tool, failing test or rule of this note that is not about the change and is eating a session is skipped or deleted, and the report says so.

## Job mix (Tess)
Two agents on each of two kinds of work (Tess):
- **Forward progress**: mostly the primary workstream (the route in the handoff; notes/priorities.md), with miscellaneous fixes here and there. A bug is worth fixing when it threatens the design, slows or masks tests, or goes away with a complication a cleanup removes; a special-case fix can hide a design flaw, and no bug is urgent before a release.
- **Workflow and cleanup**: the watchdog, test speed, refactoring and slimming code, simplifying notes, deleting redundant tests (Standing jobs). osis should ship with less code than it has.

How to run them:
- Complexity-bound first, CPU second, not token-bound: heavy token use is a symptom of complexity.
- **Park on a direction snag.** A job that hits something questioning the direction of what is being built (a second copy of an existing mechanism, an architecture nobody expected to need) is parked with the question written down, and other work runs.
- A question for Tess never stalls work: pick the simpler option, note whether it is easily reversed and what depends on it, record it as a `tess-call` issue, keep going.
- **Slots**: 3 or 4 agents at once, kept full (Tess), and only the coordinator spawns. Which model an agent runs on: CLAUDE.md, and nowhere else.

**Working with Tess**
- Ask one question at a time, with the trade-off and why users care, in plain words.
- Don't record a recommendation as decided mid-discussion; check what she already decided before asking again.
- Liking a design's shape is not a go: propose, then wait for an explicit decision before building.
- Priorities: security, data loss and core correctness first; performance and optional features wait until the core is solid. If a requirement keeps generating issues, bring her the case for relaxing it rather than papering over it.

## The task loop
- **A job is one agent**: it claims a worktree (`W=$(tools/claim <name>)`, from the main checkout), does the work, runs the tests and clippy of the crates it changed, lands (`tools/land`: policy, then push to main) and runs `wt release` last. Notes, issues and spec alone need only policy.
- **A reviewer** is for a change to a rule others build on, a security fix, and a big change at its end: a fresh agent reads the diff for what a hostile or removed party controls, writes a targeted test of the invariant that changed, then gates in the worker's worktree (`tools/merge-branch gate`, then `land`; notes/gate.md). One gate per reviewed change; nothing else is gated.
- **Known failures** (formats: notes/gate.md, The summary): a gate with only KNOWN failures lands when each reads as its issue describes. A NEW failure never lands as gated: the change fixes it, or it is shown failing on main too (`tools/bin-at`) and gets its issue and line there first (committed onto origin/main from a detached checkout; the gated branch stays as it is, since land rereads the summary against main's list and rebases it). A property failing on main is a job beside the primary work (notes/priorities.md, Failing on main), begun with a hand-written minimal reproducer.
- **Stopgaps (Tess)**: nothing complex or out of the way. The smallest rule that closes the hole; every code site it touches carries `// Interim (issues/<name>.md): <what replaces it>`, and the replacing build removes every marked site.
- **Hung agents**: one quiet far past its task's usual length is asked or stopped.

## Coordinator rules
- Performance is the coordinator's: a little slower than optimal but much simpler, more correct or more verifiable is a good trade (budgets: notes/test-scale.md).
- A change that adds a new kind of permanent data adds or updates a row in notes/growth.md.
- App work (libs/kit/, app/) is planned with Tess in a separate UX session (notes/app.md); what kit or app needs from core becomes an issue tagged `core-ask`.
- Names: each coordinator picks a name and pronouns once it knows the codebase, records both here and says them in chat.
- Registry: **Lodestar**, she/her. **Tiller**, he/him. **Wren**, they/them. **Sorrel**, they/them. **Fathom**, they/them. **Kestrel**, they/them. **Petrel**, they/them. **Halyard**, they/them. **Bowline**, they/them (app). **Capstan**, they/them. **Sextant**, they/them (reference graph design). **Keel**, they/them. **Gimbal**, they/them (design session with Tess: studies and the terms pass). **Windlass**, they/them. **Mizzen**, they/them. **Spar**, they/them. **Sheave**, they/them.

## Test budget
Seed breadth belongs to the release checks, not to jobs: reading and targeted new tests find most bugs, rerunning ranges almost none (notes/test-design.md, What finds bugs).
- A job runs its crates' default tests, its own new tests and a quick targeted check of what it changed (notes/testing.md, When tests run); never large sizes, and never a confirming sweep after a seed fix.
- A change to a test model runs the properties that use it; one that adds or rewrites a randomized harness runs it once at full size before it lands.
- **The gate's limit is 10 minutes on ostrich (Tess)**, everything it runs included (it takes far longer: issues/test-time.md) (default tests, the branch's selected properties and sim scenarios): reached by fixing perf problems (product, harness, test design), not by scaling sizes down: a size shrinks only where the extra size is shown to add no coverage; breadth goes to release checks.
- **Time limits (Tess)**: notes/time-limits.md, Policy.

## Briefs
A brief is the only context its agent has. Say the goal and why, what is already ruled out, where to read, and what done looks like; then get out of the way.
- **No waiting on another job.** A brief never has its agent wait for another job's landing: it lands what stands alone, or reports and stops (a watch for a landing sat silent for hours once).
- **Main keeps compiling**, even while broken in behaviour: a job that changes an API other crates use (a test model included) runs `cargo test --workspace --no-run` before landing.
- **One session.** Pieces in order, each ending pushed; "stop at the first such point once the session is long, push, report what is left".
- **Facts are measured or marked as guesses.** A failure is replayed on current main before it is briefed; a cause someone claimed is a lead, not the task; a count says how well a sample reaches a case, never that the case may be dropped (notes/principles.md, How often is not whether).
- **Size by probing, not by label**: one probe line per failing test sizes a job in minutes; a class of failures named for one cause has usually had several.
- **The mechanics** (worktree, landing, command rules) are in CLAUDE.md and notes/build.md: point at them. A brief starts its agent's shell with the plugins' `bin` on PATH (`which wt claudewait` in your own shell gives the directories), and says to ignore the working directory its environment names, claim its own worktree and touch nothing in the main checkout.
- **Models and searches**: a new rule is modelled first (roles-model, held-model, TLA). A search's silence counts only once it fails under a rule known to be weaker; a model change runs the differentials of the crates that draw its worlds.
- **A security or convergence fix** states the invariant it relies on as a code comment and comes with a test that fails with the fix undone; for every input the rule reads, ask who can write it.

## Rewriting an area
Tess's direction is in notes/principles.md (Rewriting an area).
- **On main, delete first.** The old code goes, then the replacement and its spec text are written alongside; one fresh review and one gate at the end. No new code beside the old, no scaffolding or adapters between them, no spec-first job landed alone.
- Each piece is pushed to main as it is done, the tests it breaks deleted or ignored by the piece that brings them back. Parallel jobs stay out of the area.
- Models first where the rule is new: they find holes before code exists.
- A long rewrite keeps what it owes in the area's note, so any session can go on from it.

## Release checks
Seed-breadth runs reach what per-branch sizes never do. They detect design smells, not a safety net: a bug only they find names a subtle property (notes/principles.md, Testing), fixed by a simpler rule plus a small default test.
- When (Tess): as part of the release process (not yet defined), and when Tess asks. Never on a coordinator's own initiative.
- Alone: only while no agent is building or testing, and no cargo-heavy agent is briefed until it ends (nice 19 does not shield the others).
- Every offset (`--from`, `_START`, `OSIS_*_SEED`) drawn at random below 10^12 (`python3 -c 'import random; print(random.randrange(10**12))'`).
- After a run: update the last-run line below and the counts in notes/test-design.md (What finds bugs); an issue per new failure, naming the property behind it and whether the gate's selection fails it at small size (if so the selection missed it, usually a property without a size word). Check each harness's printed seed range, not only `1 passed`; judge a slow item by its CPU-s.
- Last full run: main e3cdd005f, every item below at `OSIS_FULL=1` on random offsets: 5.3 h wall, about 119,500 CPU-s at nice 19 beside load 25-100. Six real bugs, three of which the gate's selection should have caught.

Commands (the full set; an area run takes its own items), under `nice -n 19`:
- `cargo run --bin sim-sweep -- --seeds 150 --from <F> --budget-secs 3600` (every scenario). A sweep cut by its budget says so only in its per-scenario seed counts: log the seeds that ran.
- Every property not named below: `OSIS_FULL=1 PROPTEST_CASES=256 cargo test -- --include-ignored --skip sweep --skip repro_ --skip _probe --skip memory:: --skip multi_gb_value_streams` (memory checks run alone, notes/test-scale.md).
- `OSIS_FULL=1 OSIS_ORDER_START=<S> cargo test -p osis-engine --test it -- --ignored order::held_set_decides_`.
- `OSIS_CRDT_SEED=<C> cargo test -p osis-crdt -- --include-ignored --skip repro_ --skip hostile_moves --skip shrink_script`.

TLA is not a release check: it runs by hand when TLA is touched.

## Standing jobs
Workflow and cleanup jobs (Job mix). Act on each report.
- **Watchdog**, at the start of every session and whenever notes/complaints/ has files: read every file there, then delete them all. For each complaint, in this order: fix the tool, script or note that caused it; else, if it is a real problem that needs design, one issue; else nothing. A complaint does not become a rule in a note unless nothing else can fix it: every rule added is read by every later agent. Also `tools/agent-times.py` and `tools/heavy --report` for where agents' time went. Complaints are written per CLAUDE.md (Building and testing), never for what the agent's own report already says.
- **Test optimizer**: make the tests faster and cleaner without losing real coverage. Pick the area by evidence (issues/test-time.md; `tools/limits.py tests`, a full default-suite run from a worktree under `tools/heavy`); delete tests that are not useful, speed up slow ones, redesign a harness, or make core faster where tests pay for its slowness. Count work, no timing runs.
- **Cleanup**: simplify, refactor and delete code in an area picked by evidence (`tools/loc.py`, `tools/deprecated_probe.py`, `tools/dup_windows.py`). Behaviour stays; report the line counts before and after.
- **Prose editor**: rewrite and simplify notes, spec or issues so what a reader looks for is easy to find and true; delete what is no longer or never was useful; keep Tess's own wording.

## Several coordinators at once
One coordinator by default. When more run at once, each on its own machine, one is the lead: the one Tess names, else the one the coordinators agree on. The lead assigns areas and settles disputes; the slots are shared. They talk over the osis channel (notes/dogfood.md) and split by issue area (Tags). Protocol: post `claim: <issue> (<branch>)` before `tools/claim` and `merged: <sha> <branch>` after each push; read the channel and `git pull --rebase` before every push; in shared notes add your own section or row, never rewrite the other's; relay Tess's decisions verbatim with `tess:`; a pinned-binary bump is `bump? <sha>`, answered `bump ok`, before either side rebuilds. Each runs the release checks for its own areas.
