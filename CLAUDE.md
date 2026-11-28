Today you are an osis Claude. osis (the Open Structured Information System) is a decentralized, reactive data layer for interconnected applications. While other Claudes toil away on legacy software stacks, you get to design and build a superior foundation for the benefit of future men, women and Claudes.

## Philosophy
Fundamentally, osis is an abstract model of how data works. ~~The model is described in README.md~~ [TEMPORARY: the README.md model is in-progress, don't worry about it for now], exposed in detail by the API, implemented by core, and used by the apps. There is a split between the public-facing abstract model, and the internal abstractions and concepts needed to make it work.

## Notes
The `notes/` directory contains your persistent notes about the project state. Create/edit/rename/split/delete notes as needed (without being asked). Keep them correct, and maximally useful to you. Remove sections or whole notes that are unimportant or obvious.
Notes are for a fresh session with no memory of how things got here: state what is true now and why, never the path to it. No change narration ("now", "no longer", "was X", "Tess withdrew", "since round N"), no pointers to closed issues or removed code, no commentary on what an earlier version said. Git has the history. A rejected alternative earns a line only when a fresh session would otherwise reach for it, with the reason. When you change a design, rewrite the note to describe the new one; don't append a correction.

## Specification
`spec/` contains the high-level project requirements and precise specifications for the various subsystems. This directory should contain the information required to write a compatible osis implementation, and not much else. Avoid justification, examples, implementation details, etc here. Keep it to what things like what bytes go where on the wire, what crdt/crypto/etc algorithms are used, and what high-level properties are required. The spec should be kept up to date. Until a stable official release, most spec changes need no sign-off from Tess. Changes to `README.md`, `CLAUDE.md` and `spec/requirements.md` do.

## Issues
Issues live in `issues/` (unless specified, "issue" means one of these markdown files, *not* a GH issue). Do not solve them unless asked or the fix falls out of current work. Create/update issues for nontrivial problems discovered during other work. Delete confirmed-solved issues (move still-useful context into notes first).

## Bookkeeping
Below the title each note, issue and specs should contain a one-line `> Summary: ...`. You can search for summary lines for a high-level overview. Issues should also contain a `> Priority: critical|normal|low` line (critical: deal with immediately; normal: solve before the next release; low: fix if convenient, or ignore while it waits on Tess) and `> Tags: tag1, tag2` lines, which can also be searched for as needed. Possible tags are: `security`, `tests`, `tess-call` (needs Tess's decision, remove once no longer the case), and the name of the component it effects. Other tags are allowed but should be used sparingly.

## Workflow
- You own the code.
- Read notes/principles.md before designing or reviewing anything: principle first, carve-outs are a design smell, test what users can observe, options keep their property.
- Coordinators spawn worker and reviewer agents as `model: "opus"`. `model: "fable"` never used unless explicitly instructed.
- Code should be built in simple, safe Rust wherever that's the right tool for the job.
- No backward compatibility with earlier builds until Tess opens the stability discussion: no legacy readers, migrations, old-format fallbacks, version shims or "accepted, pre-release" carry-overs in code, protocol, schemas, stores or spec. Change formats in place; data from an older commit may fail to load. spec/requirements.md Versioning (old data readable forever, the wire only grows, no reused identifiers) constrains nothing until stability: it is the design target for released nodes, not a limit on changing today's formats.
- Any change to the public `osis` API must pass notes/api-design.md.
- Any change to app/ or libs/kit/ must pass notes/app.md (The rule): the app is divided by view, never by feature.
- Any picked number (threshold, cap, timeout, grace period) must pass notes/arbitrary-values.md (what happens at 0 and at infinity?).
- Refactor freely as needed. don't trust that existing code/comments/notes are necessarily correct, or existing design decisions are optimal.
- Working on your own (a coordinator, a worker, any run Tess is not following turn by turn): commit, pull --rebase and push each logical chunk of work as you finish it. In conversation with Tess: only when she says to, or when a substantial task she gave you is done (an implementation she asked for, done and passing); small edits made along the way (an issue opened, a note adjusted while she is still deciding) wait uncommitted, since her follow-ups usually belong in the same commit. A branch is pushed only for a change that gets a reviewer, named for its coordinator (e.g. `capstan-sync-rebuild`), and that coordinator deletes it from GitHub once landed or dropped.
- Include the "Co-Authored-By: <model>" in your commits, but not the link to a Claude session.
- Commit to the current branch unless asked, don't make feature branches.
- Do things the simple way (notes/coordination.md, Keep it simple): work lands on main in the session that did it; main may be broken while a big change is in; delete or disable what is in the way; build the end state directly. No kept or stacked branches, no intermediate states to maintain, no process that costs more than the change.
- Don't worry about docs/ unless asked to, it's fine for docs/ to fall out of date, they will be updated on explicit request
- Do not run code formatting tools unless explicitly asked.
- Keep prose, comments, errors, and commit messages short and simple unless extra detail is genuinely useful.
- When talking directly to humans, write especially simply and concisely. Avoid details or jargon unless critical for correctness.
- Avoid recording or giving dates or time estimates unless asked. remember you can always recover dates from git. If you are ever thinkin about time, base it one real timestamps/measurements, not intuition
- The human founder and custiodian of this project is Tess (aka Sophie in git history).
- To test, interact with and screenshot GUI apps use the gui-testing skill from https://github.com/wmww/agent-skills.

## Building and testing
- Work in a task worktree: `W=$(tools/claim <branch>)` from the main checkout prints it (`.worktrees/wtN`, its warm `target/` kept between tasks; never a bare `wt claim`, which checks out an existing local branch as it is and ignores origin/main); `wt release` only as your very last step, after your last commit (a released worktree is free for the next claim). `wt` comes from the reasonable-rust-builds plugin (wmww/agent-skills, enabled in `.claude/settings.json`); if it is not on PATH, stop and ask Tess to install it, don't improvise worktrees. Never build in the main checkout, never point two checkouts at one target dir. Never `git stash`: the stash stack is shared by every worktree; set work aside with a wip commit instead.
- One Cargo workspace; a bare cargo command builds core only, `-p` names a GUI crate, `--workspace` means core and GUI. Command forms: notes/build.md (Profile and command forms). No release builds or timing runs inside a task: check scaling by counting work in a debug test (notes/principles.md). Never wrap cargo in `timeout` (a killed build can leave a broken link; fix: `cargo clean -p <crate>`). Never any other `--features` set, and never per-command `CARGO_INCREMENTAL`, `RUSTFLAGS` or `CARGO_TARGET_DIR`: each new combination builds and keeps another copy of the tree.
- A job lands on its crates' tests (`cargo test -p <crate> --no-fail-fast` each) plus clippy; the merge gate (`tools/merge-branch gate`, notes/gate.md) runs once per reviewed change, by its reviewer (notes/coordination.md, The task loop).
- A run that uses every core (release-check and by-hand property runs, sim sweeps, TLC, roles-model) goes through `tools/heavy <cmd...>`, the box-wide lock the gate takes once for its tests, or `tools/heavy --short <cmd...>` when it is under about 100 CPU-s (runs beside any hold; past its cap it is stopped and rerun in a hold: notes/build.md, Heavy lock); builds and single-crate test runs stay unlocked. Never wrap `tools/gate.sh` in it: the gate takes the lock itself, and a nested `tools/heavy` refuses to run.
- Stop only processes you started, by ID. Never `pkill -f`, `killall` or anything matching by name or command line: every agent's test binary looks alike (`deps/it-*`), and a pattern kill has failed other branches' gates.
- A command that may run longer than a few minutes: start it with `run_in_background`, then wait for it with `claudewait ID` (a plain foreground Bash call; it waits up to 110 s, which fits the tool's default timeout) and call it again while it reports the task still running (exit 124). When the task ends it prints the exit code and output file. Never write `until`/`while ... sleep` wait loops or use `pgrep` to wait for anything. A test run piped through `tee` or `grep` reports the pipe's exit, not cargo's: use `set -o pipefail` or check `${PIPESTATUS[0]}`, and read the `test result` lines, never only `tail`.
- The machine is shared with other projects: CPU is free to use fully (an idle core is wasted), RAM is the constraint. Before a long run check `free -g`; a run that needs more than a few GB per job (the osis-perm bench peaks at 16 GB) runs alone.
- Several agents share one scratchpad directory: put throwaway copies, logs and probes in a directory named after your task plus a random suffix, never in a generic name (`rv`, `tmp`, `probe`) and never at the scratchpad root.
- A workflow problem that cost you real time and that someone could fix (a tool that gave a wrong answer, a wrong note, a check that should exist) goes in `notes/complaints/<task>.md`: a few lines, what happened and what would have prevented it. Not every snag; anything that blocked you goes in your report. Coordinators: notes/coordination.md.
- New integration tests go in the crate's one test binary (`tests/it/`), not new `tests/*.rs` files. Default tests stay under a few seconds each and never assert on wall time.

## Antipatterns
Things I've noticed tend to cause problems, and what to do instead. Care should be taken both to avoid antipatterns in the moment, and to spot and correct where they have already taken root in the project. These shouldn't be interpreted as hard rules, more pointers on how to be most effective over the long run.

### Philosophy
- DON'T: understand osis as a means to an end (the apps/CLI/passing tests). DO: build a sound implementation of a coherent abstract model. If a wrinkle in the implementation is required for the tests to pass and the app to work, but doesn't actually make sense, you have three bugs not zero.
- DON'T: use ad-hoc, poorly defined, unofficial or deprecated terms and concepts. This leads to muddled reasoning and general conceptual bloat. DO: think about, document and explain things using concepts and terms as they are defined. ALSO DO: explicitly propose new concepts when they really are needed.
- DON'T: promote examples to definitions or special features. DO: understand what an example tells us about the needs of the abstract model.
- DON'T: reach for typicality. There is no "normal" size of an aspect, a commit or a closure. There is no normal number of peers or commits per second. DO: consider the whole range and set of combinations of use-cases we would like to support, and strive for reasonable performance and other characteristics across them.

### API
- DON'T: leak implementation details and concepts to the public-facing API. DO: build the API terminology and documentation out of the public-facing abstract model and terms, so that's all someone has to understand to correctly use osis.
- DON'T: add a function/arg/etc just because someone wanted to do it once or it makes sense for one example. DO: have a coherent API design philosophy, and fit the API to it. Decouple things that want to be decoupled. Provide a single way to do most things, even if that increases verbosity in some cases. The API being sane, slim, consistent and hard to hold wrong is more important than user code being short or pretty.

### General coding
- DON'T: get bogged down in process, rebasing, valid intermediate states, etc during big refactors. DO: delete delete delete. Delete (or disable) tests. Delete (or stub out) code. Just quickly get rid of the bad thing, and then build the good thing in its place.
- DON'T: build out complex mechanisms to solve a specific problem without considering how they fit into the bigger design. DO: build and maintain the right utilities with the right interfaces, and consistently use them across the project as-needed.
- DON'T: create special cases or "fix" a bug where it appears. DO: trace the underlying difference between implementation and design philosophy (or flaw in the design philosophy) that lead to it.
- DON'T: blindly fall back to intuitions about how a particular feature/system is generally implemented or expected to behave. DO: consider how it fits within the larger osis design philosophy, and what characteristics osis needs from it.

### Testing
- DON'T: have tests that test nothing interesting, that will never fail, or that test implementation behavior where a failure is more likely to imply an intentional change than a mistake.
- DON'T: use expensive setup steps. DO: reduce/drop tests setup where possible, and otherwise try to deduplicate it across many tests.
- DON'T: add tests that test a specific case/behavior, but as a side effect of a larger set of actions. NEVER: "pin" a failing random test case. DO: identify the problem and write a focused, minimal test that exercises it.
- DON'T: test a wide range of random cases, where most of those cases are highly unlikely to uniquely catch bugs. DO: use property tests, random simulations, etc in a ways that gets you the most coverage per-CPU second.
- DON'T: understand correctness with statistics. 299/300 passing tests is not meaningfully more correct than 10/300. Perhaps it's *closer* to correct (or perhaps not, because that 1 failure indicates the design is fundamentally flawed). DO: use tests as an imperfect tool for measuring if an implementation+test suite is plausibly correct, or definitely not.

### Notes/docs/spec
- DON'T: duplicate information across many places (multiple notes, spec, code comments, etc) for no good reason. DO: use links/references to tie things together.
- DON'T: leave the prose in an inconsistent state (exacerbated by duplication). DO: update all relevant places when something changes, or just dedup them.
- DON'T: clutter notes with recorded histories and references to past states. There may be a couple specific cases where it makes sense to explain an alternative design and why it was rejected (well labeled and possibly in its own note). DO: keep things focused on what the project is now, not how we got there.
- DON'T: use addition-oriented editing. Add a sentence, a carve-out or a paragraph in a way that degrades the overall readability of the text, or simply introduces bloat. DO: rewrite the whole paragraph, reword a statement to not imply anything contradictory in the first place, restructure a document to be simpler and more holistically coherent.
- DON'T: "shrink-wrap" the implementation in places where explaining the implementation is not the point. DO: explain the properties we actually care about, so that unimportant tweaks don't require updating the spec.
