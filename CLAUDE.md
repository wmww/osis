Today you are an osis Claude. osis (the Open Structured Information System) is a decentralized, reactive data layer for interconnected applications. While other Claudes toil away on legacy software stacks, you get to design and build a superior foundation for the benefit of future men, women and Claudes.

## Notes
The `notes/` directory contains your persistent notes about the project state. Create/edit/rename/split/delete notes as needed (without being asked). Keep them correct, and maximally useful to you. Remove sections or whole notes that are unimportant or obvious.

## Specification
`spec/` contains the high-level project requirements and precise specifications for the various subsystems. This directory should contain the information required to write a compatible osis implementation, and not much else. Avoid justification, examples, implementation details, etc here. Keep it to what things like what bytes go where on the wire, what crdt/crypto/etc algorithms are used, and what high-level properties are required. The spec should be kept up to date. Until a stable official release, spec changes need no human sign-off; only significant changes to or conflicts with `spec/requirements.md` do.

## Issues
Issues live in `issues/` (unless specified, "issue" means one of these markdown files, *not* a GH issue). Do not solve them unless asked or the fix falls out of current work. Create/update issues for nontrivial problems discovered during other work. Delete confirmed-solved issues (move still-useful context into notes first).

## Bookkeeping
Below the title each note, issue and specs should contain a one-line `> Summary: ...`. You can search for summary lines for a high-level overview. Issues should also contain `> Tags: tag1, tag2` lines, which can also be searched for as needed. Possible tags are: `security`, `tests`, and the name of the component it effects. Other tags are allowed but should be used sparingly.

## Workflow
- You own the code.
- Coordinators spawn worker and reviewer agents as `model: "opus"`, always.
- Code should be built in simple, safe Rust wherever that's the right tool for the job.
- Refactor freely as needed. don't trust that existing code/comments/notes are necessarily correct, or existing design decisions are optimal.
- Unless otherwise asked, commit, pull --rebase and push when you've completed your task.
- Commit to the current branch unless asked, don't make feature branches.
- Don't worry about docs/ unless asked to, it's fine for docs/ to fall out of date, they will be updated on explicit request
- Do not run code formatting tools unless explicitly asked.
- Keep prose, comments, errors, and commit messages compact unless extra detail is genuinely useful.
- When talking directly to humans, write especially simply and concisely. Avoid details or jargon unless critical for correctness.
- Avoid recording dates or time estimates unless asked, remember you can always recover dates from git
- To test, interact with and screenshot GUI apps use the gui-testing skill from https://github.com/wmww/agent-skills.

## Building and testing
- Work in a task worktree: `tools/wt claim <branch>` prints it (`.worktrees/wtN`, its warm `target/` kept between tasks); `tools/wt release` when done (commit first). Never build in the main checkout, never point two checkouts at one target dir. Never `git stash`: the stash stack is shared by every worktree; set work aside with a wip commit instead.
- Command forms (notes/build.md): `cargo test --workspace` (tier 1, about 40 s warm; narrow with `--test it <module>::` and name filters), `cargo clippy --workspace --all-targets -- -D warnings`, `cargo clippy-net`, `cargo run --bin sim-sweep`, `cargo test-net`; tier-2 oracles by name; `--release` only for timing checks (`scale::`, `bench::`, `budget`), by hand, in your worktree, keeping `target/release`. `cargo test -p <crate>` for one crate's dev loop and `cargo test --release -p <crate> --test it -- --ignored <filter>` for timing checks (the gate checks that `-p` builds share the workspace's artifacts). Never other `--features`, or per-command `CARGO_INCREMENTAL`/`RUSTFLAGS`/`CARGO_TARGET_DIR`: each new combination builds and keeps another copy of the tree.
- The merge gate is `tools/gate.sh`, run in the worktree after `git rebase main` (about a minute warm, three with the sim sweep); main is fast-forwarded, never built.
- A command that may run longer than a few minutes: start it with `run_in_background`, then wait for it with `claudewait ID` (a plain foreground Bash call; it waits up to 110 s, which fits the tool's default timeout) and call it again while it reports the task still running (exit 124). When the task ends it prints the exit code and output file. Never write `until`/`while ... sleep` wait loops or use `pgrep` to wait for anything.
- The machine is shared with other projects: CPU is free to use fully (an idle core is wasted), RAM is the constraint. Before a long run check `free -g`; a run that needs more than a few GB per job (the osis-perm bench peaks at 16 GB) runs alone.
- Several agents share one scratchpad directory: put throwaway copies, logs and probes in a directory named after your task plus a random suffix, never in a generic name (`rv`, `tmp`, `probe`) and never at the scratchpad root.
- Workflow mishaps, footguns and slow spots you met go in `notes/complaints/<branch>.md` (a few lines, committed with your branch); anything that blocked you or gave a wrong answer goes in your report too. Coordinators: notes/coordination.md.
- New integration tests go in the crate's one test binary (`tests/it/`), not new `tests/*.rs` files. Tier-1 tests stay under a few seconds each and never assert on wall time.
