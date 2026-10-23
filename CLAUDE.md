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
- Use only the command forms in notes/testing.md (Build hygiene): `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo clippy-net`, `cargo test --release --workspace -- --ignored`, `cargo run --release --bin sim-sweep`, `cargo test-net`. Narrow with `--test it <module>::` and name filters. Never `-p`, other `--features`, or per-command `CARGO_INCREMENTAL`/`RUSTFLAGS`/`CARGO_TARGET_DIR`: each new combination builds and keeps another copy of the tree.
- The merge gate is `tools/gate.sh` (every check in order; it sweeps the build dir itself).
- Run long commands in the background and act on the exit notification; never poll with `pgrep`/`sleep` loops (`pgrep -f PATTERN` matches the loop's own shell, so it never ends).
- The machine is shared with other projects: sim sweeps outside the gate use `--jobs 4`; never start a long run with more than 8 threads or jobs.
- Several agents share one scratchpad directory: put throwaway copies, logs and probes in a directory named after your task plus a random suffix, never in a generic name (`rv`, `tmp`, `probe`) and never at the scratchpad root.
- New integration tests go in the crate's one test binary (`tests/it/`), not new `tests/*.rs` files. Tier-1 tests stay under a few seconds each and never assert on wall time.
- Worktrees: each checkout builds into its own in-tree `target/`; `git worktree add` seeds it from the main checkout (hook: `git config core.hooksPath .githooks`, once per clone). Remove finished worktrees with `git worktree remove`.
