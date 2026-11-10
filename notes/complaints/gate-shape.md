# gate-shape
> Summary: Footguns met reshaping the gate (one lock hold) and the test vocabulary.
- A Python `s.index('"""', 3)` meant to find a docstring's closing quotes found the opening ones (the file starts with a shebang), and the replace rewrote every `"""` in tools/test_select.py: restored with `git checkout`. Find the close from `open + 3`.
- The old vocabulary sat in about 110 files (ignore reasons, module docs, issues), far past the four notes named; a census by regex first (`tier[- ]?[123]`, `plain size`, `derived set`) sized it before editing.
- A comment-only touch of Cargo.toml or .cargo/config.toml sets `unify=1` and selects every crate (workspace build config), so this branch's measured gate is the heaviest selection there is.
- `cargo test --no-run` at load 20 took 11 min after a branch touching comments in most crates (every crate recompiles).
- The measured gate waited 761 s for the lock behind another branch's by-hand script runs, then load rose to 40-90 during its hold (unlocked builds beside it): the hold's own CPU share was 54% of the box.
- The run failed on a property no branch touched (issues/epochs-model-side-differs.md), so the sim stage had to be timed in a second hold.
