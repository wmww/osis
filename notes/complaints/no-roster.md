# no-roster
> Summary: Footguns met deleting roster snapshots (step 1 of the owner-removal plan).

- A pure removal still reaches the wire: "several deltas per aspect" (header `hashes` list, part `di`) existed only for roster snapshots, so deleting them left a list that may hold one item. Grep for what a feature's shape forced on shared formats, not only for its name.
- Two `claudewait` calls chained with `||` in one Bash call overrun the tool's 120 s timeout; one call per Bash invocation.
- Helpers working in one worktree share the cargo lock: a long test run of one stalls every other build (a `cargo build -p` taking 2+ minutes was waiting, not building).
- `cargo clippy-net` builds the net-feature tests (`tombstone.rs`) that `cargo check --workspace --all-targets` skips: a type change there only shows under clippy-net or test-net.
- Changing a commit's bytes regenerates three places: `gen-vectors` (commit/headers.vec), `gen-vectors -- corpus` (fuzz corpus seeds renamed by hash) and the osis-node judgment vectors (`OSIS_WRITE_VECTORS=1 ... judgment_vectors_write`, bundles hold commit blobs); the vectors README lists only the first two together.
- Review: a failing `_settled_` order seed shrinks a 150-commit history for over an hour and reads as a hang (issues/settled-seed-7032.md); run full-size order harnesses with `OSIS_ORDER_SHRINK=0` first, per seed (`xargs -P`), to see which seed fails.
- Review: a changed generator makes "run the seed on main" meaningless; pin the branch's printed history (`OSIS_ORDER_STATS=1`) into a probe test and `tools/bin-at main OUT --patch` it (a local `fn Aim(s: Step) -> Step` lets the Debug print paste as-is).
