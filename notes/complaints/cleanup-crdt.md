# cleanup-crdt
> Summary: Complaints from the osis-crdt cleanup.

- The 3-line repeated-window scan found little here: osis-crdt's duplication is per encoding (struct vs enum arms, set vs bag, values vs each_value walks), the same shape with different field names, which a text scan does not see. Reading the walks side by side found it.
- dead_pub found nothing again; `Source::node_of` had no caller at all (its name is shared with osis-sim's `node_of`), and `Fragment::map_dots` (130 lines) had one user, an engine test. A useful probe: turn every `    pub fn` method of the crate into `pub(crate)` in a scratch edit, build the crate alone, and grep the names rustc then calls unused for `.name(`/`::name(` outside the crate (prod vs test files). It cascades (a method called only by another unused one shows too), so read each hit.
- A `pub(crate)` turned from a doc-comment walk into a shared helper by `str.replace` over the file also hit a look-alike line in another function (`live_value`'s bag arm); the build caught it. Replace on anchored blocks, not on one line.
- Review: a scratch worktree claimed at main only to build osis-crdt and osis-engine for a differential took 357 s to `wt release` (its mark step runs `cargo test --workspace --no-run`, building kit and app there). For a crate-only comparison, `tools/bin-at main` or a cheaper mark would do.
