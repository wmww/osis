# prune-vouches
> Summary: Workflow snags met removing role-write vouches.

- Renumbering the story's thief moves by script renumbered arms I had already written with new numbers (N5's moves): a second pass over fresh text. Rewrite and renumber in separate steps.
- `roles-model -- N paths-purge-any-path` and `paths-purge-contains` were unreachable (the `paths-purge` prefix routed them to purge worlds, which refused them); fixed in `paths::run`.
- `cargo test -p roles-model` builds the lib, not the `roles-model` binary: `--only` runs used a stale binary until `cargo build -p roles-model --bin roles-model`.
- The pieces of this job are coupled through policy's doc-reference check: dropping the draft's §5.1 Vouches fails policy at every perm and engine test citing it until those modules go, so the model-and-drafts commit cannot be policy-green alone.
- The brief's pieces 2-4 could not be green apart: perm's `HeldSet` trait is the engine's, held-model builds against roles-model (whose vouch kinds the first session removed, so held-model and perm's tests did not compile at the branch's start), and perm's tests use held-model. One commit for perm, engine, held-model and schema.
- `command grep` was needed: the shell's `grep` is ugrep and refused a bounded repeat (`.\{0,200\}`), as notes/build.md warns.
