# Complaints: d2-roles
> Summary: Workflow snags met cutting roles-model `paths` to the design (stage D2).

- `cargo test -p roles-model --lib paths -- --ignored repro_x` ORs the two filters: it ran every ignored `paths` test, both `_large` properties included, unlocked (84 s). notes/build.md says so; still easy to type. A filter after `--` alone (`-- --ignored paths::tests::repro_x`) is the safe form.
- A story run at 3,000 worlds fit the short lane before trust sets came from receipt order; with F1 (a judge per arrival tick per node) it costs about 118 CPU-s and the short lane stopped it (exit 137, no output). Time a changed search before trusting `--short`.
- The story's "trusting nodes" are a given list (`Sim::removals`), so the first time trust came from receipt order every honest-side check broke at once, mixing a rule gap (the writer's own side) with an oracle assumption (the trusting nodes are H's side): separating them took three throwaway probes.
