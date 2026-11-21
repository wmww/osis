# Complaints: review-d2-trust
> Summary: Snags met reviewing and gating roles-model `paths` D2 (first received as the rule).

- `rg -n` over notes/write-path-design.md or a README with one-line paragraphs prints tens of KB per hit; `rg -o '.{0,300}word.{0,300}'` or Read with offset/limit is the way to see one clause.
- A set-aside widened to everything left every control failing (other checks fail with it), so "a control still fails" proves little; compare the per-check counts of a control (`liveness` in `-no-own`, `-no-receipt`) under both oracles to see what the narrowed check still catches.
