# Complaints: a1-walk-review
> Summary: Notes from reviewing osis-perm's walk along stated paths (A1 step 3a).

- Comparing a model change's search counts needs the model binary at both sources: write origin's file over the source, build, copy the binary to scratch, `git checkout` the file back (on a committed tree), then run both under `tools/heavy --short` and diff the stats lines. A `roles-model --at REV` or a `tools/bin-at` case for the model binary would save the dance.
- A differential's harness maps model flags to wire shapes (`finalize` to a missing frontier): a mutant of a shape rule the harness never emits survives every agreement test. Shape rules need a test that builds the wire input directly (`paths/shapes.rs`).
