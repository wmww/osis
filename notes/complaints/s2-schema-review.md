# s2-schema-review
> Summary: Workflow snags met reviewing the S2 schema branch.

- A grant to a holder whose node keeps the holder unread fails `Keys(NoEpoch(Sync))` at the granter (probe, not pursued): worth a look if grants by sync-only holders matter.
- A probe edit by `str.replace` on a test file matched a second test's lines and flipped its grant role; the gate caught it as NEW. Diff a probe-touched test file against its base before committing.
