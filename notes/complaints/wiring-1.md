# wiring-1
> Summary: Workflow snags met wiring the walk along stated paths beside today's.

- A shadow probe writing from many test threads at once interleaved lines (`writeln!` splits): format the whole batch and `write_all` it once.
- `JMap::feed` reports only added keys, not values changed in place: what a transaction changed is `JMap::before` (its journal), read before the journal is cleared.
- Tests run worlds in unnamed scoped threads (`evidence::`, `shred::`): a check keyed by the test's thread name sees `?` there.
