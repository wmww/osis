# Nothing reports a parked commit
> Summary: `Diagnostic::Parked` (a commit from a newer format; an app can tell its user to update) exists, but the engine never constructs `DiagnosticKind::Parked`, so it never fires.
> Tags: engine, api

`apply::ingest_class`'s `Exam::Parked` arm calls `pend(.. Reason::Parked)` with no `events.diagnostic`. `osis/src/port/codec.rs` carries the kind and `osis/src/diagnostic.rs` maps it. The fix is a diagnostic there (`commit`, `peer`: the author), with a test that ingests a commit of an unknown encoding. Left for after owner removal, which is working in the engine.
