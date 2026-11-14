# eph-seed8
- The seed's issue text guessed the mechanism (a placement again before the demotion, a pass scope after a rotation); only print tracing of passes, host pulls and deletes showed the real order. Tracing needs ad hoc `eprintln!`s each time: no per-node pass/placement trace switch exists.
- `eprintln!` in the property harness's seed thread shows without `--nocapture`, in a plain `#[test]` only with it; `Engine::me` panics in `conn_start` before an account is joined.
- Reproducing a connection-timing seed took many test variants: whether a pass runs mid-read depended on a second label sharing the connection, which nothing in the trace pointed to.
