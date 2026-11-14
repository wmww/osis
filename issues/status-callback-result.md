# on_status_change's callback takes a Result that is never Err
> Summary: `Osis::on_status_change` hands `f` a `Result<Status>`, but the status is folded from the sync engine's in-memory labels and cannot fail, so `f` only ever sees `Ok`; `ReadOnly::status()` returns `Result` for the same non-reason (it fails only by tracking). Changing the callback to `Status` is a public API change (notes/api-design.md); callers in cli, osis-chat tests and core tests unwrap it.
> Priority: low
> Tags: api
