# wait-synced-scope
> Summary: mishaps met while scoping `wait_synced`.

- `cargo test -p osis --test it sync:: api::` (as briefed) fails: cargo takes one TESTNAME; several filters go after `--`.
- A queued deposit's host was never dialed unless some synced label named it, so a grant from a node with no hosted label (all receipts-only or hostless) never left; found only because the new test's last step waited for it.
