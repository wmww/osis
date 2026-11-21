# api-smells
- Piece 1 depended on mizzen-leftovers, not yet on main: built on top of it locally so the later rebase drops the identical commit instead of conflicting in the same lines.
- `cargo test -p osis-kit -p osis-app` without `--no-fail-fast` stops at app's known failure (`a_tile_tells_of_emails_it_cannot_read`) and never runs kit's tests: the CLAUDE.md GUI command form omits the flag.
