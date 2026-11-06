# notes-a
- `grep -o ".\{0,60\}x.\{0,30\}"` failed with "exceeds complexity limits" (ugrep shim); `command grep` works.
- The CLI command-table test read notes/cli.md, so rewriting that note could break a Rust test; resolved by moving command docs into `osis --help`.
