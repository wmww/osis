# purge-rights-review
- `git rebase main` was a no-op while origin/main had moved: local main lags on this box until someone pulls; a coordinator message pointed it out, I rebased on origin/main.
- `cargo test --workspace` filter errors are hidden behind `grep`: my first test compile failure only showed as E0616 with no file (grep dropped the `-->`).
