# purge-rights-review
- `git rebase main` was a no-op while origin/main had moved: local main lags on this box until someone pulls; a coordinator message pointed it out, I rebased on origin/main.
- `cargo test --workspace` filter errors are hidden behind `grep`: my first test compile failure only showed as E0616 with no file (grep dropped the `-->`).
- I piped a rebase through `tail` and started the gate in the same message: the rebase had stopped on a conflict, so the gate began mid-rebase. Stopped it and re-ran. Rebase in its own step, read the result.
- The gate took 374 s at load 23, against the documented minute and a half.
- A must-hold change that looked natural (a snapshot without the right covers nothing) passed its own tests and only showed up as a non-converging sim scenario in tier 1 (`net::coverer_revoked`); filed in issues/covered-body-new-label.md.
