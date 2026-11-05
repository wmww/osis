# leftovers
- `git checkout <rev> --` with no path detaches HEAD silently (meant to restore a file for a fix-disabled probe). Use `git checkout <rev> -- <path>` only, and check `git branch --show-current` after.
- A fix-disabled `cargo test` on the test crate rebuilt for 3 min under load (another agent building): plan those probes in one batch.
- `parts_differential` swallowed `play` panics as unplayed histories with no seed named; it now prints them.
