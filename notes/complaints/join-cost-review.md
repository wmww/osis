# join-cost-review
- `sessions::gap_cover_large` hid two failures past its default 100 seeds, both older than this branch: the harness never sent the thing's first commit again after the fall (fixed), and issues/gap-cover-fresh-node-pends.md. Worth a periodic row.
- `rotation::tests:: --include-ignored` runs `repro_later_admin_path_forgery`, a known failure (issues/keyset-name-later-admin-path.md): read which test failed before suspecting a probe.
- A mutant removing the `on_target` reset in `append` survives: `inserted` already resets the whole memo on every path that moves `applied`, so that line is belt and braces. Mutate both resets to test the index.
