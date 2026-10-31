# A re-snapshot changes a group's roster snapshot (perm seed 89000)
> Summary: `roster::snapshot_resnapshot_neutral_large` fails at `OSIS_PERM_SEED=89000` on main too (seed 0xe005eec5aae, sample 305: "snapshot of G changed"; P roles [Admin, None, None], G roles [Admin, Admin, None], applied 0b110, dropped 0b10000). Found by the tied-grants review; not caused by it.
> Tags: permissions, tests

Repro: `OSIS_PERM_SEED=89000 cargo test -p osis-perm --test it -- --ignored roster::snapshot_resnapshot_neutral_large` (10 s).
