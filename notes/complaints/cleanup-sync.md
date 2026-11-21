# cleanup-sync
- `tools/deprecated_probe.py --dead osis-sync` found 2 dead items (`idle`, both used by tests), and `dup_windows.py` almost nothing in src: on a crate this tight the probes give little; reading for repeated rules found more (a guard pattern made redundant by `Stamped::remove`, one rule written twice for memory and durable entries).
- Editing src while a background `cargo test` was still compiling left it unclear which tree a run tested: edit only between runs, rerun before committing.
