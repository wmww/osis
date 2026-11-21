# cleanup-engine complaints
> Summary: worker cleanup-engine's slow spots: the probe's dead list mixes test-only hooks with dead code, its own notes and issues cite the items it finds dead, and a test run building beside edits.

- `tools/deprecated_probe.py --dead` lists items dead in the lib build, which mixes truly unused code with unit-test hooks: each of its 44 warnings needed a grep to sort them. An "unused anywhere, tests included" section would save that.
- Items the probe found dead were still cited by notes and an issue (`judge_freed_page` in issues/sync-unbuilt.md, `sync_id_bodies_meta` in notes/engine.md and notes/engine-store.md, `subscribe_durable` in notes/ephemeral.md): grep notes/issues for every deleted name before committing.
- I edited sources while a background `cargo test -p osis-engine` was still compiling (the footgun notes/build.md names); the next run was clean, but the overlapping one tested an unknown mix.
- A regex over whole files to find small single-use fns backtracked past two minutes; a line-based scan took a second.
