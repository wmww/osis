# keel-rot-livelock
- Seed 81 does not storm on main nor at the commit that filed the issue (deterministic, alone and in a 25-seed hold under load): the storm came from an intermediate build. The reproducer had to be built from the issue's description; a filed storm should keep the build (a binary or commit) that showed it.
- `core/test/tla/run.sh` for two modules of one directory at once (cut and cover, in parallel) failed cover's first instance with "Module-Table lookup failure"; alone it parses. Run TLA modules sharing a directory one after another.
- depth0's listed instances take about 20 min at one worker (D0_nc3 474 s, D0_gone_live 263 s), past run.sh's "under 3 min" note.
