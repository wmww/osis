# sync-oddities
> Summary: footguns met chasing sync timing over the real client port.

- `git checkout .` to drop a probe trace also dropped unstaged probes: wip-commit first, as CLAUDE.md says.
- A timing bug needs many parallel runs to show (2 of 12, 8 of 48 on a loaded box): a one-off Runtime::Own test proves nothing. A temporary per-node trace of `Command`s and `ClientEvent`s found each cause in one read; `Command` has no Debug.
- The sim's FIFO queue hides races between two nodes' round trips: `w.run()` never showed the invite race. `core/node` `Net::round` with an invariant checked each round does.
- Test names say what was blamed, not what caused it: `Removed` at the kicker came from the app granted before the kick.
