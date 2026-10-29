# death-dating
- Reverting a planted-bug edit with `git checkout <file>` also threw away that file's uncommitted real change; plant bugs only on a committed tree (or revert with an inverse edit).
- Building main's binary with `git checkout main -- .` brings main's newly added files along (staged); `git checkout HEAD -- .` does not remove them: delete them by hand after.
- `pkill -f oracles.sh` killed the calling Bash wrapper too (the known footgun in notes/build.md); kill by PID.
- Review: the walks `_moves` test reads `OSIS_WALKS_MOVES_START`/`_SEEDS`, not `OSIS_WALKS_*`; a "fresh 1000" run with the latter silently ran the 6 default seeds.
- Review: planted bugs showed the dating checks were weaker than they read: the order harness never dates snapshots (its kept aspects take bounds per commit, so snapshots are unbounded), and retention.rs accepted any snapshot death the oracle lacked; an early snapshot death passed both.
- Review: squashing wip commits with `git reset --soft <worker tip>` used the tip hash from before the rebase (brief rebase changed it); caught via reflog. Take the base from `git log` after rebasing.
- Review: `order::deaths_dated_per_node_*` picked X by commit-ID order; main's ephemeral commit changed the IDs and it failed only after the rebase. Fixed to pick by commit.
