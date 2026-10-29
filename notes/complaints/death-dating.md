# death-dating
- Reverting a planted-bug edit with `git checkout <file>` also threw away that file's uncommitted real change; plant bugs only on a committed tree (or revert with an inverse edit).
- Building main's binary with `git checkout main -- .` brings main's newly added files along (staged); `git checkout HEAD -- .` does not remove them: delete them by hand after.
- `pkill -f oracles.sh` killed the calling Bash wrapper too (the known footgun in notes/build.md); kill by PID.
