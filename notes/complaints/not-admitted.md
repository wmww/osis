# not-admitted
> Summary: complaints from the code 14 (not admitted) task.

- The issue said `init --host X` exits 6 when X never takes the home label; it does not wait at all (only delivering commands, `sync`, `wait` do), so a refused home shows only in `status`/`sync`.
- The CLI's own `block_on` deadline and `wait_synced`'s deadline were the same `--timeout`, racing: whichever fired first decided the error. `sync`/`wait`/delivering commands now poll `wait_synced` on its own deadline only (`wait_sync`).
- A CLI `status` right after start cannot show `Refused`: the refusal record is in memory and a fresh process has not registered yet.
- Review: the persisted `git diff main...HEAD` was too large for one read (long note lines); `--word-diff` with a small script to excerpt the changes worked.
