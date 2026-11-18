# keel-judge-cost
- `Effects::due`'s causes name the table that moved, not the read that saw it nor whether the key was absent: finding that entry-row dues were absent-bucket fan-out took a throwaway per-`Dep` read-site label (a thread-local site set in each `Live` call, kept on the `Dep`). Worth a real `costs`-only diagnostic (issues/tooling-gaps.md).
- Editing sources while a backgrounded `cargo test` is still compiling gives a run of mixed revisions (one half of an A/B compare compiled the next edit and failed). Wait for the build before editing.
- A 200-seed full-size sweep is four heavy holds but took 25-40 min of wall here, mostly waiting for the lock behind other agents' holds; two sweeps (branch and main, for a seed comparison) took most of the task's wall time.
