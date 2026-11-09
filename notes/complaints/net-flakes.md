# net-flakes
- `taskset -c 0-1 <it> sources::` did not reproduce the issue's "14 of 15": on this box the zero-wait race failed 2 of 60 single-test runs on one core, and never in whole-suite repeats. A flake rate from an issue is a rate on that day's machine.
- A rare two-lock race (`Unsynced` from a move) did not show in hundreds of pinned runs. An env-set delay between the locks, swept over 0.2 to 20 ms, found it at 1 to 5 ms. A fixed 300 ms delay found nothing: it skipped past the window.
- `/dev/full` as a store file is a trap: reading it never ends, so `read_to_string` on it would not return (not tried). Use a directory in place of the file to make an open fail.
