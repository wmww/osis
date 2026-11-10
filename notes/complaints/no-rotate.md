# no-rotate
- The task's scratch directory did not exist; a background run redirecting into it failed at once (exit 1, nothing built). Make the directory first.
- notes/testing.md's networking command has no `-p` (workspace-wide `--tests`); a worker told "never `--workspace`" has to add its crates by hand.
