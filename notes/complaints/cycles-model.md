# cycles-model
- `pkill -f "<pattern>"` killed its own Bash call (the pattern is in the command line); use TaskStop on the runner task instead.
- Depth0 instances with 3 actors or unprompted rotations run at 1-10k states/min on a loaded box: 25-minute timeouts end unfinished. Edit the .tla only between TLC runs of a batch (each run re-parses).
