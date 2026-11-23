# slim-tests
- `claudewait` with no ID picks nothing; guessing the newest task file picked another agent's task (the tasks dir is shared): always pass your own ID.
- Two `icount` runs started as `( ... &)` inside one background Bash call detach from it, so claudewait cannot wait for them: start each as its own background call.
- Wall times under the box's load (20-40 on 16 cores) moved 3-6x between runs of one test; only icount and `/proc/thread-self/schedstat` probes compared.
