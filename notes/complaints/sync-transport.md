# sync-transport
- A backgrounded command redirecting into a scratch dir not yet made fails at once with exit 0 from the wrapper (`echo $?` printed 1 inside): read the output file, not only the task status.
- In-process transport tests under `Sched`: `block_on` may poll its own future before the tasks it waits on ever run, so a "take what is ready now" helper must `sched.run()` first.
- The review brief named `cargo test -p osis-sync`, which does not exist on this branch yet: cargo refuses the whole command (exit 101) and runs nothing, so a combined `-p` list must name only crates that exist.
