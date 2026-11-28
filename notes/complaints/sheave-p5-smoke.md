# sheave-p5-smoke
> Summary: Snags from the second dogfood smoke pass: unix socket paths too long under the scratchpad, guibox's env moving XDG_RUNTIME_DIR under the CLI, and no step durations in the first node trace.

- **Socket path too long**: a daemon on a store in the scratchpad with `XDG_RUNTIME_DIR` there serves no socket ("too long a path for a socket"); the default runtime dir works (sockets are named by store hash). A smoke recipe in notes/dogfood.md, with a short runtime dir, would have saved the detour.
- **guibox env and the CLI**: sourcing a guibox session's env sets `XDG_RUNTIME_DIR`, so CLI commands in that shell miss their daemons' sockets and fail `store in use`. Run CLI commands in a shell that has not sourced it.
- **Stall or work?** The node trace showed when each step began but not how long it ran, so a 10 s gap after one step could not be told apart from a wait; the header now carries the step's duration.
