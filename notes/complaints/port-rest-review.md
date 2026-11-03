# port-rest-review
- `XDG_RUNTIME_DIR` under the long scratchpad path: `serve` dies on a socket path over 107 bytes (`bad transport url`), where a refused socket directory only warns. Live scripts: unset it.
- `kill -INT` from a bash script does nothing to a background job there (bash ignores SIGINT for them): my script hung in `wait`. Python's `send_signal` is fine.
- A first test with 300 synced groups on one node ran over 4 CPU-minutes in debug (50 groups: 10 s): superlinear per group, not looked into.
