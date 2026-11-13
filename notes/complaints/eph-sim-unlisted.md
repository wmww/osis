# eph-sim-unlisted
- The sim trace shows a node's injected store fault only as a diagnostic, never the node sync restart in place it causes; finding that the reader's records vanished there took `eprintln!` instrumentation in `restart_in_place`. A trace line "node N sync restarted in place" would have pointed at it at once.
- The divergence dump names ephemeral commits by id and an author Tid the sim does not map to a node (an account's): matching them to the trace's writes meant decoding `Ts` and subtracting each node's clock skew by hand.
