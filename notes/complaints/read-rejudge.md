# read-rejudge
- `read: judged` counts twice per judgement (the `Effects` span of that name plus `judge::body`'s own count): halve it when comparing with a probe's per-call dump.
- An env-gated dump inside a `Cutoff` derivation also prints the debug comparison runs (`Checks`, costs paused), which grow with the followed keys: read growth from `costs` counts, not from dump lines.
- `Effects` causes (`costs::count_by`, "<effects> <- <container>") named both culprits at once; per-key causes needed a scratch accessor on `Effects`.
