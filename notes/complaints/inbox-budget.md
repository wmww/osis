# inbox-budget complaints
> Summary: Mishaps met while fixing the inbox deposit budget.

- My own slip: a stray `cat > scratchpad/.x` hung on stdin, moved to the background and left an empty `.x` at the scratchpad root. Stopped before its chained `rm` ran; the file stays, since the scratchpad takes no `rm`.
- `perf record` errors out with no message here, so the pass cost in issues/inbox-walk-per-pass.md is unprofiled.
- Running a probe beside tier 1 made tier 1 take 7 min and the probe's numbers noisy.
