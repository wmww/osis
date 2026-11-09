# net-reconnect-finish
> Summary: Slow spots on the reconnect design's last pass.

- `run.sh` swallows which invariant failed; the state count and pass/fail alone hid that a failing "positive" cfg failed `EpochReached` under an unrelated removal. `TLC_KEEP_LOGS` and `grep violated` found it; the line it prints on a mismatch could name the invariant for every fail.
- A rule-removal cfg that passes on the first base does not mean the rule is unneeded: `Quiet` conflates learned views, and a report-less stuck `Lost` violated nothing until a new invariant (`UntilEnds`) said so.
