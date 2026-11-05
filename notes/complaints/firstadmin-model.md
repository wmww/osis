# firstadmin-model
- `run.sh small FILTER | tail` hides all progress until the end; a long Depth0 batch looks hung. Pipe nothing, or tee to a log.
- Depth0 instances with a `Via` writer and a cycle run ~1k states/min with liveness (D0_fa_both: 17 min for 26k states); keep `Writes = 1` and drop `Via` where it is not the point.
- A stray `cat >> /dev/null` in a compound command blocked on stdin for 5 min in the background: pass `< /dev/null`.
