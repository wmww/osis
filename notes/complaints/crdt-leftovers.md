# crdt-leftovers
- `wt` and `claudewait` not on PATH in the subagent shell (known; used the plugin cache paths).
- vouched-by-misstated-copy's analysis was off: `rebuilt` strips the delta's copy under a misstated dot, never the snapshot's; the real cause was dot-level vouching vs (dot, key) map records. A repro first saved a wrong fix.
- First merge_elem rewrite turned "delete over undelete" into `undatable` only, which a replay ignores: the replay then lost the death entirely (seed 5016 looked unchanged for a different reason). Undated and reported both, now.
- The order harness's shrunk seeds (5016) take ~4 min each to shrink at load ~20; `OSIS_SHRINK=0` helps when only the message matters.
- Review: two `tools/bin-at main` builds took 3.5 and 10.5 min at load; a 31-line test-only change on main cost a whole rebuild each way.
