# small-crates-cleanup
> Summary: a cleanup pass over six small core crates found little volume; mutate.py's interleaved stderr/stdout rows read as mismatched.

- The six crates (store, keys, transport, crypto, blob, commit) were already dense: `tools/dup_windows.py` found mostly 3-line windows, and no pub item was dead. Most of the volume a cleanup finds here would need a redesign (e.g. pager's `txn_*` functions taking `Dirty` and rng beside `Transaction`), not a trim.
- `tools/mutate.py` with stdout and stderr in one log prints each "mutation k's output" line next to another mutation's table row (stderr and stdout interleave), so a row seems to name the wrong log. Read the row's own failing-test line, not the path above it.
