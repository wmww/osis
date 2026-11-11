# order-held-record
- The failure dump's `node pending #N: Drift` showed a stale reason: the engine stored no new reason when a re-examined pending commit was thrown out, so the dump pointed at drift, not the bad part beside an unjudgeable one. Throwaway `eprintln!` probes filtered by the commit ID prefix in `examine`/`reexamine` found it in three ~1-3 min rebuild cycles; no shrink was needed.
- The model input numbers commits by its own relabelling (`#55`) while the dump uses pack indexes (`#59`): the same commit under two numbers in one message.
