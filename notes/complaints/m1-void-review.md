# m1-void-review
- The branch's "0 in 100,000 `tiny`" held; 1,000,000 (about 300 CPU-s under `tools/heavy`) found 3 failing `void`. A property checked only at a size where it first reads 0 is a rate, not a property: a tiny search this cheap should run at 1,000,000 before a claim.
- Comparing two readings of one world (a mutant against the rule) needs both in one process: an env var read in the walk can't switch per call across `on_every_core` threads; a thread-local override did.
