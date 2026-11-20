# joined-role
> Summary: Mishaps on the joined-ness (finding 23) and list-leaf (finding 24) model work.

- A blind text replace of `grant: false,` over the engine's evidence tests also hit `regrant: false,` in held-model `Shape` literals; the build caught it. Replace whole struct literals or match with a leading space.
- Three explore batches each waited 3 to 30 minutes for the heavy lock; batching every join's explores into one hold per binary paid off, but the second batch ran a binary built before a generator fix and had to be run again.
- A generator move meant to reach a shape (finding 23's read hop) fired in 1 world of 30: its precondition (an edge nobody wrote) was rarely true after churn, and most worlds bridged it anyway. Count how often a new move reaches its shape (a probe printing the worlds where it fired) before trusting a sampled search to see it.
