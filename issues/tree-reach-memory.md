# Counted tree reach memory grows with the data asked about

> Summary: `Core::tree_reach` keeps, per thing a tree question was asked of, an entry per tree blob in each of two reaches (states, bodies), until the thing is destroyed or the node restarts: about 600 B per 80 KiB chunk per reach (about 1.5% of the value bytes held), unbounded across things.
> Priority: low
> Tags: engine, retention

Each counted link keeps its `Link` (about 210 B with three delete keys), its `Opens` key, and its parent's `Read::Kids` keeps the link again. Dropping a thing's reach is always safe (recounted at the next question) but costs that question a walk of the whole tree, which `tree_refs.rs` exists to avoid, so a plain cap trades memory for per-edit work again.

Fix direction: store less per counted chunk (a chunk is never read, so its entry needs no `Link`, only its counts), or measure first whether it matters beside the store's own memory per blob.
