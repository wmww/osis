# pending-drops
> Summary: mishaps on the pending-drops branch.

- `wt` was not on PATH; used the plugin cache path from the brief.
- The issue's "blob with parts of two expiries" case cannot happen: node-sync rejects a blob holding deltas of several retention classes. Cost a test written against it; the kept-blob case is purge-only.
- A purge's author drops the named part from its own copy at once, so a test must take the commit's package before writing the purge (cost a debug round).
