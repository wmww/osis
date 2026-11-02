# pending-drops
> Summary: mishaps on the pending-drops branch.

- `wt` was not on PATH; used the plugin cache path from the brief.
- The issue's "blob with parts of two expiries" case cannot happen: node-sync rejects a blob holding deltas of several retention classes. Cost a test written against it; the kept-blob case is purge-only.
- A purge's author drops the named part from its own copy at once, so a test must take the commit's package before writing the purge (cost a debug round).
- Review: `parts::parts_differential_large_spec_commits_4` failure lines are cut at about 350 characters, before any `got`, so the differing line is not shown; fresh ranges 934000 and 936000 each had failing seeds that fail on main too.
- Review: the rebase applied cleanly but main had added a `Why::PendingExpiry` use in order.rs; only the build caught it. Grep for renamed identifiers after a rebase.
- Round 2 (purge strip): a pending copy whose bytes `CommitBlob::decode` refuses (a part delta that is not a CBOR list) is skipped silently by `read_pending` and `check_unchanged`: the commit stays in `ix.pending` and is never examined again. Cost a debug round (an empty placeholder delta); now the placeholder is an empty list.
- Guessed background task IDs for `claudewait` twice; take the ID from the launch message.
