# paged-apply
- `paged_apply_matches_whole_*`'s failure print is one `{:?}` line of the whole index digest (about 900 KB): `first_diff` finds "line 0". A token diff (split on `,{}]`) of the two lines found the table; the digest printed pretty would let `first_diff` name it.
- A first constructed test watched the wrong body and passed on the old code; check a reproducer fails with the fix undone before trusting it (it did, once it watched the body the index rows differed on).
