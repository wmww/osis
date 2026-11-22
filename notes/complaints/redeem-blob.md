# redeem-blob
- The storage-as-fresh tests name a leaked row but not which sync ID holds a blob or why; finding the culprit took ad hoc probes (store entries by blob, `commit_blobs`, header aspects). A debug helper "blob → sync IDs naming it, copy flag, parts" next to `why_kept` would have saved several rebuilds.
- `flat_work` compares windows of three rounds strictly; a one-round spike of read work (it shifts with what earlier rounds wrote) fails it with no growth at all.
- The issue named the wrong node: by now the maker failed first (an owed fire), hiding the grantee's blob.
