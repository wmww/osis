# Which secrets back a chunk's delete tokens
> Summary: A commit blob carries one token per secret that may finish a purge (author chain plus each `purge`-class thing's write secret), but chunks get one token hash each in the header, so other writers may be unable to hard-delete a `purge`-class large value's chunks at blind nodes.
> Tags: sync, crypto

spec/crypto.md §7 and spec/commits.md §1 say a chunk token is `kdf("delete token", secret, chunk prefix salt)` and that the header lists one token hash per chunk, without saying which secret. If it is only the author chain's secret, a reset of `purge`-class large content by another writer cannot finish at blind nodes until an author device syncs, contradicting "any current writer finishes an ephemeral reset at once".

Likely fix: chunks carry the same secret list as their commit (one commitment per secret in the chunk prefix, header lists per chunk per secret). Check the size cost and the interaction with chunk reuse across commits (a reused chunk keeps its creator's prefix).
