# keel-leak13
- No test helper lists an engine's local rows by prefix (only `local_census` counts): finding which `bp/` rows grew took a throwaway accessor.
- The brief named the unheld feed as the likely driver; it cannot be: a release unnotes the commit's blobs in the same transaction, so `commit_blobs` is empty by the time the feed is read. The vestigial `Cipher::defer`/`finish` path (unused since the sync rewrite) was the crash-safe door instead.
