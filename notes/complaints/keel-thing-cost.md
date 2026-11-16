# keel-thing-cost
- `account_two_nodes()` returns the account root, not the account, while `people()` returns accounts: a thing "under the account" made with its result was plain, and the first breakdown looked keyed and plain alike.
- Logical store bytes had no API: `Engine::local_census` covers local rows only and `backend.dump()` is ciphertext pages without blobs (the old facade test's "28 KB" excluded blobs and index trees by accident of layout). `Engine::census` now lists every family.
- A redirect into a scratch subdirectory created in a parallel tool call raced and silently produced an empty log.
