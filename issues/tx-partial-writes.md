# A step failing inside a transaction keeps what it did
> Summary: only a whole failed `Engine::run` rolls back (store txn plus core journals); an error caught mid-transaction leaves the failed step's half-applied writes, which then commit. Fix by making each local step atomic (applied fully or not at all), e.g. savepoints in the store txn and the journals.
> Priority: normal
> Tags: engine

## Where errors are caught mid-transaction
- `Engine::reexamine` (apply/mod.rs): `ingest_blob` failing with `BadInput` is caught and the round goes on to commit. Anything `examine`/`apply_verified` wrote before the error (indexes, blobs, state merges) stays. Whether every `BadInput` is raised before the first write is unchecked.
- `examine` (apply/mod.rs, the per-part loop): `judge_part` failing `Parked` or `BadInput` sets the part aside or marks it bad and goes on. Safe only while `judge_part` writes nothing to `tx` before failing; nothing enforces that.

## The other side: failing the whole transaction
`answer_removals` runs at the end of every durable transaction, and the due set is persisted. It checks its one allowed wait (delete keys) before writing and fails the transaction on any other error, so a failure that repeats (a `commit_tx` check its precheck does not mirror) fails every durable transaction, ingests included, so the node can receive nothing that would clear it. Its precheck uses the same predicate as the write (`holds_listed_keys`, `role_now`), so none is known. With atomic steps it could drop its own attempt, report it, and leave the removal due without blocking the host transaction.

## Shape of a fix
One rule: a local step (one commit's apply, one local write) is applied fully or not at all. A savepoint in `osis_store::Transaction` and a mark in the `Journaled` collections (rollback to mark) would let a caller catch an error and continue from exactly the state before the step. Then the catch sites above are correct by construction instead of by an unchecked "fails before writing" assumption.
