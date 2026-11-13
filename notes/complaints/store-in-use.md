# store-in-use complaints
> Summary: Workflow notes from adding `Error::InUse` and the CLI's daemon errors.

- redb's lock error reaches `RedbBackend::with_storage` as an `io::Error::other` (the opener closure returns `io::Result`), so it is recognised by downcasting its source; a fault-injecting opener that wraps `FileBackend::new` differently loses `InUse`.
