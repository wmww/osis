# Client port rows the node does not serve
> Summary: spec/wire.md §11.2 lists `backlinks` (row 5) and the status row's kept list, both in the `osis` API, but the port serves neither, so a client session cannot read them.
> Priority: normal
> Tags: osis

- **Row 5 `backlinks`**: `Osis::backlinks` exists (core/osis/src/backlinks.rs, a paged `BacklinkQuery`), but `port::method` has no constant for 5, so a call answers "unknown method". The spec row's shape (`[tid] -> [[thing, ak, kind]*]`, unpaged) also differs from the API's pages: build the row to the API's shape and update the spec row with it.
- **Row 21 `status`, `[kept tid*]`**: the reply is `[connected, units]` with no kept list. `Osis::retained_copies` (core/osis/src/share.rs) answers it in-process.
- Rows 0-22's other forms match `port::serve::row`.
