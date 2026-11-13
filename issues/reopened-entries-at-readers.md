# Reopened entries at a label read only from readers may never be fetched again
> Summary: suspected, not reproduced. `reopen_undropped` leaves entries `Unknown` for a source's `refetch`, but a label with no source (only co-reader streams) has no pass that fetches them: nothing puts them in `reask`. And `stream_settle_all` drops a reasked entry whose blob is asked already under another label, whose reply brings only that label's wrap (`opens_here`); the `settle_by` pass `asked_for` books fetches it again only at a label with a source. Either leaves an entry unopened for good.
> Priority: low
> Tags: sync, tests

- Seen while fixing the shredded-wrap storm (`opens_here`): adding both (reopened entries into `reask`; a reasked entry kept while its blob is asked elsewhere) also fixed that seed, but neither was needed for it.
- First a default test: two co-readers, no host, a part missing again under two labels (`awaits::a_part_missing_again_is_fetched_under_every_label_spec_sync_6` has the host-side shape).
