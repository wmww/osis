# A delete seen at a source is not judged again at a start or as the verdict moves
> Summary: rows a source shows only as deleted (`Seen::deleted`) are judged toward it only when written; a restart before acting, or a body turning must-hold later, never logs it again there.
> Priority: normal
> Tags: sync, read

spec/sync-judgement.md §4 (Logged again once) says the deletes seen at a source live in its record so a restart is no change of ground. `read` wants `toward` for a (source, body) only from presence rows: `Live::seen_added` replays `Known::rows_all` (PRESENT rows) at a start, and a verdict moving wants `toward` at `Ground::shown_at` (PRESENT rows). The store's deletes-seen rows (`store::rows::tag::SEEN`, `Store::saw_deleted`) are in neither, so:
- a node restarting after seeing a delete of a must-hold body at a store source but before logging it again there (e.g. waiting on role entries first) never logs it again until the head moves or a part falls;
- a body that turns must-hold after its entry was deleted at a source (deleted-only there) is not logged again there.

Likely fix (small): a start also replays every SEEN row (records' `record_tag_rows(SEEN)`, connections' `conn_rows`), and `shown_at` adds the sources with a SEEN row of a blob of the commit (`records_with_row(s, SEEN, b)`). Needs a World test that fails without it: no World test of logging again exists yet (only `store::stands_live_in_the_record_spec_sync_judgement_4`), so building one is most of the work.
