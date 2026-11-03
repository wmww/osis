# history-chunk
- Tier 1 plus clippy took 11 min wall at load ~31 (notes say ~40 s warm for tier 1); most of it waiting on the shared box.
- `osis::Link` is not re-exported; a chat test reaching for a link needs `osis::schema::osis_base::Link`.
- `claudewait` worked from PATH this time.
- Review: blobs are stored in two places (`put_blobs`, `ingest`'s blob list); item 250's re-delivery lived only in the first, and drained `missed` inside the transaction, so a rolled back one (a bad commit's ingest) would have lost the notes. Now one `Tx::store_blobs`.
