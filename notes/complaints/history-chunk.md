# history-chunk
- Tier 1 plus clippy took 11 min wall at load ~31 (notes say ~40 s warm for tier 1); most of it waiting on the shared box.
- `osis::Link` is not re-exported; a chat test reaching for a link needs `osis::schema::osis_base::Link`.
- `claudewait` worked from PATH this time.
