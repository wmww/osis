# rearrival
> Summary: Footguns met fixing pending re-arrival cost.

- `ingest_blob` is both the arrival path and the re-examination path (`retry_pending`): a shortcut placed inside it would have skipped every wake. Arrival-only logic goes in `apply::arrive`.
- `Duplicate` and `Pending` are not interchangeable for callers: `ingest_sealed_fire` accepts `Duplicate` as applied, `ingest_uncarried` refuses only `Pending`; a shortcut must return what the full path would.
- The store already skips writing a catalog row whose bytes are unchanged, so "rows written" was 0 per re-arrival even before the fix; the cost was the decode, signature check and examination.
