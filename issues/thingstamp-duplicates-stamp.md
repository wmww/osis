# `ThingStamp` duplicates `Stamp` in the public API
> Summary: osis's public `ThingStamp` has exactly `Stamp`'s fields: one concept under two types (notes/api-design.md). Also check that `OFFER_LIFETIME_MS`, `BACKLINK_PAGE`, `COMMIT_PAGE`, `MANUAL_CAP` and `MANUAL_HORIZON_MS` are not exported from the crate root: implementation limits are not API.
> Priority: low
> Tags: osis, api

Found by a cleanup of core/osis (deprecated_probe listing unused public items). Fold into one type if their meaning is one (read each use against the model); otherwise name the difference.
