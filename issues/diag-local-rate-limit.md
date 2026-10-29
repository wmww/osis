# Mismatch diagnostics share the local rate limit
> Summary: Local diagnostics (`peer: None`) share one 64-per-minute bucket (engine `events::diagnostic`); typed reads now report one `Mismatch` per bad thing, so a screen reading over 64 distinct mistyped things in a minute suppresses that minute's `Callback`, `Stranded` and `Storage` diagnostics. Past 1024 distinct keys the dedup window also re-reports.
> Tags: api, engine

Options: a bucket per kind for local diagnostics, or Mismatch in its own bucket; dedup per (kind, tid) only for Mismatch is already what the key gives.
