# Cover candidates are written and never read
> Summary: `Core::cover_candidates` (the durable bodies a snapshot's arrival may let a cover drop) is kept up by apply, retention and every open, but its one reader, `Core::cover_judged_on`, lost its caller with the old node sync. Read's per-commit `local` effect (`Engine::covered_drops`) judges covers through the memo layer instead. Remove the index and what keeps it, or say why it still matters.
> Priority: low
> Tags: engine, retention

- Writers: `apply::atomic` (a durable delta from apply), `engine::index` (every held durable delta at open), `retention::mod` (killed writes, settings changes), `retention::bounds` (rebuilt aspects); removers: `retention::mod` (a part not held), `Engine::settle_kept` (test hook only: rotation/tests.rs, engine tests/it covered.rs).
- Stale prose that goes with it: notes/engine-retention-covers.md "Cover candidates" (says sync judges the candidates when a snapshot arrives), the comment in `retention::replace` naming node-sync and "hosts", and the comments citing `Core::cover_judged_on`.
- Before removing: check that read's `local` re-judges a body when a covering snapshot arrives without the index (a snapshot's arrival stamps the commits on its aspect), so nothing waits on the candidate set.
- Engine retention is Fathom's area; touches rotation/tests.rs.
