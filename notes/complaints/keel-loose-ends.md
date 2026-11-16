# keel-loose-ends
- `wt claim <branch> origin/main` started from a stale origin/main (no fetch first): the chat storm I chased for an hour was already fixed on main (9a8d3e702). Fetch and rebase before reproducing anything.
- The chat storm test takes 260 s to hit the 20000-delivery cap in a debug build; with a per-message probe, 11 min. A cap derived from the test's size would fail in seconds.
- No message trace exists at the osis/ManualNet level (`OSIS_SYNC_TRACE` is the osis-sync harness's only); I added throwaway eprintlns to `Session::frame` to see the wire.
- The order harness's failure dump (`OSIS_ORDER_DUMP`) lists reads by delivery, but not why a commit left; tracing a commit's header/pending/valid/missing per ingest through `deliver_with`'s callback found it in minutes.
