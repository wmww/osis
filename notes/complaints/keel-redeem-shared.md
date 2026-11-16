# keel-redeem-shared
- The issue's suspect (opens on a shared connection) was wrong: `OSIS_SYNC_TRACE` shows frames only, and the cause (an entry opened with a section sealed, never reopened) leaves no frame. Found by eprintln probes in `take_body`, `examine` and `open_commit`; a trace line for an entry's `Opening` and its sealed sections would have saved an hour.
- The trace cuts lines at 400 chars, which hides the order of a PullReply's listing, the thing that decided this bug (pulls go with `inline_limit` 0 once a member has two sources).
