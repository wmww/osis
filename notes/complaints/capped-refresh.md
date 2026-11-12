# capped-refresh complaints
> Summary: Workflow notes from fixing the ephemeral_capped refreshed-cursor failure.

- The sim trace shows wire messages only: a peer's refusal for room shows as `full true`, but nothing says which entry it refused or what its room was. Temporary `eprintln!` in `unread_refused` and the host store's ephemeral put/remove were what found the cause; a trace line for a host's refusal and expiry would have saved two rebuilds.
- notes/ephemeral.md still described an upload-era cap path (`SyncEngine::capped`, never filled since uploads went) and a "coverer refused for its cap goes up again replacing" rule with no code behind it; both read as live mechanisms.
