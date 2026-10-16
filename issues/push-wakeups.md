# Push wake-ups from blind nodes
> Summary: Mobile apps need the server to wake a device when something arrives. Proposal: per-label opaque wake handles sealed to a push proxy, so the server cannot link one device's labels. Owner calls: the official proxy's trust (it runs beside the server), whether wake priority is visible to servers, and who pays.
> Tags: sync, networking, security, owner-call

Found by the chat deep dive; any app with notifications needs it. Today a blind node knows only which connection syncs which labels, over an ephemeral key per connection, and pushes only on live subscriptions (spec/sync.md §8). A phone in the background has no connection. A push token (APNs, FCM) is a stable per-device identifier, so registering "wake me on L1..Ln" with one token links those labels at the server, which the requirements forbid beyond overlap.

## Proposal
- Per label, the device registers a **wake handle**: a sealed box to a push proxy's public key holding the push token, fresh randomness per label, so the server sees unrelated handles. On a new log event the server hands the handle to the proxy, which opens it and sends an empty push; the device then syncs (one round trip, within iOS extension limits).
- The server learns how many wake handles a label has and when wakes fire; the proxy learns tokens and wake timing, never labels. Server and proxy together can link a device's labels by timing; if both are the official service, that is a promise, not a guarantee.
- UnifiedPush: the server posts to per-label endpoint URLs of the user's chosen distributor directly, no proxy. An osis server can also act as a UnifiedPush distributor for Android without Google services and for self-hosters. iOS needs APNs through the official proxy.
- Rate limits: at most one wake per handle per short interval; events batch into one wake.

## Owner calls
- Accept the official proxy beside the official server (collusion risk above), or require a separately operated proxy.
- Priority: some writes should wake (a chat message, a call invite), others not (a read marker, a bulk edit). Options: a per-upload wake bit (the server learns which blobs matter), a separate wake label per chat (one more label, overlap shows its pairing), or wake on everything with client-side quiet filtering (battery cost).
- Who pays for push on the official server (issues/server-abuse-limits.md).
