# Push wake-ups from blind nodes
> Summary: Mobile apps need the server to wake a device when something arrives; that needs a device-to-label registration at blind nodes (a metadata trade), a UnifiedPush story, and perhaps a notion of high- and low-priority sync traffic.
> Tags: sync, networking, security

Found by the chat deep dive; any app with notifications needs it. Today a blind node knows only which connection syncs which labels, over an ephemeral key per connection, and pushes only on live subscriptions (spec/sync.md §8). A phone in the background has no connection.

Needed: a way for a device to register "wake me when label L changes" with a push token. A push token is a stable per-device identifier, so the server learns which labels one device tracks across sessions, roughly Signal's token-to-account mapping. The payload must be empty or opaque; the device syncs on wake. One round-trip sync keeps iOS notification-extension time limits reachable.

Ideas to consider:
- An osis server should be able to act as a UnifiedPush server (push distributor) and the osis app as a UnifiedPush provider, so Android users without Google services and self-hosters get push with no third party. Does not cover iOS, and probably not every Android case; those need APNs/FCM relayed by the official server.
- High and low priority traffic: some writes and signals should wake a phone (a chat message, a call invite), others should not (presence, a read marker, a bulk edit). The priority would have to be visible to the blind node, so it is metadata; decide whether it is a per-label setting, a per-upload flag, or a separate "wake" label pattern, and what the server then learns.
- Rate limits: a busy label must not wake a device per blob; batching and per-device limits.
- Who pays for push on the official server (issues/server-abuse-limits.md).
