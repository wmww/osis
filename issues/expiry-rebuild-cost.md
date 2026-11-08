# Each expiry rebuilds the aspect from every held body
> Summary: At a delta's expiry the engine rebuilds its aspect from every held body (`retention::make_leftover` then `apply::rebuild`): release, n=2000 expiring messages, one expiring per tick, about 120 ms per expiry (n=200: 6 ms), so a disappearing chat pays O(messages) per message.
> Priority: normal
> Tags: engine, performance

Expiry changes no winners (spec/crdt.md §4.7: it equals the join with the delta's values stripped), so it can be an in-place `Fragment::strip` of the state by the delta's dots, plus the leftover written, instead of a rebuild. `scale::` has no case of an aspect with many expiring deltas.
