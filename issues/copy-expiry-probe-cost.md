# The writer's copy-expiry probe resolves a write against the whole state
> Summary: `write::copy_expiry` (spec/crdt.md §4.7 copy expiry) runs a write's ops a second time against the whole state (`tx.state`, every page loaded, cloned) whenever a held delta of the aspect has an expiry ahead, and once more per op when they copy an expiring value. A chat with disappearing messages pays O(aspect) per write: about 4x a write's cost at 2000 messages.
> Tags: engine, performance

The probe also scans `ix.by_aspect` for an expiring header per write. Cheaper shapes: resolve once and take the expiry from the resolved delta (the probe runs before the resolve because chunk framing carries the commit's expiry), or probe only the pages the ops touch (`load_for_ops`). Rough measurement (test profile, one node, a map of n expiring messages, 50 more expiring puts): n=200 about 8 ms per write with or without the probe (noise); n=2000 about 85 ms with it, 20 ms without. `scale::` has no write-into-expiring-aspect case.

Beside it: each expiry rebuilds the aspect from every held body. Release, n=2000 expiring messages, one expiring per tick: about 120 ms per expiry (n=200: 6 ms); a disappearing chat pays O(messages) per message.
