# A connection's source is computed and never read
> Summary: `Connection::source` (and the relay's 16-byte source tag a target reads as a relayed connection's source, spec/sync-transport.md §3 Dial) feeds nothing: the relay's own fairness uses `ip_source` directly, and nothing above osis-transport reads a connection's source. Either per-source fairness for served connections gets built on it, or the trait method, its five impls and the tag (spec and wire) go.
> Priority: low
> Tags: transport, sync

The spec has the target count the tag as the connection's source, so dropping it is a spec change; keeping it is a feature with no reader (notes/principles.md, features shrink to purpose). The driver's peer budgets go by record or connection (notes/networking.md, `P2p`). Decide whether served connections need per-source shares (a node serving many dialers from one address) before deleting.
