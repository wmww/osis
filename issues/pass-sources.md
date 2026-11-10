# Complete-pass peer sources forget a peer when its connections drop
> Summary: `update_pass_peers` drops a source from `peer_received` once no connection to it is up, so a peer the label was received from that reconnects is waited for only after it brings an entry again: narrower than spec/permissions.md §3 ("every peer it received the label from, can reach"). Keeping the sources needs a bound (`passes` already grows per source key unpruned). Option: wait for every connection sharing the label instead.
> Priority: normal
> Tags: node, sync

spec/permissions.md §3 Complete pass waits for the log of every peer the label was received from that the node can reach and that still reads it. The code (core/node/src/sync/peers.rs `update_pass_peers`) waits for a source only while a connection to it shares the label, and forgets the source (`peer_received`) as soon as none is up. A peer that gave entries, dropped and reconnected is waited for again only once its stream brings events (`received_from`); between the shared set opening and that, a pass at the hosts alone completes and decides (re-seal, untie, removal rotation) without it. With no hosts nothing changes (the label waits out `peer_pass_wait_ms` anyway). A reconnecting peer with only an older copy has nothing to add, so the gap matters only for one holding entries the hosts lack.

The forgetting exists to bound memory: source keys are per record (`source_key`, a kdf of the record id) and records churn, and nothing maps a key back to a record to prune at eviction. `passes` (inbound.rs `bump_pass`) has the same growth today: one entry per (source key, label), pruned only when the label is forgotten.

Options:
- Keep sources across disconnects and prune both maps when a record is evicted (`records_evict` returning the ids; keys must then be computable from evicted ids, as they are).
- Simpler rule: a complete pass waits for every connection sharing the label (whatever was received from it), up to `peer_pass_wait_ms`; drop `peer_received`. Changes §3's wording.
