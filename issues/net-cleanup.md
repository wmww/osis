# Server engine: costs a peer can still cause
> Summary: What remains after the net-cleanup pass: a Reconcile over the whole space still sums every live ID of the label per message (needs a fingerprint index), and the listener backlog that `link::serve` keeps unreachable.
> Tags: proto, server, transport, security

- **Reconcile fingerprints** (`ServerConnection::dispatch`, Reconcile): reads are now limited to the asked ranges (`LabelStore::live_ids_in`; ranges are sorted and disjoint), but a fingerprint over a large range still needs every ID in it, so an opener repeating the whole-space fingerprint pays O(label) reads per message, without limit across messages. A bound needs fingerprints the store keeps per subtree (additive sums, spec/wire.md §11.3) so a range costs O(log n). Needs an open.
- **Listener backlog** (`quic.rs` `accept_loop`, used by `iroh.rs` too): a connection whose handshake completed waits in its own task for a slot in the 64-entry accept channel; if nobody accepted, those tasks would pile up. `link::serve` accepts continuously (closing past its cap), so this is not reachable today.
