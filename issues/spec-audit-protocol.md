# Spec audit: node-to-node protocol and transport gaps
> Summary: From the spec audit of spec/sync.md and spec/wire.md §5-§13 (protocol rules the code enforces were written into the spec on branch spec-audit): the P2P transport and `peer://` addresses are unspecified, so no other implementation can reach a co-reader; smaller host behaviours still only in code; host/client policy text in spec/sync.md.
> Tags: spec, sync, transport

## Needs an owner decision
- **P2P transport**: spec/sync.md §10 and §3 name `peer://` and relays but define neither. Code: `transport/src/lib.rs` (a `peer://` URL plus space-separated relay URLs, or socket addresses), `transport/src/iroh.rs` (iroh 1.x, ALPN `osis`); `node/src/sync/peers.rs` treats `peer://` entries in `label.0` hosts as never-dialed and a label with only them as hostless. Either spec iroh's protocol (a dependency's wire format becomes ours) or define our own; then add the URL grammar, transport, relay scheme and the never-dialed rule to §10.

## Still only in code (add to spec/wire.md §11.2 or spec/sync.md §5)
- Delete of an entry not held: 0 if a tombstone exists and the delete-key signature verifies, else 1; a level delete of a non-held entry 1; `at <= now` deletes at once (`proto/src/serving.rs` delete).
- Sync: tombstoned IDs never in `want`; no add events for the requester's own `entry` blobs; Path with an `after` not on the path answers 1; a re-deposit of a held entry or an upload with the same wrap and stamp logs nothing (`proto/src/store.rs`, memory store only: check the real host store agrees).
- spec/sync.md §10 "a handshake has no deadline" vs hosts closing a connection with no Hello after `hello_ms` (10 s, `host/src/store.rs`): say the osis Hello deadline is host policy.

## Code nits
- `proto/src/msg.rs` comment "Kind 24 (the old signal) is retired": compat talk, drop it (spec text dropped).
- Replay cursor position keeps 63 bits of a blob ID, so a replay page can skip an ID sharing them with the last one sent (`serving.rs` ~204-227). Negligible, but a full-ID position would be exact (the cursor is now opaque in spec).

## Misplaced in spec/sync.md (move to notes/sync.md)
- §1 repair back-off, §5 client deposit ordering of certificates and heartbeats, §6 offset diagnostic, §9 "(a diagnostic)" asides, §10 handshake bound and LAN route preference and back-off.
