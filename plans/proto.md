# Sync protocol crate: messages, framing, handshake, cursor sync, reconciliation, sans-I/O engines
> Summary: Implement spec/sync.md §5–§6, §8–§9 message layer in `osis-proto`: framing with fixed maximum sizes and paging, version negotiation, the handshake (clock, challenge, static key), every operation's request and reply, cursor sync, range-based set reconciliation, subscriptions and signal relay, plus sans-I/O state machines for the client side and the server side that transport, node and server drive. Layouts from plans/protocol-spec.md.
> Tags: sync, tests

Crate: `osis-proto`. Depends on: osis-core, osis-label (step, stamp, blob, token, envelope types). Unblocks: server, transport driver, node-sync.
Spec: spec/sync.md §5 (operations), §6 (protocol, cursor sync, reconciliation, clock offset), §8, §9, §11 (bundle as a peer with no cursor). Notes: notes/sync.md, notes/networking.md (what the transport provides; the protocol must not assume QUIC). Spec trumps this plan.

## Deliverables
- Frame codec over an ordered byte stream: length-prefixed messages, `MAX_MESSAGE` from `format`, every list paged with continuation tokens; decoder bounded; version negotiation in the first message (protocol version separate from the format version, spec/versioning.md §1).
- Handshake: wall clock ms, 32-byte challenge, static key; clock-offset estimator (round-trip corrected, outlier-robust, diagnostic above a few seconds) as a pure function the node uses.
- Messages per spec/sync.md §5 with exact layouts: Open (sync or claim key; signed-step replies for superseded keys), Claim (step ID + key, or static entry), Register (step with claim set; reply "head is …"), Upload (entries with wrap and stamp; no open), Deposit (reply with remaining budget), Delete (label key, or token + level signature; optional time), Download / specific-blob fetch, CursorSync (cursor, inline new blobs, gained IDs → log after cursor minus those, inline blobs, want list), Reconcile (RBSR rounds), Subscribe / Push (log events in cursor-reply format), Signal (envelope under write or deposit key), errors (refused reasons without leaking server policy beyond what the spec allows).
- Range-based set reconciliation over 32-byte IDs (Negentropy-style: ranges with fingerprints and ID lists, split rule, bounded rounds); specify in protocol-spec item 9; property-tested convergence for arbitrary set pairs within log rounds.
- Sans-I/O engines: `ClientLabelSession` (per peer per label: open/claim walk, cursor sync, send new blobs, answer want lists, reconciliation fallback, subscription handling) and `ServerConnection` (per connection: handshake, opened labels, dispatch to a `LabelStore` trait the server implements) as `handle(Input) -> Vec<Output>` with timers; no async, no sockets.
- Bundle import adapter: a bundle reader (osis-label) presented as a peer's log events into the client engine.

## Steps
- [ ] Frame codec, negotiation, handshake, offset estimator; fuzz target for the frame/message decoders.
- [ ] Message types with layouts (provisional module until protocol-spec is merged); vectors.
- [ ] RBSR with proptests; cursor sync shapes.
- [ ] Client and server engines with an in-crate loopback test (engine ↔ engine, in-memory `LabelStore`), scripted fault cases (lost cursor → reconciliation; oversized gained list; stale sync key → one signed step).
- [ ] Bundle adapter.

## Done when
server and node-sync are thin drivers around these engines; a loopback sync of N random entries converges in the round counts the spec's cost goals name (constant common case, log worst case; tier-2 test); notes/sync.md "Protocol" section records the message layouts summary and RBSR parameters. Delete this plan.

## Progress
