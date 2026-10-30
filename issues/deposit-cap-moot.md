# A deposit refused for the storage cap is dropped for good
> Summary: the client retries a refused deposit only for codes 13, 4 and 5 (spec/sync.md §5: "refusal for now"). Code 12 (node at its storage cap) makes it moot at that server forever, though the condition is temporary. Anyone may fill a server to `max_bytes` (accepted, notes/sync.md Open), and once full, every reader's grant, self-removal, certificate and heartbeat deposited there is lost at that server. Other nodes can then wait for good on a commit's missing parts (issues/link-race-edge-only-pending.md). Low.
> Tags: security, node, sync

- `budget` (core/node/src/sync/inbound.rs:973): `retry` holds only for UNKNOWN_LABEL, RATE_LIMITED and BUDGET_FULL. Any other code removes the outbox item and `remove_out`.
- REFUSED, MALFORMED and the like from a malicious server are the accepted "servers drop data" case. Code 12 from an honest server is not.

Fix direction: add 12 to the "for now" list in spec/sync.md §5 and in `budget`, with the same bounded back-off.
