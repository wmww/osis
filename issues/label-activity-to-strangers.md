# Anyone who knows a label ID can watch its rotations and deposits
> Summary: a Register with any well-formed step for label L gets L's head step back (spec/sync.md §5 says so), and a Deposit with a bad signature still gets L's remaining deposit budget. So an ex-member or a link holder can poll a server and learn when L rotates (removals), its current head ID (enough for the claim-set Open cost in issues/server-hub-stall.md), and its deposit activity (grants, reader heartbeats, reader liveness) forever. notes/sync.md rejected designs that let ex-members watch rotation cadence for exactly this reason. Low-medium.
> Tags: security, proto, server

- `ServerConnection::register` (core/proto/src/server.rs:591): a child that does not verify under the head is answered `Step { head }`, with no proof that the sender held any key of the path.
- Deposit (core/proto/src/server.rs:476-488): `store.budget(&label)` is returned whatever the code, REFUSED included. Only an unknown label answers zeros.
- Open answers UNKNOWN_LABEL or REFUSED, which says whether a server hosts the label. That is probably acceptable (a label ID is already key-derived), and the two items above add the leak beyond it.

Fix direction: answer the head on Register only when the step verifies under the delete key of some step on the path. A step the server holds proves the sender was an admin of it, which is the case the spec's "answer with the head" serves. A relaying non-admin then opens and reads Path. Report the budget only on OK, BUDGET_FULL or NOT_HEAD (a deposit-key signature that verified). Spec change: spec/sync.md §5 Register and Deposit.
