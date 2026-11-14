# Sync: driver
> Summary: osis-sync's `driver` (core/sync/src/driver/): `Node`, the one sans-IO step (`handle`: route, settle loop, dials, keep or close, outputs), `apply` and `Links`, store-failure restarts, dial candidates and the retry rule, the tokio `TransportLinks`, and why the step is shaped so.

Spec: spec/sync-opens.md §1, spec/sync-transport.md. Overview: notes/sync.md. The harness that drives `Node` in tests: notes/sync-test-harness.md.

## The step
```rust
impl Node {
    pub fn open(engine: Engine, store: Store, cfg: SyncConfig, rng: Box<dyn NodeRng>) -> Result<Node>;
    #[must_use] pub fn handle(&mut self, input: Input) -> Vec<Out>;   // Up, Bytes, Taken, Closed, Down, Tick, Wrote, Discovered
    pub fn engine(&mut self) -> &mut Engine;   // the osis handle's writes and reads; then handle(Wrote)
    pub fn status(&self) / status_of(s) / idle() / wait(scope) / redeem(link) / export_bundle / import_bundle;
}
pub fn apply(out: Vec<Out>, links: &mut impl Links);   // Out: Send, Dial, Close, Wake
```
`handle`, in order: the engine's reload check; the input routed to its module (bytes: `Session::receive`, then each message to the module `Incoming::to` names, notes/sync-session.md); the compaction trigger (`Engine::compactions`, spec/sync-compaction.md §1); **settle**; `Opens::flush`; dials; keep or close; closes; sessions' bytes; one `Wake`, the earliest of every module's `next_wake`, `Engine::next_timer` and the memo clock's next `until`.

- **Settle**: every module's `settle` (each returns whether it acted) in the order store, unread, opens, read, inbox, streams, status, again while one acted. Opens comes before the other sending modules so they act on this round's shared set; status's complete passes ask `Streams::pull_again` at the end of a round.
- **The loop ends** because "acted" means only that a module changed something another reads (a store row, an engine write, a member moved), each an `Effects` value moving to a new settled value; a round runs again only while values move. Two modules undoing each other would loop forever: nothing in the product bounds it; the harness fails a step past `ROUND_CAP` (16) rounds (`Node::rounds`, tests only).
- **Members moving**: opens' `Moved` values go at once to status, read, inbox, the dials (`sharing`) and streams; streams' `Reported` go back to opens (`reports`) until nothing is left.
- **No engine events as input.** After the osis handle writes it calls `handle(Wrote)`, which only settles: what the write changed reaches sync through the memos it moved. `Engine::subscribe_durable` serves the API's listeners only.
- The node's time is its engine's clock; `Tick { now }` says a wake came due (`now` moves it forward only).
- `apply` carries out sends and dials in the order made, then closes (a closing node's owed Applied goes first, spec/sync-streams.md §4 Reports), then one `Links::wake`, the earliest given. A step gives at most one `Wake`, last, and `Links::wake` replaces the node's earlier one, so no older wake overwrites a newer (an early wake costs one idle `Tick`). Only `handle` makes outputs: `status` and `wait` read.
- The client port's messages are carried as `PortEvent`s for the owner (`Node::port`); sync judges none of them (notes/client-port.md).

## Failures
- A step that fails (a store failure) sends nothing it queued, closes every connection and restarts the modules from the store, once per stretch until a durable commit of either store lands; the next wakes back off from `RETRY_FIRST_MS` (1 s) doubling to `RETRY_MAX_MS` (60 s). The store's memory part (ephemeral entries) stays. A frame of the failed step might tell of what the failure undid (an Applied of a cursor not stored, a record answered but not written), so none goes; peers see a dropped connection, which every rule survives.
- The engine having a write of unknown outcome (`store_writes().unknown` moved): it reads its whole store again, which replaces every index the modules follow, so every connection closes and the modules restart as at an open.
- Modules' effects are not durable (but opens' `changed_at`), so a start or restart settles every key once: the same reload spec/sync-judgement.md §3 names for forgetting.

## Dials (`driver/dials.rs`)
Candidates, reasons as priorities, the one retry rule (`REDIAL_MS` 30 s, quiet candidates waiting for a change), `max_peers` (`MAX_PEERS` 32 by default), `DISCOVERED_KEEP` (1024) and the pair rule's held dials: the module doc. Sources of candidates: `Engine::dial_peers(s)` per S of the sync set (followed through `Effects`, notes/sync-facade.md), `Inbox::dial_hints` (read whole each step, O(hints)), `SyncConfig::dial`, discovery (`Input::Discovered`). Unbounded candidate counts from hostile dial lists: issues/sync-dial-amplification.md.

**Keep or close**: a dialed connection closes when `Opens::idle` (no member, nothing of opens under way), `!Inbox::may_deposit` and `Session::quiet` all hold; its candidate is dialed again after a change. A served connection is never closed for sharing nothing (spec/sync-transport.md §5). Each step reads the dialed connections, at most `max_peers` sharing ones plus those about to close.

## Links
`Links { dial, send, close, wake }` is all a node needs of the world. `TransportLinks<T: osis_transport::Transport>` (`driver/links.rs`, behind the default `driver` feature, tokio) is the product's: dials, listeners, discovery, each link's bytes and what the transport took, turned into `Input`s (`TransportLinks::next`); the osis handle's driver task steps the node on them. Tests use a `Links` per node over an in-memory fabric (the harness; `internals::ManualNet` in the osis tests). Sync never learns how a peer is reached: a connection is its key, its rank and its bytes.

## Reasons
- One sans-IO step with one place outputs are carried out: an older wake overwriting a newer nested one once left a node that never ticked after a restart; with `apply` alone carrying out outputs, in order, no call path can reorder them.
- No hook, callback or queue from the engine to sync: a queue sync must drain is state two owners write; memos and `Effects` give the same change-driven work with one owner per value.
