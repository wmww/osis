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
`handle`, in order: the engine's reload check; the input routed to its module (bytes: `Session::receive`, then each message to the module `Incoming::to` names, notes/sync-session.md); the compaction trigger (`Engine::compactions`, spec/sync-compaction.md §1); **settle**; `Opens::flush`; the reload check again; dials; keep or close; closes; sessions' bytes; one `Wake`, the earliest of every module's `next_wake`, `Engine::next_timer` and the memo clock's next `until`.

- **Settle**: every module's `settle` (each returns whether it acted) in the order leave, store, unread, opens, read, inbox, streams, status, life, again while one acted. Opens comes before the other sending modules so they act on this round's shared set; status's complete passes ask `Streams::pull_again` at the end of a round.
- **The loop ends** because "acted" means only that a module changed something another reads (a store row, an engine write, a member moved), each an `Effects` value moving to a new settled value; a round runs again only while values move. Two modules undoing each other would loop forever: nothing in the product bounds it; the harness fails a step past `ROUND_CAP` (16) rounds (`Node::rounds`, tests only).
- **Pass ends**: status tells each complete pass to the engine and calls `Engine::pass_end` on S's owner: re-seals, history adds, withdraws and, for the devices actor D, the account's owed rotations (`signing_due`, spec/permissions.md §3, §5.5). The engine's `signing_due` flag is set by an account commit from elsewhere and at open; a restart judges it only at D's next pass, which only a new role commit on D wants.
- **Members moving**: opens' `Moved` values go at once to status, read, inbox, the dials (`sharing`) and streams; streams' `Reported` go back to opens (`reports`) until nothing is left.
- **No engine events as input.** After the osis handle writes it calls `handle(Wrote)`, which only settles: what the write changed reaches sync through the memos it moved. `Engine::subscribe_durable` serves the API's listeners only.
- The node's time is its engine's clock; `Tick { now }` says a wake came due (`now` moves it forward only).
- `apply` carries out sends and dials in the order made, then closes (a closing node's owed Applied goes first, spec/sync-streams.md §4 Reports), then one `Links::wake`, the earliest given. A step gives at most one `Wake`, last, and `Links::wake` replaces the node's earlier one, so no older wake overwrites a newer (an early wake costs one idle `Tick`). Only `handle` makes outputs: `status` and `wait` read.
- The client port's messages are carried as `PortEvent`s for the owner (`Node::port`); sync judges none of them (notes/client-port.md).

## Duties
Engine work sync drives, one `Effects` hook per kind over what makes it due, never polled (`life`, the last module of each settle round; spec rule per duty):
- **Role duties** (spec/permissions.md §2 Finalize, §3 Required rotation, Lost access): first, per actor the engine holds secrets of, one `Effects` key over `Engine::role_duty_due` (derived from the state, notes/engine-lost-access.md Owed role commits): `Engine::ensure_rotated` writes what this node owes before it next encrypts there (the finalize of a grant past its `until`, a departure's rotation, a stale box's), logged as own commits by the next round. Then `Engine::role_duties` (the lost-access drop) runs when `role_duties_due` settles true: the engine's durable work list (targets of role commits applied from elsewhere, due now; targets with an `until` ahead, due then) read with the memo clock up to its first entry, so an `until` passing with nothing written wakes the node (`clock_next`). The wrap gate (`Engine::wrap_secret`) refuses to encrypt meanwhile: under a blocked epoch, or while a grant this node may finalize is past its `until`, so a write made before the duty ran waits for the rotation. Losses by an `until` alone wait for their labels to be heard out: issues/sync-unbuilt.md. Where the drop will wait for "the loss stands" (a pass of the lost thing's sync IDs after the cause, Fathom's rule, its own branch): the Due scope of `rotation::lost::drop_scope`, which decides per actor whether to drop now or leave it to sync.
- **Lifetimes** (spec/commits.md §5 Lifetimes): `Engine::judge_lifetimes` runs when `lifetimes_due` moves (its work rows or the rights mark, stamped) and says work is due, or when a thing is held and a sync ID synced here was newly heard out since the last judgment (`held` true then). A group is heard out when every sync ID synced of it is (`Status::heard_out`, the stricter reading of the spec's "a source caught up": every unrefusing source caught up), a sync ID no peer shares (`Opens::shared`: no connection has it open, no kept record lists it) at once; a group with none is at once, so a thing under no synced group, or a node alone, is judged at once, and while a sharing peer is away nothing under what it shares is released. The osis handle does not judge on its own: one caller.

## Failures
- A step that fails (a store failure) sends nothing it queued, closes every connection and restarts the modules from the store, once per stretch until a durable commit of either store lands; the next wakes back off from `RETRY_FIRST_MS` (1 s) doubling to `RETRY_MAX_MS` (60 s). The store's memory part (ephemeral entries) stays. A frame of the failed step might tell of what the failure undid (an Applied of a cursor not stored, a record answered but not written), so none goes; peers see a dropped connection, which every rule survives.
- The engine reading its store again (`Engine::loads` moved: a write of unknown outcome, or a drop that forgot things: lost access, a self-removal placed, unsyncing) replaces every index the modules follow (memo stamps, feeds). One rule for each: the settle ends after the round it happened in, and the step closes every connection and restarts the modules as at an open. Leave finds a sync ID still waiting to stop at a restart as at a start (out of the sync set, its entry still synced).
- Modules' effects are not durable (but opens' `changed_at`), so a start or restart settles every key once: the same reload spec/sync-judgement.md §3 names for forgetting.

## Dials (`driver/dials.rs`)
Candidates, reasons as priorities, the one retry rule (`REDIAL_MS` 30 s, quiet candidates waiting for a change), `max_peers` (`MAX_PEERS` 32 by default), `DISCOVERED_KEEP` (1024) and the pair rule's held dials: the module doc. Sources of candidates: `Engine::dial_peers(s)` per S this node syncs (`set::SyncsFollow`, then `Effects`, notes/sync-facade.md), `Inbox::dial_hints` (read whole each step, O(hints)), `SyncConfig::dial`, discovery (`Input::Discovered`). Unbounded candidate counts from hostile dial lists: issues/sync-dial-amplification.md.

**Keep or close**: a dialed connection closes when `Opens::idle` (no member, nothing of opens under way), `!Inbox::may_deposit` and `Session::quiet` all hold; its candidate is dialed again after a change. A served connection is never closed for sharing nothing (spec/sync-transport.md §5). Each step reads the dialed connections, at most `max_peers` sharing ones plus those about to close.

## Links
`Links { dial, send, close, wake }` is all a node needs of the world. `TransportLinks<T: osis_transport::Transport>` (`driver/links.rs`, behind the default `driver` feature, tokio) is the product's: dials, listeners, discovery, each link's bytes and what the transport took, turned into `Input`s (`TransportLinks::next`); the osis handle's driver task steps the node on them. Tests use a `Links` per node over an in-memory fabric (the harness; `internals::ManualNet` in the osis tests). Sync never learns how a peer is reached: a connection is its key, its rank and its bytes.

## Reasons
- One sans-IO step with one place outputs are carried out: an older wake overwriting a newer nested one once left a node that never ticked after a restart; with `apply` alone carrying out outputs, in order, no call path can reorder them.
- No hook, callback or queue from the engine to sync: a queue sync must drain is state two owners write; memos and `Effects` give the same change-driven work with one owner per value.
