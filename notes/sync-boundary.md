# Sync boundary: the interface between the engine and the new sync, and what the engine keeps, replaces and deletes
> Summary: Phase 2 of issues/sync-rewrite.md. Interface half: the osis-sync crate's modules (owner-facing Rust signatures, state, dependencies), the sans-IO step and its one place of outputs, what sync calls on the engine (one facade, each call marked keep / replace / new), what the engine gives as `osis_base::memo` values with effects on change (and the `Effects` mechanism that makes work proportional to change), why kept unread needs nothing about what S carries, the osis API calls reimplemented or changed, and the engine and base changes proposed for Fathom. Inventory half: every pub item only old sync uses, marked delete / keep / replace with its reason.

**Principle:** the engine owns plaintext and every judgement of what a thing carries; sync owns ciphertext, connections and what peers showed. Sync reads the engine through one facade of memo-backed queries and a few commands (`osis_engine::sync`); the engine calls nothing of sync's (no hook trait, no callback, no queue sync must drain).

Judged against spec/sync.md and its area files, spec/wire.md §11, notes/sync-rewrite-inputs.md (For implementers), notes/sync-test-harness.md (the seam) and issues/derived-state-recomputed.md. Names of engine items are as of fd712b177.

## Crate layout
- **`osis-sync`** (core/sync) replaces osis-node (old sync plus re-exports of the engine) and osis-host (the hub store, rebuilt as `store` below). osis depends on osis-sync and osis-engine directly. The tokio driver sits behind osis-sync's default `driver` feature (the one feature set; osis-node has it today).
- **osis-proto** keeps the codecs below sync (`frame`, `hello`, `prove`, `filter`, `relay`); its `msg` is rewritten to spec/wire.md §11.2 by the session owner; `session`, `store`, `window` go.
- **`osis_sync::types`** holds every type two modules share, so each module builds against it and its own section's types alone; a type one module owns and others only read (`Member`, `Proven`, `Known`, `Verdict`, `StatusView`) is in that module:
```rust
pub struct ConnId(pub u64);                    // dialed: numbered by the node; accepted: by its Links, ConnId::ACCEPTED set
pub struct NodeKey(pub [u8; 32]);              // a peer's authenticated static key (a dialer's is ephemeral)
pub type Position = u64;                       // a node log position
pub type Cursor = Vec<u8>;                     // an opaque node-log cursor
pub use osis_engine::sync::{Holding, Path, Wrap};   // Holding { Read, Unread }: spec/sync.md §3, per (node, S)
pub use osis_store::RecordId;
pub enum SourceClass { Store, Reader }         // spec/sync-opens.md §4
pub enum Credential { ReadSecret(Epoch), SyncKey, SyncProof, Claim, Static([u8; 32]), Deposit, J }
pub struct Entry { pub blob: BlobId, pub wrap: Wrap, pub stamp: Option<Signature>, pub deposited: bool, pub own: bool, pub role: bool, pub class: Class, pub expires: Option<WallMs> }   // role: signed under the role-entry domain
pub enum SourceEvent { Present(Entry), Gone(BlobId), Head(Step), Full(bool), Refused(BlobId, Code) }
pub enum Input { .. }                          // The step, below
pub enum Out { Send(ConnId, Vec<u8>), Dial(ConnId, Address), Close(ConnId), Wake(WallMs) }
pub enum Scope { All, Thing(Tid), Deliveries }
pub enum Waiting { Done, Pending, Never(&'static str) }
pub struct Cx<'a> { pub engine: &'a mut Engine, pub store: &'a mut Store, pub now: WallMs, pub rng: &'a mut dyn NodeRng, pub out: &'a mut Vec<Out> }
pub enum Error { NotBuilt(&'static str), Engine(osis_engine::Error), Store(osis_store::Error), Proto(osis_proto::Error) }
pub struct SyncConfig { pub key: Option<NodeKey>, pub dial: Vec<Address> }   // own dialable key; configured dial candidates
```
  A part not built returns `Error::NotBuilt(name)` or does nothing; no path a test reaches panics.

## The step
```rust
pub enum Input { Up { conn: ConnId, peer: NodeKey, rank: u8, dialed: bool, listener: NodeKey }, Bytes { conn: ConnId, bytes: Vec<u8> }, Taken { conn: ConnId, bytes: u64 }, Closed { conn: ConnId }, Down { conn: ConnId }, Tick { now: WallMs }, Wrote }
impl Node {
    pub fn open(engine: Engine, store: Store, cfg: SyncConfig, rng: Box<dyn NodeRng>) -> Result<Node>;
    #[must_use] pub fn handle(&mut self, input: Input) -> Vec<Out>;
    pub fn engine(&mut self) -> &mut Engine;          // the osis handle's writes and reads
    pub fn status(&self) -> Arc<StatusView>;          // as of the last step (Status below)
    pub fn wait(&mut self, scope: Scope) -> Waiting;  // Done | Pending | Never(why)
}
pub trait Links { fn dial(&mut self, conn: ConnId, to: &Address); fn send(&mut self, conn: ConnId, bytes: &[u8]); fn close(&mut self, conn: ConnId); fn wake(&mut self, at: WallMs); }
pub fn apply(out: Vec<Out>, links: &mut impl Links);   // the one place outputs are carried out
```
- `handle` routes the input to its module (bytes: `Session::receive`, then each message to the module `Incoming::to` names; a message no module takes closes the connection), then **settles**: every module's `settle` (each returns `Result<bool>`, whether it acted) in the order store, unread, opens, read, inbox, streams, status (opens first among the sending modules, so the others act on this round's shared set), again while one acted, then collects sessions' bytes and the earliest wake (each module's `next_wake`, `Engine::next_timer`, the memo clock's next `until`). A settle error closes every connection (a store failure's reopen is the driver's).
- **Sending**: the driver owns every `Session` in one `session::Sessions`; each entry point and `settle` of a module that sends (opens, streams, read, inbox) takes `&mut Sessions` and sends on the connection it acts on. Nothing is sent from outside a step.
- **Members moving**: opens reports each member that joins or leaves a connection's shared set as a `Moved` (out-parameter of its `on_message`, `on_closed` and `settle`); the driver hands each to `Streams::moved` at once. Opens never calls streams; streams never diffs the shared set.
- **The settle loop ends** because `acted` means only that a module changed something another reads (a store row, an engine write, a member moved), each an `Effects` value moving to a new settled value; a round runs again only while values move. Two modules undoing each other's acts would loop forever in one step: nothing in the product bounds it, and the harness fails a step past `ROUND_CAP` rounds (`Node::rounds`, tests only).
- `apply` carries out sends and dials in the order made, then closes (a closing node's owed Applied goes first, spec/sync-streams.md §4 Reports), then one `Links::wake`, the earliest given. A step gives at most one `Wake`, last, and `Links::wake` replaces the node's earlier one, so no older wake overwrites a newer (an early wake costs one idle `Tick`). Only `handle` makes outputs: `status` and `wait` read.
- The node's time is its engine's clock; `Tick { now }` says a wake came due (`now` moves it forward only).
- **No engine events as input.** After the osis handle writes it calls `handle(Wrote)`, which only settles: what the write changed reaches sync through the memos it moved. `Engine::subscribe_durable` stays for the API's listeners only.
- A store failure closes every connection and reopens the node from the store (inputs note, store-reopen); the effects' acted values are not durable (but `changed_at`, below), so a start or reopen settles every key once: the same reload spec/sync-judgement.md §3 names for forgetting.

## Modules
Each module is a `Clone` struct (world copies: `Node::test_copy`) owning its state, with `fn settle(..) -> Result<bool>`, `fn next_wake(&self) -> Option<WallMs>`, and the entry points below. A module calls another only through the read accessors listed; it changes another's state never (one owner per row). Dependencies are acyclic in this order.

**1. `session`: wire and session** (spec/wire.md §11.1-§11.2, spec/sync-streams.md §1-§2, spec/sync-opens.md §1 Dial timeout and §2, spec/sync-transport.md §1). Pure: messages in, frames out; time comes in inputs. State: per connection, in memory: Hello and the challenges, proofs shown and proven, request ids and their send order, the window, the stall clock, unanswered-in bytes, bytes written and taken, clock samples; per dial not up, its deadline. Depends on osis-proto and the engine's proof calls (`provers`, `own_node_key`, `own_node`, `key_open`, `known_actor`, `account_tid`, `prove_rotations`, `take_rotations`).
```rust
impl Session {
    pub fn new(conn: ConnId, peer: NodeKey, dialer: bool, rank: u8, listener_key: NodeKey, cx: &mut Cx) -> Session;  // queues Hello; listener_key: `Input::Up`'s `listener` (the key dialed, or the key of the listener that took it)
    pub fn receive(&mut self, bytes: &[u8], cx: &mut Cx) -> Result<Vec<Incoming>, Close>;   // Hello, Prove/Proved, Ping/Pong run here
    pub fn request(&mut self, by: To, m: Msg) -> RequestId;   // id chosen here (top bit for kinds 19, 36-41; NoRecord 2^31); sent in order while under WINDOW; the answer goes to `by`
    pub fn answer(&mut self, to: RequestId, m: Msg);
    pub fn push(&mut self, m: Msg) -> bool;           // false: untaken bytes past REPLY_BUDGET, the pusher waits (retries at a later settle: `Input::Taken` steps the node)
    pub fn proven(&self) -> &Proven; pub fn proofs_done(&self) -> bool; pub fn proved(&self) -> &[Tid];
    pub fn binding(&self) -> Option<&Binding>;        // both Hello challenges and the listener's static key: Resume tags, Hits, open signatures, pair keys
    pub fn clock_offset(&self) -> Option<i64>;        // diagnostic (status)
    pub fn taken(&mut self, total: u64, now: WallMs); pub fn deadline(&self) -> Option<WallMs>; pub fn take_bytes(&mut self) -> Vec<u8>;
}
pub enum Incoming { Proved, Request(RequestId, Msg), Reply(To, RequestId, Msg), Push(Msg) }
impl Incoming { pub fn to(&self) -> Option<To> }   // To { Opens, Streams, Read, Inbox }: requests and pushes by kind, replies to the module that asked; the client port's to none
impl Sessions { get, get_mut (marks the session touched), conns, set_now, dialing, tick(now) -> Vec<(ConnId, Close)>, next_wake }   // the driver's: insert, remove, taken, take_sends
pub struct Proven { pub account: Option<(CreationRecord, [u8; 32])>, pub key_actors: BTreeMap<Tid, [u8; 32]>, pub node: Option<Tid> }   // account()/actors(); the key: `key_open` judges it again, a static entry is checked against a key actor's
pub struct Binding { pub dialer_challenge: [u8; 32], pub listener_challenge: [u8; 32], pub listener_key: [u8; 32] }
pub struct Close(pub &'static str);
```
- **Replies by asker, requests by kind.** A Shared may answer opens' Hits or inbox's Deposit items, a Status read's Delete: only the asker knows. Requests: Resume, Beacons, Offer, Lost, NoRecord, Digest, Members to opens; Pull, Fetch, Stream, Applied to streams; Register, Delete, Stranded, Suspect to inbox. A reply of a kind that does not answer its request (`osis_proto::msg::answers`) is dropped.
- **Skipped**: Pulls and Fetches are answered in order; one still out when a later one's answer arrives reaches its module as `Reply(.., Error 14)` (a Pull) or an empty `FetchReply`, so streams has one path for refusals. Every Fetch takes a top-bit id.
- **Deadlines**: `STALL_TIMEOUT_MS` (2 min) from the oldest request's last move, or from Up while the peer's Hello has not come; `DIAL_TIMEOUT_MS` (the same) from `Sessions::dialing`. Kept in one ordered set, refreshed only for sessions a step touched (`take_sends`), so a step's work is in proportion to the connections it reached. A world with no request out has no wake: `PINGS` (3) Pings by the dialer only, one at a time, then none.
- **`Input::Taken { conn, bytes }`**: the transport took that many bytes of the connection in all (`osis_transport` link's `taken`); the push rule and the stall clock need it. The harness answers each send with it at once.
- **Hostile peers**: memory per connection is bounded by constants (one partial frame, `UNANSWERED` of the peer's requests, unwritten bytes past `CLOSING` plus this side's in flight close it, checked as bytes arrive: what this side writes otherwise is its own window and pushes). The stall clock catches stuck peers, not hostile ones: a peer trickling a reply to the oldest request, or a small push every few minutes, holds its own connection, as does a dialer that sends Hello and nothing more (a served connection is never closed for silence, spec/sync-transport.md §5); each holds only its own connection at that bounded cost.
- Not built: the account's rotations in a Prove (`Engine::prove_rotations` and `take_rotations` return NotBuilt: none sent, those received not taken); the node-wide bound on what served connections hold (spec/sync-transport.md §5 Served connections: requests waiting for the bound's room, reading paused, the largest holders closed), which needs `Sessions` to hold answers back.
**2. `opens`: records, agreement, the shared set** (spec/sync-opens.md §2-§6, spec/sync-ids.md §6 Walk). State: records (durable, in the store's record rows, `RECORD_BUDGET` LRU), per connection the members, filter generations sent and received, Offer in flight, walk state; `changed_at` per S (durable). Depends on session, store, unread (its credentials), engine (J, credentials, known actors).
```rust
impl Opens {
    pub fn on_message(&mut self, cx: &mut Cx, sessions: &mut Sessions, unread: &Unread, conn: ConnId, m: Incoming, moved: &mut Vec<Moved>);  // Proved (Resume / NoRecord, then Digest), Resume(d), Digest, Members, Beacons, Offer, Shared, Lost
    pub fn on_closed(&mut self, cx: &mut Cx, conn: ConnId, moved: &mut Vec<Moved>);   // each member Left; the record keeps them
    pub fn members(&self, conn: ConnId) -> &BTreeMap<SyncId, Member>;
    pub fn record(&self, conn: ConnId) -> Option<RecordId>;     // where streams, read and store keep their per-peer rows (none: no record kept)
    pub fn agreed(&self, conn: ConnId) -> bool;                 // streams' Pull gate (§3 Agreement)
    pub fn on_reported(&mut self, cx: &mut Cx, sessions: &mut Sessions, unread: &Unread, reported: &mut Vec<Reported>, moved: &mut Vec<Moved>);  // streams' reports folded into `Positions`; an ended member at its until closes with Lost
    pub fn reported_at(&self, conn: ConnId, s: &SyncId) -> Option<&(Position, Cursor)>;   // a member's reported position (none: no member)
    pub fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, unread: &Unread, moved: &mut Vec<Moved>) -> Result<bool>;
}
pub enum Moved { Joined(ConnId, SyncId, Rejoin), Left(ConnId, SyncId), Until(ConnId, SyncId) }   // Left: closed, or the connection ended; Until: `until` set or cleared
pub enum Rejoin { Held, From(Option<Cursor>) }   // where a joining member reads the peer's log: as this side's stream holds it, a Lost's cursor, or the start (a digest difference)
pub enum Reported { Stream(ConnId, Position, Cursor), Member(ConnId, SyncId, Option<(Position, Cursor)>), Merged(ConnId, SyncId) }   // streams' word (it serves)
pub struct Positions;   // per connection: the stream's reported position and each joining member's own, so a report costs O(1) and an Applied checks only ended members
pub struct Member { pub class: SourceClass, pub by: Credential, pub until: Option<Position>, pub step: Option<StepId> }
pub trait Wire { fn bind(&self, c) -> Option<(Bind, Proven)>; fn request(&mut self, c, m: Msg) -> Id; fn answer(&mut self, c, to: Id, m: Msg); fn push(&mut self, c, m: Msg); fn close(&mut self, c, why) }   // Sessions; a test's Pipe
pub trait Holds { .. }   // what the node holds per S (Creds: shows, tests, step), the actors a Proven counts for now (account while `key_open`), known actors, J; NodeHolds over the engine and unread; a test's Table
```
The core (`Opens::message`, `tick`, `closed`) runs over `opens::Ctx { holds: &mut dyn Holds, wire: &mut dyn Wire, now }`, so the rules run against scripted peers (core/sync/tests/it/harness/scripted.rs) before the session and the engine facade are built. Session gives opens `binding` (both Hello challenges, the listener's static key), `request` (ids chosen there), `answer`, `push_now` (Digest and Members never wait for room) and `close` (the driver closes a connection a module marked after its message).

Settle: `NodeHolds::due` follows `sync_set` and, per S of it, the digest of its credentials (from the engine's `read_credentials(s)` or unread's `credentials(s)`) as `osis_base::memo::Effects`; a moved value advances `changed_at(s)`, re-judges members of S on the connections holding it (`holding`), and makes a filter addition and a test due on each connection. The durable `changed_at` row keeps the digest of the value it was advanced for, so a restart advances it only for a value that moved. The Hits index (expected peer Hit to S and credential) is built at a connection's first Hit, then kept per changed S, so a reconnect the peer Hits nothing on costs nothing per sync ID held.

What the integration wires (opens' rules hold only with all of it):
- `Creds::roles`: a digest of S's roster (what moves J). `node_creds` leaves it zero, so a removal without a rotation re-judges nothing (a J open outlives it): the facade must give it (e.g. in `ReadCredentials`).
- `node_creds`, read: the sync proof of the newest recorded step (shown), and the walk's tests (sync keys of the recorded steps deepest first, claims, statics claimed: spec/sync-ids.md §6); `ReadCredentials` carries neither. Unread: `Tested::SyncKey` of the head besides the proof.
- `Holds::due` must also report a change of known actors (contacts, rosters), else the audience (§4) and records' named actors are judged only at the next generation or connection.
- `NodeHolds` stubs: `until`, `cursor_at`, `grant`, `take_grant`, `behind`, `deposit`, `verify_steps`, `step_creds`: each answers as if nothing were held.
- Records and `changed_at` in the store's rows (durable, in the step that changes them), `RECORD_BUDGET` eviction counting the peer's stored filter (up to 2^22 entries, held in memory now with no bound but the format's).
- One connection per pair (spec/sync-opens.md §1) before a record is taken: two live connections taking one record share its members.
- `resync_ms` as one value for opens, streams and inbox.

**3. `store`: the store per sync ID** (spec/sync-ids.md §5-§6, spec/sync-streams.md §3, spec/sync-inbox.md §3 Deposits, spec/sync-judgement.md §4 stand state). State: entries, tombstones, blob bytes once per node, paths (steps, claim sets), the node log (osis-store `nodelog`, with a per-sync-ID index so a join costs that sync ID's events), usage per sync ID against the caps and the deposit budget, peer-budget charges, the stand rows a source's record keeps for `read`; ephemeral entries, their tombstones, bytes and the log's memory part in memory. Implements `osis_store::CipherHost`, so the engine stores and reads blob bytes through it: `Store` is a cheap handle over one locked store, held by the engine's ciphertext door and by `Cx`; the engine locks it only inside its own transactions, sync only between engine calls, so one step never holds both. Every operation is one transaction of the underlying store (crash safety is its), and every row change stamps. Learns its holdings from `Engine::sync_set` and its caps from `Engine::caps` in `settle`. Depends on osis-store, osis-label crypto, osis-proto's codes and items. Decrypts nothing.
```rust
impl Store {   // Clone: a handle
    pub fn open(backend: Box<dyn Backend>, root: Box<dyn RootStorage>, rng: Box<dyn NodeRng>) -> Result<Store>;  // drops what record-less connections brought
    pub fn cipher(&self) -> Arc<dyn osis_store::Ciphertext>;           // the engine's ciphertext door
    pub fn with_tx<T>(&mut self, f: impl FnOnce(&mut Transaction) -> osis_store::Result<T>) -> Result<T>;  // other modules' rows: records, changed_at
    pub fn set_sync_set(&mut self, set: &SyncSet); pub fn set_caps(&mut self, caps: &Caps);   // settle calls both
    pub fn holding(&self, s: &SyncId) -> Option<Holding>;
    pub fn entry(&self, s: &SyncId, b: &BlobId) -> Result<Option<Entry>>;
    pub fn entries(&self, s: &SyncId) -> Result<Vec<Entry>>;          // durable then ephemeral (memo-safe)
    pub fn deposits(&self, s: &SyncId) -> Result<Vec<Entry>>; pub fn all_deposits(&self) -> Result<Vec<(SyncId, Entry)>>;  // the deposited index (`D/`)
    pub fn entry_feed(&self) -> Feed<(SyncId, BlobId)>;   // entries added, or whose wrap, stamp or deposited flag changed
    pub fn blob_len(&self, b: &BlobId) -> Result<Option<u64>>;
    pub fn bytes(&self, b: &BlobId) -> Result<Option<Vec<u8>>>;
    pub fn tombstone(&self, s: &SyncId, b: &BlobId) -> Result<Option<Tombstone>>;   // { at, deleted, note }
    pub fn usage(&self, s: &SyncId) -> Result<(Usage, Usage)>;        // durable, memory
    pub fn head(&self, s: &SyncId) -> Result<Option<Step>>; pub fn path(&self, s: &SyncId) -> Result<Option<Arc<Path>>>;
    pub fn log(&mut self, s: &SyncId, e: Entry, bytes: Option<Vec<u8>>, from: Option<Source>) -> Result<Code>;  // own judgement
    pub fn drop_entry(&mut self, s: &SyncId, b: &BlobId, note: Vec<u8>) -> Result<bool>;   // tombstone with what it was
    pub fn lift_tombstone(&mut self, s: &SyncId, b: &BlobId) -> Result<bool>;
    pub fn uncharge(&mut self, s: &SyncId, b: &BlobId) -> Result<()>;   // it gives something held: off the peer budget
    pub fn serve_path(&mut self, s: &SyncId, p: &Path) -> Result<()>;  // a read S's head, from sync.0
    pub fn take_stamped(&mut self, s: &SyncId, e: &Entry, bytes: Vec<u8>) -> Result<Code>;   // kept unread pulling
    pub fn take_deposit(&mut self, d: &osis_proto::DepositItem, from: Option<Source>) -> Result<Code>;
    pub fn take_delete(&mut self, s: &SyncId, items: &[DeleteItem], by_store_credential: bool) -> Result<Vec<Code>>;
    pub fn take_register(&mut self, s: &SyncId, step: &Step, claims: Option<&ClaimSet>) -> Result<Code>;
    pub fn behind(&self, s: &SyncId, named: Option<&StepId>, cred: &Cred, max_steps: usize) -> Result<(Code, Option<osis_proto::Grant>)>;  // signature verified by the caller
    pub fn read_log(&self, members: &BTreeMap<SyncId, Option<Position>>, from: Option<&Cursor>, max: usize) -> Result<LogRead>;  // each member and its `until`
    pub fn read_sync(&self, s: &SyncId, until: Option<Position>, from: Option<&Cursor>, max: usize) -> Result<LogRead>;   // a join
    pub fn read_memory(&self, s: &SyncId, after: u64, max: usize) -> (Vec<(u64, BlobId, bool)>, u64);   // the log's memory part
    pub fn shred(&mut self, s: &SyncId) -> Result<()>;            // leaving: every row of S, S in every record, one transaction
    pub fn gone(&mut self, src: Source) -> Result<()>;            // a connection closed (the driver) or a record dropped (opens, with `records_evict`'s ids): what was charged to it and still gives nothing held goes
    pub fn stand(&self, src: Source, s: &SyncId, body: &[u8]) -> Result<Option<Stand>>; pub fn set_stand(..);  // read's §4 rows
    pub fn saw_deleted(&mut self, src: Source, s: &SyncId, b: &BlobId) -> Result<()>; pub fn seen_deleted(..) -> Result<bool>;
    pub fn settle(&mut self, engine: &mut Engine, now: WallMs) -> Result<bool>;   // not over Cx: Cx holds the store
    pub fn settle_at(&mut self, now: WallMs) -> Result<bool>; pub fn next_wake(&self) -> Option<WallMs>;
}
pub enum Source { Record(RecordId), Conn(ConnId) }   // who brought an unstamped entry; where its charge and stand rows live
pub enum Cred { Sync(VerifyingKey), Claim([u8; 32]), Signing(VerifyingKey) }
```
`settle` expires entries (no tombstone, no event), ends tombstones and aged stand rows after `TOMBSTONE_LIFETIME`, drops claim sets superseded for `ROLE_KEEP`, sweeps the log's deletion events, and lets the unread sync ID using most give way past the total cap. Caps (`Policy`, read from `caps^.0`'s `policy` by field name, per-thing caps replacing `entries`/`bytes`) apply to sync IDs kept unread only; role entries count toward none; the deposit budget is the policy's raised to `osis_proto::limits::deposit_budget`. A record's rows for other modules use osis-store's `record_put_row(id, tag, sync_id, key, value)` (one tag per owning module: store `b` charges, `s` stands, `d` deletes seen), gone with the record or with the sync ID. What bounds what peers make the store keep: a Delete of an entry not held writes nothing (so tombstones never outnumber what was held); unstamped entries a peer brought, by its peer budget (`log` and deposits alike), going with its connection or its dropped record (`gone`); a record-less connection's stand and delete-seen rows live in memory and age out after `TOMBSTONE_LIFETIME` like a record's; deposits per sync ID by the shared deposit budget, which any holder of the deposit key can fill until a delete-key holder clears (spec/sync-inbox.md §4).

**4. `read`: judgement for read sync IDs** (spec/sync-judgement.md §1-§5, spec/sync-compaction.md §1). State: four `Effects` (bodies per commit; the own judgement per (S, commit): verdict and own-store acts; what a body calls for per (S, commit, source keeping S unread); the destruction per S), a memo `Clock` (expiries move judgements; `next_wake`), and stamped maps (verdicts, own role commits S must hold, S told destroyed); stands live in the store's record rows (head and fall mark). Reads through `read::Ground`; `read::Live` implements it over `Cx`, opens, streams and sessions. Model: NetHold.tla, NetDestroy.tla.
```rust
impl Read {
    pub fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, streams: &Streams) -> Result<bool>;
    pub fn settle_on(&mut self, g: &mut impl Ground) -> Result<bool>;   // tests: a fake ground
    pub fn verdict(&self, s: &SyncId, c: &CommitId) -> Option<Verdict>;   // for status and inbox
}
pub enum Verdict { Must, May, MustNot(Why), Unjudged }
```
Judges to a fixpoint, then acts on what a new judgement adds: a restart or a reconnect (a new `ConnId` in each act) carries each act out once more, never in a loop; logging again is bounded by the durable stand alone. Own store: logs must-hold bodies with no own entry while a reader can pull S (a held blob verbatim, else `seal_body`), drops entries must-not-hold or covered and dropped (no delete key; never a must-hold one), lifts own tombstones of a body missing again. Toward each source keeping S unread, keyed by what its stream wrote (`seen_added`) and, where this node is no writer at its head, every must-hold body: deletes (its head's delete key; carriers in its `known`, a full source counting one it lacks; duplicates by delta set and copy; never a body dropped as invalid), deposits, logs again once per ground, deletes and loggings again waiting on role entries first. Destruction: told (sticky); emptying deletes at a source holding every request or past their expiry; forgets once every source is heard out with nothing known, at once with no delete key, or untold past the requests' expiry (deleting nothing). Work per change: a source's event judges that body at that source; a reader source joining judges nothing; a writer's store source joining judges what its stream shows; a non-writer's, each must-hold body (counted at n and 10n sources in `read::work_follows_sources`).

**Before read runs in a node** (each `Live` call answers `NotBuilt` until it lands; read does nothing meanwhile):
- Engine: a `Feed` of commits held (`commits_added`); the facts beside `BodyFacts` (`read::Facts`: must-not-hold the engine alone judges (purged, strict subset, superseded or ended card), own, role, carriers per delta, later snapshots not held (with whether judged invalid), §3 Neither, missing again); `sole_certificate`, which the facade leaves false (it needs the author's other blobs under S from the store); `closure_settled(s)` (no group of S's closure holds its `group.0` part only as a header); a held blob's parts and copy flag (`blob`, `None` once its bytes are dropped); a fall mark summed over a body's aspects (the facade's is per aspect). `body_facts.kept` and `covered` must move with the memo clock when a keep bound passes. `destruction(s)` must map a destroyed thing's kept sync IDs (`Destruction::sync_ids`), not `sync_set`, and list purge requests on `created.0` beside `released.0` ones.
- Store: entries and tombstones by (S, commit) (`own`, `own_tombstones`); a held blob of a commit not tombstoned under S, logged verbatim under a wrap for S (`log_own(.., false)`; the wrap needs the blob key from the engine); deletes seen per S (`deletes_known`).
- Opens: one source's view per (S, source), stamped (`source`), and a feed of views written (`sources_added`); `full` and `role_unheld` from streams.
- Streams: `known` by (source, S, commit) with deletes seen (`seen`), a feed of rows written (`seen_added`), present at some source (`present_anywhere`), whole per source (`seen_all`).
- Status: heard out (`heard_out`). Engine or opens: pullable (`reach.0` published or a connection sharing S).
- Inbox: Deposit items (`deposit`: relay under the own entry's stamp when the head write key verifies it, else a fresh `seal_body` encryption).
- Integration tests: HN_fallany (a snapshot arriving invalid moves the fall mark as one held valid falling does) lives in the engine's `fall_mark`, untested by read; level-key deletes (freed links, spec/sync-compaction.md §1) and a peer's entry counting as lacking for its wrap (Duplicates, spec/sync-ids.md §6 Wraps) are not built in read.

**5. `unread`: judgement for kept-unread sync IDs** (spec/sync-judgement.md §6, spec/sync-set.md §3). State: per S kept unread its `Kept` (stranded, credentials), stamped for opens and status; stamped projections of the three engine values. Nothing durable of its own (the sync record is the engine's, the head is the store's). Reads through `Ground` (engine `sync_set`, `sync_records`, `removal_notices`, `drop_sync_record`; store `path`, own entries, `shred`; `Cx` implements it) and `Sources` (an own entry present at a source by its stream: streams implements it). Nothing else.
```rust
impl Unread {
    pub fn credentials(&self, s: &SyncId) -> Option<Arc<UnreadCredentials>>;  // head sync key, its proof, head deposit key (public), head claim set; None while stranded
    pub fn stranded(&self, s: &SyncId) -> bool;
    pub fn keeps(&self, s: &SyncId) -> bool;   // listed, or leaving and waiting for its own entries
    pub fn settle(&mut self, g: &mut impl Ground, sources: &impl Sources) -> Result<bool>;   // stop on a verified removal, strand on a head move, leave when unlisted
}
```
The engine values are whole maps: each is read through one `Effects` key and diffed on change into per-key stamped maps, and one `Effects` key per S reads those and the store's path of S, so a head move, box or notice judges its own S only (counted at n and 10n); the diff costs the map's size per change of it, which per-key facade values (a `Feed`) would remove. Until the facade's `sync_set` is built, `settle` does nothing. `impl Sources for Streams` answers false until streams builds `known`, so until then a node keeping S unread with own entries never leaves an unlisted S; streams makes tests/it/unread.rs `leaves_once_own_entries_held_at_a_source` hold on a real source. The facade's `RemovalNotice::recipient` is the blob's AD recipient, never a payload value: the removal signature binds it, so a notice to another recipient re-sealed here verifies nowhere.
**6. `streams`: streams and flow control** (spec/sync-streams.md §3-§6). Both sides serve (`serve.rs`: Pulls from the log filtered by the shared set now, pages by `max_reply`, joins in pages, ephemeral listings, pushes under `follow` with `seq`, Fetches, reported positions) and pull (`pull.rs`: one Pull out, received vs stored cursors, joins by generation, messages in hand applied in order once their bodies settle, gaps read again, bodies one source at a time in fill order, Full and Refused at a node keeping S unread). State: per connection serve and pull state; per source (`store::Source`: record, else connection) a `Place` (stored cursor, members at the stream, joins in pages, where members stopped); `Known` (stamped per (source, S, blob), per (S, blob) for `present`, per (source, S) for listing; heads, full, refusals per source). Not built: durability (in memory keyed by record, as opens' records; the integration list below), relay-only entries, the engine's `wants`, bundles, `Rank::Never` (the facade has no call for a keyset without history).
```rust
impl Streams {
    pub fn moved(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, m: Moved, reported: &mut Vec<Reported>);
    pub fn on_message(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, conn: ConnId, m: Incoming, reported: &mut Vec<Reported>);
    pub fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, reported: &mut Vec<Reported>) -> Result<bool>;
    pub fn closed(&mut self, conn: ConnId);                     // the driver, before opens reports the members left
    pub fn known(&self) -> &Known;                               // knows(src, s, b), present(s, b), list(src, s), head, full, refusal
    pub fn knows(&self, src: Source, conn: Option<ConnId>, s: &SyncId, b: &BlobId) -> bool;   // durable by record, ephemeral by the connection
    pub fn caught_up(&self, conn: ConnId, s: &SyncId) -> bool;
    pub fn import(&mut self, cx: &mut Cx, bundle: &mut dyn std::io::Read) -> Result<()>;   // NotBuilt
}
impl unread::Sources for Streams   // present(s, b): some source's stream showed it
```
The core runs over `streams::Ctx { store, ground: &mut dyn Ground, wire: &mut dyn Wire, shared: &dyn Shared, now, reported }` (`Ground`: `open`, `rank` from the engine; `Wire`: Sessions; `Shared`: opens' `members`, `agreed`, `record`, `reported`), so tests run two sides over real stores with scripted opens and engine (core/sync/tests/it/streams.rs). Reported positions go to opens (`Reported`, folded into `opens::Positions`) through the driver after each message, move and settle; streams reads them back through `Shared::reported`. Ended members are known by `Moved::Until`, so serving reads the shared set per event and checks `until` only for ended members: a push costs its events, not the members.

What the integration wires for streams (its rules hold only with all of it):
- Durable in the source's record, written in the transaction that applies what they cover (the engine's take of each body, `store::take_stamped`): `Place.cursor` (the stream's stored cursor), `Place.at_stream`, `Place.joining` (each join's cursor), `Place.stopped` (where a member that left stood), and `Known` for durable entries (presence per (S, blob), heads, `full`, refusals). Opens' records hold `stopped` (`Rejoin`) and the members; both modules' rows of one record are lost together (a lost record is a first contact). `Known` under `Source::Conn` (ephemeral entries, record-less peers) stays in memory.
- A record dropped (`RECORD_BUDGET`, `records_evict`) drops its `Place` and `Known` rows with it: streams has no call for it yet.
- `room` (entries refused for room) stays in memory: after a restart the node refuses again and tells `full` again.
- Remaining costs in O(members): a Pull's reply builds the members map (per Pull: joins, gaps, pages, not per event); `inline_check` scans a connection's members when a member gains or loses a source; every connection's ephemeral listing reads each listed member's memory part when any ephemeral entry moves (issues/streams-ephemeral-scan.md).
**7. `inbox`: inbox, deposits, steps and Register** (spec/sync-inbox.md, spec/sync-ids.md §6 Steps and Register). Parts: `deliveries` (inbox blobs owed: logged stamped by a writer of the inbox, else deposited and offered; sealed again at the blob's expiry, a timer per delivery, or when the inbox moved; stopped once seen taken, by the engine's commit sign or an open of a named sync ID with the recipient proven), `offers` (Deposit items: one out per connection, refused for now backed off, one taken ends the others' back-off at that peer and S, 14 parked until the deposit key moves or the next filter), `held` (every entry through the store's entry feed: inbox blobs taken and stamped in place, deposits promoted, own deposits offered to store sources, clearing past `DEPOSITS_WAITING`), `register` (recorded steps after a store source's step, each once its stream showed the step's role commits), `serve` (Register, Delete, Stranded, Suspect), `links` (redeem kept durably until the join is held elsewhere). Durable: store rows `I/d/` (per delivery the blob sent and the open seen) and `I/r/` (links being redeemed, shredded). Seams: `inbox::Ground` (the engine calls it makes; `Eng` the product's) and `inbox::Net` (sessions, opens, streams; `Links` the product's), so tests/it/inbox.rs runs it on fakes over a real store.
```rust
impl Inbox {
    pub fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, streams: &Streams) -> Result<bool>;
    pub fn on_message(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, streams: &Streams, conn: ConnId, m: Incoming);  // requests Register/Delete/Stranded/Suspect; Shared and Register answers
    pub fn proved(&mut self, conn: ConnId, net: &impl Net);   // driver, on Proved
    pub fn moved(&mut self, m: &Moved, net: &impl Net);       // driver, beside streams
    pub fn on_closed(&mut self, conn: ConnId);
    pub fn redeem(&mut self, cx: &mut Cx, link: &ShareLink) -> Waiting;   // first contact
    pub fn dial_hints(&self) -> BTreeSet<DialHint>;          // the driver's dial candidates
}
```
Engine calls `Ground` needs beyond the facade's table (each `NotBuilt` in `Eng`): `delivery_names(c, holder)` (the sync IDs the blob names), `signers(s, actor)` (stamp, deposit and delete keys of S's head; the deposit key from `actor`'s seed for another's inbox), `blob_commit(s, b)` and `commit_blobs(c)` (the engine's blob-parts index, both ways: a promoter stamps one copy per delta), `log_chain(s, certs)` (a promotion's certificate copies: fresh encryptions, so through `seal_body`), `step_needs(s, step)` (the blob IDs of the role commits a step's epochs depend on). `held` calls `take_inbox` inside an `Effects` settle: the engine allows a write there (`Engine::run` inside a memo frame reads what its function reads), and a take that wrote what it read is judged once more and rests, so `take_inbox` must write nothing when judging again changes nothing (facade test owed). Reconciling with the facade (branch sync-facade): `deliveries` followed through `delivery_feed` (not a diff of the whole list); `take_inbox` returns `Option<InboxOpened>` with `commit: Option<CommitId>` and `osis_label::DialHint` (inbox's own `DialHint` goes); `inbox_of` without `Result`; `recorded_path` through `sync_owner` + `sync_ids`; `held_elsewhere(c)` is status's view, not the engine's (the facade's is a command); the hints `take_inbox` returns are followed by nobody yet (spec/sync-inbox.md §2 Following a payload sync ID). Not built: Stranded and Suspect are answered Ok and acted on by nobody (spec/permissions.md §4); clearing at sources keeping S unread (needs streams' `known` to carry each entry's deposited flag and blob size, and to stamp what it shows, as Register's needs presence does); a decline stamping in place; opens' members are not stamped, so a source's step moving reaches Register only through its next join.
**8. `status`** (spec/sync-status.md). State: complete passes begun per S; held-elsewhere reports (durable, kept while the entry is). Depends on opens, streams, read, engine.
```rust
impl Status {
    pub fn view(&self) -> Arc<StatusView>;   // as of the last settle; per S: sources and their state, passes waiting; idle
    pub fn wait(&self, engine: &mut Engine, scope: Scope) -> Waiting;
    pub fn settle(&mut self, cx: &mut Cx, opens: &Opens, streams: &Streams, read: &Read) -> Result<bool>;  // keeps the view; tells the engine of complete passes and own commits held elsewhere
}
```
**9. `driver`: the node, dials, timers, outputs** (spec/sync-opens.md §1, spec/sync-transport.md). State: connections and their sessions, dial candidates (`Engine::dial_peers` per S, configured addresses, discovery; grant hints and link sharers through `Inbox::dial_hints`, not read yet), redial times (quiet candidates wait for a change), dial timeouts, one connection per pair (opens). Keep or close: a dialed connection closes when `Opens::idle`, `!Inbox::may_deposit` and `Session::quiet` (a Ping that came back with no other frame before it) all hold; each step reads the dialed connections (at most `max_peers` sharing ones plus those about to close). Owns `Node`, `Input`, `apply` and `TransportLinks<T: osis_transport::Transport>` (tokio). Depends on every module. For Fathom's memo work: `Engine::provers` is read and sorted at every owner write (proves-once), O(actors this node proves for); it should be a memo value.

## What sync calls on the engine
One facade, `osis_engine::sync` (methods on `Engine`; its types are there too); every call that reads the store returns `Result` (shown below without it); every value-returning call is a memo, so a module reading it inside its own effect depends on exactly what the engine read. Marks name the inventory item it comes from: **keep** (as is, renamed for sync IDs), **replace** (reshaped from the named items), **new**.

| call | mark | from |
|---|---|---|
| **Ingest** | | |
| `fn open_entry(&mut self, s: &SyncId, blob: &BlobId, wrap: &Wrap, bytes: &[u8]) -> Result<Opened>` (the engine cannot name sync's `Entry`); `enum Opened { Commit(CommitId, Ingested), Linked, Inbox(InboxOpened), NotOpen, Bad }` | replace | `labeling::blobs::open_commit` + `apply::ingest`, `ingest_memory`, `put_blobs`: one call opens the wrap with a held read secret and takes what it holds |
| `fn ingest_relay(&mut self, bytes: &[u8]) -> Result<Option<EphCommit>>` (built) | keep | `ephemeral::signal::ingest_relay` |
| `fn wants(&mut self) -> Arc<Wants>` (built) | keep | `apply::reach::blob_wants` as a memo (pages and header lists before apply) |
| **Held parts and bodies** | | |
| `fn sync_bodies(&mut self, c: &CommitId) -> Arc<BTreeMap<SyncId, BodyMeta>>`: per sync ID of the sync set whose required set holds a body of `c`: its parts, expiry, order, copy or shared, certificate, header-only | new | `commit_bodies_under`, `label_bodies_meta`, `certificates`, `part_body`, `header_body` folded per commit |
| `fn body_facts(&mut self, s: &SyncId, c: &CommitId) -> BodyFacts` (`required`, `closure`, `dropped: Option<DropFor>`, `kept`, `covered: Option<bool>`, `sole_certificate`, `lasting_header`) | replace | `labeling::converge::Facts`, assembled in the engine; `classify` moves to `read` |
| `fn blob_parts(&mut self, b: &BlobId) -> Option<PartSet>` | keep | `Sealed::parts`, `OpenedBlob::parts`: strict subsets and duplicates are judged in `read` from the store's entries and this |
| `fn seal_body(&mut self, s: &SyncId, c: &CommitId, rng: &mut dyn NodeRng) -> Result<Option<(Sealed, Wrap)>>` (`seal` is the engine's own) | keep | `labeling::blobs::{seal, seal_to}`, the wrap for `s` included |
| `fn fall_mark(&mut self, thing: &Tid, ak: &Ak) -> u64`: falls of held parts on the aspect so far (durable) | replace | `take_fallen`, `take_fell`: the stand of spec/sync-judgement.md §4 compares marks |
| `fn own_commits(&mut self, s: &SyncId) -> Arc<BTreeSet<CommitId>>`: this node's commits and self-removals with a body under `s` | new | for held elsewhere (spec/sync-status.md §2) |
| `fn destruction(&mut self, thing: &Tid) -> Option<Arc<Destruction>>` (requests, by expiry alone) and `fn forget_destroyed(&mut self, thing: &Tid) -> Result<()>` (drops its secrets last) | replace | `retention::destroy::{emptying, emptying_things, labels_emptied, drop_destroyed_secrets, commits_keyed_by}` |
| `fn promotable(&mut self, s: &SyncId, c: &CommitId) -> Promote` (`Yes { chain: Certs }`, `NotYet`, `Never`) | replace | `author_chain`, `valid_parts`, `judged_valid` |
| `fn freed(&mut self, b: &BlobId) -> bool` (built) | keep | `retention::freed::is_freed` |
| **Keys and secrets for a sync ID** | | |
| `fn sync_set(&mut self) -> Arc<SyncSet>`; `SyncSet { ids: BTreeMap<SyncId, (Tid, Holding)>, unsyncable: BTreeSet<Tid> }` | replace | `set_syncing`, `labels_read`, `labeled_groups`, `Indexes::syncing`: the synced group's closure walked through read groups, filtered by held read or sync secrets (spec/sync-set.md §2) |
| `fn sync_ids(&mut self, thing: &Tid) -> Arc<Vec<OwnedSyncId>>`; `OwnedSyncId { id, path: Arc<Path>, hint: bool }` | replace | `labels_of`, `group_labels`, `GroupLabel`; `hint`: held while the node holds no sync secret of the thing's own (spec/sync-ids.md §4) |
| `fn read_credentials(&mut self, s: &SyncId) -> Option<Arc<ReadCredentials>>`: the recorded path's newest step, the role keys held per recorded step (sync, write, delete, deposit, established), current read secrets, static entries of S's roster | replace | `HeadKeys`, `labeling::blobs::head_keys`, `deposit_seed`, `labeling::judge::static_listed` |
| `fn claim_key(&mut self, s: &SyncId, step: &StepId) -> Option<SigningSecret>` | new | the claim key from the node's own read KEM key and the step key |
| `fn open_entry_box(&mut self, s: &SyncId, step: &Step, entry: &[u8; 32], sealed: &[u8]) -> Result<Option<EntryBoxSecrets>>` | keep | entry box opening for a key actor this node acts for (a link) |
| `fn sync_records(&mut self) -> Arc<BTreeMap<Tid, SyncRecord>>`; `SyncRecord { sync_ids: Vec<SyncId>, secrets: BTreeMap<Epoch, Secret32> }` and `fn drop_sync_record(&mut self, thing: &Tid) -> Result<()>` | new | `learn_secret`'s sync side: the engine writes a record where a box sealed to its own key opens (taking an inbox blob, an entry box, a lowering from read keeps the sync secrets it held), in that transaction |
| **Grants, removals, peers** | | |
| `fn judge_peer(&mut self, s: &SyncId, proven: &[Tid]) -> J` (`Reader`, `SyncHolder`, `Departed`, `Unknown`) and `fn covers_departures(&mut self, s: &SyncId, epoch: Epoch) -> bool` | keep | `labeling::judge::{judge, own_node}`, `Judge::of`, departures |
| `fn known_actor(&mut self, a: &Tid) -> bool`; `fn provers(&mut self, own_node: bool) -> Result<Vec<(SigningSecret, CreationRecord)>>` (in proof order: the node key when `own_node`, the account at its open epoch, key actors by tid); `fn own_node(&mut self, t: &Tid) -> bool`; `fn own_node_key(&mut self, dialable: &[u8; 32]) -> Result<bool>` (by `reach.0`); `fn key_open(&mut self, record: &CreationRecord, key: &[u8; 32]) -> bool` (a proof's key is its actor's at an epoch open here); all built. `fn prove_rotations(&mut self) -> Result<Vec<Value>>`, `fn take_rotations(&mut self, Vec<Value>) -> Result<()>` (header-only copies of the account's rotations, spec/sync-opens.md §2): not built. Proof signing and checking are osis-proto's `Prover` and `verified` (the engine does not depend on osis-proto) | keep | `Judge::known`, `labeling::proofs::{account_key_open, account_prover}` |
| `fn deliveries(&mut self) -> Arc<BTreeSet<(CommitId, Tid)>>`, `fn delivery_taken(&mut self, c: &CommitId, holder: &Tid) -> bool`, `fn inbox_blob(&mut self, c: &CommitId, holder: &Tid, rng: &mut dyn NodeRng) -> Result<Option<Sealed>>` | replace | `SyncRecords::note_unsent`, `flows::Resend`, `Done::deliveries`: what a flow owes is derived from the role commit it wrote; `flows::{inbox_of_actor, inbox_kem}` kept |
| `fn take_inbox(&mut self, s: &SyncId, blob: &BlobId, accepted: bool) -> Result<InboxOpened>`; `InboxOpened { commit, taken: Taken, hints: Vec<(Tid, SyncId)>, dial: Option<Address> }` | replace | `accept_inbox`, `hint_actors`, `inbox_named`, `learn_secret`, `flows::edges::inbox_chain` (chain only to readers) |
| `fn removal_notices(&mut self) -> Arc<Vec<RemovalNotice>>` (`sync_id`, `sig`, `recipient`, `commit`) from inbox blobs held to this node's account | new | spec/wire.md §9 position 5, for `unread` to verify under its head's delete key |
| `fn invitations(&mut self) -> Arc<Vec<Invitation>>` | replace | node-sync's `invite_requests`: spec/sync-set.md §4 |
| `fn waiting_held_elsewhere(&mut self) -> Arc<BTreeSet<CommitId>>` and `fn held_elsewhere(&mut self, c: &CommitId) -> Result<()>` | replace | `Done::drop_lost`: a self-removal's secrets drop once it is held elsewhere |
| `fn note_complete_pass(&mut self, actor: &Tid, began: WallMs)` | replace | `SyncState::complete_pass` (`reseal_due`, `signing_due`, link finalize read the stamped value) |
| **Timers and config** | | |
| `fn next_timer(&mut self) -> Result<Option<u64>>`, `fn tick(&mut self) -> Result<()>`, `fn set_now(&mut self, now: WallMs)` (built) | keep | `retention::{tick, next_timer}`; `set_now` moves the memo clock |
| `fn caps(&mut self) -> Arc<Caps>` (`caps^.0` of this node; `Caps { policy, things: BTreeMap<Tid, ThingCaps> }`) | replace | `host^.0`, `HostPolicy` |

Sync never reads `Core`, `ix`, `Tx` or commit `Meta` (inventory B). Every call not marked built returns `Error::NotBuilt(name)`.

## What the engine gives: memo values and effects
- The engine's outputs are the memo values above: `sync_set`, `sync_bodies(c)`, `body_facts(s, c)`, `read_credentials(s)`, `sync_records`, `deliveries`, `removal_notices`, `invitations`, `waiting_held_elsewhere`, `destruction(t)`. No `Changed` log, no generation counter, no `take_*` queue, no hook trait. Events (`Event`) stay for the osis API's listeners; `Event::SyncStatus` goes (status is `Node::status`).
- **`osis_base::memo::Effects<K, V>`** (new, for Fathom: it is derived-state step 5's missing piece) turns a memo into work in proportion to change:
```rust
impl<K: Hash + Eq + Clone, V: Clone + PartialEq> Effects<K, V> {
    pub fn new(name: &'static str) -> Self;
    pub fn want(&mut self, k: K);                 // follow k; its next settle reports it
    pub fn unwant(&mut self, k: &K);
    pub fn due(&mut self) -> Vec<K>;              // followed keys whose last value read a stamp written since
    pub fn settle(&mut self, k: &K, f: impl FnOnce() -> V) -> Option<(Option<V>, V)>;  // Some((acted, now)) when it differs
}
impl Stamps { pub fn feed<K>(&self) -> Feed<K>; }  // the keys an index added since this reader's mark
impl<K> Feed<K> { pub fn added(&mut self) -> Vec<K>; }
```
  `settle` records what `f` read, as a memo does, and indexes each (container, key) read to `k`; each `Stamps` keeps a log of the keys written since its oldest live mark, so `due` costs the writes since the last call times their readers, never the keys followed. A `Feed` is a cursor of one reader over an index's own log: nobody drains it and nothing writes it by hand, which is what separates it from a take-queue.
- **Subscribing, in `read`:**
```rust
fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, streams: &Streams) {
    for c in self.new_commits.added() { self.bodies.want(c) }           // Feed over the engine's held-commit index
    for c in self.bodies.due() {
        if let Some((was, now)) = self.bodies.settle(&c, || cx.engine.sync_bodies(&c)) {
            for s in keys_added(&was, &now) { self.verdicts.want((s, c)) }   // diff of one commit's sync IDs
            // a sync ID dropping it stays followed until nothing of it is left there
        }
    }
    for (s, c) in self.verdicts.due() {
        if let Some((was, now)) = self.verdicts.settle(&(s, c), || verdict(cx, &s, &c)) { self.act(cx, opens, streams, s, c, was, now) }
    }
}
```
  A write on one aspect moves the stamps of that aspect's commits only, so only their verdicts are judged again; a `group.0` change moves `sync_bodies` of the commits on the things that joined or left (inputs note: adding a subtree costs its rows, a removal re-derives `sync_set` whole, O(closure), counted at n and 10n). Source events reach `read` the same way: `known` is stamped per (record, S, blob), so a stream event moves exactly the verdicts that read it.
- **Time** is the memo clock (`memo::Clock`): a value valid until `t` reads `until(Some(t))`; `Clock::next()` (new) gives the driver its wake.

## Kept unread needs nothing of what S carries
`unread` calls exactly `sync_records()` (its thing's sync IDs and sync secrets by epoch, from boxes sealed to its own key), `sync_set()` (whether its synced group's closure, walked only through groups the node reads, lists the thing: a fact of the node's own groups, not of S), `removal_notices()` (from the node's own inbox, which it reads) and `drop_sync_record`; with the store's path, head, entries and own deposits, that is every input spec/sync-judgement.md §6 names: keep, take, serve, stop, stranded. Its credentials (sync key and proof derived from the record's secret of the head's epoch, deposit key, the head's claim set) come from the record and the store. No call reads S's roster, chain, `keys.0` or commits; `open_entry` is never called for a kept-unread S (its entries do not open). Read and unread move by the one predicate in `sync_set`: a read secret held.

## The osis API
Checked against notes/api-design.md (one way, no leaks, names).
- **Reimplemented on the new sync, shape unchanged:** `status`, `on_status_change`, `wait_synced` (`SyncScope::{All, Thing, Deliveries}`: heard out and own commits held elsewhere, spec/sync-status.md §3), `redeem`, `import_contact`, `make_link` (the link names this node and its relays, spec/wire.md §10), `export_bundle`/`import_bundle`, `listen`, `listen_socket`, `rotate_peer_address`, `group_source`, `connect_node`, `disconnect_node`, `group_sources`, `leave`, `remove_node`, `nodes`, `ManualNet` and `internals` (their shape is the integration agent's, against the harness's `Links`).
- **Deleted:** `saved_peers`, `add_peer`, `remove_peer`, `peers(group)` and `sync(group, peers)`: no peer list exists (spec/sync.md §2); a thing syncs by being in a synced group's closure, and its sync ID comes with its first grant (spec/sync-ids.md §2), so `sync` has nothing left to do. `nudge_sync`: every rule is event-driven and redials follow any change (spec/sync-opens.md §1), so a nudge does nothing a correct node needs. `Serving::admit`/`admitted` and `Admit`: no admission (issues/sync-rewrite.md Words). `SyncId` and `sync_ids(group)`: caps are keyed by thing (below), so no app sees a sync ID. `Osis::create`'s `peers` argument moves to `Config::dial: Vec<Address>`, the configured dial candidates of spec/sync-opens.md §1 (never a filter, never stored as data). kit's and app's `add_peer`/`saved_peers` calls move to `Config::dial` and to `status().connected`.
- **Changed:** `Serving`/`set_serving` become `caps()`/`set_caps(Caps)`, `Caps { policy: CapsPolicy, things: BTreeMap<Tid, ThingCaps> }` over `caps^.0`: the node keeping a thing unread knows its tid from its sync record, so per-thing caps say what per-sync-ID caps say without the leaked word (a thing has one home sync ID; the API applies a thing's caps to each sync ID it owns). `invite_requests() -> Vec<InviteId>` becomes `invitations() -> Vec<Invitation { thing, role, from: Tid, taken: bool }>` (spec/sync-set.md §4); `accept_invite(thing, into: Tid)` writes the thing as a subgroup of `into` (`Invalid` unless `into` is in a synced group's closure) and takes its inbox blob if untaken: one call for the user's accept whatever the blob's state; `decline_invite(thing)` answers an untaken one only (a taken one is declined by `leave`, which an untaken one cannot use: this node never applied its grant). `InviteId` goes. `Status`: `SyncState::Refused` goes (a full or refusing source is a source that lacks; with none connected it is `NotConnected`), `GroupSync::refused_by` becomes `not_taking: Vec<Address>` (full or refusing sources, informational); `Status::groups` holds every thing with a sync ID in the sync set, kept unread included (any thing is a group of itself).

## Proposed engine and base changes (for Fathom)
Minimal; each removes a hook or a raw access the new sync would otherwise need.
- **E1** `osis_engine::sync`: the facade above; `pub` goes from `Engine::core`, `Core::ix`, `Tx::txn` and the rest of inventory B.
- **E2** `osis_base::memo::Effects`, `Stamps::feed`, `Clock::next`: the change-driven mechanism; also closes derived-state step 5's open item (listing the parts whose reads moved).
- **E3** Sync records as one engine table written where a box to this node's own key opens; `learn_secret` stops keeping sync secrets in thing state.
- **E4** Deliveries derived from the role commits a flow wrote (`deliveries`, `delivery_taken`): `SyncRecords`, `Core::sync_records`, `set_sync_records`, `flows::owe`, `Resend` and `Done::deliveries` go; a flow returns its commits.
- **E5** `note_complete_pass` replaces the `&dyn SyncState` argument of `reseal_due` and `signing_due`.
- **E6** `fall_mark` per aspect replaces `take_fallen`/`take_fell`; `waiting_held_elsewhere`/`held_elsewhere` replace `Done::drop_lost`.
- **E7** `destruction`/`forget_destroyed` replace the emptying sets and `destroyed_*` indexes.
- **E8** `take_inbox` and `removal_notices` replace `accept_inbox`, `hint_actors`, `inbox_named`.
- **E9** `Event::SyncStatus` goes.

## Inventory
Marks: **delete** (only old sync uses it, the new design needs nothing like it); **keep** (the new sync or another caller needs it as it is, possibly renamed for the words of issues/sync-rewrite.md); **replace** (the new design needs something like it, said what; the interface above names the new shape).

## What to steer clear of (for Fathom)
Branches on keys, rotation, perm and engine judgement should not build on, extend or rename these until Phase 3 lands; they change or go there.
- **Delete:** `Core::generation`, `role_generation`, `memory_generation` and `Core::role_changed`; `Core::changed` with `Changed`, `Wakes` and `Engine::take_changed`; `Core::made_labels`; `Engine::recheck`; the kept-unread branches inside `rotation::lost::may_hold`/`may_take` (the `Role::Sync` arm), `flows::retake`'s sync boxes, `drop_actors`' sync-secret keep, `labeling::certs::boxed_by`'s sync invariant, `labeling::actors::inbox_actors`' count of a thing held for sync only, `rotation::add_history` with `role_now` = Sync, `retention::destroy::hold_secrets` counting a sync secret; `GroupLabel::hosts`; `apply::hint_actors`, `apply::keys::inbox_named`; the hook `SyncRecords` (with `Core::sync_records`, `Engine::set_sync_records`), `flows::owe`, `flows::Resend`, `Done::{deliveries, drop_lost}`; `Event::SyncStatus`.
- **Replace:** the sync-ID layer (`labeling::actors::{labels_of, labels_read, group_labels, labeled, labeled_groups, published_under}`, `GroupLabel`, `Indexes::labeled`, `Core::labels`, `Core::published`: becomes `sync.0` and one home sync ID per actor); `Indexes::syncing` and `Engine::set_syncing` (becomes the synced group S); `SyncState::complete_pass`; the take-queues `take_fallen`, `take_fell`, `take_pended`, `take_redeliver`, `take_freed_new`, `take_destroyed_secrets_due`, `take_memory_drops` and their sets; destruction emptying (`emptying`, `emptying_things`, `labels_emptied`, `drop_destroyed_secrets`, `commits_keyed_by`, `Indexes::destroyed_labels`, `Indexes::destroyed_secrets`); `flows::edges::inbox_chain` and `deliver_parts`' chain to holders below read; `learn_secret`'s sync secret; `labeling::converge` (`Facts`, `classify`, `may_delete`); `purge_resnapshots`' caller (the fn stays); the raw state access listed under B below.
- **Free to change:** everything marked keep, including all of rotation (`ensure_rotated`, `reseal_due`, `blocked_roles_of`, departures), lost access (`judge_lost`, `forget_lost`, `lost_leaving`), validity, retention bounds and certificates. Only their call sites in `core/node/src/sync` go.

## How it was found
Every `pub`, `pub(crate)` and `pub(super)` fn, const and field of core/engine, core/label, core/store, core/proto and core/osis got `#[deprecated]` (3713 items, a throwaway probe); `cargo clippy --all-targets --message-format=json` gave every use site; an item counts as only-old-sync when every use is in `core/node/src/sync`, `core/host`, `core/node/tests/it`, `core/proto/src/{session,store,window}.rs`, `core/test/sim/src/{net,scenarios.rs,world.rs}`, or inside the body of another such item (to a fixpoint). Result: 575 items (engine 451: 284 methods, 145 fields, 13 fns, 8 associated fns, 1 const; label 24; store 22; proto 76; osis 2), plus about 180 store and proto items used only by deleted code and their own crate's tests.

The node wraps the engine (`SyncEngine` owns the `Engine`; osis reaches the engine only through it), so "only old sync calls it" covers much of the engine's whole API: opening, writing, ingesting, the clock. Those are marked keep in group A. The named start points that have no item of that name: `keeper_due` (nearest: `lost_leaving`, `would_forget`, both keep) and `destroyed_labeled` (it is `Indexes::destroyed_labels`, replace).

## Engine functions
### A. The engine's API the node needs whatever sync is: keep
| items | mark | reason |
|---|---|---|
| `Engine::open`, `create`, `run`, `reload`, `now`, `tid`, `account_tid`, `identity`, `first_admin`, `record_chain`, `store_writes`, `subscribe_durable`, `blobs`, `clock` | keep | opening, transactions, identity: any node |
| `Identity::keys`, `Identity::record`, `Mutation::new`, `op`, `replace`, `write::commit`, `write::role_of` | keep | writes the node makes (peer records, links) |
| `events::Events::diagnostic`, `flush`; `Diagnostic` fields `commit`, `detail`, `kind`, `peer`, `tids`; `DisputeInfo` fields, `Side::chosen`, `trust` | keep | events and API types, read through the node |
| `read::epochs`, `get_typed`, `references_to`, `role_on` | keep | plain reads |
| `records::Rd`, `records::Wr` (16 methods) | keep | the store record codec; the new sync's records use it or it goes in Phase 3 if none does |
| `Engine::examined` | keep | scale-test counter |

### B. Raw state access: replace by the boundary's queries
The new sync asks narrow questions (per sync ID: held commits and their bodies, judgement, keys); these give it the whole engine. The fields stay, the `pub` access goes.
| items | mark | reason |
|---|---|---|
| `Engine::core`, `Core::ix`, `Tx::txn`, `Tx::scan`, `Tx::get_commit`, `Tx::in_class` | replace | whole-engine handles; the boundary names what sync reads |
| `Indexes::by_aspect`, `commits`, `held`, `own_keys`, `pending`, `secrets`, `snapshots`, `destroyed_secrets` (read side) | replace | raw indexes; each use becomes a boundary query |
| `JMap::get`, `contains_key`, `JSet::contains`, `JSetMap::get` | replace | journal internals exposed only for the above |
| `Meta::{header, origin, received, valid, view, body_gone, dropped, missing, missing_as}`, `View::{actor, aspects, author, kind, memory, purges, ts}`, `AspectView::tid`, `Trees::{blobs, missing}`, `refs::Reference::{ak, source}`, `Dropped::why` | replace | commit metadata read field by field; the boundary returns what a judgement needs |
| `Core::{account, accounts, id, key_actors, timelines, time, horizon, events, aspects_of, durable_on, held_on, cover_judged_on, destroyed, exists}`, `Core::created`, `held::Timelines::get` | replace | same; `horizon` and `time` become the memo clock the boundary's memos read |
| `held::Held::{below, holders_of, named_on, reach, upstream}` | keep | pure perm queries J and the open rule need |
| `held::Held::named_holders` | delete | `granted_on` collected; its caller (`marks::downstream`) takes `granted_on` |

### C. Change tracking for old sync
| items | mark | reason |
|---|---|---|
| `Core::generation`, `role_generation`, `memory_generation`, `Core::role_changed` | delete | hand-keyed counters; memos compare stamps (derived-state step 3's done-when) |
| `Core::changed`, `Changed::{commits, aspects, undropped, edges, wakes, is_empty}`, `Wakes::{records, moved, reread, woken, reopen_awaits}`, `Engine::take_changed` | delete | a change log for old sync's work sets; the new sync's values are memos over the stamps and its effects run when a value moves |
| `Core::made_labels` | delete | old sync learning new labels; a new sync ID is a `sync.0` change a memo sees |
| `Engine::recheck` | delete | polices the hand caches; goes with them (derived-state step 3) |
| `Engine::take_fallen`, `take_fell`, `take_pended`, `take_redeliver`, `name_redeliver`, `redeliver_named`, `take_freed_new`, `take_destroyed_secrets_due`, `take_memory_drops`, `MemoryDrop::by` | replace | take-since-last-call queues; each rule stays (snapshot turning invalid, logged again once after a fall, pending sweep, junk copy re-fetch, freed blobs, destroyed secrets, memory drops), each becomes an event the engine emits or a memo value |
| `Engine::set_sync_records` | delete | `SyncRecords` hook: deliveries are derived (E4) |

### D. Sync IDs: replace
| items | mark | reason |
|---|---|---|
| `labeling::actors::labels_of`, `labels_read`, `group_labels`, `labeled`, `labeled_groups`, `published_under` | replace | label per group from `label.0`; the new design has one home sync ID per actor in `sync.0` (spec/sync-ids.md) |
| `GroupLabel::{id, steps, tips}` | replace | the sync ID with its path; same content under the new name |
| `GroupLabel::hosts` | delete | addresses in group data; readers dial what they know, never from group data |
| `labeling::HeadKeys::{delete, deposit, epochs, is_writer, sync, sync_established, write}`, `labeling::blobs::head_keys`, `deposit_seed` | keep | a head's keys; same rule per sync ID |
| `flows::labels::issue_step`, `drop_old_claims` | keep | steps and claim sets (area 2), renamed |
| `apply::set_syncing` | replace | the node's own list of synced groups; the sync set is the synced group S's closure (spec/sync-set.md) |
| `apply::hint_actors`, `apply::keys::inbox_named` | delete | hints come from `take_inbox` and `sync_ids` (U1) |

### E. Kept-unread and inbox hooks
| items | mark | reason |
|---|---|---|
| `labeling::certs::boxed_by` | replace | keep the read rule (follow a payload's sync ID only for a thing the commit gave a read secret of); drop its sync invariant |
| `apply::keys::learn_secret` | replace | keep for read secrets from an entry box (links); a sync secret goes to the sync record, not engine state |
| `flows::edges::inbox_chain`, `deliver_parts` | replace | the chain and `keys.0` go only to readers; a sync grant carries its box and sync IDs (stranded-holder-unread (old issue, at 1dcacb6b0)) |
| `labeling::actors::inbox`, `inbox_actors` | keep / replace | `inbox` keep; `inbox_actors` replace: readers' actors only (audit row Inbox actors) |
| `Engine::note_delete_hints`, `own_delete_keys` | keep | delete keys an inbox payload names (spec/wire.md §9), for holders that delete |
| `flows::{inbox_kem, inbox_of_actor}`, `Engine::account_kems` | keep | sealing and opening inbox blobs |
| `SyncState::complete_pass` (via `reseal_due`, `signing_due`) | replace | "a complete pass" becomes status per sync ID: every source's stream read to its end (area 7) |

### F. Judgement per sync ID for readers
| items | mark | reason |
|---|---|---|
| `labeling::actors::{closure, group_actor, may_read, reader_of, secret_actor}`, `engine::groups::enclosing` | keep | closure and entitlement: what S carries |
| `engine::groups::closure_whole` | keep | the header-only `group.0` wait is still an area 4 rule (inputs note) |
| `labeling::blobs::{body, body_ctx, body_carried, body_plaintext, commit_bodies_under, label_bodies_meta, readable_parts, reads_in, carries_secrets, copy_stale, await_reading}`, `Body` fields, `BodyCtx` fields | keep | what S carries per commit (Carry, spec/sync §3); renamed; `label_bodies_meta` is already a memo |
| `labeling::blobs::{seal, seal_to, open_commit, read_secrets, wrap_secret}`, `Sealed` and `OpenedBlob` fields, `fetch_order` | keep | the blob format (label crate's crypto, kept) |
| `labeling::blobs::{delete_secrets_of, delete_secrets_by_group}`, `labeling::delete_item`, `delete_item_by_level` | keep | delete keys and Delete items |
| `labeling::converge::{Facts fields, classify, may_delete}` | replace | the must-hold / may-hold / must-not-hold rule set, rewritten from spec/sync-judgement.md as one memo per (sync ID, commit) |
| `labeling::certs::{certificates, author_chain, removal_certificates, revoke_certificates, minting_evidence, mintings_of, witness, header_body, part_body, linked_blobs, holders_named, current_keys, destroyed_needed, latest_by, aspect_commits, valid_parts, judged_valid}`, `Certs` fields and methods, `retention::Minting` fields | keep | certificate copies and minting evidence (spec/permissions.md §4, spec/commits.md §5); readers only |
| `labeling::judge::{judge, own_node, static_listed}`, `Judge::{known, of}`, `labeling::proofs::{account_key_open, account_prover}` | keep | J and account proofs: the open rule |
| `engine::large::{body_links, tree_missing, relink}`, `apply::reach::blob_wants`, `Wants::{missing, reached}` | keep | what to fetch; trees and chunks |

### G. Ingest, blobs and relay: keep
| items | mark | reason |
|---|---|---|
| `apply::{ingest, ingest_valid, ingest_with_lists, ingest_memory, apply_waiting_memory, learn_records, reexamine, pending, header, blob, commit_bytes, signed_at, parts_genuine}` | keep | taking commits and records in; any node that reads |
| `apply::{copy_awaits, records_awaited_by, destroyed_records_awaited, settled_slots, spent_copy}` | keep | unjudgeable and never-received rules (spec/commits.md §4-§5) |
| `apply::{forget_pending, no_entry_left, forget_awaiting, reading_sources}` | keep | the engine half of "the last entry carrying a commit left"; the new sync calls them from its store |
| `apply::memory::{holds_memory, memory_body_held, memory_bound, memory_charge, memory_pending}` | keep | ephemeral caps (spec/sync §9 caps) |
| `engine::blobs::{put_blobs, put_memory_blobs, has_blob, blobs_stored}`, `Tx::store_blobs`, `Cipher::{store, get, held, defer}` | keep | the engine's ciphertext door; the node's store per sync ID implements `osis_store::CipherHost` in place of the hub |
| `ephemeral::signal::{ingest_relay, take_signals}`, `EphCommit` fields | keep | relay-only commits (an emitted output) |
| `local_peer::package`, `header_list_blobs` | keep | a commit with its blobs, for relaying |

### H. Retention, destruction, forgetting
| items | mark | reason |
|---|---|---|
| `retention::bounds::{part_keeps, drop_from, body_not_dropped, coverers_of, delta_live, droppable_if_covered, may_last_on, own_kept_under, part_valueless, permanent, settle_kept}` | keep | keep bounds and covers (spec/commits.md §5), memos already |
| `Engine::{drop_body, own_covers, own_held_before, own_newly_covered, own_older, own_replace, part_held, kept_invalid, kept_purged, forgettable, all_forgettable, forget_commits}` | keep | covers and forgetting |
| `retention::{tick, timers_due, next_timer}`, `compact::compactions`, `snapshot::{snapshot, covered}`, `suspect::{suspects, state_digest}`, `purge::named_by_a_fallen_purge` | keep | engine retention; the driver's timer asks `next_timer` |
| `snapshot::purge_resnapshots` | keep | a re-snapshot every writer takes; only its caller (old sync's delete pass) goes: the engine runs it as an effect when `resnapshots_due` moves (replace, state below) |
| `Engine::left_at_hosts`, `Dropped::hosts_from` | keep | rules stay (no right deletes a part dropped while invalid; deletes at peers wait for `MAX_DRIFT`); renamed |
| `retention::freed::{judge_freed, judge_freed_page, freed_wants, freed_done, freed_delete_secrets, is_freed}`, `Freed` and `Judgment` fields | keep | freed links: deleting chunks through an entry the prefix commits to |
| `retention::destroy::{emptying, emptying_things, labels_emptied, drop_destroyed_secrets, commits_keyed_by}` | replace | destruction emptying stays (told, then emptied, sync IDs forgotten once heard out, secrets last); becomes a memo of the things to empty per sync ID with an effect, without the hand-kept due set |
| `retention::lifetimes::{judge_lifetimes, lifetimes_due}`, `Judged::request` | keep | lifetimes; "heard out" comes from status per sync ID |
| `retention::forget::Forgotten` fields | keep | what forgetting dropped; the new store drops its entries by it |
| `compact::compact_memory_now` | keep | test helper |

### I. Flows, rotation and lost access (Fathom's)
| items | mark | reason |
|---|---|---|
| `rotation::{ensure_rotated, rotated_already, blocked_roles_of, departures_placing, may_rotate, reseal_due, reshare, give_own_secrets_again, own_secrets_candidates, LOST_HEARD_WAIT_MS}`, `rotation::Leaving` and `Dropped` fields | keep | engine judgement; `reseal_due`'s `&dyn SyncState` argument changes (E) |
| `rotation::lost::{judge_lost, forget_lost, lost_due, next_lost_due, lost_leaving, would_forget, keys_write_unapplied}` | keep | lost access; "once its self-removals are placed" reads "logged" |
| `flows::{demote, removal_scope, finalize_link, joined_links_ended, links_due, next_link_expiry, may_remove, tied_unplaced, untie, signing_due, account_rotations, hold_lists, list_blob, rotation_lists}` | keep | flows and their triggers |
| `flows::{current_holders, is_key_actor, key_holders, role_now}`, `flows::account::{account_devices, counts_at_epoch, home_owner, is_account}` | keep | perm queries |
| `flows::Done::commits`, `Demotion` fields, `HeldLink` fields | keep | a flow's result |
| `flows::Done::{deliveries, drop_lost}`, `flows::owe` | delete | deliveries derived from the commit (E4); `held_elsewhere` (E6) |
| `flows::Resend` fields | delete | the re-send state is `inbox`'s, the delivery the engine's derived value (E4) |

### J. Test helpers
| items | mark | reason |
|---|---|---|
| `testing::{rebuild_index, test_copy}`, `Engine::test_subscribe_with` | keep | copied worlds and index rebuilds for the Phase 4 harness |
| `local_peer::LocalPeer::{new, cached, peers}`, `Peer::{backend, clock, engine, root}` | keep | U2 |

## Engine state that serves only old sync
| state | mark | reason |
|---|---|---|
| `Core::generation`, `role_generation`, `memory_generation` | delete | counters for old sync's caches |
| `Core::changed` (`Changed`, `Wakes`) | delete | change log |
| `Core::made_labels` | delete | queue of new labels |
| `Core::sync_records` and trait `SyncRecords` (`note_unsent`, `owe`, `forget`) | delete | what a flow owes is a function of the commit it wrote (`deliveries`, own must-hold bodies), so a crash loses nothing without a row; forgetting reaches the store through `sync_bodies` going empty |
| trait `SyncState` | replace | status per sync ID (E) |
| `Core::redeliver`, `pended`, `fallen`, `fell`, `freed_new`, `destroyed_secrets_due`, `memory.dropped` (`MemorySync`) | replace | take-queues (C) |
| `Indexes::syncing` (`records::SYNCING`) | replace | the synced group S |
| `Indexes::labeled`, `Core::labels`, `Core::published` | replace | `sync.0` per actor |
| `Core::inbox_actors` memo | replace | readers' actors only |
| `Indexes::destroyed_labels` (`records::DESTROYED_LABELS`), `Indexes::destroyed_secrets` (`records::DESTROYED_SECRETS`) | replace | destruction emptying per sync ID (H) |
| `Core::resnapshots_due` | replace | a memo of the owed re-snapshots, its effect the re-snapshot; no sync caller |
| `Core::walks` (`apply::reach::Walks`) | replace | a cache kept for `blob_wants`: a memo over the pending set and held blobs |
| `Waits::untaken` sync entries | delete | sync boxes held back for `retake`; a sync secret goes to the sync record |
| `Core::memory_room`, `memory_waits`, `memory_tx`, `cover_candidates`, `missed`, `cut_subs`, `sourced_elsewhere`, `delete_hints`, `holder_keys`, `head_keys` and `holders_named` memos | keep | caps, covers, watch re-delivery, stranded reports, osis sources, inbox delete keys, perm |

## Other crates
| items | mark | reason |
|---|---|---|
| osis-label: `verify_stamp`, `verify_deposit`, `match_secret`, `open_inbox_item`, `entry_digest`, `wrap_order`, `tips`, `parse_record`, `Prefix::{agrees, for_groups, key_at}`, `Step::claims_hash`, `StepKeys::get`, `DeleteItem` fields and `verify`, `Class::in_memory`, `StrandedNotice` fields, `seal_stranded_notice` | keep | the crate's crypto parts (stamps, deposits, delete keys, steps), kept by the plan |
| osis-label: `host_prefix`, `prefix_bytes` | replace | the hub store's key layout; the new store per sync ID defines its own |
| osis-store: `nodelog` (`log_*`, `LogRead`, `LoggedEvent`) | keep | spec/sync.md (area 6) keeps one stream per peer over its node log; check its rules against spec/sync-streams.md |
| osis-store: `record` (`record_*`, `records_*`, `Record`, `Member`, `Filter`, `RECORD_BUDGET`) | keep | U3 |
| osis-store: `changed` (`changed_at`, `changed_after`, `changed_note`, `changed_forget`, `changed_labels`) | replace | `changed_at` stays durable (spec/sync-opens.md §3) but moves only by `opens`' effect on `admissible(s)`, its row keeping the digest of the value acted on |
| osis-store: `Transaction::{put_blob, get_blob, read_blob, delete_blob, blob_len, suspend, table_len, random32}`, `Store::resume`, `prefix_end`, `Writes::{committed, failed}`, `test_copy*`, `Faults::test_copy` | keep | store primitives the new store per sync ID builds on |
| osis-proto: `session`, `store` (`LabelStore`, `MemoryLabelStore`, `HeadKeys`, `EntryMeta`), `window`, `Session::*`, `Relayed` fields, `session::{deposit, pulled, reply_bound, PUSH_POLL_MS}` | delete | the old session layer (Scope) |
| osis-proto: `filter` (`encode_gcs`, `decode_gcs`, `pages`, `beacon_value`, `BEACON_P`, `Page`) | keep | U4 |
| osis-proto: `msg` | replaced | rewritten to spec/wire.md §11.2: `Msg` (sync IDs, `Prove` with `rotations`), `Code` (`NOT_OPEN`, `UNKNOWN_SYNC_ID`, `DECLINED`, `NOT_HEAD_KEY`, `DEPOSIT_BUDGET_FULL`), `Cursor`, `DepositItem`, `BehindItem`, `OfferItem`, `SharedItem`, `Grant`, `Event`, `Join`, `flow`, `peek_head`, `stream_event_len`; every limit in `limits` |
| osis-proto: `prove` (`verified`, `ActorProof`), `frame`, `hello`, `relay` (`RelayGate`, `RelayLimits`) | keep | actor proofs for opens, framing, the relay (below sync); `MAX_PROOFS` and `MAX_RESUME_TAGS` are in `limits` |
| osis: `internals::ManualNet::dbs`, `test_copy` | replace | the sim's world uses them; Phase 4's one harness decides its shape |

## Resolved
- **U1 Hint sync IDs:** delete `hint_actors` and `inbox_named`. spec/sync-inbox.md §2 follows a payload sync ID only for a thing whose box in that blob opened, so the box names the thing: `take_inbox` returns `hints: Vec<(Tid, SyncId)>` from opened boxes; spec/sync-ids.md §4's hints from `sync.0` entries of a thing read by derived secrets are `sync_ids(t)` entries with `hint: true`. Nothing names actors from an unverified commit.
- **U2 `LocalPeer`:** keep. About 25 engine test files exchange commits through it (no sync involved); the sync harness builds nodes on `osis_sync::Node` only, and the node tests that used it go in Phase 3.
- **U3 per-peer records:** keep osis-store `record` (pair-key lookup, actor index, `RECORD_BUDGET` LRU, one transaction per change): spec/sync-opens.md §3 keeps exactly that. Its rows grow to the record's list there; each row has one owner: `opens` (members with class, beacon, `until`, position; `acked_pos`; filter generations; how left members rejoin; the source's step), `streams` (cursor, members at the stream, joins, where its stream held members that left, `known`), `read` (deletes seen, the logged-again-once stand), `store` (peer budget charges). Reported positions last the connection (opens, in memory).
- **U4 wire and filter:** keep `filter` (spec/wire.md §11.2 Beacons is the same Golomb-Rice coding). Rewrite `msg` to §11.2's list (the session owner). `Code` takes the words of spec/wire.md's table (13 unknown sync ID, 8 not open; 14 named for a refusal, never admission); naming is the session owner's.
