//! The client port (notes/client-port.md): the `osis` API over the node-to-node protocol's
//! client-port kinds (spec/wire.md §11.2). `serve`: a node answers the requests its served
//! sessions make, on a worker thread off the handle lock; `client`: a process attached to such
//! a node (`Osis::attach`, `Osis::attach_client`) routes its tid-addressed calls there
//! (`Source::Remote`). Sessions: the Owner (the unix socket, `Peer::Unix`) and thin clients (a
//! bearer secret matching `clients.0^`), whose rows run as the client's actor (`serve`).

pub(crate) mod client;
pub(crate) mod codec;
pub(crate) mod serve;

pub use client::socket_path;

/// The method table (`Call.method`): each row's args and result in `codec` forms. A method number
/// not listed is answered `Unsupported`; a row is Owner-only unless `for_client` lists it.
pub(crate) mod method {
    /// `[]` -> `[me, node]`
    pub const WHOAMI: u64 = 0;
    /// `[tid, ak, path]` -> read result (path `[]`: the aspect, else the typed position)
    pub const GET: u64 = 1;
    /// `[tid]` -> `[ak*]`
    pub const ASPECTS: u64 = 2;
    /// `[tid]` -> bool
    pub const KNOWS: u64 = 3;
    /// `[tid]` -> bool: its creation is here, content or not (what routing asks of a node)
    pub const HOLDS: u64 = 69;
    /// `[tid]` -> groups
    pub const GROUPS_OF: u64 = 4;
    /// `[tid]` -> roster
    pub const ROSTER: u64 = 5;
    /// `[tid]` -> Opt(role)
    pub const ROLE_ON: u64 = 6;
    /// `[tid]` -> Opt(tid)
    pub const OWNER_OF: u64 = 7;
    /// `[tid]` -> Opt(stamp)
    pub const CREATED: u64 = 8;
    pub const CHANGED: u64 = 9;
    /// `[nonce, actor, [ak*], [op*]]` -> Opt(committed)
    pub const WRITE: u64 = 10;
    /// `[query]` -> `[entry*]`
    pub const COMMITS: u64 = 11;
    /// `[nonce, scope]` -> Opt(committed)
    pub const UNDO: u64 = 12;
    pub const REDO: u64 = 13;
    /// `[nonce, change]` -> committed
    pub const REVERT: u64 = 14;
    /// `[]` -> status
    pub const STATUS: u64 = 15;
    /// `[file, source]` -> `[]` (registered on the node: Owner only)
    pub const REGISTER_SCHEMA: u64 = 16;
    /// `[tid, ak, path]` -> Opt(len)
    pub const LEN: u64 = 17;
    /// `[tid, ak, path, offset, n]` -> bytes (`n` at most `STREAM_CHUNK`)
    pub const STREAM_READ: u64 = 18;
    /// `[]` -> `[]` once every Notify for changes before it went (`Osis::settle`). The worker
    /// runs the node's `settle`, waiting for its dispatcher: a callback in the node's process
    /// that waits on the port worker (an attached handle of its own node) deadlocks it.
    pub const SETTLE: u64 = 19;
    /// `[]` -> wall ms
    pub const NOW: u64 = 20;
    /// `[]` -> `[host addr text*]`
    pub const HOSTS: u64 = 21;
    /// `[]` -> `[]` (`Osis::sync_now`: pokes the driver, waits for nothing)
    pub const SYNC_NOW: u64 = 22;
    /// `[group, [host addr text*]]` -> `[]`
    pub const SYNC: u64 = 23;
    /// `[group]` -> `[]`
    pub const UNSYNC: u64 = 24;
    /// `[target, holder, role, edge opts]` -> `[]`
    pub const GRANT: u64 = 25;
    pub const CHANGE_EDGE: u64 = 26;
    /// `[tid, group, role, subgroup, place_anyway]` -> share
    pub const SHARE_INTO: u64 = 27;
    /// `[group, target]` -> `[]`
    pub const REMOVE_EDGE_OF: u64 = 28;
    /// `[target]` -> `[]`
    pub const LEAVE: u64 = 29;
    /// `[target, role, Opt(until), single_use, direct]` -> link text
    pub const MAKE_LINK: u64 = 30;
    /// `[tid]` -> `[[group, placed, share]*]`
    pub const REACH: u64 = 31;
    /// `[target, actor]` -> `[[thing, holder]*]`
    pub const HOLDER_PATH: u64 = 32;
    /// `[]` -> `[[id, target, role, Opt(until), single_use]*]`
    pub const LINKS: u64 = 33;
    /// `[Opt(until)]` -> `[actor, secret]` (`Osis::add_client`)
    pub const ADD_CLIENT: u64 = 34;
    /// `[]` -> `[[actor, Opt(until)]*]`
    pub const CLIENTS: u64 = 35;
    /// `[actor]` -> bool
    pub const REMOVE_CLIENT: u64 = 36;
    /// `[actor]` -> secret
    pub const ROTATE_CLIENT_SECRET: u64 = 37;
    /// `[]` -> `[node addr text*]`
    pub const ROTATE_CLIENT_KEY: u64 = 38;
    /// `[]` -> `[actor*]`
    pub const KEPT: u64 = 39;
    /// `[actor]` -> `[]`
    pub const DROP_KEPT: u64 = 40;
    /// `[tid, ak, from, limit, max bytes]` -> `[[entry*], more, complete]`
    pub const HISTORY: u64 = 41;
    /// `[target, holder, role, edge opts]` -> `[]` (`Osis::share`: `sync` when the holder has
    /// no route, then `grant`)
    pub const SHARE: u64 = 42;
    /// `[admin]` -> tid (`Osis::create_ownerless`)
    pub const CREATE_OWNERLESS: u64 = 43;
    /// `[]` -> `[[node, role]*]`
    pub const DEVICES: u64 = 44;
    /// `[host addr text]` -> `[]`
    pub const ADD_HOST: u64 = 45;
    pub const REMOVE_HOST: u64 = 46;
    /// `[]` -> Opt(key bytes)
    pub const HOST_KEY: u64 = 47;
    /// `[]` -> offer text
    pub const PAIR_OFFER: u64 = 48;
    /// `[request text]` -> `[node, reply text]`
    pub const PAIR_ACCEPT: u64 = 49;
    /// `[]` -> card text
    pub const CONTACT_CARD: u64 = 50;
    /// `[person]` -> Opt(tid)
    pub const PROFILE_OF: u64 = 51;
    /// `[]` -> `[invite id bytes*]`
    pub const INVITE_REQUESTS: u64 = 52;
    /// `[invite id bytes]` -> `[]`
    pub const ACCEPT_INVITE: u64 = 53;
    pub const DECLINE_INVITE: u64 = 54;
    /// `[group]` -> `[Opt(publish_reach), receipts_only]`
    pub const GROUP_POLICY: u64 = 55;
    /// `[group, Opt(publish_reach), receipts_only]` -> `[]`
    pub const SYNC_POLICY: u64 = 56;
    /// `[]` -> `[]`
    pub const ROTATE_REACH: u64 = 57;
    /// `[[group*]]` -> length: the bundle waits on this connection for `BUNDLE_READ`, replacing one
    /// waiting there, until its last page was read. A bundle does not fit a frame; held per
    /// connection, it goes with it.
    pub const EXPORT_BUNDLE: u64 = 58;
    /// `[offset, n]` -> bytes of the waiting bundle (`n` at most `STREAM_CHUNK`)
    pub const BUNDLE_READ: u64 = 59;
    /// `[bytes]` -> `[]`: appended to the bundle coming on this connection for `IMPORT_BUNDLE`
    pub const BUNDLE_WRITE: u64 = 60;
    /// `[length]` -> `[]`: imports the waiting bundle, which must have that length (a reconnect
    /// between pages loses what was sent on the old connection)
    pub const IMPORT_BUNDLE: u64 = 61;

    // Rows that wait on other nodes: a `[5, method, [arg*]]` subscription, never a Call (`filter`).
    /// `[sync scope, timeout ms]` -> `[]`
    pub const WAIT_SYNCED: u64 = 62;
    /// `[link text]` -> tid
    pub const REDEEM: u64 = 63;
    /// `[target, holder, Opt(role), demotion]` -> `[]` (no role: removed)
    pub const DEMOTE: u64 = 64;
    /// `[link id, demotion]` -> `[]`
    pub const REVOKE_LINK: u64 = 65;
    /// `[link id, joiner, demotion]` -> `[]`
    pub const REVOKE_JOINER: u64 = 66;
    /// `[card text]` -> person
    pub const IMPORT_CONTACT: u64 = 67;

    /// The rows a thin client's session may call, each running on a handle acting as its actor.
    /// Absent: process-wide rows, and the sharing and sync rows, whose engine flows act with this
    /// node's authority and take no actor (they would be a confused deputy).
    pub fn for_client(m: u64) -> bool {
        matches!(m, WHOAMI | GET | ASPECTS | KNOWS | HOLDS | GROUPS_OF | ROSTER | ROLE_ON | OWNER_OF | CREATED | CHANGED | WRITE | COMMITS | UNDO | REDO | REVERT | STATUS | LEN | STREAM_READ | SETTLE | NOW | KEPT | HISTORY)
    }
}

/// Subscription filters (`Sub.filter`): `[0, tid, ak]` aspect, `[1, tid]` thing, `[2, tid]`
/// roster, `[3]` status, `[4]` diagnostics, `[5, method, [arg*]]` a row that waits, run at the node
/// without holding its worker: the Reply and at most one Notify carry `Opt(outcome)`, the outcome
/// once known; an Unsub or the connection's end cancels it, as dropping the future does locally;
/// `[6, tid, ak]` an aspect's history: each Notify `[change, Opt(entry)]`, the entry read when sent.
pub(crate) mod filter {
    pub const ASPECT: u64 = 0;
    pub const THING: u64 = 1;
    pub const ROSTER: u64 = 2;
    pub const STATUS: u64 = 3;
    pub const DIAGNOSTICS: u64 = 4;
    pub const TASK: u64 = 5;
    pub const HISTORY: u64 = 6;
}

/// Write outcomes a node remembers per (tier identity, session) for retries under the same
/// nonce. Resource bound: 0 makes every retry an unknown outcome, infinity is unbounded per
/// session.
pub const WRITE_NONCES: usize = 64;
/// Bytes of fired signals and diagnostics a connection holds while it has no push room: past
/// it the subscription whose delivery does not fit lapses (the client subscribes again).
/// Resource bound: 0 drops every signal under backpressure, infinity lets a slow client hold
/// unbounded memory.
pub const SIGNAL_BYTES: usize = 1 << 20;
/// Distinct schema source bytes the node's Owners may register through the port (per node:
/// registrations are process-wide and kept). Resource bound: 0 forbids typed sets through
/// the port, infinity lets one client fill memory.
pub const MAX_SCHEMA_BYTES: usize = 1 << 20;
/// Rows that wait (`filter::TASK`) per connection still running (each is a waiter the node checks
/// after every change, O(labels)). Resource bound: 0 forbids waiting through the port, infinity
/// (`MAX_SUBS`) multiplies the per-change cost of the lock the sync driver needs. Past it `Invalid`.
pub const MAX_WAITS: usize = 16;
/// What one commit waiting in a history subscription counts against `SIGNAL_BYTES`: its ID in a set
/// (a fall of an aspect behind a slow client lapses, and the client reads again).
pub const HISTORY_DIRTY_BYTES: usize = 64;
/// History entries read per send. Performance switch: each is read when sent, and a send may fit
/// few of those waiting, so reading them all would be quadratic; 0 sends nothing, infinity reads
/// everything waiting per send.
pub const HISTORY_SEND: usize = 64;
/// Bytes of a `stream_read` page. Performance switch: 0 moves nothing, infinity is one page
/// bounded by `REPLY_BUDGET`.
pub const STREAM_CHUNK: usize = 1 << 20;
/// Ops of one `write` batch (spec/wire.md §13 decoder limits).
pub const MAX_BATCH_OPS: usize = 1024;
