//! The client port (spec/wire.md §11.2 kinds 24-29, spec/sync-transport.md §6,
//! notes/client-port.md): the `osis` API over a sync connection. `serve`: a node answers the
//! requests its connections carry, as itself for a main session or as a client's thing;
//! `client`: a process uses a node it is a client of (a thin client, `Osis::connect`, or a
//! node's sync unit source, `Osis::connect_node`); `codec`: the values both sides exchange.

pub(crate) mod client;
pub(crate) mod codec;
mod serve;

pub(crate) use serve::{Port, answer_all, serve};

/// The method table (notes/client-port.md §2): each row's arguments and result. A method not
/// listed is answered `Unsupported`. Every row runs as the session's actor (spec/wire.md §11.2
/// A client's rights), and is one API call, its arguments and result in `codec::Form`
/// forms (`serve::row`, `ReadOnly::forward`), but the write rows, which carry a nonce.
pub mod method {
    /// `[] -> [author, node, Opt(settings thing)]`: who this session acts as, at which node.
    pub const WHOAMI: u64 = 0;
    /// `[tid, ak, path] -> read result`: the value at `path` of an aspect, untyped (`[]`: the
    /// whole value).
    pub const GET: u64 = 1;
    /// `[tid] -> [ak*]`
    pub const ASPECTS: u64 = 2;
    /// `[tid] -> bool`
    pub const HAS_CONTENT: u64 = 3;
    /// `[tid] -> bool`: the thing is known here, content or not (where a thin client of several
    /// nodes finds a thing).
    pub const HAS_RECORD: u64 = 4;
    /// `[tid] -> [[holder, role, Opt(until), retain_copy, may_grant, from_now]*]`
    pub const GRANTS: u64 = 6;
    /// `[tid] -> Opt(role)`
    pub const ROLE_ON: u64 = 7;
    /// `[tid] -> Opt([commit id, actor, ts, received])`
    pub const CREATED: u64 = 8;
    /// `[tid] -> Opt([commit id, actor, ts, received])`
    pub const CHANGED: u64 = 9;
    /// `[nonce, actor, [ak*], [op*], Opt(expiry)] -> Opt(commit)`
    pub const WRITE: u64 = 10;
    /// `[nonce, scope] -> Opt(commit)`: the revert made
    pub const UNDO: u64 = 11;
    /// `[nonce, scope] -> Opt(commit)`
    pub const REDO: u64 = 12;
    /// `[nonce, commit id] -> commit`
    pub const REVERT: u64 = 13;
    /// `[scope] -> Opt(commit)`: what `UNDO` would revert now
    pub const UNDO_TARGET: u64 = 14;
    /// `[scope] -> Opt(commit)`
    pub const REDO_TARGET: u64 = 15;
    /// `[] -> []`, once every Notify for changes before it went.
    pub const SETTLE: u64 = 19;
    /// `[] -> wall ms`
    pub const NOW: u64 = 20;
    /// `[] -> [connected, [[tid, state, not_taking, leaving]*]]`: for a client's thing, the things
    /// it may read and the connections with one of them open.
    pub const STATUS: u64 = 21;
    /// `[tid] -> [[thing, kind, role, Opt(until), [through*]]*]`
    pub const HOLDERS: u64 = 22;

    /// `[address, query] -> page` (`writes`, `fired`, `versions`): at most what fits the Call's
    /// `max_reply`, `more` set when it cut the page.
    pub const LISTING: u64 = 16;
    /// `[address, commit id] -> Opt(commit)` (`AspectRef::commit`)
    pub const LISTED_COMMIT: u64 = 17;
    /// `[tid, role, admin, Opt(until), single_use] -> link text` (`make_link`)
    pub const MAKE_LINK: u64 = 18;
    /// `[tid] -> link text` (`public_link`)
    pub const PUBLIC_LINK: u64 = 23;

    // Rows that wait: never a Call, only as a Sub `[filter::WAIT, method, [arg*]]`.

    /// `[sync scope] -> []` (`wait_synced`), scope `[0]` all, `[1, tid]`.
    pub const WAIT_SYNCED: u64 = 27;
    /// `[link text, joiner] -> tid` (`redeem`)
    pub const REDEEM: u64 = 29;

    /// Whether a client session may call `m`: a row on things the actor may read. The
    /// others carry the node's own state (spec/wire.md §11.2), so a new row is main only unless
    /// listed here.
    pub fn for_client(m: u64) -> bool {
        m <= REDO_TARGET || matches!(m, SETTLE | NOW | STATUS | HOLDERS | LISTING | LISTED_COMMIT)
    }
}

/// The Sub filters (notes/client-port.md §2).
pub mod filter {
    /// `[0, tid, ak, path]`: the value at `path` of an aspect; the Reply carries it now, each
    /// Notify `[read result, origin]` when it reads otherwise.
    pub const VALUE: u64 = 0;
    /// `[1, tid]`: the thing's aspects; the Reply `[[ak, read result]*]` (those present), each
    /// Notify `[ak, read result, origin]` when one reads otherwise, above `max_reply` `[2, [ak,
    /// max_reply]]`.
    pub const THING: u64 = 1;
    /// `[2, tid]`: its grants, as `GRANTS` answers; a Notify when they read otherwise.
    pub const GRANTS: u64 = 2;
    /// `[3]`: the status, as `STATUS` answers; a Notify when it reads otherwise.
    pub const STATUS: u64 = 3;
    /// `[4]`: each diagnostic of the node (`on_diagnostic`); the Reply `[]`. Main only.
    pub const DIAGNOSTICS: u64 = 4;
    /// `[5, method, [arg*]]`: a row that waits, run at the node; the Reply `[]`, then one Notify
    /// with its outcome (`[0, value]` or `[1, code, detail*]`). An Unsub or the connection's end
    /// drops it, as dropping the future does locally. Main only.
    pub const WAIT: u64 = 5;
    /// `[6, address]`: the commits listed at a `LISTING` address (`on_write`, `on_fire`); the
    /// Reply `[]`, each Notify a commit event `[0, commit id, Opt(commit)]`, `[1]` (read again)
    /// or `[2, code, detail*]` (ended).
    pub const COMMITS: u64 = 6;
}

/// Ops of one write through another node (notes/client-port.md §2 Decoder limits): a write's
/// cost at the node, which serves its clients one request at a time, is bounded by it.
/// Restrictive (an app splits a larger write into several commits). At 0 nothing is written
/// through a node; at infinity one client's write stalls every other client of the node for as
/// long as it likes.
pub(crate) const MAX_WRITE_OPS: usize = 1024;

/// Write outcomes a node keeps per (identity, session id) for resends (spec/wire.md §11.2 Write
/// nonces). Minor: a client resends only what it had no answer to, which is what it sent within
/// one window; at 0 every resend is `OutcomeUnknown`; at infinity a session's memory grows with
/// every write it makes.
pub(crate) const WRITE_NONCES: usize = 64;

/// Client sessions a node serves at once, all clients together (spec/wire.md §11.2 Auth:
/// past it Error 4); also the main session's nonce sessions kept. Restrictive: at 0 no client is
/// served; at infinity clients take every connection.
pub(crate) const MAX_CLIENTS: usize = 64;

/// The reply allowance of a call that reads a value: the largest reply a frame takes, so a value
/// within `AppConfig::read_limit` that fits a frame is never refused `TooLarge` for the allowance.
pub(crate) const VALUE_REPLY: u64 = osis_proto::limits::REPLY_BUDGET as u64;

/// The reply allowance of every other call (spec/sync-streams.md §1).
pub(crate) const SMALL_REPLY: u64 = osis_proto::limits::SMALL_REPLY as u64;
