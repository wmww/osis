//! The client port (spec/wire.md §11.2 kinds 24-29, spec/sync-transport.md §6,
//! notes/client-port.md): the `osis` API over a sync connection. `serve`: a node answers the
//! requests its connections carry, as itself for a main session or as a client actor;
//! `client`: a process uses a node it is a client of (a thin client, `Osis::connect`, or a
//! node's group source, `Osis::connect_node`); `codec`: the values both sides exchange.

pub(crate) mod client;
pub(crate) mod codec;
mod serve;

pub(crate) use serve::{Port, answer_all, serve};

/// The method table (notes/client-port.md §2): each row's arguments and result. A method not
/// listed is answered `Unsupported`. Every row runs as the session's actor (spec/wire.md §11.2
/// A client actor's rights).
pub mod method {
    /// `[] -> [me, node, home]`: who this session acts as, at which node.
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
    pub const HOLDS: u64 = 4;
    /// `[tid] -> [[item_of*], [subgroup_of*], [within*]]`
    pub const GROUPS_OF: u64 = 5;
    /// `[tid] -> [[holder, role, Opt(until), Opt(may_grant), with_membership]*]`
    pub const GRANTS: u64 = 6;
    /// `[tid] -> Opt(role)`
    pub const ROLE_ON: u64 = 7;
    /// `[tid] -> Opt([commit id, actor, ts, received])`
    pub const CREATED: u64 = 8;
    /// `[tid] -> Opt([commit id, actor, ts, received])`
    pub const CHANGED: u64 = 9;
    /// `[nonce, actor, [ak*], [op*], Opt(expiry)] -> Opt(commit)`
    pub const WRITE: u64 = 10;
    /// `[] -> []`, once every Notify for changes before it went.
    pub const SETTLE: u64 = 19;
    /// `[] -> wall ms`
    pub const NOW: u64 = 20;
    /// `[] -> [connected, [[tid, state, not_taking, leaving]*]]`: for a client actor, the things
    /// it may read and the connections with one of them open.
    pub const STATUS: u64 = 21;
    /// `[tid] -> [[actor, kind, role, Opt(until), [through*]]*]`
    pub const HOLDERS: u64 = 22;
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

/// Client-actor sessions a node serves at once, all clients together (spec/wire.md §11.2 Auth:
/// past it Error 4); also the main session's nonce sessions kept. Restrictive: at 0 no client is
/// served; at infinity clients take every connection.
pub(crate) const MAX_CLIENTS: usize = 64;

/// The reply allowance of a call that reads a value: the largest reply a frame takes, so a value
/// within `AppConfig::read_limit` that fits a frame is never refused `TooLarge` for the allowance.
pub(crate) const VALUE_REPLY: u64 = osis_proto::limits::REPLY_BUDGET as u64;

/// The reply allowance of every other call (spec/sync-streams.md §1).
pub(crate) const SMALL_REPLY: u64 = osis_proto::limits::SMALL_REPLY as u64;
