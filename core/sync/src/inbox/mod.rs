//! Inbox, deposits, steps and Register (spec/sync-inbox.md, spec/sync-ids.md §6 Steps and
//! Register, spec/wire.md §9-§10).
//!
//! Principle: an inbox is a sync ID like any other; a deposit is the one way a non-writer adds an
//! entry. This module carries what this node owes others and what others left in its store:
//! - `deliveries`: the inbox blobs this node owes (the engine's `deliveries`), logged stamped or
//!   deposited under the recipient's inbox, sealed again at their expiry or once the inbox moved,
//!   until the recipient is seen taking the grant (a commit of its, the engine's; an open of a
//!   sync ID the blob names with the recipient proven, this module's).
//! - `offers`: Deposit items out, one unanswered per connection, refused-for-now backed off.
//! - `held`: entries in this node's store to act on: inbox blobs taken (and stamped in place by a
//!   writer), deposits promoted by a writer, own deposits offered, clearing past the bounds.
//! - `register`: the recorded steps a source keeping S unread lacks, each once its stream showed
//!   the role commits it depends on.
//! - `serve`: Register, Delete, Stranded and Suspect from peers.
//! - `links`: first contact through a link, durable until the join is held elsewhere.
//!
//! Work follows change: the engine's values are read through `Effects` keys, the store's entries
//! through its entry feed, peers' moves through `moved`; a re-send is due at its blob's expiry
//! (a timer per delivery), never by walking what was sent.
//!
//! It reads the engine through its facade (`osis_engine::sync`) and the store directly; `Net`
//! is how it reads and sends through sessions, opens and streams (`Links` is the product's).
//! Each rule's decision is a function of plain values (`held::act_of`, `held::adds_delta`,
//! `held::to_clear`, `register::plan`) that tests drive directly; `Offers` takes its deposit
//! keys as a function, so it runs over a test's `Net` and store as in a node.

mod deliveries;
mod held;
mod links;
mod offers;
mod register;
mod serve;

pub use deliveries::Sent;
pub use held::{Act, Facts, act_of, adds_delta, to_clear};
pub use offers::{BACKOFF_MAX_MS, BACKOFF_MIN_MS, Offers, Target, backoff_ms};
pub use osis_engine::sync::Signers;
pub use register::{Plan, Progress, plan};

use crate::opens::{Member, Moved, Opens};
use crate::session::{Incoming, RequestId, Sessions, To};
use crate::store::{Source, Store};
use crate::streams::Streams;
use crate::types::{ConnId, Cx, Entry, Result, Waiting, Wrap};
use osis_base::{BlobId, SyncId, Tid, WallMs};
use osis_crypto::NodeRng;
use osis_engine::Engine;
use osis_label::{DialHint, ShareLink, StepId};
use osis_proto::Msg;
use std::collections::BTreeSet;

/// What this module reads of sessions, opens and streams, and how it sends.
pub trait Net {
    /// The actors a connection's proofs count for (opens' `proven`).
    fn actors(&self, conn: ConnId) -> Vec<Tid>;
    fn member(&self, conn: ConnId, s: &SyncId) -> Option<Member>;
    /// That source's step for S: the head its stream last named (spec/sync-ids.md §6 Walk).
    fn head(&self, conn: ConnId, s: &SyncId) -> Option<StepId>;
    /// Whether that source's stream showed `b` present under S.
    fn present(&self, conn: ConnId, s: &SyncId, b: &BlobId) -> bool;
    /// Moves at each arrival of the peer's filter (spec/sync-inbox.md §3: a refused Deposit item
    /// waits for the next; a new one may show a deposit key).
    fn filter_generation(&self, conn: ConnId) -> u64;
    /// Whether the peer's filter shows `key` as S's deposit key: it may keep S unread.
    fn shows_deposit_key(&self, conn: ConnId, s: &SyncId, key: &[u8; 32]) -> bool;
    /// Where that peer's charges and rows live.
    fn source(&self, conn: ConnId) -> Source;
    fn request(&mut self, conn: ConnId, m: Msg) -> Option<RequestId>;
    fn answer(&mut self, conn: ConnId, id: RequestId, m: Msg);
}

/// The product's `Net`: sessions, opens and streams.
pub struct Links<'a> {
    pub sessions: &'a mut Sessions,
    pub opens: &'a Opens,
    pub streams: &'a Streams,
}

impl Net for Links<'_> {
    fn actors(&self, conn: ConnId) -> Vec<Tid> {
        self.opens.proven(conn).to_vec()
    }
    fn member(&self, conn: ConnId, s: &SyncId) -> Option<Member> {
        self.opens.members(conn).get(s).cloned()
    }
    fn head(&self, conn: ConnId, s: &SyncId) -> Option<StepId> {
        self.streams.known().head(self.streams.source(self.opens, conn), s)
    }
    fn present(&self, conn: ConnId, s: &SyncId, b: &BlobId) -> bool {
        self.streams.knows(self.streams.source(self.opens, conn), Some(conn), s, b)
    }
    fn filter_generation(&self, conn: ConnId) -> u64 {
        self.opens.filter_arrivals(conn)
    }
    fn shows_deposit_key(&self, conn: ConnId, s: &SyncId, key: &[u8; 32]) -> bool {
        self.opens.shows_deposit_key(conn, s, key)
    }
    fn source(&self, conn: ConnId) -> Source {
        self.opens.record(conn).map_or(Source::Conn(conn), Source::Record)
    }
    fn request(&mut self, conn: ConnId, m: Msg) -> Option<RequestId> {
        self.sessions.get_mut(conn).map(|s| s.request(To::Inbox, m))
    }
    fn answer(&mut self, conn: ConnId, id: RequestId, m: Msg) {
        if let Some(s) = self.sessions.get_mut(conn) {
            s.answer(id, m);
        }
    }
}

#[derive(Clone, Default)]
pub struct Inbox {
    started: bool,
    deliveries: deliveries::Deliveries,
    offers: offers::Offers,
    held: held::Held,
    register: register::Register,
    links: links::Redemptions,
}

impl std::fmt::Debug for Inbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inbox").field("started", &self.started).finish_non_exhaustive()
    }
}

/// One step's context for the module: the engine, the store, the time and the rng; status at a
/// settle (own commits held elsewhere).
pub(crate) struct Here<'a> {
    pub engine: &'a mut Engine,
    pub status: Option<&'a crate::status::Status>,
    pub store: &'a mut Store,
    pub now: WallMs,
    pub rng: &'a mut dyn NodeRng,
}

impl Inbox {
    /// Whether anything acted.
    pub fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, streams: &Streams, status: &crate::status::Status) -> Result<bool> {
        let Cx { engine, store, now, rng, .. } = cx;
        let mut here = Here { engine, status: Some(status), store, now: *now, rng: &mut **rng };
        let mut net = Links { sessions, opens, streams };
        self.step(&mut here, &mut net)
    }

    fn step(&mut self, h: &mut Here<'_>, net: &mut impl Net) -> Result<bool> {
        let mut acted = false;
        if !self.started {
            self.links.start(h)?;
            self.deliveries.start(h, &mut self.offers)?;
            self.held.start(h, &mut self.offers)?;
            self.started = true;
            acted = true;
        }
        acted |= self.deliveries.settle(h, &mut self.offers)?;
        acted |= self.held.settle(h, &mut self.offers)?;
        acted |= self.links.settle(h)?;
        acted |= self.register.settle(h, net)?;
        let engine = &mut *h.engine;
        acted |= self.offers.settle(h.now, h.store, net, &mut |s, actor| Ok(engine.signers(s, actor.as_ref())?.deposit))?;
        Ok(acted)
    }

    /// Register, Delete, Stranded and Suspect requests; Deposit and Register answers.
    pub fn on_message(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, streams: &Streams, conn: ConnId, m: Incoming) {
        let Cx { engine, store, now, rng, .. } = cx;
        let mut here = Here { engine, status: None, store, now: *now, rng: &mut **rng };
        let mut net = Links { sessions, opens, streams };
        self.receive(&mut here, &mut net, conn, m);
    }

    fn receive(&mut self, h: &mut Here<'_>, net: &mut impl Net, conn: ConnId, m: Incoming) {
        match m {
            Incoming::Request(id, m) => serve::request(h, net, conn, id, m),
            Incoming::Reply(_, id, m) => {
                if !self.offers.answered(h.now, conn, id, &m) {
                    self.register.answered(h.now, conn, id, &m);
                }
            }
            Incoming::Proved | Incoming::Push(_) => {}
        }
    }

    /// A connection's proofs are done: it may take deposits.
    pub fn proved(&mut self, conn: ConnId, net: &impl Net) {
        self.offers.connected(conn, net);
    }

    /// A member joined or left a connection's shared set.
    pub fn moved(&mut self, m: &Moved, net: &impl Net) {
        match *m {
            Moved::Joined(conn, s, _) => {
                self.deliveries.opened(conn, &s, net);
                self.offers.joined(conn, &s, net);
                self.register.joined(conn, s);
            }
            Moved::Left(conn, s, _) => self.register.left(conn, &s),
            Moved::Until(..) => {}
        }
    }

    /// A connection ended.
    pub fn on_closed(&mut self, conn: ConnId) {
        self.offers.closed(conn);
        self.register.closed(conn);
    }

    /// First contact through a link (spec/sync-inbox.md §6): durable until the join is held
    /// elsewhere. `Done` once the join is written.
    pub fn redeem(&mut self, cx: &mut Cx, link: &ShareLink) -> Waiting {
        let Cx { engine, store, now, rng, .. } = cx;
        let mut here = Here { engine, status: None, store, now: *now, rng: &mut **rng };
        self.redeem_on(&mut here, link)
    }

    fn redeem_on(&mut self, h: &mut Here<'_>, link: &ShareLink) -> Waiting {
        match self.links.redeem(h, link) {
            Ok(w) => w,
            Err(_) => Waiting::Never("the link could not be kept"),
        }
    }

    /// Dial hints from inbox blobs taken and links being redeemed: dial candidates
    /// (spec/sync-opens.md §1), for dialing only. Stamped reads: the driver follows them in an
    /// `Effects` key, read again only as they move.
    pub fn dial_hints(&self) -> BTreeSet<DialHint> {
        self.held.hints().chain(self.links.hints()).cloned().collect()
    }

    /// Whether a deposit to `conn` may land (spec/sync-opens.md §1 Keep or close).
    pub fn may_deposit(&self, conn: ConnId) -> bool {
        self.offers.may_land(conn)
    }

    pub fn next_wake(&self) -> Option<WallMs> {
        [self.deliveries.next_wake(), self.offers.next_wake(), self.register.next_wake(), self.held.next_wake()].into_iter().flatten().min()
    }
}

/// An entry this node logs of its own.
fn own_entry(blob: BlobId, wrap: Wrap, stamp: Option<osis_crypto::Signature>, expires: Option<WallMs>) -> Entry {
    Entry { blob, wrap, stamp, deposited: stamp.is_none(), own: true, role: false, class: osis_label::Class::Durable, expires }
}
