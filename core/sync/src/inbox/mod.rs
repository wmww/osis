//! Deposits, steps and Register (spec/sync-inbox.md, spec/sync-ids.md §6 Steps and Register,
//! spec/wire.md §10).
//!
//! Principle: a deposit is the one way a non-writer adds an entry. This module carries what this
//! node owes others and what others left in its store:
//! - `offers`: Deposit items out, one unanswered per connection, refused-for-now backed off.
//! - `fires`: sealed fires this node owes, offered until a peer takes one.
//! - `tickets`: the account's tickets in D's `tickets.0`, one per thing entered outside the
//!   node root's local part.
//! - `held`: entries in this node's store to act on: deposits promoted by a writer, own deposits
//!   offered, clearing past the bounds.
//! - `register`: the recorded steps a source keeping S unread lacks, each once its stream showed
//!   the role commits it depends on.
//! - `serve`: Register, Delete and Stranded from peers (a Stranded report taken by the
//!   engine's `take_stranded`).
//! - `stranded`: this node's own stranded reports (status's `strandings`), by message to a
//!   connected writer of S's actor.
//! - `suspect`: suspect lists out (the engine's flags per S) and in (a writer's repair).
//! - `links`: first contact through a link, durable until the join is held elsewhere.
//!
//! Work follows change: the engine's values are read through `Effects` keys, the store's entries
//! through its entry feed, peers' moves through `moved`, never by walking what was sent.
//!
//! It reads the engine through its facade (`osis_engine::sync`) and the store directly; `Net`
//! is how it reads and sends through sessions, opens and streams (`Links` is the product's).
//! Each rule's decision is a function of plain values (`held::act_of`, `held::adds_delta`,
//! `held::to_clear`, `register::plan`) that tests drive directly; `Offers` reads the
//! engine through `offers::Judge`, so it runs over a test's `Net`, `Judge` and store as in a node.

mod fires;
mod held;
mod links;
mod offers;
mod register;
mod serve;
mod stranded;
mod suspect;
mod tickets;

pub use held::{Act, Facts, Judged, Promotion, act_of, adds_delta, promotion, to_clear};
pub use offers::{BACKOFF_MAX_MS, BACKOFF_MIN_MS, Judge, Offers, Target, backoff_ms};
pub use osis_engine::sync::Signers;
pub use register::{Plan, Progress, plan};

use crate::opens::{Member, Moved, Opens};
use crate::session::{Incoming, RequestId, Sessions, To};
use crate::store::{Source, Store};
use crate::streams::Streams;
use crate::types::{ConnId, Cx, Result, SourceClass, Waiting};
use osis_base::{BlobId, Mono, SyncId, Tid, WallMs};
use osis_engine::Engine;
use osis_blob::{DialHint, ShareLink, StepId};
use osis_proto::Msg;
use osis_store::Named;
use std::collections::BTreeSet;

/// What this module reads of sessions, opens and streams, and how it sends.
pub trait Net {
    /// What a connection's proofs counted for at its proof (opens' `named`): never who the peer
    /// is; that is `opens::counted` of it, judged now.
    fn named(&self, conn: ConnId) -> Named;
    fn member(&self, conn: ConnId, s: &SyncId) -> Option<Member>;
    /// That source's step for S: the head its stream last named (spec/sync-ids.md §6 Walk).
    fn head(&self, conn: ConnId, s: &SyncId) -> Option<StepId>;
    /// Whether that source's stream showed `b` present under S.
    fn present(&self, conn: ConnId, s: &SyncId, b: &BlobId) -> bool;
    /// Whether some source's stream showed `b` present under S (stamped).
    fn shown(&self, s: &SyncId, b: &BlobId) -> bool;
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
    fn named(&self, conn: ConnId) -> Named {
        self.opens.named(conn)
    }
    fn member(&self, conn: ConnId, s: &SyncId) -> Option<Member> {
        self.opens.member(conn, s).cloned()
    }
    fn head(&self, conn: ConnId, s: &SyncId) -> Option<StepId> {
        self.streams.known().head(self.streams.source(self.opens, conn), s)
    }
    fn present(&self, conn: ConnId, s: &SyncId, b: &BlobId) -> bool {
        self.streams.knows(self.streams.source(self.opens, conn), Some(conn), s, b)
    }
    fn shown(&self, s: &SyncId, b: &BlobId) -> bool {
        self.streams.known().present(s, b)
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
    offers: offers::Offers,
    fires: fires::Fires,
    tickets: tickets::AccountTickets,
    held: held::Held,
    register: register::Register,
    links: links::Redemptions,
    reports: stranded::Reports,
    suspects: suspect::Suspects,
}

impl std::fmt::Debug for Inbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inbox").field("started", &self.started).finish_non_exhaustive()
    }
}

/// One step's context for the module: the engine, the store and the time; status at a
/// settle (own commits held elsewhere).
pub(crate) struct Here<'a> {
    pub engine: &'a mut Engine,
    pub status: Option<&'a crate::status::Status>,
    pub store: &'a mut Store,
    /// The wall clock (a link's follow time is dated by it: it outlives a restart).
    pub now: WallMs,
    /// The monotonic clock the back-offs run on.
    pub mono: Mono,
    pub policy: &'a crate::types::Policy,
}

impl Inbox {
    /// Whether anything acted.
    pub fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, streams: &Streams, status: &crate::status::Status) -> Result<bool> {
        let Cx { engine, store, now, mono, policy, .. } = cx;
        let mut here = Here { engine, status: Some(status), store, now: *now, mono: *mono, policy };
        let mut net = Links { sessions, opens, streams };
        self.step(&mut here, &mut net)
    }

    /// A start: what this module makes the engine follow (links being redeemed) is
    /// followed again from the store, before any module reads the sync set (`leave` judges what
    /// left it by the set as it stands). Whether it started now.
    pub fn start(&mut self, cx: &mut Cx) -> Result<bool> {
        let Cx { engine, store, now, mono, policy, .. } = cx;
        let mut here = Here { engine, status: None, store, now: *now, mono: *mono, policy };
        self.begin(&mut here)
    }

    fn begin(&mut self, h: &mut Here<'_>) -> Result<bool> {
        if self.started {
            return Ok(false);
        }
        self.links.start(h)?;
        self.held.start(h, &mut self.offers)?;
        self.fires.start(h);
        self.tickets.start(h)?;
        self.reports.start(h)?;
        self.suspects.start(h);
        self.started = true;
        Ok(true)
    }

    fn step(&mut self, h: &mut Here<'_>, net: &mut impl Net) -> Result<bool> {
        let mut acted = self.begin(h)?;
        acted |= self.held.settle(h, &mut self.offers)?;
        acted |= self.fires.settle(h, &mut self.offers)?;
        acted |= self.tickets.settle(h)?;
        acted |= self.links.settle(h)?;
        acted |= self.register.settle(h, net)?;
        acted |= self.reports.settle(h, net)?;
        acted |= self.suspects.settle(h, net)?;
        acted |= self.offers.settle(h.mono, h.store, net, &mut *h.engine)?;
        Ok(acted)
    }

    /// Register, Delete, Stranded and Suspect requests; Deposit, Stranded and Register answers.
    pub fn on_message(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, streams: &Streams, conn: ConnId, m: Incoming) {
        let Cx { engine, store, now, mono, policy, .. } = cx;
        let mut here = Here { engine, status: None, store, now: *now, mono: *mono, policy };
        let mut net = Links { sessions, opens, streams };
        self.receive(&mut here, &mut net, conn, m);
    }

    fn receive(&mut self, h: &mut Here<'_>, net: &mut impl Net, conn: ConnId, m: Incoming) {
        match m {
            // judged here (spec/sync-compaction.md §1 Repair), answered Ok whatever it judges
            // (spec/wire.md §11.2); a failure judges the rest of the list at no later time
            Incoming::Request(id, Msg::Suspect { sync_id, entries, .. }) => {
                let _ = self.suspects.received(h, net, conn, sync_id, entries);
                net.answer(conn, id, Msg::Ok { id });
            }
            Incoming::Request(id, m) => serve::request(h, net, conn, id, m),
            Incoming::Reply(_, id, m) => {
                if !self.offers.answered(h.mono, conn, id, &m) && !self.reports.answered(conn, id, &m) {
                    self.register.answered(h.mono, conn, id, &m);
                }
            }
            Incoming::Proved | Incoming::Push(_) => {}
        }
    }

    /// A connection's proofs are done: it may take deposits.
    pub fn proved(&mut self, conn: ConnId, net: &impl Net) {
        self.offers.connected(conn, net);
        self.reports.proved(conn);
    }

    /// A member joined or left a connection's shared set.
    pub fn moved(&mut self, m: &Moved, net: &impl Net) {
        match *m {
            Moved::Joined(conn, s, _) => {
                self.offers.joined(conn, &s, net);
                // only a store keeping S unread registers steps (spec/sync-ids.md §6 Steps)
                if net.member(conn, &s).is_some_and(|m| m.class == SourceClass::Store) {
                    self.register.joined(conn, s);
                }
                self.suspects.joined(conn, s, net);
            }
            Moved::Left(conn, s, _) => {
                self.register.left(conn, &s);
                self.suspects.left(conn, &s);
            }
            Moved::Until(..) | Moved::Forgot(..) => {}
        }
    }

    /// A connection ended.
    pub fn on_closed(&mut self, conn: ConnId) {
        self.offers.closed(conn);
        self.register.closed(conn);
        self.reports.closed(conn);
        self.suspects.closed(conn);
    }

    /// First contact through a link (spec/sync-inbox.md §6): durable until the join is held
    /// elsewhere. `Done` once the join is written.
    pub fn redeem(&mut self, cx: &mut Cx, link: &ShareLink) -> Waiting {
        let Cx { engine, store, now, mono, policy, .. } = cx;
        let mut here = Here { engine, status: None, store, now: *now, mono: *mono, policy };
        self.redeem_on(&mut here, link)
    }

    fn redeem_on(&mut self, h: &mut Here<'_>, link: &ShareLink) -> Waiting {
        match self.links.redeem(h, link) {
            Ok(w) => w,
            Err(_) => Waiting::Never("the link could not be kept"),
        }
    }

    /// Whether link K is being redeemed here: a redeem not joined and not ended, nor given up
    /// (`Policy::follow_link_ms`).
    pub fn redeeming(&self, k: &Tid) -> bool {
        self.links.redeeming(k)
    }

    /// Dial hints from links being redeemed: dial candidates
    /// (spec/sync-opens.md §1), for dialing only. Stamped reads: the driver follows them in an
    /// `Effects` key, read again only as they move.
    pub fn dial_hints(&self) -> BTreeSet<DialHint> {
        self.links.hints().cloned().collect()
    }

    /// Whether a deposit to `conn` may land (spec/sync-opens.md §1 Keep or close).
    pub fn may_deposit(&self, conn: ConnId) -> bool {
        self.offers.may_land(conn)
    }

    pub fn next_wake(&self) -> Option<Mono> {
        [self.offers.next_wake(), self.register.next_wake()].into_iter().flatten().min()
    }
}
