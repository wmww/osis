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
//! Seams: `Ground` (the engine facade's calls this module makes; `Eng` is the product's),
//! `Net` (sessions, opens and streams as this module reads and sends through them; `Links` is
//! the product's), and the store itself.

mod deliveries;
mod held;
mod links;
mod offers;
mod register;
mod serve;

pub use deliveries::Sent;
pub use offers::{BACKOFF_MAX_MS, BACKOFF_MIN_MS, backoff_ms};

use crate::opens::{Member, Moved, Opens};
use crate::session::{Incoming, RequestId, Sessions, To};
use crate::store::{Source, Store};
use crate::streams::Streams;
use crate::types::{ConnId, Cx, Entry, Error, Result, Waiting, Wrap};
use osis_base::{BlobId, CommitId, SyncId, Tid, WallMs};
use osis_crypto::{NodeRng, SigningSecret};
use osis_engine::Engine;
use osis_engine::labeling::Certs;
use osis_engine::sync::{InboxOpened, PartSet, Path, Promote};
use osis_label::{ShareLink, StepId};
use osis_proto::Msg;
use std::collections::BTreeSet;
use std::sync::Arc;

/// The keys this node signs entries of S with.
#[derive(Clone, Default)]
pub struct Signers {
    /// Its head's write key, established here: stamps.
    pub stamp: Option<SigningSecret>,
    /// The deposit key S's head bears, from a held deposit seed.
    pub deposit: Option<SigningSecret>,
    /// Its head's delete key, established here: clearing deposits.
    pub delete: Option<SigningSecret>,
}

/// A dial hint: the sending node's dialable key and URLs (spec/wire.md §9 position 4, a link's
/// peers, spec/wire.md §10), for dialing only.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DialHint {
    pub key: [u8; 32],
    pub urls: Vec<String>,
}

/// What this module reads of the engine and the few commands it gives it (the facade,
/// `osis_engine::sync`, and the link flows). Every value call is a memo (or a stamped read), so
/// an `Effects` reading it follows exactly what it read. `Eng` is the product's.
pub trait Ground {
    // What this node owes (spec/sync-inbox.md §2)
    /// The deliveries owed and not seen taken by a commit of the recipient's.
    fn deliveries(&mut self) -> Result<Arc<BTreeSet<(CommitId, Tid)>>>;
    fn delivery_taken(&mut self, c: &CommitId, holder: &Tid) -> Result<bool>;
    /// The sync IDs a delivery's blob names (its payload's position 1): an open of one with the
    /// recipient proven shows it took the grant.
    fn delivery_names(&mut self, c: &CommitId, holder: &Tid) -> Result<Arc<Vec<SyncId>>>;
    /// The inbox actor `a`'s `keys.0` names.
    fn inbox_of(&mut self, a: &Tid) -> Result<Option<SyncId>>;
    /// The delivery's inbox blob, sealed now.
    fn inbox_blob(&mut self, c: &CommitId, holder: &Tid, rng: &mut dyn NodeRng) -> Result<Option<Vec<u8>>>;
    /// The keys this node signs entries of S with; `actor`: the actor whose `keys.0` names the
    /// deposit seed (the recipient of an inbox blob), else S's own thing's.
    fn signers(&mut self, s: &SyncId, actor: Option<&Tid>) -> Result<Signers>;

    // What others left here
    /// The inboxes this node reads: its own actors' (spec/sync-inbox.md §1).
    fn inboxes(&mut self) -> Result<Arc<BTreeSet<SyncId>>>;
    /// Takes the inbox blob held under `s`, or judges it again (spec/sync-inbox.md §2 Taking);
    /// `None`: nothing here opens it.
    fn take_inbox(&mut self, s: &SyncId, b: &BlobId) -> Result<Option<InboxOpened>>;
    /// The commit a held blob of S opened as.
    fn blob_commit(&mut self, s: &SyncId, b: &BlobId) -> Result<Option<CommitId>>;
    fn promotable(&mut self, s: &SyncId, c: &CommitId) -> Result<Promote>;
    /// The blobs held here that opened as commit `c` (any sync ID): a promoter stamps one copy
    /// per delta under S.
    fn commit_blobs(&mut self, c: &CommitId) -> Result<Arc<Vec<BlobId>>>;
    /// The parts an opened blob holds.
    fn blob_parts(&mut self, b: &BlobId) -> Result<Option<PartSet>>;
    /// The parts of `c` S must hold (its body under S).
    fn body_parts(&mut self, s: &SyncId, c: &CommitId) -> Result<Option<PartSet>>;
    /// Logs a promoted commit's author's chain under S as this node's certificate copies.
    fn log_chain(&mut self, s: &SyncId, chain: &Certs) -> Result<()>;

    // Steps (spec/sync-ids.md §6 Steps)
    /// S's path as this node's `sync.0` records it (its head last); `None`: S not read here.
    fn recorded_path(&mut self, s: &SyncId) -> Result<Option<Arc<Path>>>;
    /// The role commits of S's thing's actor step `step`'s epochs depend on, as the blob IDs this
    /// node logged them under S: a source must hold each before the step is registered there.
    fn step_needs(&mut self, s: &SyncId, step: &StepId) -> Result<Arc<Vec<BlobId>>>;

    // Links (spec/sync-inbox.md §6)
    /// Holds link key L from its seed for this start: it proves L and L's boxes open.
    fn hold_link(&mut self, link: &ShareLink) -> Result<()>;
    /// K's roster here lists L alive: the join can be written.
    fn link_ready(&mut self, link: &ShareLink) -> Result<bool>;
    /// Writes the join (`Engine::redeem`): its commit.
    fn redeem(&mut self, link: &ShareLink) -> Result<Option<CommitId>>;
    /// An own commit is held at a source (spec/sync-status.md §2).
    fn held_elsewhere(&mut self, c: &CommitId) -> Result<bool>;
}

/// What this module reads of sessions, opens and streams, and how it sends.
pub trait Net {
    /// The known actors a connection's proofs count for (opens' `proven`).
    fn actors(&self, conn: ConnId) -> Vec<Tid>;
    fn member(&self, conn: ConnId, s: &SyncId) -> Option<Member>;
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

/// The product's `Ground`: the engine.
pub struct Eng<'a> {
    pub engine: &'a mut Engine,
}

fn not_built<T>(what: &'static str) -> Result<T> {
    Err(Error::NotBuilt(what))
}

impl Ground for Eng<'_> {
    fn deliveries(&mut self) -> Result<Arc<BTreeSet<(CommitId, Tid)>>> {
        Ok(self.engine.deliveries()?)
    }
    fn delivery_taken(&mut self, c: &CommitId, holder: &Tid) -> Result<bool> {
        Ok(self.engine.delivery_taken(c, holder)?)
    }
    fn delivery_names(&mut self, _c: &CommitId, _holder: &Tid) -> Result<Arc<Vec<SyncId>>> {
        not_built("Engine::delivery_names")
    }
    fn inbox_of(&mut self, a: &Tid) -> Result<Option<SyncId>> {
        Ok(self.engine.inbox(a))
    }
    fn inbox_blob(&mut self, c: &CommitId, holder: &Tid, rng: &mut dyn NodeRng) -> Result<Option<Vec<u8>>> {
        Ok(self.engine.inbox_blob(c, holder, rng)?.map(|s| s.blob))
    }
    fn signers(&mut self, _s: &SyncId, _actor: Option<&Tid>) -> Result<Signers> {
        not_built("Engine::signers")
    }
    fn inboxes(&mut self) -> Result<Arc<BTreeSet<SyncId>>> {
        Ok(Arc::new(self.engine.inbox_actors().keys().copied().collect()))
    }
    fn take_inbox(&mut self, s: &SyncId, b: &BlobId) -> Result<Option<InboxOpened>> {
        Ok(Some(self.engine.take_inbox(s, b, false)?))
    }
    fn blob_commit(&mut self, _s: &SyncId, _b: &BlobId) -> Result<Option<CommitId>> {
        not_built("Engine::blob_commit")
    }
    fn promotable(&mut self, s: &SyncId, c: &CommitId) -> Result<Promote> {
        Ok(self.engine.promotable(s, c)?)
    }
    fn commit_blobs(&mut self, _c: &CommitId) -> Result<Arc<Vec<BlobId>>> {
        not_built("Engine::commit_blobs")
    }
    fn blob_parts(&mut self, b: &BlobId) -> Result<Option<PartSet>> {
        Ok(self.engine.blob_parts(b)?)
    }
    fn body_parts(&mut self, s: &SyncId, c: &CommitId) -> Result<Option<PartSet>> {
        Ok(self.engine.sync_bodies(c)?.get(s).map(|m| m.parts.clone()))
    }
    fn log_chain(&mut self, _s: &SyncId, _chain: &Certs) -> Result<()> {
        not_built("Engine::log_chain")
    }
    fn recorded_path(&mut self, s: &SyncId) -> Result<Option<Arc<Path>>> {
        let Some(t) = self.engine.sync_set()?.ids.get(s).map(|(t, _)| *t) else { return Ok(None) };
        Ok(self.engine.sync_ids(&t)?.iter().find(|o| o.id == *s && !o.hint).map(|o| o.path.clone()))
    }
    fn step_needs(&mut self, _s: &SyncId, _step: &StepId) -> Result<Arc<Vec<BlobId>>> {
        not_built("Engine::step_needs")
    }
    fn hold_link(&mut self, link: &ShareLink) -> Result<()> {
        self.engine.hold_key_actor(link.seed.clone())?;
        Ok(())
    }
    fn link_ready(&mut self, link: &ShareLink) -> Result<bool> {
        let l = osis_engine::identity::key_actor_tid(&link.seed);
        Ok(self.engine.roster(&link.k).contains_key(&l))
    }
    fn redeem(&mut self, link: &ShareLink) -> Result<Option<CommitId>> {
        let me = self.engine.me();
        Ok(self.engine.redeem(link, &me, link.single_use)?.commits.first().copied())
    }
    fn held_elsewhere(&mut self, _c: &CommitId) -> Result<bool> {
        not_built("Engine::held_elsewhere (status: own commits held at a source)")
    }
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

/// One step's context for the module: the engine, the store, the time and the rng.
pub struct Here<'a, G: Ground> {
    pub g: &'a mut G,
    pub store: &'a mut Store,
    pub now: WallMs,
    pub rng: &'a mut dyn NodeRng,
}

impl Inbox {
    /// Whether anything acted.
    pub fn settle(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, streams: &Streams) -> Result<bool> {
        let Cx { engine, store, now, rng, .. } = cx;
        let mut here = Here { g: &mut Eng { engine }, store, now: *now, rng: &mut **rng };
        let mut net = Links { sessions, opens, streams };
        self.step(&mut here, &mut net)
    }

    /// `settle` over any `Ground` and `Net`.
    pub fn step<G: Ground>(&mut self, h: &mut Here<'_, G>, net: &mut impl Net) -> Result<bool> {
        let mut acted = false;
        if !self.started {
            self.links.start(h)?;
            self.deliveries.start(h, &mut self.offers)?;
            self.held.start(h, &mut self.offers)?;
            self.started = true;
            acted = true;
        }
        // each part on its own: one the facade cannot serve yet leaves the others working
        acted |= built(self.deliveries.settle(h, &mut self.offers))?;
        acted |= built(self.held.settle(h, &mut self.offers))?;
        acted |= built(self.links.settle(h))?;
        acted |= built(self.register.settle(h, net))?;
        acted |= built(self.offers.settle(h, net))?;
        Ok(acted)
    }

    /// Register, Delete, Stranded and Suspect requests; Deposit and Register answers.
    pub fn on_message(&mut self, cx: &mut Cx, sessions: &mut Sessions, opens: &Opens, streams: &Streams, conn: ConnId, m: Incoming) {
        let Cx { engine, store, now, rng, .. } = cx;
        let mut here = Here { g: &mut Eng { engine }, store, now: *now, rng: &mut **rng };
        let mut net = Links { sessions, opens, streams };
        self.receive(&mut here, &mut net, conn, m);
    }

    /// `on_message` over any `Ground` and `Net`.
    pub fn receive<G: Ground>(&mut self, h: &mut Here<'_, G>, net: &mut impl Net, conn: ConnId, m: Incoming) {
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
            Moved::Left(conn, s) => self.register.left(conn, &s),
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
        let mut here = Here { g: &mut Eng { engine }, store, now: *now, rng: &mut **rng };
        self.redeem_on(&mut here, link)
    }

    /// `redeem` over any `Ground`.
    pub fn redeem_on<G: Ground>(&mut self, h: &mut Here<'_, G>, link: &ShareLink) -> Waiting {
        match self.links.redeem(h, link) {
            Ok(w) => w,
            Err(_) => Waiting::Never("the link could not be kept"),
        }
    }

    /// Dial hints from inbox blobs taken and links being redeemed: dial candidates
    /// (spec/sync-opens.md §1), for dialing only.
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

/// A part whose engine facade call is not built yet (branch sync-facade) does nothing until it
/// is (its keys stay due). Goes when the facade lands.
fn built(r: Result<bool>) -> Result<bool> {
    match r {
        Err(Error::NotBuilt(_) | Error::Engine(osis_engine::Error::NotBuilt(_))) => Ok(false),
        r => r,
    }
}

/// An entry this node logs of its own.
fn own_entry(blob: BlobId, wrap: Wrap, stamp: Option<osis_crypto::Signature>, expires: Option<WallMs>) -> Entry {
    Entry { blob, wrap, stamp, deposited: stamp.is_none(), own: true, role: false, class: osis_label::Class::Durable, expires }
}

/// Runs `f` in an `Effects` settle and hands back its error, keeping the key due.
fn settled<K: std::hash::Hash + Eq + Clone, V: Clone + PartialEq>(fx: &mut osis_base::memo::Effects<K, V>, k: &K, fallback: V, f: impl FnOnce() -> Result<V>) -> Result<Option<(Option<V>, V)>> {
    let mut failed = None;
    let moved = fx.settle(k, || {
        f().unwrap_or_else(|e| {
            failed = Some(e);
            fallback
        })
    });
    if let Some(e) = failed {
        fx.unwant(k);
        fx.want(k.clone());
        return Err(e);
    }
    Ok(moved)
}
