//! First contact through a link (spec/sync-inbox.md §6), on the redeemer's side.
//!
//! `redeem` keeps the link durably (store rows `I/r/`, shredded: they hold the seed) and follows
//! it in the engine for this start (`Engine::follow_link`: L held, K's sync ID read in the sync
//! set), so the node proves L, opens K by L's static entry (opens) and its boxes open; the
//! link's peers are dial hints. Once the join can be written
//! (`Engine::redeemable`: the target's roster lists K, K's lists L, K's keyset is held) it is
//! written (`Engine::redeem`, which writes strongs to K and the target in D, so
//! both sync by the sync set from then on, link or not), once; the link is kept, and L held at
//! every start, until the join is held at a source of K's sync ID (status's view, spec/sync-
//! status.md §2: the join is an own commit while L is followed, `Engine::own_commits`); then it
//! is unfollowed and L forgotten (spec/permissions.md §7), its peers kept as dial hints (rows
//! `I/p/`, no seed) while the account holds K by a grant (`Engine::joined_link`; so too for a
//! link forgotten because a sibling joined), which is while the account reads the target through
//! K. So a redeem dropped or a restart before
//! the join reached the sharer's node still completes (`redeem-dropped-before-delivery`).
//!
//! One rule says whether there is anything to write: the account holding K by a grant
//! (`Engine::joined_link`, a join by this node or a sibling). Then `redeem` answers `Done` at once,
//! with no row, and a redeem under way is forgotten. A link that ends before the join (the held
//! role history shows L's edge on K, or K's on the target, removed or past `until`) is forgotten
//! the same way, and redeeming it again answers `Never`. So is a link not joined within the node's
//! follow time (`Policy::follow_link_ms`, from the redeem's start kept in its row, judged on the
//! engine's clock, whose wake comes through `Engine::clock_next`): a sharer that never answers is
//! followed no longer (spec/sync-inbox.md §6); the user may redeem it again. A joined link has no
//! follow time: its join is an own write waiting for a source like any other, and the seed is its
//! only way there (spec/permissions.md §7). Limit: a node stopping between the join's write and
//! its row's forgets the link at its next start (the join is the account's), so that join waits
//! for a source through D's strong to K alone. Not built: the other end, every route refusing L's static
//! entry (a link revoked before its join was taken is followed until then).
//!
//! Finalize is the sharer's engine's, on a complete pass of K's sync ID (status tells it).
//!
//! A locator (spec/sync-set.md §4) has no join: `redeem_public` follows it in the engine
//! (`Engine::follow_public`: the target's sync ID from the text read in the sync set, its public
//! entry tested) until the public's grant on the target is held here, then writes the strong to
//! the target in the joiner's `holds.0` (`Engine::redeem_public`) and forgets it: the strong brings
//! the target into the joiner's sync unit from then on. It is kept as a share link's is (a row
//! `I/r/` under its target, not shredded: no secret), so a restart goes on with it. Its follow
//! time is a share link's.
//!
//! Pairing (spec/permissions.md §8) hands over the account's locator: redeemed like any, so a
//! node paired and restarted before it entered the account still dials the pairer.

use super::Here;
use crate::types::{Result, Waiting};
use osis_base::memo::{Effects, Stamped};
use osis_base::{CommitId, Tid, WallMs};
use osis_engine::Engine;
use osis_blob::{DialHint, Link, Locator, ShareLink};
use osis_store::Shred;
use std::collections::BTreeMap;

const ROWS: &[u8] = b"I/r/";
/// A joined link's peers, kept once the link is forgotten.
const PEERS: &[u8] = b"I/p/";

#[derive(Clone, Debug)]
struct Pending {
    link: ShareLink,
    /// When this node started redeeming it (node clock): its follow time runs from here.
    since: WallMs,
    /// Whom the join grants K (spec/permissions.md §7 Redeem: an own thing or a thing its own
    /// things administer, such as the node's account).
    joiner: Tid,
    joined: Option<CommitId>,
}

/// A link's peers as dial hints.
fn link_hints(link: &ShareLink) -> Vec<DialHint> {
    link.peers.clone()
}

/// A redeem's durable row (`I/r/`, keyed by K or a locator's target), either kind of link:
/// `[joined: 0 | 1 commit][since][joiner][link text]`.
fn encode_row(link: &Link, since: WallMs, joiner: &Tid, joined: Option<CommitId>) -> Result<Vec<u8>> {
    let text = link.to_text().map_err(|_| crate::types::Error::NotBuilt("link text"))?;
    let joined = joined.map_or(vec![0], |c| [&[1u8][..], &c.0].concat());
    Ok([joined, since.0.to_be_bytes().to_vec(), joiner.as_bytes().to_vec(), text.into_bytes()].concat())
}

fn decode_row(v: &[u8]) -> Option<(Link, WallMs, Tid, Option<CommitId>)> {
    let (joined, rest) = match v.first()? {
        0 => (None, v.get(1..)?),
        _ => (Some(CommitId(v.get(1..33)?.try_into().ok()?)), v.get(33..)?),
    };
    let since = WallMs(u64::from_be_bytes(rest.get(..8)?.try_into().ok()?));
    let joiner = Tid::from_bytes(rest.get(8..8 + osis_base::format::TID_LEN)?.try_into().ok()?);
    let link = Link::from_text(std::str::from_utf8(rest.get(8 + osis_base::format::TID_LEN..)?).ok()?).ok()?;
    Some((link, since, joiner, joined))
}

impl Pending {
    fn encode(&self) -> Result<Vec<u8>> {
        encode_row(&Link::Share(self.link.clone()), self.since, &self.joiner, self.joined)
    }
}

impl PublicPending {
    fn encode(&self) -> Result<Vec<u8>> {
        encode_row(&Link::Locator(self.link.clone()), self.since, &self.joiner, None)
    }
}

fn row_key(k: &Tid) -> Vec<u8> {
    [ROWS, k.as_bytes()].concat()
}

fn peers_key(k: &Tid) -> Vec<u8> {
    [PEERS, k.as_bytes()].concat()
}

fn encode_peers(hints: &[DialHint]) -> Vec<u8> {
    osis_base::cbor::encode(&osis_base::Value::List(hints.iter().map(DialHint::to_value).collect()))
}

fn decode_peers(v: &[u8]) -> Option<Vec<DialHint>> {
    let osis_base::Value::List(l) = osis_base::cbor::decode(v, &osis_base::cbor::Limits::DEFAULT).ok()? else { return None };
    l.iter().map(|x| DialHint::from_value(x, usize::MAX, "kept link peer").ok()).collect()
}

/// What a link not joined yet waits on.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Stage {
    /// The join cannot be written yet (`Engine::redeemable`).
    Waiting,
    /// The join can be written.
    Ready,
    /// The link has ended (`Engine::link_ended`): the redeemer stops.
    Ended,
    /// The account holds K by a join another node wrote (`Engine::joined_link`): held here, so at
    /// a source; the redeemer stops.
    Joined,
    /// Not joined within the node's follow time: the redeemer stops.
    GaveUp,
}

/// A locator being redeemed (`redeem_public`).
#[derive(Clone, Debug)]
struct PublicPending {
    link: Locator,
    since: WallMs,
    joiner: Tid,
}

/// What a locator being redeemed waits on.
#[derive(Clone, Copy, PartialEq, Debug)]
enum PublicStage {
    /// The public's grant on the target is not held here yet.
    Waiting,
    /// It is: the strong can be written.
    Ready,
    /// The node closure holds the target: nothing to write.
    Held,
    /// Not redeemed within the node's follow time.
    GaveUp,
}

#[derive(Clone)]
pub(super) struct Redemptions {
    pending: BTreeMap<Tid, Pending>,
    /// Locators being redeemed, by target.
    public: BTreeMap<Tid, PublicPending>,
    public_ready: Effects<Tid, PublicStage>,
    /// Stamped: the driver follows the dial hints as they move.
    hints: Stamped<Tid, Vec<DialHint>>,
    ready: Effects<Tid, Stage>,
    held: Effects<Tid, bool>,
    /// Links forgotten while the account holds K by a grant, and offers taken: their peers stay
    /// dial hints (rows `I/p/`) while a joiner this node acts as holds the thing by a grant
    /// (`Engine::joiner_of`, spec/permissions.md §7 First contact).
    kept: Effects<Tid, bool>,
}

impl Default for Redemptions {
    fn default() -> Self {
        Redemptions { pending: BTreeMap::new(), public: BTreeMap::new(), public_ready: Effects::new("inbox: locator ready"), hints: Stamped::default(), ready: Effects::new("inbox: link ready"), held: Effects::new("inbox: join held"), kept: Effects::new("inbox: joined link's peers") }
    }
}

impl Redemptions {
    /// A start: every link being redeemed is held again.
    pub(super) fn start(&mut self, h: &mut Here<'_>) -> Result<()> {
        for (k, v) in h.store.with_tx(|t| t.scan_local(ROWS, b"", usize::MAX))? {
            let Some(k) = k.get(ROWS.len()..).and_then(|x| <[u8; 15]>::try_from(x).ok()).map(Tid::from_bytes) else { continue };
            match decode_row(&v) {
                Some((Link::Share(link), since, joiner, joined)) => self.follow(h, k, Pending { link, since, joiner, joined })?,
                Some((Link::Locator(link), since, joiner, None)) => self.follow_public(h, PublicPending { link, since, joiner }),
                _ => {}
            }
        }
        for (k, v) in h.store.with_tx(|t| t.scan_local(PEERS, b"", usize::MAX))? {
            let Some(hints) = decode_peers(&v) else { continue };
            let Some(k) = k.get(PEERS.len()..).and_then(|x| <[u8; 15]>::try_from(x).ok()).map(Tid::from_bytes) else { continue };
            if !self.pending.contains_key(&k) {
                self.hints.insert(k, hints);
                self.kept.want(k);
            }
        }
        Ok(())
    }

    fn follow(&mut self, h: &mut Here<'_>, k: Tid, p: Pending) -> Result<()> {
        h.engine.follow_link(&p.link)?;
        match p.joined {
            None => self.ready.want(k),
            Some(_) => self.held.want(k),
        }
        self.hints.insert(k, link_hints(&p.link));
        self.pending.insert(k, p);
        Ok(())
    }

    pub(super) fn redeem(&mut self, h: &mut Here<'_>, link: &ShareLink, joiner: Tid) -> Result<Waiting> {
        // a redeem before this start's: the kept row, with its start
        if !self.pending.contains_key(&link.k)
            && let Some((Link::Share(l), since, joiner, joined)) = h.store.with_tx(|t| t.get_local(&row_key(&link.k)))?.as_deref().and_then(decode_row)
        {
            self.follow(h, link.k, Pending { link: l, since, joiner, joined })?;
        }
        if let Some(p) = self.pending.get(&link.k) {
            return Ok(if p.joined.is_some() { Waiting::Done } else { Waiting::Pending });
        }
        // joined (here or at a sibling), the link forgotten or never followed here: nothing to write
        if h.engine.joined_link(&link.k) {
            return Ok(Waiting::Done);
        }
        if h.engine.link_ended(link) {
            return Ok(Waiting::Never("the link has ended"));
        }
        let p = Pending { link: link.clone(), since: h.now, joiner, joined: None };
        let row = p.encode()?;
        h.store.with_tx(|t| t.put_local(&row_key(&link.k), &row, Shred::Yes))?;
        self.follow(h, link.k, p)?;
        Ok(Waiting::Pending)
    }

    /// Redeems a locator (module doc): `Done` once the node closure holds its target.
    pub(super) fn redeem_public(&mut self, h: &mut Here<'_>, link: &Locator, joiner: Tid) -> Result<Waiting> {
        let t = link.target;
        if h.engine.closure_holds(&t) {
            return Ok(Waiting::Done);
        }
        if !self.public.contains_key(&t) {
            let p = PublicPending { link: link.clone(), since: h.now, joiner };
            let row = p.encode()?;
            h.store.with_tx(|x| x.put_local(&row_key(&t), &row, Shred::No))?;
            self.follow_public(h, p);
        }
        Ok(Waiting::Pending)
    }

    fn follow_public(&mut self, h: &mut Here<'_>, p: PublicPending) {
        let t = p.link.target;
        h.engine.follow_public(&p.link);
        self.hints.insert(t, p.link.peers.clone());
        self.public.insert(t, p);
        self.public_ready.want(t);
    }

    pub(super) fn settle(&mut self, h: &mut Here<'_>) -> Result<bool> {
        let mut acted = false;
        for t in self.public_ready.due() {
            let Some(p) = self.public.get(&t).cloned() else {
                self.public_ready.unwant(&t);
                continue;
            };
            let engine = &mut *h.engine;
            let until = WallMs(p.since.0.saturating_add(h.policy.follow_link_ms()));
            let stage = || match () {
                _ if engine.closure_holds(&t) && engine.reaches(&t) => PublicStage::Held,
                _ if engine.reaches(&t) => PublicStage::Ready,
                _ if engine.reached(until) => PublicStage::GaveUp,
                _ => PublicStage::Waiting,
            };
            let Some((_, stage)) = self.public_ready.settle(&t, stage) else { continue };
            match stage {
                PublicStage::Waiting => continue,
                // kept wanted until written: a failed write is tried again at the next change
                PublicStage::Ready if h.engine.redeem_public(&p.link, &p.joiner).is_err() => continue,
                _ => {}
            }
            self.public_ready.unwant(&t);
            self.public.remove(&t);
            self.hints.remove(&t);
            // the independent it follows, unless another locator being redeemed follows it
            let f = p.link.followed();
            if !self.public.values().any(|o| o.link.followed() == f) {
                h.engine.unfollow_link(&f);
            }
            h.store.with_tx(|x| x.remove_local(&row_key(&t), Shred::No))?;
            acted = true;
        }
        for k in self.ready.due() {
            let Some((link, since, joiner)) = self.pending.get(&k).map(|p| (p.link.clone(), p.since, p.joiner)) else {
                self.ready.unwant(&k);
                continue;
            };
            let engine = &mut *h.engine;
            let until = WallMs(since.0.saturating_add(h.policy.follow_link_ms()));
            let Some((_, stage)) = self.ready.settle(&k, || link_stage(engine, &link, until)) else { continue };
            if stage == Stage::Waiting {
                continue;
            }
            if matches!(stage, Stage::Ended | Stage::Joined | Stage::GaveUp) {
                self.ready.unwant(&k);
                self.forget(h, &k)?;
                acted = true;
                continue;
            }
            // kept wanted until the join is written: a failed write is tried again at the next
            // change of what it read
            let Some(c) = h.engine.redeem(&link, &joiner, link.single_use)?.commits.first().copied() else { continue };
            self.ready.unwant(&k);
            let p = Pending { link, since, joiner, joined: Some(c) };
            let row = p.encode()?;
            h.store.with_tx(|t| t.put_local(&row_key(&k), &row, Shred::Yes))?;
            self.pending.insert(k, p);
            self.held.want(k);
            acted = true;
        }
        for k in self.held.due() {
            let Some((s, c)) = self.pending.get(&k).and_then(|p| Some((p.link.k_sync_id, p.joined?))) else {
                self.held.unwant(&k);
                continue;
            };
            // at a source of K's sync ID (spec/permissions.md §7), whatever else it is under (D,
            // which files K, has no source while the account has one node)
            let status = h.status;
            let Some((_, true)) = self.held.settle(&k, || status.is_some_and(|st| st.held_under(&s, &c))) else { continue };
            self.held.unwant(&k);
            self.forget(h, &k)?;
            acted = true;
        }
        for k in self.kept.due() {
            let engine = &mut *h.engine;
            let Some((_, false)) = self.kept.settle(&k, || engine.joiner_of(&k).is_some()) else { continue };
            self.kept.unwant(&k);
            self.hints.remove(&k);
            h.store.with_tx(|t| t.remove_local(&peers_key(&k), Shred::No))?;
            acted = true;
        }
        Ok(acted)
    }

    /// Stops redeeming link K: unfollowed, L and the kept link forgotten (spec/permissions.md §7).
    /// Its peers stay dial hints while the account holds K by a grant (`kept`), else go.
    fn forget(&mut self, h: &mut Here<'_>, k: &Tid) -> Result<()> {
        let peers = self.pending.remove(k).map(|p| link_hints(&p.link)).unwrap_or_default();
        h.engine.unfollow_link(k);
        let keep = !peers.is_empty() && h.engine.joined_link(k);
        let row = encode_peers(&peers);
        h.store.with_tx(|t| {
            t.remove_local(&row_key(k), Shred::Yes)?;
            if keep { t.put_local(&peers_key(k), &row, Shred::No) } else { Ok(()) }
        })?;
        if keep {
            self.kept.want(*k);
        } else {
            self.hints.remove(k);
        }
        Ok(())
    }

    /// Whether link K, or a locator of target `k`, is being redeemed here.
    pub(super) fn redeeming(&self, k: &Tid) -> bool {
        self.pending.contains_key(k) || self.public.contains_key(k)
    }

    /// The peers of the links being redeemed (spec/wire.md §10: first-contact hints) and of
    /// those forgotten joined (`kept`).
    pub(super) fn hints(&self) -> impl Iterator<Item = &DialHint> {
        self.hints.values().flatten()
    }
}

/// The account joined K already, the link has ended, the join can be written (`Engine::redeemable`), or the follow time ran out
/// at `until` (the engine's clock read up to `until`, so its passing moves this).
fn link_stage(engine: &mut Engine, link: &ShareLink, until: WallMs) -> Stage {
    if engine.joined_link(&link.k) {
        return Stage::Joined;
    }
    if engine.link_ended(link) {
        return Stage::Ended;
    }
    if engine.redeemable(link) {
        return Stage::Ready;
    }
    if engine.reached(until) { Stage::GaveUp } else { Stage::Waiting }
}
