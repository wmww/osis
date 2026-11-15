//! First contact through a link (spec/sync-inbox.md §6), on the redeemer's side.
//!
//! `redeem` keeps the link durably (store rows `I/r/`, shredded: they hold the seed) and follows
//! it in the engine for this start (`Engine::follow_link`: L held, K's sync ID read in the sync
//! set), so the node proves L, opens K by L's static entry (opens) and its boxes open; the
//! link's peers are dial hints. Once the join can be written
//! (`Engine::redeemable`: the target's roster lists K, K's lists L, K's keyset is held) it is
//! written (`Engine::redeem`, which files K and the target under D: a redeem is an accept, so
//! both sync by the sync set from then on, link or not), once; the link is kept, and L held at
//! every start, until the join is held at a source of K's sync ID (status's view, spec/sync-
//! status.md §2: the join is an own commit while L is followed, `Engine::own_commits`); then it
//! is unfollowed and L forgotten (spec/permissions.md §7). So a redeem dropped or a restart before
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
//! for a source by K's filing alone. Not built: the other end, every route refusing L's static
//! entry (a link revoked before its join was taken is followed until then).
//!
//! Finalize is the sharer's engine's, on a complete pass of K's sync ID (status tells it).

use super::{DialHint, Here};
use crate::types::{Result, Waiting};
use osis_base::memo::{Effects, Stamped};
use osis_base::{CommitId, Tid, WallMs};
use osis_engine::Engine;
use osis_blob::ShareLink;
use osis_store::Shred;
use std::collections::BTreeMap;

const ROWS: &[u8] = b"I/r/";

#[derive(Clone, Debug)]
struct Pending {
    link: ShareLink,
    /// When this node started redeeming it (node clock): its follow time runs from here.
    since: WallMs,
    joined: Option<CommitId>,
}

/// A link's peers as dial hints.
fn link_hints(link: &ShareLink) -> Vec<DialHint> {
    link.peers.clone()
}

impl Pending {
    fn encode(&self) -> Result<Vec<u8>> {
        let text = self.link.to_text().map_err(|_| crate::types::Error::NotBuilt("link text"))?;
        let joined = self.joined.map_or(vec![0], |c| [&[1u8][..], &c.0].concat());
        Ok([joined, self.since.0.to_be_bytes().to_vec(), text.into_bytes()].concat())
    }
    fn decode(v: &[u8]) -> Option<Pending> {
        let (joined, rest) = match v.first()? {
            0 => (None, v.get(1..)?),
            _ => (Some(CommitId(v.get(1..33)?.try_into().ok()?)), v.get(33..)?),
        };
        let since = WallMs(u64::from_be_bytes(rest.get(..8)?.try_into().ok()?));
        let link = ShareLink::from_text(std::str::from_utf8(rest.get(8..)?).ok()?).ok()?;
        Some(Pending { link, since, joined })
    }
}

fn row_key(k: &Tid) -> Vec<u8> {
    [ROWS, k.as_bytes()].concat()
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

#[derive(Clone)]
pub(super) struct Redemptions {
    pending: BTreeMap<Tid, Pending>,
    /// Stamped: the driver follows the dial hints as they move.
    hints: Stamped<Tid, Vec<DialHint>>,
    ready: Effects<Tid, Stage>,
    held: Effects<Tid, bool>,
}

impl Default for Redemptions {
    fn default() -> Self {
        Redemptions { pending: BTreeMap::new(), hints: Stamped::default(), ready: Effects::new("inbox: link ready"), held: Effects::new("inbox: join held") }
    }
}

impl Redemptions {
    /// A start: every link being redeemed is held again.
    pub(super) fn start(&mut self, h: &mut Here<'_>) -> Result<()> {
        for (k, v) in h.store.with_tx(|t| t.scan_local(ROWS, b"", usize::MAX))? {
            let Some(p) = Pending::decode(&v) else { continue };
            let Some(k) = k.get(ROWS.len()..).and_then(|x| <[u8; 15]>::try_from(x).ok()).map(Tid::from_bytes) else { continue };
            self.follow(h, k, p)?;
        }
        Ok(())
    }

    fn follow(&mut self, h: &mut Here<'_>, k: Tid, p: Pending) -> Result<()> {
        h.engine.follow_link(&p.link)?;
        match p.joined {
            None => self.ready.want(k),
            Some(_) => self.held.want(k),
        }
        let hints = link_hints(&p.link);
        if self.hints.get(&k) != Some(&hints) {
            self.hints.insert(k, hints);
        }
        self.pending.insert(k, p);
        Ok(())
    }

    pub(super) fn redeem(&mut self, h: &mut Here<'_>, link: &ShareLink) -> Result<Waiting> {
        // a redeem before this start's: the kept row, with its start
        if !self.pending.contains_key(&link.k)
            && let Some(p) = h.store.with_tx(|t| t.get_local(&row_key(&link.k)))?.as_deref().and_then(Pending::decode)
        {
            self.follow(h, link.k, p)?;
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
        let p = Pending { link: link.clone(), since: h.now, joined: None };
        let row = p.encode()?;
        h.store.with_tx(|t| t.put_local(&row_key(&link.k), &row, Shred::Yes))?;
        self.follow(h, link.k, p)?;
        Ok(Waiting::Pending)
    }

    pub(super) fn settle(&mut self, h: &mut Here<'_>) -> Result<bool> {
        let mut acted = false;
        for k in self.ready.due() {
            let Some((link, since)) = self.pending.get(&k).map(|p| (p.link.clone(), p.since)) else {
                self.ready.unwant(&k);
                continue;
            };
            let engine = &mut *h.engine;
            let until = WallMs(since.0.saturating_add(h.policy.follow_link_ms()));
            let Some((_, stage)) = self.ready.try_settle(&k, || link_stage(engine, &link, until))? else { continue };
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
            let me = h.engine.me();
            let Some(c) = h.engine.redeem(&link, &me, link.single_use)?.commits.first().copied() else { continue };
            self.ready.unwant(&k);
            let p = Pending { link, since, joined: Some(c) };
            let row = p.encode()?;
            h.store.with_tx(|t| t.put_local(&row_key(&k), &row, Shred::Yes))?;
            self.pending.insert(k, p);
            self.held.want(k);
            acted = true;
        }
        for k in self.held.due() {
            let Some((s, c)) = self.pending.get(&k).and_then(|p| Some((p.link.k_label, p.joined?))) else {
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
        Ok(acted)
    }

    /// Stops redeeming link K: unfollowed, L and the kept link forgotten (spec/permissions.md §7).
    fn forget(&mut self, h: &mut Here<'_>, k: &Tid) -> Result<()> {
        self.pending.remove(k);
        h.engine.unfollow_link(k);
        if self.hints.contains_key(k) {
            self.hints.remove(k);
        }
        h.store.with_tx(|t| t.remove_local(&row_key(k), Shred::Yes))?;
        Ok(())
    }

    /// Whether link K is being redeemed here.
    pub(super) fn redeeming(&self, k: &Tid) -> bool {
        self.pending.contains_key(k)
    }

    /// The sharer nodes of the links being redeemed (spec/wire.md §10: first-contact hints).
    pub(super) fn hints(&self) -> impl Iterator<Item = &DialHint> {
        self.hints.values().flatten()
    }
}

/// The account joined K already, the link has ended, the join can be written (`Engine::redeemable`), or the follow time ran out
/// at `until` (the engine's clock read up to `until`, so its passing moves this).
fn link_stage(engine: &mut Engine, link: &ShareLink, until: WallMs) -> Result<Stage> {
    if engine.joined_link(&link.k) {
        return Ok(Stage::Joined);
    }
    if engine.link_ended(link) {
        return Ok(Stage::Ended);
    }
    if engine.redeemable(link) {
        return Ok(Stage::Ready);
    }
    Ok(if engine.reached(until) { Stage::GaveUp } else { Stage::Waiting })
}
