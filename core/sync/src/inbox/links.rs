//! First contact through a link (spec/sync-inbox.md §6), on the redeemer's side.
//!
//! `redeem` keeps the link durably (store rows `I/r/`, shredded: they hold the seed) and holds
//! link key L for this start, so the node proves L, opens K by L's static entry (opens) and its
//! boxes open; the sharer's dialable key and relays are dial hints. Once K's roster here lists L
//! the join is written (`Ground::redeem`), once; the link is kept, and L held at every start,
//! until the join is held at a source (a redeemer proves L until its join is there). So a redeem
//! dropped or a restart before the join reached the sharer's node still completes
//! (`redeem-dropped-before-delivery`).
//!
//! Finalize is the sharer's engine's, on a complete pass of K's sync ID (status tells it).

use super::{DialHint, Ground, Here, settled};
use crate::types::{Result, Waiting};
use osis_base::memo::Effects;
use osis_base::{CommitId, Tid};
use osis_label::ShareLink;
use osis_store::Shred;
use std::collections::BTreeMap;

const ROWS: &[u8] = b"I/r/";

#[derive(Clone, Debug)]
struct Pending {
    link: ShareLink,
    joined: Option<CommitId>,
}

/// A link's sharer nodes as dial hints.
fn link_hints(link: &ShareLink) -> Vec<DialHint> {
    link.peers.iter().map(|p| DialHint { dialable: p.dialable, urls: p.relays.clone() }).collect()
}

impl Pending {
    fn encode(&self) -> Result<Vec<u8>> {
        let text = self.link.to_text().map_err(|_| crate::types::Error::NotBuilt("link text"))?;
        let joined = self.joined.map_or(vec![0], |c| [&[1u8][..], &c.0].concat());
        Ok([joined, text.into_bytes()].concat())
    }
    fn decode(v: &[u8]) -> Option<Pending> {
        let (joined, rest) = match v.first()? {
            0 => (None, v.get(1..)?),
            _ => (Some(CommitId(v.get(1..33)?.try_into().ok()?)), v.get(33..)?),
        };
        let link = ShareLink::from_text(std::str::from_utf8(rest).ok()?).ok()?;
        Some(Pending { link, joined })
    }
}

fn row_key(k: &Tid) -> Vec<u8> {
    [ROWS, k.as_bytes()].concat()
}

#[derive(Clone)]
pub(super) struct Redemptions {
    pending: BTreeMap<Tid, Pending>,
    hints: BTreeMap<Tid, Vec<DialHint>>,
    ready: Effects<Tid, bool>,
    held: Effects<Tid, bool>,
}

impl Default for Redemptions {
    fn default() -> Self {
        Redemptions { pending: BTreeMap::new(), hints: BTreeMap::new(), ready: Effects::new("inbox: link ready"), held: Effects::new("inbox: join held") }
    }
}

impl Redemptions {
    /// A start: every link being redeemed is held again.
    pub(super) fn start<G: Ground>(&mut self, h: &mut Here<'_, G>) -> Result<()> {
        for (k, v) in h.store.with_tx(|t| t.scan_local(ROWS, b"", usize::MAX))? {
            let Some(p) = Pending::decode(&v) else { continue };
            let Some(k) = k.get(ROWS.len()..).and_then(|x| <[u8; 15]>::try_from(x).ok()).map(Tid::from_bytes) else { continue };
            self.follow(h, k, p)?;
        }
        Ok(())
    }

    fn follow<G: Ground>(&mut self, h: &mut Here<'_, G>, k: Tid, p: Pending) -> Result<()> {
        h.g.hold_link(&p.link)?;
        match p.joined {
            None => self.ready.want(k),
            Some(_) => self.held.want(k),
        }
        self.hints.insert(k, link_hints(&p.link));
        self.pending.insert(k, p);
        Ok(())
    }

    pub(super) fn redeem<G: Ground>(&mut self, h: &mut Here<'_, G>, link: &ShareLink) -> Result<Waiting> {
        if let Some(p) = self.pending.get(&link.k) {
            return Ok(if p.joined.is_some() { Waiting::Done } else { Waiting::Pending });
        }
        let p = Pending { link: link.clone(), joined: None };
        let row = p.encode()?;
        h.store.with_tx(|t| t.put_local(&row_key(&link.k), &row, Shred::Yes))?;
        self.follow(h, link.k, p)?;
        Ok(Waiting::Pending)
    }

    pub(super) fn settle<G: Ground>(&mut self, h: &mut Here<'_, G>) -> Result<bool> {
        let mut acted = false;
        for k in self.ready.due() {
            let Some(link) = self.pending.get(&k).map(|p| p.link.clone()) else {
                self.ready.unwant(&k);
                continue;
            };
            let g = &mut *h.g;
            let Some((_, true)) = settled(&mut self.ready, &k, false, || g.link_ready(&link))? else { continue };
            self.ready.unwant(&k);
            let Some(c) = h.g.redeem(&link)? else { continue };
            let p = Pending { link, joined: Some(c) };
            let row = p.encode()?;
            h.store.with_tx(|t| t.put_local(&row_key(&k), &row, Shred::Yes))?;
            self.pending.insert(k, p);
            self.held.want(k);
            acted = true;
        }
        for k in self.held.due() {
            let Some(c) = self.pending.get(&k).and_then(|p| p.joined) else {
                self.held.unwant(&k);
                continue;
            };
            let g = &mut *h.g;
            let Some((_, true)) = settled(&mut self.held, &k, false, || g.held_elsewhere(&c))? else { continue };
            self.held.unwant(&k);
            self.pending.remove(&k);
            self.hints.remove(&k);
            h.store.with_tx(|t| t.remove_local(&row_key(&k), Shred::Yes))?;
            acted = true;
        }
        Ok(acted)
    }

    /// The sharer nodes of the links being redeemed (spec/wire.md §10: first-contact hints).
    pub(super) fn hints(&self) -> impl Iterator<Item = &DialHint> {
        self.hints.values().flatten()
    }
}
