//! Stranded reports out (spec/permissions.md §4 Stranded, spec/sync-status.md §3 Stranded,
//! spec/wire.md §9 Stranded notice, §11.2 Stranded).
//!
//! Status says where this node is stranded (`Status::strandings`: a read S heard out with no
//! current read secret held, and what the report names). Per such S this part sends a Stranded
//! message, naming the holder with its holder keys, to each connected peer that proved an
//! account holding write or above on S's actor (`Engine::writer_of`); with none connected, it
//! logs a stranded notice under the inbox of each admin of the actor (stamped where it writes
//! that inbox, else deposited and offered). Each once per peer's account and per admin for each
//! report key: the step's sync key and the holder's current `keys.0` commits, so a report goes
//! again when the node reaches a newer step or its holder's keys move. A peer counts as told on
//! its Ok answer: one closed first, or answering otherwise (a store failure there), is told again
//! at the next proof of a connection.
//!
//! A node keeping S unread sends none: it judges no peer's role and holds no roster of S's
//! actor, so it knows no recipient (spec/permissions.md §4 "as the node judges it"); its way
//! back is a grant's boxes (spec/sync-judgement.md §6).
//!
//! Work follows change: status's strandings are read whole through one `Effects` key (moved
//! only when one is added, changes or goes); the connections proven are told by `proved` and
//! `closed`. A send pass runs only on such a move, over the strandings (normally none) and the
//! connections. Durable: per S reported, the latest report key and whom it went to (store rows
//! `I/x/`), so neither a restart nor a source reconnecting sends it again; a row goes when S is
//! no longer read here (checked at a start and as strandings move), a new key replacing it.

use super::offers::Offers;
use super::{Here, Net};
use crate::session::RequestId;
use crate::types::{ConnId, Result};
use osis_base::memo::Effects;
use osis_base::{SyncId, Tid};
use osis_engine::sync::Stranding;
use osis_proto::Msg;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const ROWS: &[u8] = b"I/x/";

/// Whom a report went to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum To {
    /// A connected peer, by the account it proved holding write or above.
    Peer(Tid),
    /// An admin's inbox.
    Admin(Tid),
}

/// The reports sent for one S, at one report key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Sent {
    key: [u8; 32],
    to: BTreeSet<To>,
}

impl Sent {
    fn encode(&self) -> Vec<u8> {
        let mut v = self.key.to_vec();
        for t in &self.to {
            let (k, x) = match t {
                To::Peer(x) => (0u8, x),
                To::Admin(x) => (1u8, x),
            };
            v.push(k);
            v.extend_from_slice(x.as_bytes());
        }
        v
    }
    fn decode(v: &[u8]) -> Option<Sent> {
        let key = v.get(..32)?.try_into().ok()?;
        let mut to = BTreeSet::new();
        for c in v.get(32..)?.chunks(16) {
            let x = Tid::from_bytes(c.get(1..)?.try_into().ok()?);
            to.insert(if c.first() == Some(&0) { To::Peer(x) } else { To::Admin(x) });
        }
        Some(Sent { key, to })
    }
}

/// A report's key: the step reached and the holder's current keys (spec/permissions.md §4: once
/// per sync key of the newest step; spec/sync-status.md §3: again when the holder's keys move).
fn report_key(st: &Stranding) -> [u8; 32] {
    let mut h = osis_base::hash::Hasher::new();
    h.update(&st.step).update(st.holder.as_bytes());
    for k in &st.keys {
        h.update(&k.0);
    }
    h.finalize()
}

#[derive(Clone)]
pub(super) struct Reports {
    seen: Effects<(), Arc<BTreeMap<SyncId, Arc<Stranding>>>>,
    now: Arc<BTreeMap<SyncId, Arc<Stranding>>>,
    sent: BTreeMap<SyncId, Sent>,
    /// Stranded messages awaiting their answer: S, the report key, the account told.
    out: BTreeMap<(ConnId, RequestId), (SyncId, [u8; 32], Tid)>,
    /// S whose `sent` an answer moved, written at the next settle.
    unsaved: BTreeSet<SyncId>,
    conns: BTreeSet<ConnId>,
    dirty: bool,
}

impl Default for Reports {
    fn default() -> Self {
        let mut seen = Effects::new("inbox: stranded");
        seen.want(());
        Reports { seen, now: Arc::default(), sent: BTreeMap::new(), out: BTreeMap::new(), unsaved: BTreeSet::new(), conns: BTreeSet::new(), dirty: false }
    }
}

impl Reports {
    /// Loads whom each report went to before this start.
    pub(super) fn start(&mut self, h: &mut Here<'_>) -> Result<()> {
        for (row, v) in h.store.with_tx(|t| t.scan_local(ROWS, b"", usize::MAX))? {
            let (Some(s), Some(sent)) = (row.get(ROWS.len()..).and_then(|x| Some(SyncId(x.try_into().ok()?))), Sent::decode(&v)) else { continue };
            self.sent.insert(s, sent);
        }
        for s in self.sent.keys().copied().collect::<Vec<_>>() {
            self.forget_unread(h, s)?;
        }
        Ok(())
    }

    /// Drops what S's report was sent to once S is no longer read here. Not on S merely judged
    /// not stranded: that is also status not having judged it yet (a restart, a source
    /// reconnecting), and the report goes once per key (spec/permissions.md §4).
    fn forget_unread(&mut self, h: &mut Here<'_>, s: SyncId) -> Result<()> {
        if h.engine.read_credentials(&s)?.is_some() {
            return Ok(());
        }
        self.sent.remove(&s);
        h.store.with_tx(|t| t.remove_local(&[ROWS, &s.0[..]].concat(), Shred::No))?;
        Ok(())
    }

    pub(super) fn proved(&mut self, conn: ConnId) {
        self.conns.insert(conn);
        self.dirty |= !self.now.is_empty();
    }

    pub(super) fn closed(&mut self, conn: ConnId) {
        self.conns.remove(&conn);
        self.out.retain(|(c, _), _| *c != conn);
    }

    /// An answer to a Stranded message: an Ok tells its account at that report key. Whether it
    /// was one of ours.
    pub(super) fn answered(&mut self, conn: ConnId, id: RequestId, m: &Msg) -> bool {
        let Some((s, key, acct)) = self.out.remove(&(conn, id)) else { return false };
        if matches!(m, Msg::Ok { .. })
            && let Some(sent) = self.sent.get_mut(&s).filter(|x| x.key == key)
            && sent.to.insert(To::Peer(acct))
        {
            self.unsaved.insert(s);
        }
        true
    }

    pub(super) fn settle(&mut self, h: &mut Here<'_>, net: &mut impl Net, offers: &mut Offers) -> Result<bool> {
        if let Some(status) = h.status
            && !self.seen.due().is_empty()
            && let Some((_, now)) = self.seen.settle(&(), || Arc::new(status.strandings().iter().map(|(s, x)| (*s, x.clone())).collect()))
        {
            self.now = now;
            self.dirty = true;
            let unjudged: Vec<SyncId> = self.sent.keys().filter(|s| !self.now.contains_key(*s)).copied().collect();
            for s in unjudged {
                self.forget_unread(h, s)?;
            }
        }
        let mut acted = false;
        for s in std::mem::take(&mut self.unsaved) {
            if let Some(sent) = self.sent.get(&s) {
                h.store.with_tx(|t| t.put_local(&[ROWS, &s.0[..]].concat(), &sent.encode(), Shred::No))?;
                acted = true;
            }
        }
        if !std::mem::take(&mut self.dirty) {
            return Ok(acted);
        }
        for (s, st) in self.now.clone().iter() {
            acted |= self.report(h, net, offers, *s, st)?;
        }
        Ok(acted)
    }

    /// Sends what is owed of S's report: a Stranded message to each connected writer's account
    /// not told at this key, else a notice to each admin not told.
    fn report(&mut self, h: &mut Here<'_>, net: &mut impl Net, offers: &mut Offers, s: SyncId, st: &Stranding) -> Result<bool> {
        let key = report_key(st);
        let was = self.sent.get(&s).cloned();
        let sent = was.clone().filter(|x| x.key == key).unwrap_or(Sent { key, to: BTreeSet::new() });
        let mut keys = None;
        let mut writers = 0;
        for conn in self.conns.clone() {
            let actors = crate::opens::counted(h.engine, &net.named(conn));
            let Some(acct) = h.engine.writer_of(&s, &actors)? else { continue };
            writers += 1;
            if sent.to.contains(&To::Peer(acct)) || self.out.values().any(|o| *o == (s, key, acct)) {
                continue;
            }
            let k = match &keys {
                Some(k) => k,
                None => keys.insert(h.engine.holder_keys(&st.holder)?),
            };
            if let Some(id) = net.request(conn, Msg::Stranded { id: 0, sync_id: s, holder: st.holder, keys: k.clone() }) {
                osis_base::costs::count("inbox: stranded sent", 1);
                self.out.insert((conn, id), (s, key, acct));
            }
        }
        if writers == 0 {
            // refgraph: (c) with no writer connected, fire a stranded notice on S's thing
            // (spec/sync-inbox.md §5), once per report key
            let _ = offers;
        }
        if was.as_ref() == Some(&sent) {
            return Ok(false);
        }
        h.store.with_tx(|t| t.put_local(&[ROWS, &s.0[..]].concat(), &sent.encode(), Shred::No))?;
        self.sent.insert(s, sent);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_proto::Code;

    // spec/permissions.md §4 (stranded), spec/wire.md §11.2: a peer counts as told only on its Ok
    // answer; one answering otherwise (a store failure there) or closed first is told again.
    #[test]
    fn a_peer_is_told_only_on_its_ok_spec_permissions_4() {
        let (s, key, acct) = (SyncId([1; 16]), [2; 32], Tid::from_bytes([3; 15]));
        let mut r = Reports::default();
        r.sent.insert(s, Sent { key, to: BTreeSet::new() });
        let told = |r: &Reports| r.sent[&s].to.contains(&To::Peer(acct));
        r.out.insert((ConnId(1), 5), (s, key, acct));
        assert!(r.answered(ConnId(1), 5, &Msg::Error { id: 5, code: Code::REFUSED }));
        assert!(!told(&r) && r.unsaved.is_empty(), "refused: untold");
        r.out.insert((ConnId(1), 6), (s, key, acct));
        r.closed(ConnId(1));
        assert!(!r.answered(ConnId(1), 6, &Msg::Ok { id: 6 }), "closed first: no longer awaited");
        assert!(!told(&r));
        r.out.insert((ConnId(2), 7), (s, key, acct));
        assert!(r.answered(ConnId(2), 7, &Msg::Ok { id: 7 }));
        assert!(told(&r) && r.unsaved.contains(&s), "Ok: told, written at the next settle");
    }
}
