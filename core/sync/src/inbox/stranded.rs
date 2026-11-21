//! Stranded reports out (spec/permissions.md §4 Stranded, spec/sync-status.md §3 Stranded,
//! spec/wire.md §11.2 Stranded).
//!
//! Status says where this node is stranded (`Status::strandings`: a read S heard out with no
//! current read secret held, and what the report names). Per such S this part sends a Stranded
//! message, naming the holder with its holder keys, to each connected peer that proved an
//! account holding write or above on S's actor (`Engine::writer_of`); with none connected, it
//! fires a stranded notice on S's thing (`Engine::fire_stranded`, a sealed fire its writers see
//! later). Each once per peer's account, and the fire once, for each report key: the step's sync key and the holder's current `keys.0` commits, so a report goes
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
    /// A stranded notice fired on S's thing, naming this holder.
    Fire(Tid),
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
                To::Fire(x) => (1u8, x),
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
            to.insert(if c.first() == Some(&0) { To::Peer(x) } else { To::Fire(x) });
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

    pub(super) fn settle(&mut self, h: &mut Here<'_>, net: &mut impl Net) -> Result<bool> {
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
            acted |= self.report(h, net, *s, st)?;
        }
        Ok(acted)
    }

    /// Sends what is owed of S's report: a Stranded message to each connected writer's account
    /// not told at this key; with none connected, a stranded notice fired once at this key.
    fn report(&mut self, h: &mut Here<'_>, net: &mut impl Net, s: SyncId, st: &Stranding) -> Result<bool> {
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
        let mut sent = sent;
        if writers == 0 && !sent.to.contains(&To::Fire(st.holder)) {
            h.engine.fire_stranded(&s, &st.holder)?;
            osis_base::costs::count("inbox: stranded fired", 1);
            sent.to.insert(To::Fire(st.holder));
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
    use crate::store::Store;
    use osis_base::WallMs;
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

    // spec/sync-inbox.md §5 (Stranded notice: fired by a stranded node with no writer of it
    // connected), spec/permissions.md §4 (Stranded: once per sync key of the newest step): peer 0
    // rotates g's read leaving out reader m (peer 1), who takes it and is stranded. With nobody
    // connected m fires a stranded notice, once: a second settle and a start over the same store
    // fire none. (The writer's side: osis-engine `a_writer_taking_a_stranded_notice_reseals_its_holder`.)
    #[test]
    fn a_stranded_node_with_no_writer_connected_fires_once_spec_sync_inbox_5() {
        use osis_engine::local_peer::LocalPeer;
        let mut lp = LocalPeer::new(2, 0, WallMs(1_000_000)).unwrap();
        lp.sync_all().unwrap();
        let m = lp.peers[1].engine.me();
        let mut mu = osis_engine::Mutation::new();
        let me = lp.peers[0].engine.me();
        let g = lp.peers[0].engine.new_thing(&mut mu, me);
        lp.peers[0].commit(mu).unwrap();
        lp.peers[0].engine.make_independent(&g).unwrap();
        lp.hold(g);
        let edge = osis_schema::core_types::Edge { role: osis_base::Role::Read, until: None, invite: None, retain: false, floor: None };
        lp.peers[0].engine.grant(&g, &m, &edge).unwrap();
        lp.sync_all().unwrap();
        lp.peers[0].engine.rotate_leaving_out(&g, &[osis_base::Role::Read], &[m]).unwrap().unwrap();
        lp.sync(0, 1).unwrap();
        let e = &mut lp.peers[1].engine;
        let s = e.sync_ids(&g).unwrap()[0].id;
        let st = Arc::new(e.stranded(&s).unwrap().expect("m is stranded"));
        let (backend, root) = (osis_store::MemoryBackend::new(), osis_store::MemoryRoot::new());
        let mut store = Store::open(Box::new(backend.clone()), Box::new(root.clone()), Box::new(osis_crypto::SeededRng::from_u64(1))).unwrap();
        let policy = crate::types::Policy::default();
        let fired = |e: &mut osis_engine::Engine, store: &mut Store, r: &mut Reports| {
            let before = e.fires_owed().len();
            let mut h = Here { engine: e, status: None, store, now: WallMs(1_000_000), mono: osis_base::Mono(0), policy: &policy };
            r.now = Arc::new(BTreeMap::from([(s, st.clone())]));
            r.dirty = true;
            r.settle(&mut h, &mut super::super::suspect::tests::Records::default()).unwrap();
            h.engine.fires_owed().len() - before
        };
        let mut r = Reports::default();
        assert_eq!(fired(e, &mut store, &mut r), 1, "a stranded notice fired");
        assert_eq!(fired(e, &mut store, &mut r), 0, "once at this key");
        let mut store = Store::open(Box::new(backend), Box::new(root), Box::new(osis_crypto::SeededRng::from_u64(2))).unwrap();
        let mut r = Reports::default();
        r.start(&mut Here { engine: e, status: None, store: &mut store, now: WallMs(1_000_000), mono: osis_base::Mono(0), policy: &policy }).unwrap();
        assert_eq!(fired(e, &mut store, &mut r), 0, "nor again after a start");
    }
}
