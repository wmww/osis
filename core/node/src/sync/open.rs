//! A label at a peer that cannot read it (spec/sync.md §5, §10; issues/net-one-peer.md 3h2, Stale
//! head): the credential of the newest step this node knows is tested against the peer's filter
//! and Hit; not shown, the recorded path's earlier credentials are walked, then the path is
//! registered from genesis; a peer whose head is past the recorded path is caught up with by
//! a Behind item, answered with the steps to its head, each verified under the one before. No
//! credential of the newest step held reports the label stranded (`reports`).

use super::{ConnId, LConn, Phase, SyncEngine};
use crate::error::Result;
use crate::labeling::{GroupLabel, HeadKeys};
use osis_base::{LabelId, Role, Tid};
use osis_crypto::{LabelRole, SigningSecret, X25519Secret, label_role_key, role_kem};
use osis_label::{ClaimSet, Step, StepId};
use osis_proto::{Code, Command, Request};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_schema::Codec;
use std::collections::BTreeMap;

/// Recorded steps by ID with their claim sets (`GroupLabel::steps`).
pub(crate) type Steps = BTreeMap<StepId, (Step, Option<ClaimSet>)>;

/// The recorded steps from `tip` back to the first one not recorded, oldest first; `None` on a
/// cycle.
pub(crate) fn path_to(steps: &Steps, tip: StepId) -> Option<Vec<&(Step, Option<ClaimSet>)>> {
    let mut path = Vec::new();
    let mut cur = Some(tip);
    while let Some(c) = cur {
        let Some(x) = steps.get(&c) else { break };
        if path.len() >= steps.len() {
            return None;
        }
        path.push(x);
        cur = x.0.prev;
    }
    path.reverse();
    Some(path)
}

/// The path to the deepest step that reaches a genesis step (the lowest ID among equals).
pub(crate) fn deepest_path(steps: &Steps) -> Option<Vec<&(Step, Option<ClaimSet>)>> {
    let rooted = |p: &Vec<&(Step, Option<ClaimSet>)>| p.first().is_some_and(|(s, _)| s.prev.is_none());
    steps.keys().rev().filter_map(|id| path_to(steps, *id).filter(rooted)).max_by_key(Vec::len)
}

/// Every recorded step reaching a genesis step, deepest first (ties by ID). O(steps).
pub(crate) fn deepest_first(steps: &Steps) -> Vec<Step> {
    let mut depth: BTreeMap<StepId, Option<usize>> = BTreeMap::new();
    for id in steps.keys() {
        // the chain back to a step whose depth is known, or to a genesis step or a gap
        let mut chain = Vec::new();
        let mut cur = Some(*id);
        let base = loop {
            let Some(c) = cur else { break Some(0) };
            if let Some(d) = depth.get(&c) {
                break *d;
            }
            let Some((st, _)) = steps.get(&c) else { break None };
            if chain.len() > steps.len() {
                break None;
            }
            chain.push(c);
            cur = st.prev;
        };
        for (i, c) in chain.iter().rev().enumerate() {
            depth.insert(*c, base.map(|b| b + i + 1));
        }
    }
    let mut out: Vec<(usize, &Step)> = steps.iter().filter_map(|(id, (st, _))| depth.get(id).copied().flatten().map(|d| (d, st))).collect();
    out.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.id().cmp(&b.1.id())));
    out.into_iter().map(|(_, st)| st.clone()).collect()
}

impl SyncEngine {
    /// X25519 keys this node may be listed by in a claim set: its own, the KEM key of each held
    /// epoch of its accounts, and the read-role KEM key of every held read epoch of the actors it
    /// holds secrets of (spec/sync.md §2); of the actors in `only` (this node's own key if it is
    /// one), when given.
    fn claim_keys_of(&self, only: Option<&std::collections::BTreeSet<Tid>>) -> Vec<X25519Secret> {
        let mut v = Vec::new();
        if only.is_none_or(|o| o.contains(&self.engine.tid())) {
            v.push(self.engine.identity().keys().kem.x25519().clone());
        }
        for p in self.engine.core.accounts.keys().filter(|t| only.is_none_or(|o| o.contains(t))) {
            v.extend(self.engine.account_kems(p).iter().map(|k| k.x25519().clone()));
        }
        for (_, e) in self.engine.core.ix.secrets.iter().filter(|(t, _)| only.is_none_or(|o| o.contains(t))) {
            for (_, s) in e.read.held_newest_first() {
                v.push(role_kem(s).x25519().clone());
            }
        }
        v
    }

    /// The group label `l` as recorded, or a hint's.
    pub(crate) fn group_label(&mut self, g: &Tid, l: &LabelId) -> Option<std::sync::Arc<GroupLabel>> {
        self.engine.labels_of(g).into_iter().find(|x| x.id == *l)
    }

    /// Follows `thing`'s label known only by ID and hosts (a
    /// link's label: the thing's first, index 0, spec/wire.md §10): opened by the static entry
    /// of `via`, a held key actor, or a held read secret.
    pub fn follow(&mut self, via: Tid, thing: Tid, label: LabelId, hosts: Vec<osis_label::Address>) -> Vec<super::Action> {
        self.state.add_hint(label, super::state::Hint { thing, index: 0, hosts, via: Some(via), inbox: None });
        self.handle(super::Event::Local)
    }

    /// Starts `l` on `conn`: it waits for the peer's filter to show the credential of the newest
    /// recorded head, or of a hint's (`Phase::Testing`); holding none of it (sync key, claim key
    /// or static entry), L is stranded here and nothing is tested.
    pub(crate) fn start_label(&mut self, conn: ConnId, g: Tid, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let index = self.group_label(&g, &l).map(|gl| gl.index).or_else(|| self.state.hints.get(&l).map(|h| h.index)).unwrap_or(0);
        let now = self.now();
        if let Some(c) = self.conns.get_mut(&conn) {
            let mut lc = Self::new_lc(g, index);
            lc.last_sync = now;
            c.labels.insert(l, lc);
            // a start (or a retry once a back-off passed) walks against the latest filter, from
            // scratch: a path registered before is no reason to strand (the peer's head may have
            // moved past it since, which only a Behind item finds)
            c.req.walked.remove(&l);
            c.req.registered.remove(&l);
        }
        if self.strands(conn, l, out)? {
            return Ok(());
        }
        // open there already by the connection's restored record
        if self.shared_member(conn, &l) {
            return self.member_unread_there(conn, l, true, out);
        }
        self.shared_retest(conn, out)
    }

    fn new_lc(group: Tid, index: u64) -> LConn {
        LConn {
            group,
            index,
            phase: Phase::Testing { shown: None },
            head: None,
            keys: HeadKeys::default(),
            sync_seq: 0,
            synced: false,
            fill: None,
            registering: None,
            step_retry: 0,
            step_refusals: 0,
            last_sync: 0,
            relisted: None,
            report_at: None,
            full: false,
            lacking: 0,
            refused: 0,
            writers: Vec::new(),
        }
    }

    /// The newest recorded head of `l`: the tip of the served path (`deepest_path`).
    pub(crate) fn newest_step(&mut self, g: &Tid, l: &LabelId) -> Option<Step> {
        let gl = self.group_label(g, l)?;
        deepest_path(&gl.steps)?.last().map(|(s, _)| s.clone())
    }

    /// The key a Hit on `step`'s credential signs with: its sync key when this node holds the
    /// epoch's sync secret, else this node's claim key on it (as `claimants`) while the step's
    /// claim set is held and lists it.
    pub(crate) fn step_key(&mut self, g: &Tid, index: u64, l: &LabelId, step: &Step) -> Option<SigningSecret> {
        match self.step_keys(g, index, l, step) {
            (keys, true) => keys.into_iter().next(),
            (_, false) => None,
        }
    }

    /// The keys a Hit on one of `step`'s credentials may sign with, and whether they are known to
    /// be its: its sync key when held; else, while the step's claim set is held, this node's claim
    /// key it lists; else every claim key of this node's on it (as `claimants`), which only its
    /// filter tells apart (the walk's, `walk_candidates`).
    fn step_keys(&mut self, g: &Tid, index: u64, l: &LabelId, step: &Step) -> (Vec<SigningSecret>, bool) {
        if let Some(e) = self.engine.epochs(g)
            && let Some(k) = e.sync.held_newest_first().into_iter().map(|(_, s)| label_role_key(LabelRole::Sync, s, index)).find(|k| k.verifying_key() == step.keys.sync)
        {
            return (vec![k], true);
        }
        let set = self.group_label(g, l).and_then(|gl| gl.steps.get(&step.id()).and_then(|x| x.1.clone()));
        let hinted = self.state.hints.contains_key(l);
        let Ok(only) = self.claimants(g, hinted) else { return (Vec::new(), true) };
        let keys: Vec<SigningSecret> = self.claim_keys_of(Some(&only)).iter().filter_map(|x| step.claim_key(x).ok()).collect();
        self.stats.claim_keys += keys.len() as u64;
        match set {
            Some(set) => (keys.into_iter().filter(|k| set.contains(&k.verifying_key().to_bytes())).take(1).collect(), true),
            None => (keys, false),
        }
    }

    /// The newest step of `l` this node knows at `conn` (`LConn::head`: the head there while
    /// open, else where a walk, a grant or the last open there got to), else the newest recorded
    /// head.
    pub(crate) fn newest_known(&mut self, conn: ConnId, l: &LabelId) -> Option<Step> {
        let (g, head) = self.lc(conn, l).map(|x| (x.group, x.head.clone()))?;
        head.or_else(|| self.newest_step(&g, l))
    }

    /// The key a Hit on `step`'s credential at `conn` signs with: its sync key when held, else
    /// this node's claim key its held claim set lists, else (the set not held) the claim key of
    /// this node's on it that the peer's latest filter shows and did not refuse since.
    pub(crate) fn test_key(&mut self, conn: ConnId, l: &LabelId, step: &Step) -> Option<SigningSecret> {
        let (g, index) = self.lc(conn, l).map(|x| (x.group, x.index))?;
        match self.step_keys(&g, index, l, step) {
            (keys, true) => keys.into_iter().next(),
            (keys, false) => keys.into_iter().find(|k| {
                let v = k.verifying_key().to_bytes();
                !self.conns.get(&conn).is_some_and(|c| c.req.refused.contains(&(*l, v))) && self.shared_shows(conn, l, &v)
            }),
        }
    }

    /// The sync key a hint's label (no step known) is Hit by at `conn`: of the sync secrets held
    /// of its thing, at the hint's index, the newest the peer's latest filter shows and did not
    /// refuse since (a filter keeps a moved head's entries until a whole one goes), else the
    /// newest (the head need not bear the newest epoch: one made and not established yet).
    /// Whatever head bears it at a peer opens; nothing else does. O(sync epochs held).
    pub(crate) fn hint_key(&mut self, conn: ConnId, l: &LabelId, g: &Tid, index: u64) -> Option<SigningSecret> {
        let e = self.engine.epochs(g)?;
        let keys: Vec<SigningSecret> = e.sync.held_newest_first().into_iter().map(|(_, s)| label_role_key(LabelRole::Sync, s, index)).collect();
        let refused = |s: &Self, k: &[u8; 32]| s.conns.get(&conn).is_some_and(|c| c.req.refused.contains(&(*l, *k)));
        let shown = keys.iter().position(|k| {
            let v = k.verifying_key().to_bytes();
            !refused(self, &v) && self.shared_shows(conn, l, &v)
        });
        keys.into_iter().nth(shown.unwrap_or(0))
    }

    /// `l` on `conn` holds no credential of the newest step it knows (sync key, claim key or
    /// static entry): it is stranded here (spec/permissions.md §4), tests, walks and registers
    /// nothing, and is tried again after `resync_ms` (`Phase::Failed`). A hint's label knowing
    /// no step fails so when it holds neither a sync key nor the static entry it follows by.
    /// Whether it is.
    pub(crate) fn strands(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<bool> {
        let Some((g, index)) = self.lc(conn, &l).map(|x| (x.group, x.index)) else { return Ok(false) };
        let Some(newest) = self.newest_known(conn, &l) else {
            let via = self.state.hints.get(&l).is_some_and(|h| h.via.is_some());
            if via || self.hint_key(conn, &l, &g, index).is_some() {
                return Ok(false);
            }
            self.fail(conn, l);
            return Ok(true);
        };
        if !self.step_keys(&g, index, &l, &newest).0.is_empty() || self.static_listed_at(&g, &l, &newest) {
            return Ok(false);
        }
        self.fail(conn, l);
        self.stranded(conn, g, l, out)?;
        Ok(true)
    }

    /// Whether `step`'s held claim set lists the static entry of a key actor this node holds.
    fn static_listed_at(&mut self, g: &Tid, l: &LabelId, step: &Step) -> bool {
        let Some(set) = self.group_label(g, l).and_then(|gl| gl.steps.get(&step.id()).and_then(|x| x.1.clone())) else { return false };
        self.engine.core.key_actors.values().any(|id| set.contains(&osis_crypto::static_entry(l, &id.keys().signing.verifying_key())))
    }

    /// The walk's credentials of `l` at `conn` (issues/net-one-peer.md 3h2, Stale head): of the
    /// recorded steps, every branch of the tree (two admins' concurrent children: the peer holds
    /// one), deepest first, each distinct one once, but `tested` (what the arrival's test
    /// offered). O(steps).
    pub(crate) fn walk_candidates(&mut self, conn: ConnId, l: LabelId, tested: Option<[u8; 32]>) -> Result<Vec<(Step, SigningSecret)>> {
        let Some((g, index)) = self.lc(conn, &l).map(|x| (x.group, x.index)) else { return Ok(Vec::new()) };
        let Some(steps) = self.group_label(&g, &l).map(|gl| deepest_first(&gl.steps)) else { return Ok(Vec::new()) };
        let mut seen: Vec<[u8; 32]> = tested.into_iter().collect();
        let mut out = Vec::new();
        for step in steps {
            for k in self.step_keys(&g, index, &l, &step).0 {
                let v = k.verifying_key().to_bytes();
                if seen.contains(&v) {
                    continue;
                }
                seen.push(v);
                self.stats.walk_tests += 1;
                out.push((step.clone(), k));
            }
        }
        Ok(out)
    }

    /// The walk's outcome: the step whose credential the peer's filter showed is Hit, and L opens
    /// at it. None shown: the peer holds L past the newest step known, or lacks it: a Behind item
    /// on that step asks (a credential of it held), and the recorded path is registered from
    /// genesis only where it is refused (or no credential of it is held). A genesis alone is
    /// registered first, a 9 to it then asking by a Behind item.
    pub(crate) fn walked(&mut self, conn: ConnId, l: LabelId, shown: Option<(Step, SigningSecret)>, out: &mut Vec<super::Action>) -> Result<()> {
        match shown {
            Some(x) => {
                if let Some(lc) = self.lc_mut(conn, &l) {
                    lc.phase = Phase::Testing { shown: Some(Box::new(x)) };
                }
                self.shared_retest(conn, out)
            }
            None => {
                let Some((g, index)) = self.lc(conn, &l).map(|x| (x.group, x.index)) else { return Ok(()) };
                let newest = self.newest_known(conn, &l);
                let held = newest.as_ref().is_some_and(|s| !self.step_keys(&g, index, &l, s).0.is_empty());
                // a genesis alone costs one Register, as a Behind item does, and covers a
                // peer lacking L (a new label); a 9 to it is answered by a Behind item
                let genesis = newest.as_ref().is_none_or(|s| s.prev.is_none());
                if held && !genesis && !self.conns.get(&conn).is_some_and(|c| c.req.registered.contains_key(&l)) {
                    return self.behind(conn, l, out);
                }
                self.register_path(conn, l, out)
            }
        }
    }

    /// `l` became a member of `conn`'s shared set (a Hit on this node's credential, a static
    /// entry's grant, the peer's own Hit, read credentials, or a record restored on connecting):
    /// open there, whatever it waited for (`Phase::Open` is membership), at the step it was tested
    /// at (the walk's, else the newest known), or, restored, at the head last known there. A
    /// hint's label knowing no step opens with no head: the stream's head event names it
    /// (`new_head`).
    pub(crate) fn member_unread_there(&mut self, conn: ConnId, l: LabelId, restored: bool, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(c) = self.conns.get(&conn).filter(|c| !c.peer) else { return Ok(()) };
        let host = c.host;
        let Some(lc) = c.labels.get(&l).filter(|x| !x.phase.is_open()) else { return Ok(()) };
        let (g, index) = (lc.group, lc.index);
        let shown = match &lc.phase {
            Phase::Testing { shown } => shown.as_deref().cloned(),
            _ => None,
        };
        let known = if restored { self.state.heads.get(&(host, l)).cloned() } else { None };
        let (step, by) = match shown {
            Some((s, k)) => (Some(s), Some(k)),
            None => match known.or_else(|| self.newest_known(conn, &l)) {
                Some(step) => {
                    let key = self.test_key(conn, &l, &step);
                    (Some(step), key)
                }
                None => (None, self.hint_key(conn, &l, &g, index)),
            },
        };
        if let Some(step) = step {
            self.set_head(conn, l, step)?;
        }
        if let Some(c) = self.conns.get_mut(&conn) {
            c.req.registered.remove(&l);
            self.refusals.remove(&(host, l));
        }
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.phase = Phase::Open { by: by.map(Box::new), doubted: None };
            (lc.step_retry, lc.step_refusals) = (0, 0);
        }
        self.stream_source_gained(conn, &l, out)?;
        // a stream resumed by the record read it to the peer's end already: a pass end there
        if self.stream_read_through(conn, &l) {
            self.stream_read(conn, l, out)?;
        }
        Ok(())
    }

    /// No key opens `l` on `conn`: tried again from scratch after `resync_ms`. A hinted label:
    /// the next thing a blob names it under gets its turn (`vet_inbox_hints`).
    pub(crate) fn fail(&mut self, conn: ConnId, l: LabelId) {
        let now = self.now();
        let Some(lc) = self.lc_mut(conn, &l) else { return };
        lc.phase = Phase::Failed { entry_refused: false };
        lc.last_sync = now;
        let tried = (l, lc.group, lc.index);
        if self.state.hints.get(&l).is_some_and(|h| h.via.is_none()) {
            self.hint_failed.insert(tried);
            self.vetted = None;
        }
    }

    /// Learns the read secret an accepted static-entry Hit's grant carries (spec/sync.md §10,
    /// Shared set): the path verified from the genesis step, the head's box opened by the key
    /// actor whose static entry `entry` is, and its sync secret deriving the head's sync key.
    /// The head is the newest step known at `conn` (`LConn::head`) and the path's write keys vouch
    /// for entries there before `label.0` records it. Whether it held.
    pub(crate) fn granted(&mut self, conn: ConnId, l: LabelId, entry: &[u8; 32], grant: &osis_proto::msg::Grant) -> Result<bool> {
        let things = self.things();
        let Some(g) = things.get(&l).copied() else { return Ok(false) };
        let Some(entry_box) = &grant.entry_box else { return Ok(false) };
        let index = self.group_label(&g, &l).map(|gl| gl.index).or_else(|| self.state.hints.get(&l).map(|h| h.index)).unwrap_or(0);
        let mut prev: Option<&Step> = None;
        for st in &grant.steps {
            let ok = match prev {
                None => st.label == l && st.verify_genesis().is_ok(),
                Some(p) => st.verify_child(p).is_ok(),
            };
            if !ok {
                self.diag("granted path does not verify".into());
                return Ok(false);
            }
            prev = Some(st);
        }
        let Some(head) = grant.steps.last() else { return Ok(false) };
        let kem = self.engine.core.key_actors.values().find(|id| osis_crypto::static_entry(&l, &id.keys().signing.verifying_key()) == *entry).map(|id| id.keys().kem.clone());
        let Some(kem) = kem else { return Ok(false) };
        let item = match osis_label::open_entry_box(entry_box, head, &kem, &g) {
            Ok(x) => x,
            Err(e) => {
                self.diag(format!("entry box: {e}"));
                return Ok(false);
            }
        };
        if osis_label::match_secret(&head.keys.sync, LabelRole::Sync, index, [&item.sync.1]).is_none() {
            self.diag("entry box sync secret does not derive the head's sync key".into());
            return Ok(false);
        }
        self.record_steps(&g, &l, &grant.steps, None)?;
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.head = Some(head.clone());
            for st in &grant.steps {
                if !lc.writers.contains(&st.keys.write) {
                    lc.writers.push(st.keys.write);
                }
            }
        }
        self.learn_entry(&g, item)
    }

    /// Learns an entry box's secrets: the earlier read secret opens the epoch's rotation commit,
    /// and with it all the rest.
    fn learn_entry(&mut self, g: &Tid, item: osis_crypto::EntryItem) -> Result<bool> {
        if let Some((e, s)) = item.earlier {
            self.engine.learn_secret(g, Role::Read, e, s)?;
        }
        let (e, s) = item.sync;
        self.engine.learn_secret(g, Role::Sync, e, s)?;
        self.engine.learn_secret(g, Role::Read, item.epoch, item.secret)
    }

    /// The actors a claim on `g`'s label goes as (spec/sync.md §2, §5): those this node is or holds
    /// that a held edge write names on `g`, of any validity and whatever followed, or `g`'s applied
    /// `secrets.0` boxes (`Engine::hint_actors`); for a hint's label (`hinted`) also those the
    /// inbox blobs naming `g` say hold it (a grant not applied yet: its chain comes by the label).
    /// Not by this node's judgment of `g`'s roster: the step's claim set is the registrar's, and
    /// what the open brings may change that judgment (a link's redeemer that holds a rival's
    /// earlier redemption but not the finalize leaving it out). Never any other actor: a claim is
    /// Hit only where the peer's filter lists it, and a listed one names nothing new to the peer.
    fn claimants(&mut self, g: &Tid, hinted: bool) -> Result<std::collections::BTreeSet<Tid>> {
        let mut named: Vec<Tid> = self.engine.core.ix.held.holders_of(g).copied().collect();
        if hinted {
            let inbox: Vec<(LabelId, osis_base::BlobId)> = self.state.entries.iter().filter_map(|((x, id), e)| matches!(e.kind, super::state::Kind::Inbox(Some(_))).then_some((*x, *id))).collect();
            for (x, id) in inbox {
                if let Some((_, things)) = self.inbox_parts(&x, &id)?
                    && things.contains(g)
                    && let Some(o) = self.inbox_opened(&x, &id)?
                {
                    named.extend(o.named.get(g).into_iter().flatten().copied());
                }
            }
        }
        self.engine.hint_actors(g, named)
    }

    /// The peer on `conn` holds `l` at a head past the newest step this node knows there, or lacks
    /// it (its filter shows no credential of it, a stream head off it): a Behind item on that step,
    /// by a credential of it this node holds (its sync key, else the key it opened by there,
    /// else its claim keys), asks for the steps after it to the peer's head (spec/sync.md §5, Behind). A hint's label, knowing no step, asks by
    /// every sync key it holds at once, naming none. Not open there and holding no sync key to ask
    /// by, a link's label asks by its key actor's signing key, naming no step: answered with the
    /// head's entry box for its static entry, or refused (the head does not list it). Holding no
    /// key to ask by, or no shared set there to send it on, `l` fails here (tried again after
    /// `resync_ms`). Open there, on the open head (`doubt`): L stays open, the answer moves its
    /// head.
    pub(crate) fn behind(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(open) = self.lc(conn, &l).map(|x| x.phase.is_open()) else { return Ok(()) };
        let from = if open { self.lc(conn, &l).and_then(|x| x.head.clone()) } else { self.newest_known(conn, &l) };
        self.behind_from(conn, l, from, out)
    }

    /// The open head of `l` on `conn` is not where the peer is: the peer refused a child of it (9),
    /// or its stream named a head that is neither a child of it nor recorded (two admins' sibling
    /// steps share their keys, so a Hit opens at whichever the peer holds, and a walk assumes
    /// this node's own branch). No child is registered under it (`doubting`), and a Behind item on
    /// it asks for the steps after it (spec/sync.md §5, Behind); refused, off the peer's path, the
    /// nearest earlier step holding a credential asks next (`doubt_answered`). L stays open; the
    /// answer, or a head the stream names, moves its head. Once per head.
    pub(crate) fn doubt(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(lc) = self.lc_mut(conn, &l) else { return Ok(()) };
        let head = lc.head.as_ref().map(Step::id);
        let Phase::Open { doubted, .. } = &mut lc.phase else { return Ok(()) };
        if head.is_none() || *doubted == head {
            return Ok(());
        }
        *doubted = head;
        self.behind(conn, l, out)
    }

    /// Whether `l` is open on `conn` at a head the peer refused a child of or named another head
    /// past (`doubt`): nothing is registered under it until the head moves.
    pub(crate) fn doubting(&self, conn: ConnId, l: &LabelId) -> bool {
        self.lc(conn, l).is_some_and(|x| matches!(&x.phase, Phase::Open { doubted: Some(d), .. } if x.head.as_ref().is_some_and(|h| h.id() == *d)))
    }

    /// A Behind item on `asked`, asked while doubting the open head (`doubt`), was refused: 4,
    /// past the peer's budget for one Offer, a child is registered again after a back-off (its
    /// 9 doubts again); else `asked` is off the peer's path (or the peer's head, its child
    /// refused for another reason): the nearest earlier recorded step holding a credential asks
    /// next. None left: L stays open at the head, registering nothing under it, until the stream
    /// names another.
    fn doubt_answered(&mut self, conn: ConnId, l: LabelId, asked: &Step, code: Code, out: &mut Vec<super::Action>) -> Result<()> {
        if code == Code::RATE_LIMITED {
            let (now, first, cap) = (self.now(), self.cfg.retry_ms, self.cfg.resync_ms);
            let Some(lc) = self.lc_mut(conn, &l) else { return Ok(()) };
            if let Phase::Open { doubted, .. } = &mut lc.phase {
                *doubted = None;
            }
            lc.step_retry = now.saturating_add(backoff(first, cap, lc.step_refusals));
            lc.step_refusals = lc.step_refusals.saturating_add(1);
            let at = lc.step_retry;
            self.settle_by(at, l);
            return Ok(());
        }
        match self.asked_before(conn, l, asked) {
            Some(p) => self.behind_from(conn, l, Some(p), out),
            None => {
                self.diag(format!("label {l:?}: open at a head off the peer's path, no earlier step to ask on"));
                Ok(())
            }
        }
    }

    /// Takes `step`, on the peer's path, as the head of open `l` on `conn`: when its credential is
    /// another (a new sync key, or the open was by a claim, which is the old step's) the open by
    /// the old one ends, and L tests the new head's credential (`shared_end`).
    pub(crate) fn open_moved(&mut self, conn: ConnId, l: LabelId, step: Step, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(lc) = self.lc(conn, &l) else { return Ok(()) };
        if lc.head.as_ref().is_some_and(|h| h.id() == step.id()) {
            return Ok(());
        }
        let ended = lc.keys.sync.is_none() || lc.head.as_ref().is_some_and(|h| h.keys.sync != step.keys.sync);
        self.set_head(conn, l, step)?;
        if ended {
            self.shared_end(conn, l, out)?;
        }
        Ok(())
    }

    /// `behind` on step `from` (none: a hint's, knowing no step). A step the peer refused a
    /// Behind item on in this walk is not asked again.
    fn behind_from(&mut self, conn: ConnId, l: LabelId, from: Option<Step>, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(lc) = self.lc(conn, &l) else { return Ok(()) };
        let (g, index, open) = (lc.group, lc.index, lc.phase.is_open());
        let at_head = from.as_ref().is_some_and(|s| lc.head.as_ref().is_some_and(|h| h.id() == s.id()));
        let (by, refused) = match &lc.phase {
            // the key it opened by is a credential of the open head only (a claim key is per step)
            Phase::Open { by, .. } => (by.as_deref().cloned().filter(|_| at_head), Vec::new()),
            Phase::Behind { refused } => (None, refused.clone()),
            _ => (None, Vec::new()),
        };
        let from = from.filter(|s| !refused.contains(&s.id()));
        let none_left = from.is_none() && !refused.is_empty();
        let held: Vec<SigningSecret> = self.engine.epochs(&g).map(|e| e.sync.held_newest_first().into_iter().map(|(_, x)| label_role_key(LabelRole::Sync, x, index)).collect()).unwrap_or_default();
        let mut asks: Vec<(Option<Step>, SigningSecret)> = match from {
            // the step's sync key, else (the open head) the key it opened by there, else its claim keys
            Some(s) => {
                let keys = match held.into_iter().find(|k| k.verifying_key() == s.keys.sync).or(by) {
                    Some(k) => vec![k],
                    None => self.step_keys(&g, index, &l, &s).0,
                };
                keys.into_iter().map(|k| (Some(s.clone()), k)).collect()
            }
            None => held.into_iter().map(|k| (None, k)).collect(),
        };
        if none_left {
            asks.clear();
        }
        let via = self.state.hints.get(&l).and_then(|h| h.via);
        let by_static = asks.is_empty() && !open && !none_left && via.is_some();
        if by_static {
            asks.extend(via.and_then(|v| self.engine.core.key_actors.get(&v)).map(|id| (None, id.keys().signing.clone())));
        }
        if asks.is_empty() {
            self.diag(format!("label {l:?}: behind the peer's head with no key to ask by"));
            // open: membership stays; nothing is registered under the doubted head
            if !open {
                self.fail(conn, l);
            }
            return Ok(());
        }
        if let Some(lc) = self.lc_mut(conn, &l).filter(|_| !open) {
            lc.phase = Phase::Behind { refused };
        }
        if !self.shared_behind(conn, l, asks, by_static, out)? && !open {
            self.fail(conn, l);
        }
        Ok(())
    }

    /// Behind items on `asked` (none: a hint's) were answered, `steps` the first answer's steps
    /// after it, through the first under another sync key (spec/sync.md §5, Behind): each verified under the one before,
    /// the first under `asked`'s delete key (a hint's is the peer's word: it knows no parent; its
    /// credential opens only if the peer's filter lists it), the last is the newest step known
    /// there. Open there, the head moves along them; else the last one's credential is tested
    /// against the peer's latest filter: shown, it is Hit; not shown, a Behind item asks on while
    /// this node holds a credential of it, else L is stranded there (tried again after
    /// `resync_ms`; `step_known`). None given: a hint's label
    /// is not at the peer yet (tried again after a back-off); 4, past the peer's budget for one
    /// Offer: tried again after a back-off; 13, the peer does not keep L: the recorded path goes
    /// there; else (14) the step given as a child was the peer's
    /// head (stranded), or a recorded one is off its path: an earlier step asks
    /// (`asked_before`).
    pub(crate) fn behind_answered(&mut self, conn: ConnId, l: LabelId, asked: Option<Step>, steps: Vec<Step>, code: Code, out: &mut Vec<super::Action>) -> Result<()> {
        let unknown = code == Code::UNKNOWN_LABEL;
        let Some((g, phase)) = self.lc(conn, &l).map(|x| (x.group, x.phase.clone())) else { return Ok(()) };
        // each step a child of the one before, the first of the asked one (a hint's: the peer's word)
        let mut parent = asked.as_ref();
        let mut verified = true;
        for c in &steps {
            verified &= c.label == l && parent.is_none_or(|a| c.verify_child(a).is_ok());
            parent = Some(c);
        }
        if !steps.is_empty() && !verified {
            self.diag(format!("label {l:?}: a Behind item answered with steps that do not verify"));
        }
        // an answer to a doubt of the open head (`doubt`); any other answer while open crossed
        // the open or a head move, and asks nothing any more
        let doubting = self.doubting(conn, &l);
        let Some(last) = steps.last().cloned().filter(|_| verified) else {
            if let Some(a) = asked.as_ref().filter(|_| doubting) {
                return self.doubt_answered(conn, l, a, code, out);
            }
            if matches!(phase, Phase::Behind { .. }) {
                return match asked {
                    // past the peer's budget for one Offer: asked again after a back-off
                    _ if code == Code::RATE_LIMITED => {
                        self.refused_for_now(conn, l, code);
                        Ok(())
                    }
                    None => {
                        self.refused_for_now(conn, l, Code::UNKNOWN_LABEL);
                        Ok(())
                    }
                    // the peer lacks L: the recorded path goes there (a genesis asked after its own
                    // Register was answered 9: off the path; a step known on a peer's word alone:
                    // nothing to register)
                    Some(a) if unknown => {
                        if a.prev.is_some() && self.group_label(&g, &l).is_some() {
                            self.register_path(conn, l, out)
                        } else {
                            self.fail(conn, l);
                            Ok(())
                        }
                    }
                    // a step the peer gave as a child (on its path): its head, showing none of
                    // this node's credentials: stranded there (spec/permissions.md §4)
                    Some(a) if self.lc(conn, &l).and_then(|x| x.head.as_ref()).is_some_and(|w| w.id() == a.id()) => {
                        self.fail(conn, l);
                        self.stranded(conn, g, l, out)
                    }
                    // a recorded step off the peer's path (another admin's branch of the tree),
                    // or its head showing none of this node's credentials: the nearest recorded
                    // step before it holding a credential asks next, each step once a walk
                    Some(a) => {
                        if let Some(Phase::Behind { refused }) = self.lc_mut(conn, &l).map(|x| &mut x.phase) {
                            refused.push(a.id());
                        }
                        match self.asked_before(conn, l, &a) {
                            Some(p) => self.behind_from(conn, l, Some(p), out),
                            None => {
                                self.fail(conn, l);
                                Ok(())
                            }
                        }
                    }
                };
            }
            return Ok(());
        };
        if let Some(a) = &asked {
            let mut path = vec![a.clone()];
            path.extend(steps.iter().cloned());
            self.record_steps(&g, &l, &path, None)?;
        }
        if let Some(lc) = self.lc_mut(conn, &l) {
            for st in &steps {
                if !lc.writers.contains(&st.keys.write) {
                    lc.writers.push(st.keys.write);
                }
            }
        }
        match phase {
            // asked on the doubted open head or a step before it: the last is on the peer's path
            Phase::Open { .. } if doubting && asked.is_some() => self.open_moved(conn, l, last, out),
            Phase::Behind { .. } => {
                if let Some(lc) = self.lc_mut(conn, &l) {
                    lc.head = Some(last.clone());
                }
                self.step_known(conn, l, last, asked.is_some(), out)
            }
            _ => Ok(()),
        }
    }

    /// The nearest recorded step before `step` whose credential this node holds and that the peer
    /// on `conn` did not refuse a Behind item on in this walk.
    fn asked_before(&mut self, conn: ConnId, l: LabelId, step: &Step) -> Option<Step> {
        let (g, index) = self.lc(conn, &l).map(|x| (x.group, x.index))?;
        let gl = self.group_label(&g, &l)?;
        let mut cur = step.prev;
        let mut n = 0;
        while let Some(id) = cur {
            let (st, _) = gl.steps.get(&id)?.clone();
            n += 1;
            if n > gl.steps.len() {
                return None;
            }
            let refused = self.lc(conn, &l).is_some_and(|x| matches!(&x.phase, Phase::Behind { refused } if refused.contains(&id)));
            if !refused && !self.step_keys(&g, index, &l, &st).0.is_empty() {
                return Some(st);
            }
            cur = st.prev;
        }
        None
    }

    /// `step` became the newest step of `l` known at `conn` (a Behind item's answer, a static
    /// entry's grant): its credential the peer's filter shows is Hit; none shown, a Behind item
    /// asks on by a credential of it held; else `l` fails there, stranded (spec/permissions.md §4)
    /// unless the step was taken on the peer's word (`verified` false: a hint's).
    fn step_known(&mut self, conn: ConnId, l: LabelId, step: Step, verified: bool, out: &mut Vec<super::Action>) -> Result<()> {
        let Some((g, index)) = self.lc(conn, &l).map(|x| (x.group, x.index)) else { return Ok(()) };
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.phase = Phase::Testing { shown: None };
        }
        let refused = |s: &Self, k: &[u8; 32]| s.conns.get(&conn).is_some_and(|c| c.req.refused.contains(&(l, *k)));
        let keys: Vec<SigningSecret> = self.step_keys(&g, index, &l, &step).0.into_iter().filter(|k| !refused(self, &k.verifying_key().to_bytes())).collect();
        let held = !keys.is_empty();
        let shown = keys.into_iter().find(|k| self.shared_shows(conn, &l, &k.verifying_key().to_bytes()));
        match shown {
            Some(k) => self.walked(conn, l, Some((step, k)), out),
            None if held => self.behind(conn, l, out),
            None if !verified => {
                self.fail(conn, l);
                Ok(())
            }
            None => {
                self.fail(conn, l);
                self.stranded(conn, g, l, out)
            }
        }
    }

    /// A Behind item by the static entry `entry` of `l` was answered (spec/sync.md §5, Behind):
    /// with the head's entry box and the path, the secrets learnt, the head is the newest step
    /// known there (`step_known`); 13, the peer does not hold `l` yet, or 4, past its budget for
    /// one Offer (tried again after a back-off); else its head does not list the entry: refused there
    /// (`static_entry_refused`).
    pub(crate) fn static_answered(&mut self, conn: ConnId, l: LabelId, entry: &[u8; 32], code: Code, grant: Option<&osis_proto::msg::Grant>, out: &mut Vec<super::Action>) -> Result<()> {
        if self.lc(conn, &l).is_none_or(|x| !matches!(x.phase, Phase::Behind { .. })) {
            return Ok(());
        }
        match (code, grant) {
            (Code::OK, Some(g)) if g.entry_box.is_some() => {
                if !self.granted(conn, l, entry, g)? {
                    self.fail(conn, l);
                    return Ok(());
                }
                let Some(head) = g.steps.last().cloned() else { return Ok(()) };
                self.step_known(conn, l, head, true, out)
            }
            (Code::UNKNOWN_LABEL | Code::RATE_LIMITED, _) => {
                self.refused_for_now(conn, l, code);
                Ok(())
            }
            _ => {
                self.diag(format!("label {l:?}: the peer's head does not list this node's static entry"));
                self.fail(conn, l);
                if let Some(lc) = self.lc_mut(conn, &l) {
                    lc.phase = Phase::Failed { entry_refused: true };
                }
                Ok(())
            }
        }
    }

    /// A request about `l` was refused.
    pub(crate) fn refused(&mut self, conn: ConnId, l: Option<LabelId>, kind: Request, code: Code, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(l) = l else { return Ok(()) };
        // a delete refused whole goes again at a later pass
        if kind == Request::Delete
            && let Some(c) = self.conns.get_mut(&conn)
        {
            c.req.deleting.retain(|(x, _), _| *x != l);
        }
        let phase = self.lc(conn, &l).map(|x| x.phase.clone());
        match (kind, phase) {
            // a pass's step refused for now (a full peer, the rate, not admitted): the open stays,
            // a later pass registers again after a back-off (else every pass sent it again), and
            // the pass that waited for the step runs now under the peer's head
            (Request::Register, Some(Phase::Open { .. })) if matches!(code, Code::STORAGE_CAP | Code::RATE_LIMITED | Code::NOT_ADMITTED) => {
                let (now, first, cap) = (self.now(), self.cfg.retry_ms, self.cfg.resync_ms);
                if let Some(lc) = self.lc_mut(conn, &l) {
                    lc.registering = None;
                    lc.step_retry = now.saturating_add(backoff(first, cap, lc.step_refusals));
                    lc.step_refusals = lc.step_refusals.saturating_add(1);
                    let at = lc.step_retry;
                    self.mark_labels(&[l]);
                    self.settle_by(at, l);
                }
                self.diag(format!("label {l:?}: step refused for now (code {})", code.0));
                Ok(())
            }
            // registering a path refused for now (not admitted: a peer learns what it admits by
            // syncing, spec/data-model.md §9): tested again after a back-off
            (Request::Register, Some(Phase::Registering { .. })) if matches!(code, Code::STORAGE_CAP | Code::RATE_LIMITED | Code::NOT_ADMITTED) => {
                self.refused_for_now(conn, l, code);
                Ok(())
            }
            // a step of the path before the peer's head (spec/sync.md §5: 9 for a step that is
            // not a child of its head): the steps after it still register. The last answered
            // 9: a genesis alone is asked past by a Behind item; a longer path's Behind item was
            // refused (or none could go): the peer holds L off this node's path
            (Request::Register, Some(Phase::Registering { .. })) if code == Code::NOT_HEAD => {
                let Some(Phase::Registering { path }) = self.lc_mut(conn, &l).map(|x| &mut x.phase) else { return Ok(()) };
                if !path.is_empty() {
                    path.remove(0);
                }
                if path.is_empty() {
                    if self.newest_known(conn, &l).is_some_and(|s| s.prev.is_none()) {
                        return self.behind(conn, l, out);
                    }
                    self.diag(format!("label {l:?}: the peer holds it off the recorded path"));
                    self.fail(conn, l);
                }
                Ok(())
            }
            // the open head's child refused: the head is not the peer's (its stream may name the
            // new one, or the peer holds a sibling sharing its keys): doubted, never registered
            // under again (`doubt`); a child of a head the stream moved past since: the next pass
            // registers under the new one
            (Request::Register, Some(Phase::Open { .. })) => {
                let head = self.lc(conn, &l).and_then(|x| x.head.as_ref().map(Step::id));
                let Some(lc) = self.lc_mut(conn, &l) else { return Ok(()) };
                let under_head = lc.registering.take().is_some_and(|(s, _)| s.prev.is_some() && s.prev == head);
                self.diag(format!("label {l:?}: step refused (code {})", code.0));
                if under_head {
                    return self.doubt(conn, l, out);
                }
                self.mark_labels(&[l]);
                Ok(())
            }
            // a child step refused after the open ended, or the rest of a path's steps whose
            // registration ended
            (Request::Register, _) => {
                if let Some(lc) = self.lc_mut(conn, &l) {
                    lc.registering = None;
                }
                self.diag(format!("label {l:?}: step refused (code {})", code.0));
                self.mark_labels(&[l]);
                Ok(())
            }
            _ => {
                self.diag(format!("{kind:?} refused: code {}", code.0));
                Ok(())
            }
        }
    }

    /// The peer refused registering `l` for now, or does not hold it and this node has nothing to
    /// register: tested again after a back-off, `retry_ms` doubling per refusal in a row by that
    /// peer, across connections (an open there resets it), up to `resync_ms`.
    fn refused_for_now(&mut self, conn: ConnId, l: LabelId, code: Code) {
        let now = self.now();
        let (first, cap) = (self.cfg.retry_ms, self.cfg.resync_ms);
        let Some(c) = self.conns.get_mut(&conn) else { return };
        let (n, last) = self.refusals.entry((c.host, l)).or_insert((0, code));
        let wait = backoff(first, cap, *n);
        *n = n.saturating_add(1);
        *last = code;
        if let Some(lc) = c.labels.get_mut(&l) {
            lc.phase = Phase::Refused { retry_at: now.saturating_add(wait) };
        }
        self.diag(format!("label {l:?}: not opened for now (code {}), again in {} s", code.0, wait / 1000));
    }

    /// The host does not hold the label: register the recorded path from the genesis step
    /// along the deepest branch (relayable by any node, spec/sync.md §5), then open.
    fn register_path(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(g) = self.lc(conn, &l).map(|x| x.group) else { return Ok(()) };
        // nothing to register with: it is not at this host yet (an inbox blob's sender still
        // registering it, a card whose first admin has not), so no other key would open it either
        let Some(path) = self.group_label(&g, &l).and_then(|gl| deepest_path(&gl.steps).map(|p| p.into_iter().cloned().collect::<Vec<_>>())) else {
            // a link's label whose static entry the peer's filter does not show: refused there
            // (`static_entry_refused`)
            if self.state.hints.get(&l).is_some_and(|h| h.via.is_some()) && self.shared_static_missing(&l) {
                self.fail(conn, l);
                return Ok(());
            }
            // a hint's label: the peer may hold it at a head past the sync keys held
            return self.behind(conn, l, out);
        };
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.phase = Phase::Registering { path: path.iter().map(|(s, _)| s.clone()).collect() };
        }
        for (step, claim_set) in path {
            self.command(conn, Command::Register { label: l, step, claim_set }, out)?;
        }
        Ok(())
    }

    /// A Register was accepted: the next step of a path registration, or the child step a pass
    /// issued.
    pub(crate) fn registered(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(lc) = self.lc_mut(conn, &l) else { return Ok(()) };
        if let Phase::Registering { path } = &mut lc.phase {
            if !path.is_empty() {
                path.remove(0);
            }
            if path.is_empty() {
                let at = (self.records.shared.get(&conn).map_or(0, |s| s.arrivals), self.now());
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.req.registered.insert(l, at);
                }
                // deposits refused while the label was unknown there go now, not after their
                // back-off (a node's own deposits under a label it just created)
                if let Some(host) = self.conns.get(&conn).map(|c| c.host) {
                    for (_, o) in self.outbox.range_mut((host, l, osis_base::BlobId([0; 32]))..=(host, l, osis_base::BlobId([0xff; 32]))) {
                        o.after = 0;
                    }
                }
                // the peer holds L at the recorded head: its next filter shows the head's
                // credential
                return self.retest_label(conn, l, out);
            }
            return Ok(());
        }
        let Some((step, set)) = lc.registering.take() else { return Ok(()) };
        (lc.step_retry, lc.step_refusals) = (0, 0);
        let g = lc.group;
        let parent = lc.head.clone();
        // a new sync key ended this connection's open too (spec/sync.md §5): opened again under
        // it, the first try (one round trip, the cursor kept)
        let ended = parent.as_ref().is_some_and(|p| p.keys.sync != step.keys.sync);
        let mut steps = Vec::new();
        if let Some(p) = parent {
            steps.push(p);
        }
        steps.push(step.clone());
        self.record_steps(&g, &l, &steps, Some((step.id(), set)))?;
        self.set_head(conn, l, step)?;
        if ended {
            // the open by the old key ends; the next filter shows the new one's
            self.shared_end(conn, l, out)?;
        }
        self.run_dirty(out)
    }

    /// `l` on `conn` waits for the peer's filter again, testing the newest recorded head's
    /// credential; a member of the connection's set already (the peer's Hit came while this node
    /// registered L there, `member_unread_there` waiting for no Testing then) is open there at once.
    pub(crate) fn retest_label(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.phase = Phase::Testing { shown: None };
        }
        if self.shared_member(conn, &l) {
            return self.member_unread_there(conn, l, false, out);
        }
        self.shared_retest(conn, out)
    }

    /// Takes `step` as the head of `l` on `conn`: its keys derived, recorded for the peer, a
    /// pass wanted (judging everything when the head moved).
    pub(crate) fn set_head(&mut self, conn: ConnId, l: LabelId, step: Step) -> Result<()> {
        let Some(host) = self.conns.get(&conn).map(|c| c.host) else { return Ok(()) };
        let Some(lc) = self.lc(conn, &l) else { return Ok(()) };
        let (g, index) = (lc.group, lc.index);
        let keys = self.engine.head_keys(&g, index, &step)?;
        self.state.set_head(host, l, &step);
        let mut moved = false;
        if let Some(lc) = self.lc_mut(conn, &l) {
            moved = lc.head.as_ref().is_some_and(|h| h.id() != step.id());
            lc.head = Some(step);
            lc.keys = keys;
        }
        // the stamps the peer takes changed: every entry is judged against them again
        if moved {
            self.work_mut(l).touched.full = true;
        }
        self.mark_labels(&[l]);
        Ok(())
    }

    /// Records steps in `label.0` of `g` when this node may write it (an admin; spec/sync.md
    /// §2, §5: "records the steps in label.0"). Steps already recorded are left alone.
    pub(crate) fn record_steps(&mut self, g: &Tid, l: &LabelId, steps: &[Step], claims: Option<(StepId, ClaimSet)>) -> Result<()> {
        // a handed-off group: nothing is placed there from here
        if self.state.handed_off.contains(g) {
            return Ok(());
        }
        let Some(gl) = self.group_label(g, l) else { return Ok(()) };
        let new: Vec<&Step> = steps.iter().filter(|s| !gl.steps.contains_key(&s.id())).collect();
        if new.is_empty() || self.engine.role_on(g) < Some(osis_base::Role::Admin) {
            return Ok(());
        }
        let mut m = crate::Mutation::new();
        for s in new {
            let set = claims.as_ref().filter(|(id, _)| *id == s.id()).map(|(_, c)| c);
            let rec = osis_label::step_record(s, set);
            let path = vec![PathSeg::Key(l.to_value()), PathSeg::Field(1), PathSeg::Key(s.id().0.to_value())];
            m.op(*g, &osis_schema::core_types::LABEL, PathOp { path, op: Op::Set(rec.to_value()) })?;
        }
        self.engine.drop_old_claims(&mut m, g)?;
        self.engine.commit(m)?;
        Ok(())
    }
}

/// A back-off after `n` refusals in a row: `first` doubling per refusal, up to `cap`.
fn backoff(first: u64, cap: u64, n: u32) -> u64 {
    first.saturating_mul(1u64 << n.min(63)).min(cap)
}
