//! What opens reads of its own node (spec/sync-opens.md §4): per sync ID the credentials it
//! holds now and the judgement J of a peer's proven actors. `Holds` is the one seam: the product
//! reads it from the engine's facade and `unread` (`NodeHolds`); a test from a table.

use std::collections::BTreeSet;
use super::cred::{Shown, Tested};
use crate::session::Proven;
use crate::types::{Credential, Cursor, Cx, Holding, Position, RecordId};
use crate::unread::{Unread, UnreadCredentials};
use osis_base::SyncId;
use osis_crypto::Epoch;
use osis_engine::sync::{J, Path, ProvenThing, ReadCredentials};
use osis_blob::{Step, StepId};
use osis_proto::{BehindItem, Code, DepositItem, Grant, SharedItem};
use osis_base::memo::Effects;
use osis_store::Named;
use std::sync::Arc;

/// What a record of `proven`'s connection names (spec/sync-opens.md §3): its claims.
pub fn named(proven: &Proven) -> Named {
    proven.named.clone()
}



/// One sync ID's credentials at this node, before a connection's J filters them
/// (spec/sync-opens.md §4 Admissible): each with the epoch it is at, for the Departed rule.
#[derive(Clone, Debug, Default)]
pub struct Creds {
    /// How the node holds S: read, for keys, or kept unread.
    pub holding: Option<Holding>,
    /// Credentials it shows, each with its epoch (none: at no epoch covering a departure).
    pub shows: Vec<(Shown, Option<Epoch>)>,
    /// Credentials it tests, in test order (spec/sync-ids.md §6 Walk: deepest step first, then
    /// sync keys newest first), each with its epoch.
    pub tests: Vec<(Tested, Option<Epoch>)>,
    /// The sync key of this node's step (its step kept unread, its newest recorded step read)
    /// and its epoch: what answers a Hit on a sync key, claim or static entry.
    pub step: Option<(osis_crypto::SigningSecret, Option<Epoch>)>,
    /// At a reader, the sync proofs of its recorded steps but the newest and its read secrets at
    /// superseded epochs: shown to a peer J judges departed only, they answer a departed store's
    /// Hit on its step and a departed reader's on the epoch it holds, opening S ended
    /// (spec/sync-opens.md §4 Admissible, §6).
    pub walk: Vec<Shown>,
    /// At a reader, while the public is named on S's thing and reads it no more, its read
    /// secrets at superseded epochs: shown to every peer, an open by one ended at once, served up
    /// to that epoch's supersession (spec/sync-opens.md §4 Admissible, §6).
    /// Invariant (security): only secrets, never a public value (the public entry): a party that
    /// never held the epoch's secret (one that read S while the public did, or a former reader)
    /// hits none, so learns nothing of who holds S and is served nothing once the public is
    /// removed.
    pub lapsed: Vec<Shown>,
}

impl Creds {
    /// What a node keeping S unread holds (spec/sync-opens.md §4 Admissible): it shows each of
    /// its steps' sync key and the sync proof of it, and its head's deposit key and every key of
    /// the head's claim set; it tests the sync keys and the proofs; its step answers a Hit on what
    /// it shows (§5 Proof: a sync key by itself), so everything it shows it can accept.
    pub fn kept_unread(s: &SyncId, uc: &UnreadCredentials) -> Creds {
        let mut c = Creds { holding: Some(Holding::Unread), ..Creds::default() };
        for (k, p) in &uc.keys {
            c.shows.push((Shown::SyncKey(k.verifying_key().to_bytes()), None));
            c.shows.push((Shown::Proof(*p.expose(), k.verifying_key().to_bytes()), None));
        }
        if let Some(d) = &uc.deposit {
            c.shows.push((Shown::Deposit(d.to_bytes()), None));
        }
        // the public entry, where the head lists it, is shown as itself: its Hit carries no proof
        if let Some(cs) = &uc.claims {
            let public = osis_crypto::public_entry(s);
            c.shows.extend(cs.claims.iter().filter(|k| **k != public).map(|k| (Shown::Claim(*k), None)));
            c.shows.extend(cs.entries.keys().filter(|k| **k != public).map(|k| (Shown::Static(*k), None)));
            if cs.contains(&public) {
                c.shows.push((Shown::Public(public), None));
            }
        }
        for (k, p) in &uc.keys {
            c.tests.push((Tested::SyncKey { step: uc.step, key: k.clone() }, None));
            c.tests.push((Tested::Proof(*p.expose(), k.verifying_key().to_bytes()), None));
        }
        c.step = uc.keys.first().map(|(k, _)| (k.clone(), None));
        c
    }

    /// The digest `changed_at` compares (spec/sync-opens.md §3): what is shown and tested, and
    /// the step that answers.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = osis_base::hash::Hasher::new();
        h.update(&[self.holding.map_or(0, |x| x as u8 + 1)]);
        for (c, e) in &self.shows {
            h.update(b"s").update(c.matched()).update(&epoch_bytes(e));
        }
        for (c, e) in &self.tests {
            h.update(b"t").update(&c.matched(&SyncId([0; 16]))).update(&epoch_bytes(e));
        }
        if let Some((k, e)) = &self.step {
            h.update(b"k").update(&k.verifying_key().to_bytes()).update(&epoch_bytes(e));
        }
        for c in &self.lapsed {
            h.update(b"l").update(c.matched());
        }
        h.finalize()
    }
}

fn epoch_bytes(e: &Option<Epoch>) -> Vec<u8> {
    e.as_ref().map_or_else(Vec::new, |e| [&e.n().to_be_bytes()[..], e.nonce()].concat())
}

/// What a connection's peer is to this node for S, judged now (spec/sync-opens.md §4 J).
pub trait Holds {
    /// The node's generator (nonces, record ids).
    fn rng(&mut self) -> &mut dyn osis_crypto::NodeRng;
    /// The sync IDs whose `Creds` may have moved since the last call (each settled again; the
    /// product's is the memo effects' `due`).
    fn due(&mut self) -> Vec<SyncId>;
    /// S's credentials, `None` when this node does not sync S.
    fn creds(&mut self, s: &SyncId) -> Option<Arc<Creds>>;
    /// What a connection's proofs count for at its proof (spec/sync-opens.md §2): what its
    /// record names (`named`).
    fn named(&mut self, proven: &Proven) -> Named;
    /// What `named`'s claims prove now, with `copies` (none for a record judged with no
    /// connection; `Engine::proven`).
    fn counts(&mut self, named: &Named, copies: &osis_blob::Certificates) -> Vec<ProvenThing>;
    /// J of a peer whose proofs prove `proven` (`counts`) for S.
    fn judge(&mut self, s: &SyncId, proven: &[ProvenThing]) -> J;
    /// J for S of the peer record `rec` names (`named`), now (`judge` of `counts`), for member S
    /// of `rec`, which is followed from then on, across its connections: `standing_due` gives it
    /// once anything this read moves (the peer's removal or demotion, its account's revocation,
    /// its node's removal, an `until` passing; spec/sync-opens.md §6). Followed and nothing it
    /// read moved, the value kept, read nothing again. `None`: the peer is no one (`awaited` of
    /// a `named` that names someone is empty; spec/sync-opens.md §3 who it may be), so it never
    /// resumes the record. `copies`: those of the connection holding `rec` (none with none): a
    /// member whose record's connection moves is judged with its copies at its next due.
    fn standing(&mut self, rec: RecordId, s: &SyncId, named: &Named, copies: &osis_blob::Certificates) -> Option<J>;
    /// The members followed (`standing`) whose J may have moved since the last call.
    fn standing_due(&mut self) -> Vec<(RecordId, SyncId)>;
    /// Member S of `rec` is followed no more.
    fn unfollow(&mut self, rec: RecordId, s: &SyncId);
    /// Whether `epoch` of S's thing covers every departure this node knows of (spec/crypto.md §4).
    fn covers_departures(&mut self, s: &SyncId, epoch: &Epoch) -> bool;
    /// An ended member's `until` (spec/sync-opens.md §6): the highest position at which an entry
    /// in S of a rotation superseding `by`'s epoch was first logged, else the node log's end; at
    /// a node keeping S unread the position of its head's event.
    fn until(&mut self, s: &SyncId, by: &Credential) -> Position;
    /// A member ended for its peer's departure at a reader, the peer proving `proven`: the
    /// highest position at which a notice in S of their removals (`Engine::told`) or an entry of
    /// the public's edge (`Engine::public_edge`) was first logged; none while no such notice is
    /// logged here.
    fn departure_until(&mut self, s: &SyncId, proven: &BTreeSet<osis_base::Tid>) -> Option<Position>;
    /// The cursor naming `pos` of this node's log, for a Lost.
    fn cursor_at(&mut self, pos: Position) -> Option<Cursor>;
    /// The grant a static entry's answer carries (spec/sync-opens.md §5): the head's entry box
    /// for `entry` and the path to the head, when this node keeps them.
    fn grant(&mut self, s: &SyncId, entry: &[u8; 32]) -> Option<Grant>;
    /// Takes a static entry's grant (spec/sync-opens.md §5): when the path verifies from its
    /// genesis step, the box's sync secret derives the head's sync key and `signed` (the answer's
    /// `sig`) verifies under that key, the box's secrets are taken, and only then.
    fn take_grant(&mut self, s: &SyncId, entry: &[u8; 32], grant: &Grant, signed: &dyn Fn(&[u8; 32]) -> bool) -> bool;
    /// Answers a Behind item whose open signature verified (spec/sync-ids.md §6 Behind).
    fn behind(&mut self, item: &BehindItem) -> SharedItem;
    /// Answers a Behind item whose signature did not verify: 13 for a sync ID not kept unread
    /// here, else 14.
    fn behind_unsigned(&mut self, s: &SyncId) -> SharedItem;
    /// Takes a Deposit item (spec/sync-inbox.md §3) a peer offered; `src` is where its peer
    /// budget charge lives (the peer's record, else the connection).
    fn deposit(&mut self, src: crate::store::Source, item: &DepositItem) -> Code;
    /// Verifies steps a source gave (spec/sync-ids.md §6 Known steps): `known_steps` over this
    /// node's recorded path and `known` (the steps the walk there knows). Those that verify and
    /// are not recorded, in order.
    fn verify_steps(&mut self, s: &SyncId, known: &[Step], steps: &[Step]) -> Vec<Step>;
    /// The walk credentials of a step a source gave (spec/sync-ids.md §6 Test): its sync key when
    /// a held sync secret derives it (a source's answer carries no claim set, so no claim or
    /// static entry of such a step is known).
    fn step_creds(&mut self, s: &SyncId, step: &Step) -> Vec<(Tested, Option<Epoch>)>;
}

/// The memo effects opens follows (notes/sync-facade.md, Effects): the sync IDs this node syncs,
/// and per sync ID of it the digest of its credentials. A step settles only the keys whose reads
/// moved.
#[derive(Clone)]
pub struct Fx {
    set: crate::set::SyncsFollow,
    creds: Effects<SyncId, Option<[u8; 32]>>,
    /// Per member of a record, J of its peer for S (`Holds::standing`).
    standing: Effects<(RecordId, SyncId), Option<J>>,
}

impl Default for Fx {
    fn default() -> Fx {
        Fx { set: crate::set::SyncsFollow::default(), creds: Effects::new("opens credentials"), standing: Effects::new("opens standing") }
    }
}

impl std::fmt::Debug for Fx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fx")
    }
}

/// The product's `Holds`: the engine's facade for sync IDs read here, `unread` for those kept
/// unread. Every engine call not built answers as if the node held nothing.
pub struct NodeHolds<'a, 'c> {
    pub cx: &'a mut Cx<'c>,
    pub unread: &'a Unread,
    pub fx: &'a mut Fx,
}

/// S's recorded path, read here.
fn path_of(cx: &mut Cx, s: &SyncId) -> Option<Arc<osis_engine::sync::Path>> {
    let (things, _) = cx.store.synced(s)?;
    things.iter().find_map(|t| cx.engine.sync_ids(t).ok()?.iter().find(|o| o.id == *s && !o.hint).map(|o| o.path.clone()))
}

/// S's credentials as the engine (read) or `unread` (kept unread) gives them.
fn node_creds(cx: &mut Cx, unread: &Unread, s: &SyncId) -> Option<Arc<Creds>> {
    let (_, holding) = cx.store.synced(s)?;
    let mut c = Creds { holding: Some(holding), ..Creds::default() };
    match holding {
        // held in the keys class it opens as a reader does: by the read secret a box gave it
        Holding::Read | Holding::Keys => {
            let rc = cx.engine.read_credentials(s).ok()??;
            for (e, k) in &rc.read_secrets {
                c.shows.push((Shown::Read(*e, *k.expose()), Some(*e)));
                c.tests.push((Tested::Read(*e, k.clone()), Some(*e)));
            }
            for st in &rc.statics {
                c.shows.push((Shown::Static(*st), None));
            }
            // the static entries of the link keys it acts for (its link, spec/sync-opens.md §4)
            for k in &rc.acting {
                c.tests.push((Tested::Static { key: k.clone(), step: None }, None));
            }
            // S's public entry: shown where the public holds a role on S's thing, at the epoch of
            // the box it gives (the newest read epoch held where the public reads, else the head's
            // sync epoch), so Departed judges it as any credential; tested where this node redeems
            // a public link to it; once the public's read is removed, the superseded read secrets
            // lapsed instead (spec/sync-opens.md §4)
            if rc.shows_public {
                let at = match rc.public_reads {
                    true => rc.read_secrets.iter().map(|(e, _)| *e).max(),
                    false => rc.head.as_ref().and_then(|h| rc.keys.get(&h.id())).and_then(|k| k.epochs[0]),
                };
                c.shows.push((Shown::Public(osis_crypto::public_entry(s)), at));
            }
            if rc.lapsed_public {
                c.lapsed = rc.old_read_secrets.iter().map(|(e, k)| Shown::Read(*e, *k.expose())).collect();
            }
            if rc.tests_public {
                c.tests.push((Tested::Public, None));
            }
            // the sync proof of the newest recorded step's sync key (spec/sync-opens.md §4)
            if let (Some(head), Some((id, p))) = (&rc.head, rc.proofs.first())
                && head.id() == *id
            {
                c.shows.push((Shown::Proof(*p, head.keys.sync.to_bytes()), None));
            }
            c.walk = rc.proofs.iter().filter(|(id, _)| rc.head.as_ref().is_none_or(|h| h.id() != *id)).filter_map(|(id, p)| Some(Shown::Proof(*p, rc.keys.get(id)?.sync.as_ref()?.verifying_key().to_bytes()))).collect();
            c.walk.extend(rc.old_read_secrets.iter().map(|(e, k)| Shown::Read(*e, *k.expose())));
            let path = path_of(cx, s).unwrap_or_default();
            c.tests.extend(walk_tests(&rc, &path, &mut |id| cx.engine.claim_key(s, id).ok().flatten()));
            if let Some(head) = &rc.head {
                let keys = rc.keys.get(&head.id());
                if let Some(k) = keys.and_then(|k| k.sync.clone()) {
                    let e = keys.and_then(|k| k.epochs[0]);
                    c.step = Some((k, e));
                }
            }
        }
        // at a head past its keys it holds S and shows only the secrets no step of its path
        // bears: S is still in the sync set, so its `changed_at` moves and the peer hears a
        // generation
        Holding::Unread => {
            if let Some(uc) = unread.credentials(s) {
                c = Creds::kept_unread(s, &uc);
            }
        }
    }
    Some(Arc::new(c))
}

/// A reader's walk tests (spec/sync-ids.md §6 Test): the credentials of its recorded steps,
/// deepest first, each by its sync key when held, else its claim key (`claim`); then the sync key
/// of each sync secret it holds, newest first, so a store granted at an epoch no recorded step
/// bears opens; each distinct credential once.
pub fn walk_tests(rc: &ReadCredentials, path: &Path, claim: &mut dyn FnMut(&StepId) -> Option<osis_crypto::SigningSecret>) -> Vec<(Tested, Option<Epoch>)> {
    let mut out = Vec::new();
    let mut keys = std::collections::BTreeSet::new();
    for (step, _) in path.steps.iter().rev() {
        let id = step.id();
        let held = rc.keys.get(&id);
        if let Some(k) = held.and_then(|k| k.sync.clone()) {
            keys.insert(k.verifying_key().to_bytes());
            out.push((Tested::SyncKey { step: Some(id), key: k }, held.and_then(|k| k.epochs[0])));
        } else if let Some(k) = claim(&id) {
            out.push((Tested::Claim { step: id, key: k, sync: step.keys.sync.to_bytes() }, None));
        }
    }
    for (e, k) in &rc.sync_keys {
        if keys.insert(k.verifying_key().to_bytes()) {
            out.push((Tested::SyncKey { step: None, key: k.clone() }, Some(*e)));
        }
    }
    out
}

/// An ended member's `until` (spec/sync-opens.md §6): kept unread, the position of S's head
/// event; read and opened by a read secret (a lapsed one too), the highest position at which an
/// entry in S of a rotation superseding its epoch was first logged; by the public entry, of a
/// commit of the public's edge on S's thing (the public's read since removed: judged at the
/// removal's arrival, before it is logged here, so the log's end would leave it out); else (or
/// none such) the log's end. A credential with no epoch here (a sync key, claim, proof, static entry or deposit key at a
/// reader) ends at the log's end.
pub(crate) fn member_until(cx: &mut Cx, s: &SyncId, by: &Credential) -> crate::types::Result<Position> {
    let end = cx.store.log_bounds()?.0;
    match (cx.store.synced(s), by) {
        (Some((_, Holding::Unread)), _) => Ok(cx.store.head_at(s)?.unwrap_or(end)),
        // the public entry, the public's read since removed: up to its edge, the removal last
        (Some((_, Holding::Read | Holding::Keys)), Credential::Public) => Ok(public_edge_at(cx, s)?.unwrap_or(end)),
        (Some((_, Holding::Read | Holding::Keys)), Credential::ReadSecret(e)) => Ok(superseded_at(cx, s, e)?.unwrap_or(end)),
        _ => Ok(end),
    }
}

/// `Holds::departure_until`.
pub(crate) fn departure_until(cx: &mut Cx, s: &SyncId, proven: &BTreeSet<osis_base::Tid>) -> crate::types::Result<Option<Position>> {
    let told = cx.engine.told(s, proven)?;

    let mut at = None;
    for (b, n) in cx.engine.notice_rows(s) {
        if told.contains(&n.commit) {
            at = at.max(cx.store.first_logged(s, &b)?);
        }
    }
    // the public's edge goes with them (`Engine::departed_shown`)
    let Some(at) = at else { return Ok(None) };
    Ok(Some(at.max(public_edge_at(cx, s)?.unwrap_or(0))))
}

/// The highest position at which an entry in S of a commit of the public's edge on S's thing
/// (`Engine::public_edge`) was first logged.
fn public_edge_at(cx: &mut Cx, s: &SyncId) -> crate::types::Result<Option<Position>> {
    let mut at = None;
    for c in cx.engine.public_edge(s)? {
        for b in cx.engine.commit_blobs(&c)?.iter() {
            at = at.max(cx.store.first_logged(s, b)?);
        }
    }
    Ok(at)
}

/// The highest position at which an entry in S of a rotation superseding read epoch `e` was
/// first logged.
fn superseded_at(cx: &mut Cx, s: &SyncId, e: &Epoch) -> crate::types::Result<Option<Position>> {
    let mut at = None;
    for c in cx.engine.rotations_superseding(s, e)? {
        for b in cx.engine.commit_blobs(&c)?.iter() {
            at = at.max(cx.store.first_logged(s, b)?);
        }
    }
    Ok(at)
}

impl Holds for NodeHolds<'_, '_> {
    fn rng(&mut self) -> &mut dyn osis_crypto::NodeRng {
        &mut *self.cx.rng
    }

    fn due(&mut self) -> Vec<SyncId> {
        let mut out = Vec::new();
        // the sync IDs this node syncs: what moved of them alone
        for (s, _, now) in self.fx.set.settle(self.cx.store) {
            match now {
                Some(_) => self.fx.creds.want(s),
                None => {
                    self.fx.creds.unwant(&s);
                    out.push(s);
                }
            }
        }
        for s in self.fx.creds.due() {
            let (cx, unread) = (&mut *self.cx, self.unread);
            if self.fx.creds.settle(&s, || node_creds(cx, unread, &s).map(|c| c.digest())).is_some() {
                out.push(s);
            }
        }
        out
    }

    fn creds(&mut self, s: &SyncId) -> Option<Arc<Creds>> {
        node_creds(self.cx, self.unread, s)
    }

    fn named(&mut self, proven: &Proven) -> Named {
        named(proven)
    }

    fn counts(&mut self, named: &Named, copies: &osis_blob::Certificates) -> Vec<ProvenThing> {
        self.cx.engine.proven(&named.claims, copies).map(|p| (*p).clone()).unwrap_or_default()
    }

    fn judge(&mut self, s: &SyncId, proven: &[ProvenThing]) -> J {
        self.cx.engine.judge_peer(s, proven).unwrap_or(J::Unknown)
    }

    fn standing(&mut self, rec: RecordId, s: &SyncId, named: &Named, copies: &osis_blob::Certificates) -> Option<J> {
        let k = (rec, *s);
        if let Some(j) = self.fx.standing.current(&k) {
            return j;
        }
        self.fx.standing.want(k);
        let engine = &mut *self.cx.engine;
        let mut j = None;
        self.fx.standing.settle(&k, || {
            let proven = engine.proven(&named.claims, copies).map(|p| (*p).clone()).unwrap_or_default();
            j = Some(engine.judge_peer(s, &proven).unwrap_or(J::Unknown));
            j
        });
        j
    }

    fn standing_due(&mut self) -> Vec<(RecordId, SyncId)> {
        self.fx.standing.due()
    }

    fn unfollow(&mut self, rec: RecordId, s: &SyncId) {
        self.fx.standing.unwant(&(rec, *s));
    }

    fn covers_departures(&mut self, s: &SyncId, epoch: &Epoch) -> bool {
        self.cx.engine.covers_departures(s, *epoch).unwrap_or(false)
    }

    fn until(&mut self, s: &SyncId, by: &Credential) -> Position {
        // a store failure ends the member at the log's end read before it (0: nothing served)
        member_until(self.cx, s, by).unwrap_or(0)
    }

    fn departure_until(&mut self, s: &SyncId, proven: &BTreeSet<osis_base::Tid>) -> Option<Position> {
        departure_until(self.cx, s, proven).ok().flatten()
    }

    fn cursor_at(&mut self, pos: Position) -> Option<Cursor> {
        self.cx.store.cursor_at(pos).ok().flatten()
    }

    fn grant(&mut self, s: &SyncId, entry: &[u8; 32]) -> Option<Grant> {
        // the path this node keeps: a reader's recorded one, else the one registered here
        let steps: Vec<(Step, Option<osis_blob::ClaimSet>)> = match self.cx.store.synced(s)? {
            (_, Holding::Read | Holding::Keys) => path_of(self.cx, s)?.steps.clone(),
            (_, Holding::Unread) => self.cx.store.path(s).ok()??.steps.clone(),
        };
        let (_, claims) = steps.last()?;
        let entry_box = claims.as_ref()?.entries.get(entry)?.clone();
        Some(Grant { entry_box: Some(entry_box), steps: steps.into_iter().map(|(st, _)| st).collect() })
    }

    fn take_grant(&mut self, s: &SyncId, entry: &[u8; 32], grant: &Grant, signed: &dyn Fn(&[u8; 32]) -> bool) -> bool {
        let Some(b) = grant.entry_box.as_ref() else { return false };
        let Ok(Some(g)) = self.cx.engine.open_grant(s, entry, &grant.steps, b) else { return false };
        // verify first, learn after (spec/sync-opens.md §5)
        signed(&g.key) && self.cx.engine.learn_grant(&g).is_ok()
    }

    fn behind(&mut self, item: &BehindItem) -> SharedItem {
        use crate::store::Cred;
        let Ok(k) = osis_crypto::VerifyingKey::from_bytes(&item.key) else { return SharedItem::code(Code::DECLINED) };
        // the item names no kind of key: each kind it may be, in turn (a key is one of them)
        let creds = match item.step {
            Some(_) => vec![Cred::Sync(k), Cred::Claim(item.key), Cred::Signing(k)],
            None => vec![Cred::Sync(k), Cred::Signing(k)],
        };
        let max = osis_proto::limits::MAX_BEHIND_STEPS;
        let mut last = SharedItem::code(Code::DECLINED);
        for c in &creds {
            match self.cx.store.behind(&item.sync_id, item.step.as_ref(), c, max) {
                Ok((Code::OK, grant)) => return SharedItem { grant, ..SharedItem::code(Code::OK) },
                Ok((code, _)) => last = SharedItem::code(code),
                // a store failure refuses for now: the asker asks again after a back-off
                Err(_) => return SharedItem::code(Code::RATE_LIMITED),
            }
        }
        last
    }

    fn behind_unsigned(&mut self, s: &SyncId) -> SharedItem {
        // a store failure refuses for now: the asker asks again after a back-off
        SharedItem::code(self.cx.store.behind_refusal(s).unwrap_or(Code::RATE_LIMITED))
    }

    fn deposit(&mut self, src: crate::store::Source, item: &DepositItem) -> Code {
        // a store failure refuses for now: the sender offers it again after its back-off
        self.cx.store.take_deposit(item, Some(src)).unwrap_or(Code::RATE_LIMITED)
    }

    fn verify_steps(&mut self, s: &SyncId, known: &[Step], steps: &[Step]) -> Vec<Step> {
        let recorded: Vec<Step> = path_of(self.cx, s).map(|p| p.steps.iter().map(|(st, _)| st.clone()).collect()).unwrap_or_default();
        let ids: std::collections::BTreeSet<StepId> = recorded.iter().map(Step::id).collect();
        let mut out = known_steps(s, recorded.iter().chain(known), steps);
        out.retain(|st| !ids.contains(&st.id()));
        out
    }

    fn step_creds(&mut self, s: &SyncId, step: &Step) -> Vec<(Tested, Option<Epoch>)> {
        let Ok(Some(rc)) = self.cx.engine.read_credentials(s) else { return Vec::new() };
        let pk = step.keys.sync.to_bytes();
        let held = rc.keys.get(&step.id()).and_then(|k| k.sync.clone().map(|x| (x, k.epochs[0])));
        let held = held.or_else(|| rc.sync_keys.iter().find(|(_, k)| k.verifying_key().to_bytes() == pk).map(|(e, k)| (k.clone(), Some(*e))));
        held.filter(|(k, _)| k.verifying_key().to_bytes() == pk).map(|(key, e)| (Tested::SyncKey { step: Some(step.id()), key }, e)).into_iter().collect()
    }
}

/// The steps of `steps` that verify (spec/sync-ids.md §6 Known steps), in order up to the first
/// that does not: each a step of S, a genesis step verified as one, else a child of the step
/// before it in `steps` or, for the first, of the step of `parents` its `prev` names.
pub fn known_steps<'a>(s: &SyncId, parents: impl Iterator<Item = &'a Step> + Clone, steps: &[Step]) -> Vec<Step> {
    let mut out: Vec<Step> = Vec::new();
    for st in steps {
        let ok = st.sync_id == *s
            && match (out.last(), st.prev) {
                (Some(p), _) => st.verify_child(p).is_ok(),
                (None, None) => st.verify_genesis().is_ok(),
                (None, Some(prev)) => parents.clone().find(|p| p.id() == prev).is_some_and(|p| st.verify_child(p).is_ok()),
            };
        if !ok {
            break;
        }
        out.push(st.clone());
    }
    out
}
