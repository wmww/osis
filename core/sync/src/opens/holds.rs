//! What opens reads of its own node (spec/sync-opens.md §4): per sync ID the credentials it
//! holds now and the judgement J of a peer's proven actors. `Holds` is the one seam: the product
//! reads it from the engine's facade and `unread` (`NodeHolds`); a test from a table.

use super::cred::{Shown, Tested};
use crate::session::Proven;
use crate::types::{Credential, Cursor, Cx, Holding, Position};
use crate::unread::Unread;
use osis_base::{SyncId, Tid};
use osis_crypto::Epoch;
use osis_engine::sync::J;
use osis_label::Step;
use osis_proto::{BehindItem, Code, DepositItem, Grant, SharedItem};
use osis_base::memo::Effects;
use std::sync::Arc;

/// One sync ID's credentials at this node, before a connection's J filters them
/// (spec/sync-opens.md §4 Admissible): each with the epoch it is at, for the Departed rule.
#[derive(Clone, Debug, Default)]
pub struct Creds {
    /// How the node holds S: read, or kept unread.
    pub holding: Option<Holding>,
    /// Credentials it shows, each with its epoch (none: at no epoch covering a departure).
    pub shows: Vec<(Shown, Option<Epoch>)>,
    /// Credentials it tests, in test order (spec/sync-ids.md §6 Walk: deepest step first, then
    /// sync keys newest first), each with its epoch.
    pub tests: Vec<(Tested, Option<Epoch>)>,
    /// The sync key of this node's step (its head kept unread, its newest recorded step read),
    /// the step's id, and its epoch: what answers a Hit on a sync key, claim or static entry.
    pub step: Option<(osis_label::StepId, osis_crypto::SigningSecret, Option<Epoch>)>,
    /// A digest of what moves J for S here (its roster, spec/sync-opens.md §3 `changed_at`):
    /// two values with equal credentials and equal roles are one value.
    pub roles: [u8; 32],
}

impl Creds {
    /// The digest `changed_at` compares (spec/sync-opens.md §3): what is shown and tested, the
    /// step that answers, and the roles. Secrets enter only through a keyed hash.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = osis_base::hash::Hasher::new_keyed(&self.roles);
        h.update(&[self.holding.map_or(0, |x| x as u8 + 1)]);
        for (c, e) in &self.shows {
            h.update(b"s").update(c.matched()).update(&epoch_bytes(e));
        }
        for (c, e) in &self.tests {
            h.update(b"t").update(&c.matched(&SyncId([0; 16]))).update(&epoch_bytes(e));
        }
        if let Some((id, k, e)) = &self.step {
            h.update(b"k").update(&id.0).update(&k.verifying_key().to_bytes()).update(&epoch_bytes(e));
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
    /// S's credentials, `None` when S is not in the sync set.
    fn creds(&mut self, s: &SyncId) -> Option<Arc<Creds>>;
    /// The actors a connection's proofs count for now (spec/sync-opens.md §2): its account only
    /// while the key it proved with is at an epoch open here, its node, its key actors; sorted.
    fn actors(&mut self, proven: &Proven) -> Vec<Tid>;
    /// J of a peer's proven actors (`actors`) for S.
    fn judge(&mut self, s: &SyncId, actors: &[Tid]) -> J;
    /// Whether `epoch` of S's thing covers every departure this node knows of (spec/crypto.md §4).
    fn covers_departures(&mut self, s: &SyncId, epoch: &Epoch) -> bool;
    /// Whether `actor` is a known actor here now (spec/sync-opens.md §2 Known actor).
    fn known_actor(&mut self, actor: &Tid) -> bool;
    /// An ended member's `until` (spec/sync-opens.md §6): the highest position at which an entry
    /// in S of a rotation superseding `by`'s epoch was first logged, else the node log's end; at
    /// a node keeping S unread the position of its head's event.
    fn until(&mut self, s: &SyncId, by: &Credential) -> Position;
    /// The cursor naming `pos` of this node's log, for a Lost.
    fn cursor_at(&mut self, pos: Position) -> Option<Cursor>;
    /// The grant a static entry's answer carries (spec/sync-opens.md §5): the head's entry box
    /// for `entry` and the path to the head, when this node keeps them.
    fn grant(&mut self, s: &SyncId, entry: &[u8; 32]) -> Option<Grant>;
    /// Takes a static entry's grant: the head's sync key when the path verifies from its genesis
    /// step and the box's sync secret derives it (spec/sync-opens.md §5), the box's secrets taken.
    fn take_grant(&mut self, s: &SyncId, entry: &[u8; 32], grant: &Grant) -> Option<[u8; 32]>;
    /// Answers a Behind item whose open signature verified (spec/sync-ids.md §6 Behind).
    fn behind(&mut self, item: &BehindItem) -> SharedItem;
    /// Answers a Behind item whose signature did not verify: 13 for a sync ID not kept unread
    /// here, else 14.
    fn behind_unsigned(&mut self, s: &SyncId) -> SharedItem;
    /// S's recorded genesis step and its claim set, when this node reads S (a Register from
    /// genesis, spec/sync-ids.md §6 Walk).
    fn genesis(&mut self, s: &SyncId) -> Option<(Step, Option<osis_label::ClaimSet>)>;
    /// Takes a Deposit item (spec/sync-inbox.md §3) a peer offered; `src` is where its peer
    /// budget charge lives (the peer's record, else the connection).
    fn deposit(&mut self, src: crate::store::Source, item: &DepositItem) -> Code;
    /// Verifies steps a source gave (spec/sync-ids.md §6 Known steps): each under its parent,
    /// the first under the named step (or from genesis). Those that verify.
    fn verify_steps(&mut self, s: &SyncId, named: Option<&osis_label::StepId>, steps: &[Step]) -> Vec<Step>;
    /// The walk credentials of a step a source gave (spec/sync-ids.md §6 Test).
    fn step_creds(&mut self, s: &SyncId, step: &Step) -> Vec<(Tested, Option<Epoch>)>;
}

/// The memo effects opens follows (notes/sync-boundary.md, What the engine gives): the sync set,
/// and per sync ID of it the digest of its credentials. A step settles only the keys whose reads
/// moved.
#[derive(Clone)]
pub struct Fx {
    set: crate::set::SetFollow,
    creds: Effects<SyncId, Option<[u8; 32]>>,
}

impl Default for Fx {
    fn default() -> Fx {
        Fx { set: crate::set::SetFollow::new("opens sync set"), creds: Effects::new("opens credentials") }
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
    let (t, _) = cx.engine.sync_holding(s).ok()??;
    cx.engine.sync_ids(&t).ok()?.iter().find(|o| o.id == *s && !o.hint).map(|o| o.path.clone())
}

/// S's credentials as the engine (read) or `unread` (kept unread) gives them.
fn node_creds(cx: &mut Cx, unread: &Unread, s: &SyncId) -> Option<Arc<Creds>> {
    {
        let (_, holding) = cx.engine.sync_holding(s).ok()??;
        let mut c = Creds { holding: Some(holding), ..Creds::default() };
        match holding {
            Holding::Read => {
                let rc = cx.engine.read_credentials(s).ok()??;
                // what moves J (spec/sync-opens.md §3 `changed_at`: a role on S changes)
                c.roles = rc.roster;
                for (e, k) in &rc.read_secrets {
                    c.shows.push((Shown::Read(*e, *k.expose()), Some(*e)));
                    c.tests.push((Tested::Read(*e, k.clone()), Some(*e)));
                }
                for st in &rc.statics {
                    c.shows.push((Shown::Static(*st), None));
                }
                // the sync proof of the newest recorded step's sync key (spec/sync-opens.md §4)
                if let (Some(head), Some((id, p))) = (&rc.head, rc.proofs.first())
                    && head.id() == *id
                {
                    c.shows.push((Shown::Proof(*p), None));
                }
                // the walk's tests (spec/sync-ids.md §6 Walk): the recorded steps deepest first,
                // each by its sync key when held, else its claim key
                if let Some(path) = path_of(cx, s) {
                    for (step, _) in path.steps.iter().rev() {
                        let id = step.id();
                        let keys = rc.keys.get(&id);
                        if let Some(k) = keys.and_then(|k| k.sync.clone()) {
                            c.tests.push((Tested::SyncKey { step: id, key: k }, keys.and_then(|k| k.epochs[0])));
                        } else if let Ok(Some(k)) = cx.engine.claim_key(s, &id) {
                            c.tests.push((Tested::Claim { step: id, key: k, sync: step.keys.sync.to_bytes() }, None));
                        }
                    }
                }
                if let Some(head) = &rc.head {
                    let keys = rc.keys.get(&head.id());
                    if let Some(k) = keys.and_then(|k| k.sync.clone()) {
                        let e = keys.and_then(|k| k.epochs[0]);
                        c.step = Some((head.id(), k, e));
                    }
                }
            }
            Holding::Unread => {
                let uc = unread.credentials(s)?;
                c.shows.push((Shown::SyncKey(uc.sync.verifying_key().to_bytes()), None));
                c.shows.push((Shown::Proof(*uc.proof.expose()), None));
                c.tests.push((Tested::Proof(*uc.proof.expose()), None));
                c.shows.push((Shown::Deposit(uc.deposit.to_bytes()), None));
                if let Some(cs) = &uc.claims {
                    c.shows.extend(cs.claims.iter().map(|k| (Shown::Claim(*k), None)));
                    c.shows.extend(cs.entries.keys().map(|k| (Shown::Static(*k), None)));
                }
            }
        }
        Some(Arc::new(c))
    }
}

impl Holds for NodeHolds<'_, '_> {
    fn rng(&mut self) -> &mut dyn osis_crypto::NodeRng {
        &mut *self.cx.rng
    }

    fn due(&mut self) -> Vec<SyncId> {
        let mut out = Vec::new();
        // the sync set per key: what moved of it alone (a failing engine read is tried again at
        // the next settle; nothing moved is reported meanwhile)
        for (s, now) in self.fx.set.settle(self.cx.engine).unwrap_or_default() {
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

    fn actors(&mut self, proven: &Proven) -> Vec<Tid> {
        let engine = &mut *self.cx.engine;
        let account = proven.account.as_ref().filter(|(r, k)| engine.key_open(r, k)).map(|(r, _)| r.tid());
        let mut v: Vec<Tid> = account.into_iter().chain(proven.node).chain(proven.key_actors.keys().copied()).collect();
        v.sort();
        v.dedup();
        v
    }

    fn judge(&mut self, s: &SyncId, actors: &[Tid]) -> J {
        self.cx.engine.judge_peer(s, actors).unwrap_or(J::Unknown)
    }

    fn covers_departures(&mut self, s: &SyncId, epoch: &Epoch) -> bool {
        self.cx.engine.covers_departures(s, *epoch).unwrap_or(false)
    }

    fn known_actor(&mut self, actor: &Tid) -> bool {
        self.cx.engine.known_actor(actor)
    }

    fn until(&mut self, _s: &SyncId, _by: &Credential) -> Position {
        0
    }

    fn cursor_at(&mut self, _pos: Position) -> Option<Cursor> {
        None
    }

    fn grant(&mut self, _s: &SyncId, _entry: &[u8; 32]) -> Option<Grant> {
        None
    }

    fn take_grant(&mut self, _s: &SyncId, _entry: &[u8; 32], _grant: &Grant) -> Option<[u8; 32]> {
        None
    }

    fn behind(&mut self, item: &BehindItem) -> SharedItem {
        use crate::store::Cred;
        let Ok(k) = osis_crypto::VerifyingKey::from_bytes(&item.key) else { return SharedItem::code(Code::DECLINED) };
        // the item names no kind of key: each kind it may be, in turn (a key is one of them)
        let creds = match item.step {
            Some(_) => vec![Cred::Sync(k), Cred::Claim(item.key), Cred::Signing(k)],
            None => vec![Cred::Sync(k), Cred::Signing(k)],
        };
        let max = osis_proto::limits::REPLY_BUDGET / 326;
        let mut last = SharedItem::code(Code::DECLINED);
        for c in &creds {
            match self.cx.store.behind(&item.sync_id, item.step.as_ref(), c, max as usize) {
                Ok((Code::OK, grant)) => return SharedItem { grant, ..SharedItem::code(Code::OK) },
                Ok((code, _)) => last = SharedItem::code(code),
                // a store failure refuses for now: the asker asks again after a back-off
                Err(_) => return SharedItem::code(Code::RATE_LIMITED),
            }
        }
        last
    }

    fn behind_unsigned(&mut self, s: &SyncId) -> SharedItem {
        SharedItem::code(if self.cx.store.holding(s) == Some(Holding::Unread) { Code::DECLINED } else { Code::UNKNOWN_SYNC_ID })
    }

    fn genesis(&mut self, s: &SyncId) -> Option<(Step, Option<osis_label::ClaimSet>)> {
        let (t, Holding::Read) = self.cx.engine.sync_holding(s).ok()?? else { return None };
        let ids = self.cx.engine.sync_ids(&t).ok()?;
        let o = ids.iter().find(|o| o.id == *s && !o.hint)?;
        o.path.steps.first().cloned()
    }

    fn deposit(&mut self, src: crate::store::Source, item: &DepositItem) -> Code {
        // a store failure refuses for now: the sender offers it again after its back-off
        self.cx.store.take_deposit(item, Some(src)).unwrap_or(Code::RATE_LIMITED)
    }

    fn verify_steps(&mut self, _s: &SyncId, _named: Option<&osis_label::StepId>, _steps: &[Step]) -> Vec<Step> {
        Vec::new()
    }

    fn step_creds(&mut self, _s: &SyncId, _step: &Step) -> Vec<(Tested, Option<Epoch>)> {
        Vec::new()
    }
}
