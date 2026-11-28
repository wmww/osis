//! What opens reads of its own node (spec/sync-opens.md §4): per sync ID the credentials it
//! holds now. `Holds` is the one seam: the product reads it from the engine's facade and `unread`
//! (`NodeHolds`); a test from a table.

use super::cred::{Shown, Tested};
use crate::session::Proven;
use crate::types::{Credential, Cursor, Cx, Holding, Position};
use crate::unread::{Unread, UnreadCredentials};
use osis_base::SyncId;
use osis_engine::sync::ReadCredentials;
use osis_proto::{Code, DepositItem};
use osis_base::memo::Effects;
use osis_store::Named;
use std::sync::Arc;

/// What a record of `proven`'s connection names (spec/sync-opens.md §3): its claims.
pub fn named(proven: &Proven) -> Named {
    proven.named.clone()
}

/// One sync ID's credentials at this node (spec/sync-opens.md §4 Admissible).
#[derive(Clone, Debug, Default)]
pub struct Creds {
    /// How the node holds S: read, as a stub, or kept unread.
    pub holding: Option<Holding>,
    /// Credentials it shows.
    pub shows: Vec<Shown>,
    /// Credentials it tests, in test order.
    pub tests: Vec<Tested>,
    /// The sync key of this node's head (its step kept unread, its newest recorded step read):
    /// what signs an answer to a Hit on a claim key.
    pub step: Option<osis_crypto::SigningSecret>,
    /// The sync key of its head (none: no head here): a member opened by a credential of another
    /// is ended (spec/sync-opens.md §4 One open rule).
    pub head: Option<[u8; 32]>,
}

impl Creds {
    /// What a node keeping S unread holds (spec/sync-opens.md §4 Admissible): it shows and tests
    /// the sync proof of each sync secret it shows (`UnreadCredentials::keys`), and shows its
    /// head claim keys (`claims`) and its head's deposit key; its head's sync key, held, answers.
    pub fn kept_unread(uc: &UnreadCredentials, claims: &[[u8; 32]]) -> Creds {
        let mut c = Creds { holding: Some(Holding::Unread), ..Creds::default() };
        for (k, p) in &uc.keys {
            c.shows.push(Shown::Proof(*p.expose(), k.verifying_key().to_bytes()));
        }
        if uc.step.is_some() {
            c.shows.extend(claims.iter().map(|x| Shown::ClaimKey(*x)));
        }
        if let Some(d) = &uc.deposit {
            c.shows.push(Shown::Deposit(d.to_bytes()));
        }
        for (k, p) in &uc.keys {
            c.tests.push(Tested::Proof(*p.expose(), k.verifying_key().to_bytes()));
        }
        c.step = uc.step.and(uc.keys.first().map(|(k, _)| k.clone()));
        c.head = uc.head;
        c
    }

    /// What a reader of S holds (spec/sync-opens.md §4 Admissible): it shows the sync proof of
    /// each distinct sync key on its path whose sync secret it holds, its head claim keys
    /// (`claims`) and its head's deposit key, and tests the sync proofs of the sync secrets it
    /// holds, newest first, then its claim keys (`ReadCredentials::claim_keys`).
    pub fn reader(rc: &ReadCredentials, claims: &[[u8; 32]]) -> Creds {
        let mut c = Creds::default();
        let mut keys = std::collections::BTreeSet::new();
        for (id, p) in &rc.proofs {
            let Some(k) = rc.keys.get(id).and_then(|k| k.sync.as_ref()).map(|k| k.verifying_key().to_bytes()) else { continue };
            if keys.insert(k) {
                c.shows.push(Shown::Proof(*p, k));
            }
        }
        if let Some(head) = &rc.head {
            c.shows.extend(claims.iter().map(|x| Shown::ClaimKey(*x)));
            c.shows.push(Shown::Deposit(head.keys.deposit.to_bytes()));
            c.head = Some(head.keys.sync.to_bytes());
            c.step = rc.keys.get(&head.id()).and_then(|k| k.sync.clone());
        }
        c.tests = rc.held_proofs.iter().map(|(p, k)| Tested::Proof(*p, *k)).collect();
        c.tests.extend(rc.claim_keys.iter().map(|(sync, key)| Tested::ClaimKey { key: key.clone(), sync: *sync }));
        c
    }

    /// The digest `changed_at` compares (spec/sync-opens.md §3): what is shown and tested, and
    /// the step that answers.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = osis_base::hash::Hasher::new();
        h.update(&[self.holding.map_or(0, |x| x as u8 + 1)]);
        for c in &self.shows {
            h.update(b"s").update(c.matched());
        }
        for c in &self.tests {
            h.update(b"t").update(&c.matched());
        }
        if let Some(k) = &self.step {
            h.update(b"k").update(&k.verifying_key().to_bytes());
        }
        if let Some(k) = &self.head {
            h.update(b"h").update(k);
        }
        h.finalize()
    }
}

/// What opens reads of its node now (spec/sync-opens.md §4).
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
    /// An ended member's `until` (spec/sync-opens.md §6): at a node keeping S unread the position
    /// of its head's event; at a reader the highest position at which an entry in S of a rotation
    /// superseding `by`'s sync epoch, or of a role commit the recorded step past `by`'s sync key
    /// waits on, was first logged, else the node log's end.
    fn until(&mut self, s: &SyncId, by: &Credential) -> Position;
    /// The cursor naming `pos` of this node's log, for a Lost.
    fn cursor_at(&mut self, pos: Position) -> Option<Cursor>;
    /// Takes a Deposit item (spec/sync-inbox.md §3) a peer offered; `src` is where its peer
    /// budget charge lives (the peer's record, else the connection).
    fn deposit(&mut self, src: crate::store::Source, item: &DepositItem) -> Code;
    /// A verified path of S a Head answer gave (`Engine::hear_path`).
    fn hear_path(&mut self, s: &SyncId, steps: Vec<osis_blob::Step>);
}

/// The memo effects opens follows (notes/sync-facade.md, Effects): the sync IDs this node syncs,
/// and per sync ID of it the digest of its credentials. A step settles only the keys whose reads
/// moved.
#[derive(Clone)]
pub struct Fx {
    set: crate::set::SyncsFollow,
    creds: Effects<SyncId, Option<[u8; 32]>>,
}

impl Default for Fx {
    fn default() -> Fx {
        Fx { set: crate::set::SyncsFollow::default(), creds: Effects::new("opens credentials") }
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

/// S's credentials as the engine (read) or `unread` (kept unread) gives them.
fn node_creds(cx: &mut Cx, unread: &Unread, s: &SyncId) -> Option<Arc<Creds>> {
    let (_, holding) = cx.store.synced(s)?;
    let c = match holding {
        // held as a stub it opens as a reader does
        Holding::Read | Holding::Stub => {
            let rc = cx.engine.read_credentials(s).ok()??;
            let claims = cx.store.head_claim_keys(s).ok()?;
            Creds { holding: Some(holding), ..Creds::reader(&rc, &claims) }
        }
        // at a head past its keys it holds S and shows only the secrets no step of its path
        // bears: S is still in the sync set, so its `changed_at` moves and the peer hears a
        // generation
        Holding::Unread => match unread.credentials(s) {
            Some(uc) => Creds::kept_unread(&uc, &cx.store.head_claim_keys(s).ok()?),
            None => Creds { holding: Some(holding), ..Creds::default() },
        },
    };
    Some(Arc::new(c))
}

/// An ended member's `until` (spec/sync-opens.md §6): kept unread, the position of S's head
/// event; read and opened by an older step's sync proof, the highest position at which an entry
/// in S of a rotation superseding that step's sync epoch, or of a role commit the recorded step
/// past that sync key waits on, was first logged (a store takes that step only holding those);
/// else (or none such) the log's end.
pub(crate) fn member_until(cx: &mut Cx, s: &SyncId, by: &Credential) -> crate::types::Result<Position> {
    let end = cx.store.log_bounds()?.0;
    match (cx.store.synced(s), by) {
        (Some((_, Holding::Unread)), _) => Ok(cx.store.head_at(s)?.unwrap_or(end)),
        (Some((_, Holding::Read | Holding::Stub)), Credential::SyncProof(k)) => {
            let rc = cx.engine.read_credentials(s)?;
            let e = rc.as_ref().and_then(|rc| rc.keys.values().find(|h| h.sync.as_ref().is_some_and(|x| x.verifying_key().to_bytes() == *k)).and_then(|h| h.epochs[0]));
            let mut commits = match e {
                Some(e) => cx.engine.rotations_superseding(s, &e)?,
                None => Vec::new(),
            };
            commits.extend(step_past_needs(cx, s, k)?);
            let mut at = None;
            for c in commits {
                for b in cx.engine.commit_blobs(&c)?.iter() {
                    at = at.max(cx.store.first_logged(s, b)?);
                }
            }
            Ok(at.unwrap_or(end))
        }
        _ => Ok(end),
    }
}

/// The role commits the recorded step of S moving past sync key `k` waits on (`Engine::step_needs`):
/// the first recorded step not bearing `k` after the last bearing it.
fn step_past_needs(cx: &mut Cx, s: &SyncId, k: &[u8; 32]) -> crate::types::Result<Vec<osis_base::CommitId>> {
    let Some(path) = cx.store.path(s)? else { return Ok(Vec::new()) };
    let Some(last) = path.steps.iter().rposition(|st| st.keys.sync.to_bytes() == *k) else { return Ok(Vec::new()) };
    let Some(past) = path.steps.get(last + 1) else { return Ok(Vec::new()) };
    Ok(cx.engine.step_needs(s, &past.id())?.to_vec())
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

    fn until(&mut self, s: &SyncId, by: &Credential) -> Position {
        // a store failure ends the member at the log's end read before it (0: nothing served)
        member_until(self.cx, s, by).unwrap_or(0)
    }

    fn cursor_at(&mut self, pos: Position) -> Option<Cursor> {
        self.cx.store.cursor_at(pos).ok().flatten()
    }

    fn deposit(&mut self, src: crate::store::Source, item: &DepositItem) -> Code {
        // a store failure refuses for now: the sender offers it again after its back-off
        self.cx.store.take_deposit(item, Some(src)).unwrap_or(Code::RATE_LIMITED)
    }

    fn hear_path(&mut self, s: &SyncId, steps: Vec<osis_blob::Step>) {
        // the longest path heard stands: a shorter answer is a peer behind
        let known = self.cx.engine.heard_len(s);
        let Some(head) = steps.last().map(|st| st.keys.sync.to_bytes()) else { return };
        if steps.len() <= known {
            return;
        }
        self.cx.engine.hear_path(s, steps);
        // held as a stub: its entries bound to the heard head, come before the step was known,
        // are taken now (spec/sync-ids.md §3 Taking a claim), as a store's at a head move
        if self.cx.store.synced(s).is_some_and(|(_, h)| h == Holding::Stub) {
            for b in self.cx.store.entries_bound_to(s, &head).unwrap_or_default() {
                let (Ok(Some(e)), Ok(Some(bytes))) = (self.cx.store.entry(s, &b), crate::store::blob_bytes(self.cx.engine, self.cx.store, &b)) else { continue };
                let pages = crate::store::page_bytes(self.cx.engine, self.cx.store, &bytes).unwrap_or_default();
                let _ = self.cx.engine.open_entry(s, &b, &e.wrap, &bytes, &pages, 0);
            }
        }
    }
}
