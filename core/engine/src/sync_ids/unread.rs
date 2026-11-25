//! What a node keeping a thing unread holds of it (spec/sync.md §3 Kept unread, Kept sync IDs):
//! its sync secrets and the sync IDs it keeps for it, with their steps, and nothing else (no
//! roster, chain, `keys.0` or commit). Filled from the sync copies it takes (spec/wire.md §4
//! `SyncCopyPlaintext`: a holder's `secrets.0` piece and the `sync.0` delta, no header) and, for a
//! node that holds role commits of the thing too (a lowering from read, a certificate copy under
//! another sync ID), from what those gave (`Indexes::secrets`, `Indexes::steps`). One derivation
//! (`Core::unread`) over what is held, live and at an open alike: the copies are rows, read again
//! by `load`.
//!
//! Invariant (security; spec/sync.md §3 "only a step on the node's own path bearing the sync key
//! of a held secret keeps S's entries"): a sync copy is anyone's word who may log under its
//! holder's sync ID (a writer of the holder, or a depositor) or seal to its holder's read key, and
//! is judged by nothing but its bytes: a box keyed with another holder, or a history entry, makes
//! it bad input (`parse`); a secret it gives is kept only where a step on a path verified from its
//! sync ID's genesis (each step signed by its parent's delete key, the genesis by its own, whose
//! delete key the sync ID commits to) bears the secret's sync key: the thing's `sync.0` state as
//! judged (an admin's word), and the copies' own steps only where the node holds no record of the
//! thing (a genesis is anyone's making: with the record, a copy's step would make a dependent
//! thing count independent, or put a forged sync ID in a reader's place), for what the walk and
//! ownership read (`Unread::secrets`), the steps
//! registered with this node for what it shows at peers (`Unread::candidates`, judged by
//! osis-sync's unread judgement against its stored path). A forger may still make a sync
//! ID of its own (its own genesis, its own secret): that one is kept beside the real one and never
//! displaces it (a node keeping a thing unread syncs every sync ID it keeps for it,
//! `Engine::thing_sync_now`), costing only what its deposit budget lets it log.

use crate::engine::{Core, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, Role, Tid};
use osis_crypto::{Epoch, Secret32};
use osis_schema::core_types as ct;
use osis_schema::core_types::{BoxKey, SecretBox};
use osis_schema::RawKey;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `su/` + blob ID: a sync copy taken here (`HeldSyncCopy`): the thing it came under (15 bytes),
/// whether it came sealed (one byte, 1), then its `SyncCopyPlaintext` bytes.
/// Invariant (bounds; spec/sync-ids.md §5 Peer budget): a row lives exactly as long as the store
/// holds an entry of its blob (`Engine::unnamed_sync_copy`), and that entry is charged to its
/// bringer unless stamped (`Opened::SyncCopy`), so what a party makes this node keep is bounded
/// by its budget, a writer's stamp aside.
pub(crate) const SYNC_COPIES: &[u8] = b"su/";

/// A sync copy as taken here: the thing it came under (whose sync ID it is an entry of, or whose
/// inbox it was sealed to), the holder whose copy it is (its piece's, else that thing), whether
/// it came sealed (a sealed copy, never a log under the sync ID), the copy, its content key, and
/// what its deltas say: its boxes and its steps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldSyncCopy {
    pub under: Tid,
    pub holder: Tid,
    pub sealed: bool,
    pub copy: osis_commit::SyncCopy,
    pub key: ContentKey,
    pub boxes: BTreeMap<BoxKey, SecretBox>,
    pub steps: ct::SyncIds,
}

/// What two blobs of one sync copy share: the hash of its canonical plaintext. Two copies of one
/// (commit, thing, holder) with different bytes (a forged box beside the real one) are two
/// copies, so neither displaces the other (spec/permissions.md §4 Logging certificates).
pub type ContentKey = [u8; 32];

/// The content key of sync copy plaintext `plain` (canonical: `SyncCopy::decode` checks).
pub fn content_key(plain: &[u8]) -> ContentKey {
    osis_base::hash::hash(&[b"osis sync copy".as_slice(), plain].concat())
}

/// The sync copies a sync ID carries, by content: the thing reading it each is under, and its
/// plaintext (`Engine::sync_copies_carried`).
pub type Carried = BTreeMap<ContentKey, (Tid, Arc<Vec<u8>>)>;

/// A sync copy as certificates name it: (commit, thing, holder).
pub type CopyName = (CommitId, Tid, Tid);

/// Per thing, the sync copies on it taken here, by blob.
pub type SyncCopies = BTreeMap<BlobId, Arc<HeldSyncCopy>>;

/// A delta of a sync copy read without its header: its values alone (its stamps are no one's:
/// nothing of it applies, spec/wire.md §4). Pages are bad input (a holder's piece and a
/// `sync.0` delta fit a blob).
fn read_headerless(bytes: &[u8], commit: &CommitId) -> Option<osis_crdt::Fragment> {
    let mut interner = osis_crdt::Interner::new();
    let own = interner.commit(*commit);
    let cx = osis_crdt::DeltaCtx { ts: osis_base::Ts::default(), own, range: osis_crdt::CounterRange { lo: 0, hi: u64::MAX }, kind: osis_crdt::DeltaKind::Writer };
    osis_crdt::decode_delta(bytes, &cx, &mut interner, None).ok().map(|d| d.fragment)
}

/// The step records a `sync.0` delta writes, as the delta alone gives them: a sync ID set whole
/// (a genesis) and each step record set into one (a later step: its delta reads as nothing
/// without the state it joins). A record that does not decode is no step.
fn delta_steps(f: &osis_crdt::Fragment) -> ct::SyncIds {
    use crate::apply::keys::{field, map};
    use osis_schema::Codec;
    let mut out: ct::SyncIds = f.read().and_then(|v| ct::SYNC.decode(&v).ok()).unwrap_or_default();
    for (_, _, k, sub) in map(Some(f)).into_iter().flat_map(|m| m.entries()) {
        let (Some(id), Some(sub)) = (k.and_then(|k| osis_base::SyncId::from_value(k).ok()), sub) else { continue };
        for (_, _, sk, rf) in map(field(sub, 0)).into_iter().flat_map(|m| m.entries()) {
            let Some(Ok(sk)) = sk.map(<[u8; 32]>::from_value) else { continue };
            let Some(Ok(rec)) = rf.and_then(osis_crdt::Fragment::read).map(|v| ct::StepRecord::from_value(&v)) else { continue };
            out.entry(id).or_insert_with(|| ct::SyncEntry { steps: BTreeMap::new() }).steps.entry(sk).or_insert(rec);
        }
    }
    out
}

/// Reads sync copy `plain`, come under `under` (`sealed`: sealed to it): `None` when it is bad
/// input (spec/wire.md §4: not a sync copy; a copy of `under` itself; its piece holding records
/// keyed with two holders, or one keyed with none: a history box; a delta that does not decode).
/// Its holder is its piece's, else `under`: whether `under` may carry that holder's copy is the
/// taker's check (`Engine::take_sync_copy`).
pub(crate) fn parse(under: Tid, sealed: bool, plain: &[u8]) -> Option<HeldSyncCopy> {
    let copy = osis_commit::SyncCopy::decode(plain).ok().filter(|c| c.thing != under)?;
    let mut boxes = BTreeMap::new();
    let mut holder = under;
    if let Some(p) = &copy.piece {
        let w = crate::apply::keys::secrets_write(&read_headerless(p, &copy.commit)?);
        let holders: BTreeSet<Tid> = w.boxes.keys().chain(&w.removed).map(|k| k.holder.0).collect();
        if !w.history.is_empty() || holders.len() > 1 {
            return None;
        }
        holder = holders.first().copied().unwrap_or(under);
        boxes = w.boxes;
    }
    if holder == copy.thing {
        return None;
    }
    let steps = match &copy.sync {
        Some(s) => delta_steps(&read_headerless(s, &copy.commit)?),
        None => ct::SyncIds::default(),
    };
    Some(HeldSyncCopy { under, holder, sealed, key: content_key(plain), copy, boxes, steps })
}

/// The (thing, holder) of sync copy `plain` (its piece's holder): `None` where it is bad input
/// or boxes no holder.
pub(crate) fn holder_of(plain: &[u8]) -> Option<(Tid, Tid)> {
    let copy = osis_commit::SyncCopy::decode(plain).ok()?;
    let w = crate::apply::keys::secrets_write(&read_headerless(copy.piece.as_ref()?, &copy.commit)?);
    let h = w.boxes.keys().map(|k| k.holder.0).next()?;
    Some((copy.thing, h))
}

/// Loads the sync copies taken (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("sync copy row");
    let mut rows: Vec<(BlobId, HeldSyncCopy)> = Vec::new();
    tx.scan(SYNC_COPIES, |k, v| {
        let b = BlobId(k.try_into().map_err(|_| bad())?);
        let (u, rest) = v.split_at_checked(15).ok_or_else(bad)?;
        let (sealed, plain) = rest.split_first().ok_or_else(bad)?;
        rows.push((b, parse(Tid::from_bytes(u.try_into().map_err(|_| bad())?), *sealed == 1, plain).ok_or_else(bad)?));
        Ok(())
    })?;
    for (b, c) in rows {
        index(tx, b, c);
    }
    Ok(())
}

fn index(tx: &mut Tx<'_>, b: BlobId, c: HeldSyncCopy) {
    let (t, c_under, ids, holder) = (c.copy.thing, c.under, c.steps.clone(), c.holder);
    let mut m = tx.core.ix.sync_copies.get(&t).map(|x| (**x).clone()).unwrap_or_default();
    m.insert(b, Arc::new(c));
    tx.core.ix.sync_copies.insert(t, Arc::new(m));
    tx.core.ix.sync_copies_under.insert(c_under, b);
    tx.core.ix.sync_copy_on.insert(b, t);
    for id in ids.keys() {
        tx.core.ix.sync_copy_ids.insert(*id, t);
    }
    tx.core.ix.sync_copy_holders.insert(holder, t);
}

/// The sync IDs `m`'s copies carry steps of.
fn ids_of(m: &SyncCopies) -> BTreeSet<osis_base::SyncId> {
    m.values().flat_map(|c| c.steps.keys().copied()).collect()
}

/// Takes sync copy `c`, blob `b` (one taken already changes nothing).
pub(crate) fn note(tx: &mut Tx<'_>, b: &BlobId, c: HeldSyncCopy) -> Result<()> {
    if tx.core.ix.sync_copy_on.contains_key(b) {
        return Ok(());
    }
    let v = [c.under.as_bytes().as_slice(), &[u8::from(c.sealed)], &c.copy.encode()].concat();
    tx.txn.put_local(&[SYNC_COPIES, &b.0].concat(), &v, Shred::No)?;
    index(tx, *b, c);
    Ok(())
}

/// Sync copy blob `b`'s row goes (the store holds no entry of it).
pub(crate) fn drop_blob(tx: &mut Tx<'_>, b: &BlobId) -> Result<()> {
    let Some(t) = tx.core.ix.sync_copy_on.get(b).copied() else { return Ok(()) };
    tx.txn.remove_local(&[SYNC_COPIES, &b.0].concat(), Shred::No)?;
    tx.core.ix.sync_copy_on.remove(b);
    let mut m = tx.core.ix.sync_copies.get(&t).map(|x| (**x).clone()).unwrap_or_default();
    if let Some(c) = m.remove(b) {
        tx.core.ix.sync_copies_under.remove(&c.under, b);
        let left = ids_of(&m);
        for id in c.steps.keys().filter(|id| !left.contains(*id)) {
            tx.core.ix.sync_copy_ids.remove(id, &t);
        }
        if !m.values().any(|x| x.holder == c.holder) {
            tx.core.ix.sync_copy_holders.remove(&c.holder, &t);
        }
    }
    match m.is_empty() {
        true => tx.core.ix.sync_copies.remove(&t),
        false => tx.core.ix.sync_copies.insert(t, Arc::new(m)),
    };
    Ok(())
}

/// The sync copies on `t` go (it is forgotten whole).
pub(crate) fn forget(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    let Some(m) = tx.core.ix.sync_copies.get(t).cloned() else { return Ok(()) };
    for id in ids_of(&m) {
        tx.core.ix.sync_copy_ids.remove(&id, t);
    }
    for (b, c) in m.iter() {
        tx.core.ix.sync_copy_holders.remove(&c.holder, t);
        tx.txn.remove_local(&[SYNC_COPIES, &b.0].concat(), Shred::No)?;
        tx.core.ix.sync_copy_on.remove(b);
        tx.core.ix.sync_copies_under.remove(&c.under, b);
    }
    tx.core.ix.sync_copies.remove(t);
    Ok(())
}

/// What this node keeps of thing `t` unread (spec/sync.md §3): the sync secrets it holds that a
/// step bears, the steps its sync copies carry, and which copies count (spec/permissions.md §4
/// Logging certificates: a sync copy counts once its box opens to a secret whose sync key a step
/// bears, or, boxing nothing, once each step it carries verifies from its sync ID's genesis).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Unread {
    /// The secrets held that a step of the thing's `sync.0` state bears, or, with no record of
    /// the thing held, a step of the copies'.
    pub secrets: BTreeMap<Epoch, Secret32>,
    /// Every sync secret held of the thing (`secrets` and those no such step bears yet): what
    /// is judged against the steps registered with this node (its stored path, osis-sync's;
    /// spec/crypto.md §4 Established: a step of its stored path bearing the secret's sync key).
    pub candidates: BTreeMap<Epoch, Secret32>,
    /// The steps of every sync copy on `t`, joined, where no record of `t` is held (else none):
    /// what `owned_sync_ids` judges.
    pub steps: ct::SyncIds,
    pub counted: BTreeSet<BlobId>,
    /// The holders of counted copies of a box opening to a secret whose sync key a head bears
    /// (the newest step of a sync ID of `t` held: `heads`): things holding sync or above on `t`
    /// as this node knows it from them (`stubs_of`). A head past every key a holder's boxes give
    /// is its removal (spec/sync-judgement.md §6 Stops): a holder of sync alone is told so by
    /// that step, never by a header (spec/sync-ids.md §2 What a sync holder learns).
    /// Invariant (security): a holder is named only by a box opening to a secret a step bears,
    /// so what anyone may bring (a copy boxing nothing) names no role.
    pub holders: BTreeSet<Tid>,
}

impl Unread {
    pub(crate) fn holds_any(&self) -> bool {
        !self.secrets.is_empty()
    }
}

/// A sync copy's blob, holder and the sync secrets its box gave.
type Given = (BlobId, Tid, Vec<(Epoch, Secret32)>);

/// The sync key of sync secret `s` (spec/sync-ids.md §2).
pub(crate) fn sync_key(s: &Secret32) -> [u8; 32] {
    osis_crypto::role_key(osis_crypto::RoleKey::Sync, s).verifying_key().to_bytes()
}

/// The sync keys of the steps of `steps` on a path verified from their sync ID's genesis.
fn borne(steps: &ct::SyncIds) -> BTreeSet<[u8; 32]> {
    let mut out = BTreeSet::new();
    for (id, e) in steps {
        let Ok(st) = osis_blob::sync_steps(e) else { continue };
        let plain: BTreeMap<osis_blob::StepId, osis_blob::Step> = st.iter().map(|(k, (s, _))| (*k, s.clone())).collect();
        for (k, (s, _)) in &st {
            if osis_blob::path_to(&plain, k).is_ok_and(|p| p.first().is_some_and(|g| g.sync_id == *id)) {
                out.insert(s.keys.sync.to_bytes());
            }
        }
    }
    out
}

/// The sync keys the heads bear (`Unread::holders`): per sync ID, its newest step held, of
/// `recorded` or carried by a copy (`steps`, on a path verified from the sync ID's genesis), the
/// deepest, ties by lowest step ID (`sync_ids::actors::head_of`). With `recorded` (the thing's
/// record held), a copy's steps count only on a sync ID it places: a child of a placed step is
/// signed by its parent's delete key, an admin secret's, while a genesis is anyone's making.
fn head_keys(steps: &ct::SyncIds, recorded: Option<&crate::sync_ids::steps::Recorded>) -> BTreeSet<[u8; 32]> {
    use std::cmp::Reverse;
    let mut best: BTreeMap<osis_base::SyncId, (u32, Reverse<osis_blob::StepId>, [u8; 32])> = BTreeMap::new();
    for (k, p) in recorded.into_iter().flat_map(|r| r.heads()) {
        best.insert(p.sync_id, (p.depth, Reverse(*k), p.sync));
    }
    for (id, e) in steps {
        if recorded.is_some() && !best.contains_key(id) {
            continue;
        }
        let Ok(mut st) = osis_blob::sync_steps(e) else { continue };
        st.retain(|_, (s, _)| s.sync_id == *id);
        let Some(h) = crate::sync_ids::actors::head_of(&st) else { continue };
        let plain: BTreeMap<osis_blob::StepId, osis_blob::Step> = st.iter().map(|(k, (s, _))| (*k, s.clone())).collect();
        let Ok(path) = osis_blob::path_to(&plain, &h) else { continue };
        if path.first().is_none_or(|g| g.sync_id != *id) {
            continue;
        }
        let Some((s, _)) = st.get(&h) else { continue };
        let at = (u32::try_from(path.len().saturating_sub(1)).unwrap_or(u32::MAX), Reverse(h), s.keys.sync.to_bytes());
        let b = best.entry(*id).or_insert(at);
        if (at.0, at.1) > (b.0, b.1) {
            *b = at;
        }
    }
    best.into_values().map(|b| b.2).collect()
}

/// The verified step IDs of `steps` per sync ID (`borne`'s paths).
fn verified(steps: &ct::SyncIds) -> BTreeSet<[u8; 32]> {
    let mut out = BTreeSet::new();
    for (id, e) in steps {
        let Ok(st) = osis_blob::sync_steps(e) else { continue };
        let plain: BTreeMap<osis_blob::StepId, osis_blob::Step> = st.iter().map(|(k, (s, _))| (*k, s.clone())).collect();
        out.extend(st.keys().filter(|k| osis_blob::path_to(&plain, k).is_ok_and(|p| p.first().is_some_and(|g| g.sync_id == *id))).map(|k| k.0));
    }
    out
}

/// `a` joined with `b`: per sync ID, the step records of both (one per step ID: its bytes
/// commit to it, `sync_steps` checks).
fn join_steps(a: &mut ct::SyncIds, b: &ct::SyncIds) {
    for (id, e) in b {
        let at = a.entry(*id).or_insert_with(|| ct::SyncEntry { steps: BTreeMap::new() });
        for (k, r) in &e.steps {
            at.steps.entry(*k).or_insert_with(|| r.clone());
        }
    }
}

impl Core {
    /// Whether `h`'s edge pieces on `x` go as sync copies (spec/permissions.md §4 Key part): a
    /// held edge write on `x` gives `h` a role, none gives it read or above (its own self-writes
    /// aside) and `h` is not `x`'s mint admin, whatever their validity: no edge of the evidence's
    /// read graph (`evidence::Write::gives_read`), so Role changes travel carries no write of it.
    /// A holder that read `x` keeps certificate copies after a lowering or removal: its readers
    /// hold `x`'s record and judge its role commits. A holder no held write gives a role (a
    /// removal by a node that never held its grant) goes as a reader does: its fire is the one
    /// way a removed reader hears of it from a blind remover.
    /// Invariant (security; spec/sync-ids.md §2 What a sync holder learns): every path a commit
    /// of `x` naming `h` takes to `h`'s readers (key part, sealed copy, fire, offer) reads this
    /// one predicate, so none carries a header where another carries a sync copy.
    pub(crate) fn sync_alone_on(&self, h: &Tid, x: &Tid) -> bool {
        let hd = osis_base::Holder::Thing(*h);
        if self.ix.held.created(x).is_some_and(|r| r.holder() == hd) {
            return false;
        }
        let mut role = false;
        for rc in self.ix.held.edge_commits(x).iter() {
            let leave = osis_base::Holder::Thing(*rc.path_to(x).last().unwrap_or(&rc.signer));
            for e in rc.ops.iter().filter(|o| o.target == *x && o.holder == hd).filter_map(|o| o.edge) {
                if e.role >= Role::Read && hd != leave {
                    return false;
                }
                role = true;
            }
        }
        role
    }

    /// Whether `u` holds sync on `y` as the sync copies of `y` counting here tell (no grant of
    /// `y` held): a counted copy's holder is `u`, or one `u` holds sync or above on with key
    /// access (its chain, as a grant held would give it).
    pub(crate) fn syncs_by_copies(&self, u: &Tid, y: &Tid) -> bool {
        self.unread(y).holders.iter().any(|h| h == u || self.keyed_role_now(u, h) >= Some(Role::Sync))
    }

    /// The things counted sync copies here name `h` holder on (`Unread::holders`): its edges
    /// as a holder of sync alone shows them, no edge write held.
    pub(crate) fn copies_naming(&self, h: &Tid) -> Vec<Tid> {
        self.ix.sync_copy_holders.get(h).into_iter().flatten().copied().filter(|y| self.unread(y).holders.contains(h)).collect()
    }

    /// `t` as this node keeps it unread (`Unread`; `memo`: every walk entering `t` and every
    /// sync ID judgement of it asks).
    pub(crate) fn unread(&self, t: &Tid) -> Arc<Unread> {
        self.unread_of.get(t, || Arc::new(self.unread_derived(t)))
    }

    fn unread_derived(&self, t: &Tid) -> Unread {
        let mut out = Unread::default();
        let copies = self.ix.sync_copies.get(t).cloned().unwrap_or_default();
        // a copy's own steps verify only to a genesis of anyone's making: they speak for `t` only
        // where this node holds no record of it, having nothing else to judge by. With its record,
        // `t`'s steps are its admins' word alone (`Indexes::steps`, from `sync.0` as judged), so a
        // forged genesis neither makes a dependent thing independent nor gives a reader of `t` a
        // sync ID in place of its own (`tests_delivery::a_forged_*`)
        let unknown = self.created(t).is_none();
        // what each copy's box gives, opened by its holder's keys held here
        let mut given: Vec<Given> = Vec::new();
        for (b, c) in copies.iter() {
            if unknown {
                join_steps(&mut out.steps, &c.steps);
            }
            let mut opened = Vec::new();
            if !c.boxes.is_empty()
                // the holder's own secrets as held (an independent thing: its keysets are its
                // own), never a derivation that could ask this thing again
                && let Some(e) = self.ix.secrets.get(&c.holder)
            {
                let s = ct::Secrets { boxes: c.boxes.clone(), history: BTreeMap::new() };
                let (o, _) = osis_keys::open_boxes(t, &s, &osis_keys::Opener { holder: c.holder, epochs: e });
                opened.extend(o.into_iter().filter(|o| o.role == Role::Sync).map(|o| (o.epoch, o.secret)));
            }
            given.push((*b, c.holder, opened));
        }
        // what role commits gave (a box applied, a lowering, an entry box), where they make `t`
        // independent here (`own_record`: a held keyset part decides), judged alike
        let mut candidates: BTreeMap<Epoch, Secret32> = self.own_record(t).map(|e| e.role(Role::Sync).held().map(|(e, s)| (e, s.secret().clone())).collect()).unwrap_or_default();
        for (_, _, o) in &given {
            candidates.extend(o.iter().cloned());
        }
        let bearing = borne(&out.steps);
        let recorded = self.ix.steps.get(t);
        let bears = |s: &Secret32| {
            let k = sync_key(s);
            bearing.contains(&k) || recorded.as_ref().is_some_and(|r| r.bears_sync(&k))
        };
        out.secrets = candidates.iter().filter(|(_, s)| bears(s)).map(|(e, s)| (*e, s.clone())).collect();
        out.candidates = candidates;
        let ok = match unknown {
            true => verified(&out.steps),
            false => recorded.iter().flat_map(|r| r.steps.keys().map(|k| k.0)).collect(),
        };
        // every copy's steps, joined: with the record held, on a sync ID its steps place
        let heads = {
            let mut joined = ct::SyncIds::default();
            for c in copies.values() {
                join_steps(&mut joined, &c.steps);
            }
            head_keys(&joined, if unknown { None } else { recorded.as_ref().map(|r| &***r) })
        };
        for (b, h, o) in given {
            let c = copies.get(&b);
            let boxes = c.is_some_and(|c| !c.boxes.is_empty());
            let counts = match boxes {
                true => o.iter().any(|(e, _)| out.secrets.contains_key(e)),
                // boxing nothing: each step it carries verified (with `t`'s record, placed)
                false => c.is_some_and(|c| !c.steps.is_empty() && c.steps.values().all(|e| e.steps.keys().all(|k| ok.contains(k)))),
            };
            // a holder by a box alone: a copy boxing nothing (a `sync.0` write's, which any
            // syncer of `t` holds and anyone may seal or log) gives steps, never a role
            if counts {
                out.counted.insert(b);
                if boxes && o.iter().any(|(_, s)| heads.contains(&sync_key(s))) {
                    out.holders.insert(h);
                }
            }
        }
        out
    }
}

impl crate::engine::Engine {
    /// Holder `h`'s sync copy of held commit `c` on `x` (spec/wire.md §4; spec/permissions.md §4
    /// Key part: where `h` holds sync alone on `x`): `h`'s `secrets.0` piece and the `sync.0`
    /// delta, each as held, with the part indices they are (what its prefix commits to, spec/wire.md
    /// §5). `None` where `c` is not held or holds neither for `h`.
    pub(crate) fn sync_copy(&mut self, c: &CommitId, x: &Tid, h: &Tid) -> Result<Option<(osis_commit::SyncCopy, Vec<usize>)>> {
        let id = *c;
        let Some(full) = self.read(|tx| tx.get_commit(&id))? else { return Ok(None) };
        let on = BTreeSet::from([*x]);
        let named = self.holders_named(c);
        let piece = self.parts_of(c, &on, &["secrets.0"]).into_iter().find(|ai| named.get(ai).is_some_and(|hs| hs.len() == 1 && hs.contains(h)));
        let sync = self.parts_of(c, &on, &["sync.0"]).into_iter().next();
        let delta = |ai: Option<usize>| ai.and_then(|ai| full.part(ai)).map(|p| p.delta.clone());
        let copy = osis_commit::SyncCopy { commit: id, thing: *x, piece: delta(piece), sync: delta(sync) };
        if copy.piece.is_none() && copy.sync.is_none() {
            return Ok(None);
        }
        let ais = [piece.filter(|_| copy.piece.is_some()), sync.filter(|_| copy.sync.is_some())].into_iter().flatten().collect();
        Ok(Some((copy, ais)))
    }

    /// Takes sync copy `plain`, blob `b`, come under `under` (`sealed`: sealed to it; `parse`;
    /// `note`): `false` when it is bad input, or the copy of a holder other than `under` that
    /// `under` holds no sync on with key access (a stub's copy, spec/sync-set.md §2: `under`'s
    /// readers open that holder's box by its keys).
    pub(crate) fn take_sync_copy(&mut self, under: &Tid, b: &BlobId, plain: &[u8], sealed: bool) -> Result<bool> {
        let Some(c) = parse(*under, sealed, plain) else { return Ok(false) };
        if c.holder != c.under && self.core.keyed_role_now(&c.under, &c.holder) < Some(Role::Sync) {
            return Ok(false);
        }
        let b = *b;
        self.run(|tx| note(tx, &b, c))?;
        Ok(true)
    }

    /// No store entry names blob `b` any more: its sync copy row, if any, goes (`SYNC_COPIES`).
    pub fn unnamed_sync_copy(&mut self, b: &BlobId) -> Result<()> {
        if !self.core.ix.sync_copy_on.contains_key(b) {
            return Ok(());
        }
        let b = *b;
        self.run(|tx| drop_blob(tx, &b))
    }

    /// The blobs of every sync copy row (a start drops those the store does not hold).
    pub fn sync_copy_blobs(&self) -> Vec<BlobId> {
        self.core.ix.sync_copy_on.keys().copied().collect()
    }

    /// The sync copies read sync ID `s` carries (spec/permissions.md §4 Key part), by content
    /// (`ContentKey`), each with the thing reading `s` it is under and its plaintext: those its
    /// read things' certificates name (`Certs::sync_copies`, of commits held here), and each
    /// counted copy taken under one of them (`Unread::counted`), a sealed copy's included (H's
    /// writers log what it carries, spec/sync-inbox.md §2).
    /// Invariant (security): what a node with no commit of the thing logs is a copy that counts
    /// here, so a forged copy is logged only where its own steps bear its box (a genesis of the
    /// forger's at a node holding no record of the thing), which gives nothing a reader of the
    /// thing's own sync ID takes (`Core::unread`).
    pub fn sync_copies_carried(&mut self, s: &osis_base::SyncId) -> Result<Arc<Carried>> {
        self.follow_certificates()?;
        let mut out = BTreeMap::new();
        for t in self.read_things_of(s)? {
            let named: Vec<(CommitId, Tid, Tid)> = self.core.certified.sync_copies.get(&t).into_iter().flat_map(|x| x.iter().copied()).collect();
            for (c, x, h) in named {
                if let Some((copy, _)) = self.sync_copy(&c, &x, &h)? {
                    let plain = copy.encode();
                    out.insert(content_key(&plain), (t, Arc::new(plain)));
                }
            }
            let blobs: Vec<BlobId> = self.core.ix.sync_copies_under.get(&t).into_iter().flatten().copied().collect();
            for b in blobs {
                let Some(x) = self.core.ix.sync_copy_on.get(&b).copied() else { continue };
                if !self.core.unread(&x).counted.contains(&b) {
                    continue;
                }
                if let Some(c) = self.core.ix.sync_copies.get(&x).and_then(|m| m.get(&b).cloned()) {
                    out.entry(c.key).or_insert_with(|| (t, Arc::new(c.copy.encode())));
                }
            }
        }
        Ok(Arc::new(out))
    }

    /// The sync copy rows taken under the things reading `s`: per blob, its content and whether
    /// it came sealed.
    pub fn sync_copy_rows(&mut self, s: &osis_base::SyncId) -> BTreeMap<BlobId, (ContentKey, bool)> {
        let mut out = BTreeMap::new();
        for t in self.read_things_of(s).unwrap_or_default() {
            for b in self.core.ix.sync_copies_under.get(&t).into_iter().flatten() {
                let Some(x) = self.core.ix.sync_copy_on.get(b) else { continue };
                if let Some(c) = self.core.ix.sync_copies.get(x).and_then(|m| m.get(b).cloned()) {
                    out.insert(*b, (c.key, c.sealed));
                }
            }
        }
        out
    }

    /// A fresh blob under `s` of the sync copy of content `key` it carries
    /// (`sync_copies_carried`), framed as a record blob is (spec/wire.md §3, §4: committing to a
    /// writer delete key of the thing it is under), its row taken as this node's: `None` where
    /// `s` carries none such or nothing may be wrapped for it now.
    pub fn seal_sync_copy(&mut self, s: &osis_base::SyncId, key: &ContentKey, rng: &mut dyn osis_crypto::NodeRng) -> Result<Option<(BlobId, Vec<u8>, crate::sync::Wrap)>> {
        let carried = self.sync_copies_carried(s)?;
        let Some((t, plain)) = carried.get(key).cloned() else { return Ok(None) };
        let Some(w) = self.wrap_secret(&t, None)? else { return Ok(None) };
        let Some(dk) = self.read(|tx| crate::engine::secrets::writer_delete_key_in(tx, &t))? else { return Ok(None) };
        let (id, blob, wrap, _) = crate::sync::certblobs::seal_cert_blob(&w, &dk, &plain, BTreeSet::new(), rng)?;
        let Some(c) = parse(t, false, &plain) else { return Ok(None) };
        self.run(|tx| note(tx, &id, c))?;
        Ok(Some((id, blob, wrap)))
    }

    /// The sync copies of `t` taken here, each with whether it counts (`Unread::counted`): tests.
    #[doc(hidden)]
    pub fn sync_copies_of(&self, t: &Tid) -> Vec<(BlobId, Arc<HeldSyncCopy>, bool)> {
        let u = self.core.unread(t);
        self.core.ix.sync_copies.get(t).map(|m| m.iter().map(|(b, c)| (*b, c.clone(), u.counted.contains(b))).collect()).unwrap_or_default()
    }
}
