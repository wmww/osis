//! What a node of account P writes of P's signing chain (spec/permissions.md §3, §5.5,
//! spec/crypto.md §9): the rotation a removal from P's devices actor D requires, with its thing
//! lists; its take-up of the seeds D's `account.0` holds.
//!
//! Principle: closing an epoch ends the standing of what was signed at it, so a rotation names
//! what its rotator holds there (its thing lists), as a demotion's frontier names what its
//! demoter holds.

use super::account::things_of;
use super::Done;
use crate::engine::{Engine, Tx, records};
use crate::error::{Error, Result};
use crate::Mutation;
use osis_base::format::CHUNK_THRESHOLD;
use osis_base::{CommitId, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_store::Shred;
use osis_commit::RotationHeader;
use osis_commit::thing_list::{ListIds, ThingCert, ThingList};
use osis_crypto::{AccountEpochKeys, Secret32, SigningSecret};
use osis_perm::epochs::{fit_list, list_leaf, list_tree};
use osis_schema::Codec;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A rotation of the signing account's chain as its commit carries it: the header's rotation,
/// the key of each fork it names (a merge's signatures), and its thing lists by leaf (index,
/// sibling hashes), certs once its commit ID is known.
#[derive(Clone, Debug)]
pub(crate) struct AccountRotation {
    pub header: RotationHeader,
    pub merge_keys: Vec<SigningSecret>,
    pub lists: Vec<(u64, Vec<[u8; 32]>, ThingList)>,
    /// A merge's: the head it is signed at and that epoch's keys (else the open epoch).
    pub at: Option<(CommitId, AccountEpochKeys)>,
}

impl AccountRotation {
    pub(crate) fn certs(&self, rotation: CommitId) -> Vec<ThingCert> {
        self.lists.iter().map(|(index, siblings, list)| ThingCert { rotation, index: *index, siblings: siblings.clone(), list: list.clone() }).collect()
    }
}

/// A thing's listed commits: role-class and purge-request ones, then plain ones by receipt.
type PerThing = (BTreeSet<CommitId>, Vec<(osis_base::WallMs, CommitId)>);

/// Rotates account `p`'s epoch (spec/permissions.md §3, §5.5; spec/crypto.md §9): a role commit
/// signed at the open epoch, minting one whose seed goes into D's `account.0` (under D's newest
/// read epoch, so only D's current nodes open it) and its public keys into P's `keys.0`. In a
/// fork (several heads) it is a merge of the heads: superseding each, signed at the lowest one D's roster authorizes and naming the other
/// authorized ones with a signature by each one's key; a head no current node minted (a removed
/// node's fork) is superseded unnamed, so the merge rejects it.
/// Its thing lists name the commits of P this node holds at the epochs it closes that no word
/// names, by the cutoff (`nameable`: at an open epoch every one received), cut per thing it has
/// a delta on or acts for; within the bound, plain content past it left to this node's listings.
/// `None`: an authorized head's seed is not held here, or no head is authorized.
pub(crate) fn rotate_in(tx: &mut Tx<'_>, p: Tid, also: &[CommitId]) -> Result<Option<CommitId>> {
    let held = tx.core.accounts.get(&p).cloned().ok_or(Error::Misuse("not an account held here"))?;
    let v = tx.core.account_view(&p).ok_or(Error::Misuse("no signing chain for the account"))?;
    let signing = tx.core.account_signing(&p).ok().flatten();
    let mut names = Vec::new();
    let (at, supersedes, merge_keys, closes) = match signing {
        Some((e, _)) if v.heads().len() == 1 => (None, vec![e], Vec::new(), vec![e]),
        // an open epoch whose seed is not here yet (its removal has not arrived): nothing to act at
        None if v.heads().len() == 1 => return Ok(None),
        _ => {
            // the merge supersedes every head and names (accepts) only those D's roster
            // authorizes: a removed node's fork is superseded unnamed, so it is rejected with
            // its lists (spec/permissions.md §5.4)
            let heads = v.heads();
            let mut named = Vec::new();
            for h in heads.iter().copied().filter(|h| v.authorized_by(h).is_some()) {
                let Some(k) = v.seed_of(&h, &held).map(|s| AccountEpochKeys::from_seed(&s)) else { return Ok(None) };
                named.push((h, k));
            }
            let Some((first, k)) = named.first().cloned() else { return Ok(None) };
            names = named.iter().skip(1).map(|x| x.0).collect();
            (Some((first, k)), heads.clone(), named.into_iter().skip(1).map(|x| x.1.signing).collect(), heads)
        }
    };
    // per thing: role-class and purge-request commits, then plain ones by receipt
    let mut per: BTreeMap<Tid, PerThing> = BTreeMap::new();
    let mut listed = nameable(tx, &p, &v, &closes, true)?;
    for c in also {
        if !listed.iter().any(|x| x.0 == *c)
            && let Some(m) = tx.core.ix.commits.get(c).cloned()
        {
            listed.push((*c, m));
        }
    }
    for (c, m) in listed {
        let special = m.view.kind.is_role() || m.view.purges;
        for t in things_of(&m.view) {
            let x = per.entry(t).or_default();
            if special {
                x.0.insert(c);
            } else {
                x.1.push((m.received, c));
            }
        }
    }
    let mut leaves: Vec<(u64, ThingList)> = Vec::new();
    let mut used = BTreeSet::new();
    for (t, (special, mut plain)) in per {
        plain.sort();
        let plain: Vec<CommitId> = plain.into_iter().map(|x| x.1).collect();
        // inline lists only (linked thing lists are not written yet: issues/account-signing.md)
        let (ids, _) = fit_list(&special, &plain, CHUNK_THRESHOLD).ok_or(Error::Misuse("the account's role and purge changes since its last rotation pass the list bound on a thing"))?;
        let index = loop {
            let i = u64::from(tx.rng.next_u32());
            if used.insert(i) {
                break i;
            }
        };
        let mut salt = [0u8; 16];
        tx.rng.fill_bytes(&mut salt);
        leaves.push((index, ThingList { thing: t, ids: ListIds::Inline(ids.into_iter().collect()), salt }));
    }
    let hashed: Vec<(u64, [u8; 32])> = leaves.iter().map(|(i, l)| (*i, list_leaf(&l.encode()))).collect();
    let rng = &mut *tx.rng;
    let (root, paths) = list_tree(&hashed, || {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        b
    })
    .ok_or(Error::Misuse("list tree"))?;
    let seed = Secret32::random(&mut *tx.rng);
    let keys = AccountEpochKeys::from_seed(&seed);
    let signing = keys.signing.verifying_key();
    let mut m = Mutation::new();
    m.sign_as(p);
    let mut k = crate::engine::Core::keys_in(tx, &p)?.unwrap_or_default();
    let fresh = osis_keys::aspects::account_keys(&keys);
    (k.signing, k.key) = (fresh.signing, fresh.key);
    // D's deposit seed is the account's: fresh with each rotation, the read rotation of D a
    // removal makes being one (spec/crypto.md §3)
    let mut dep = [0u8; 32];
    tx.rng.fill_bytes(&mut dep);
    k.deposit_seed = Some(dep);
    m.set(p, &ct::KEYS, &k)?;
    let ak = osis_base::Ak::new("account.0").map_err(|_| Error::Misuse("ak"))?;
    let mut acct: ct::Account = tx.state(&held.devices, &ak)?.and_then(osis_crdt::Fragment::read).and_then(|x| osis_schema::Codec::from_value(&x).ok()).unwrap_or_default();
    acct.seeds.insert(signing.to_bytes().to_vec(), seed.expose().to_vec());
    m.set(held.devices, &ct::ACCOUNT, &acct)?;
    let lists = leaves.into_iter().zip(paths).map(|((i, l), path)| (i, path.siblings, l)).collect();
    let mut sup = supersedes;
    sup.sort();
    m.rotation = Some(AccountRotation { header: RotationHeader { signing_key: signing, kem_key: keys.kem.public().clone(), supersedes: sup, names, list_root: root }, merge_keys, lists, at });
    // the new seed is taken up from `account.0` as the commit applies (`take_seeds`)
    Engine::commit_tx(tx, m)
}

/// Takes up the seeds D's `account.0` holds as it now reads, where D is the devices actor of an
/// account held here (a rotation of it applied): an entry that is not its epoch's seed opens and
/// signs nothing.
pub(crate) fn take_seeds(tx: &mut Tx<'_>, d: &Tid) -> Result<()> {
    let Some((p, a)) = tx.core.accounts.iter().find(|(_, a)| a.devices == *d).map(|(p, a)| (*p, a.clone())) else { return Ok(()) };
    if !tx.core.of_devices(d) {
        return Ok(());
    }
    let ak = osis_base::Ak::new("account.0").map_err(|_| Error::Misuse("ak"))?;
    let Some(acct) = tx.state(d, &ak)?.and_then(osis_crdt::Fragment::read).and_then(|x| <ct::Account as osis_schema::Codec>::from_value(&x).ok()) else { return Ok(()) };
    let mut seeds = a.seeds.clone();
    for (k, v) in acct.seeds {
        let (Ok(k), Ok(v)) = (<[u8; 32]>::try_from(k), <[u8; 32]>::try_from(v)) else { continue };
        let seed = Secret32::from_bytes(v);
        if !seeds.contains_key(&k) && AccountEpochKeys::from_seed(&seed).signing.verifying_key().to_bytes() == k {
            seeds.insert(k, seed);
        }
    }
    if seeds.len() != a.seeds.len() {
        let mut n = (*a).clone();
        n.seeds = seeds;
        tx.core.accounts.insert(p, Arc::new(n));
        tx.core.role_changed();
        // the epoch it can sign at may move
        tx.core.ix.epochs_due.insert(p);
        crate::apply::keyset_changed(tx.core, &p);
    }
    Ok(())
}

/// Rotation `r` of an account is due this node's answer, kept across restarts
/// (`records::ROTATIONS_DUE`).
pub(crate) fn note_rotation_due(tx: &mut Tx<'_>, r: &CommitId) -> Result<()> {
    if tx.core.ix.rotations_due.insert(*r) {
        tx.txn.put_local(&[records::ROTATIONS_DUE, &r.0[..]].concat(), &[], Shred::No)?;
    }
    Ok(())
}

/// Answers every account's rotation not yet answered (`Indexes::rotations_due`), each once: a
/// rotation of this node's account with its listing, another account's with its addenda as a
/// writer (spec/permissions.md §5.5, Listings, Addenda against a rotation). One waits while it is
/// pending, while the open epoch's seed is not here to sign at, or while an addendum's thing's
/// delete keys are not here; a void one is answered by nothing.
pub(crate) fn answer_rotations(tx: &mut Tx<'_>) -> Result<()> {
    let due: Vec<CommitId> = tx.core.ix.rotations_due.iter().copied().collect();
    for r in due {
        if answer_rotation(tx, &r)? {
            tx.core.ix.rotations_due.remove(&r);
            tx.txn.remove_local(&[records::ROTATIONS_DUE, &r.0[..]].concat(), Shred::No)?;
        }
    }
    Ok(())
}

/// The commits of account `p` at `epochs` the cutoff lets this node name (spec/permissions.md
/// §5.5, Cutoff) that no word held names: received before the earliest closer of their epoch held
/// (at an epoch with none, every one received), or (`own`) made by this node, per its inner
/// signature. Rotations count by the chain; ephemeral commits are never named.
fn nameable(tx: &mut Tx<'_>, p: &Tid, v: &super::account::AccountView, epochs: &[CommitId], own: bool) -> Result<Vec<(CommitId, crate::engine::Meta)>> {
    let me = tx.core.id.tid();
    let mut out = Vec::new();
    for e in epochs {
        let closers = v.closers(e);
        let earliest = closers.iter().filter_map(|c| tx.core.ix.commits.get(c).map(|m| m.received)).min();
        let open = v.open() == *e;
        let at: Vec<CommitId> = tx.core.ix.by_epoch.get(&(*p, *e)).into_iter().flatten().copied().collect();
        for c in at {
            let Some(m) = tx.core.ix.commits.get(&c).cloned() else { continue };
            if m.view.memory || v.is_rotation(&c) || !open && tx.core.standing(&c, &m.view) == osis_perm::EpochStanding::Counts {
                continue;
            }
            let cut = closers.is_empty() || earliest.is_some_and(|x| m.received < x);
            if !cut && !(own && tx.get_commit(&c)?.as_ref().and_then(|b| tx.core.inner_node(b)) == Some(me)) {
                continue;
            }
            out.push((c, m));
        }
    }
    Ok(out)
}

/// This node's answer to rotation `r`; whether `r` is answered.
fn answer_rotation(tx: &mut Tx<'_>, r: &CommitId) -> Result<bool> {
    let Some(p) = tx.core.ix.commits.get(r).map(|m| m.view.author) else { return Ok(true) };
    let Some(v) = tx.core.account_view(&p) else { return Ok(true) };
    if !v.holds(r) {
        return Ok(false);
    }
    if !v.rotation_counts(r) {
        return Ok(true);
    }
    if tx.core.accounts.contains_key(&p) {
        // a fork off the line this node follows is answered by the merge that ends it, which
        // closes all it closes: a removed node re-forking costs no listing per fork
        if !v.on_open_line(r) {
            return Ok(true);
        }
        return listing(tx, p, &v, r);
    }
    witness(tx, p, &v, r)
}

/// A node of account `p` answers its rotation `r` with a listing: per thing, the commits of `p`
/// at the epochs `r` closes that no word held names, this node's own (by inner signature) and
/// others' by the cutoff (spec/permissions.md §5.5, Listings).
fn listing(tx: &mut Tx<'_>, p: Tid, v: &super::account::AccountView, r: &CommitId) -> Result<bool> {
    if tx.core.accounts.get(&p).is_none_or(|a| !tx.core.of_devices(&a.devices)) {
        return Ok(true);
    }
    if tx.core.account_signing(&p).ok().flatten().is_none() {
        return Ok(false);
    }
    let mut names: BTreeMap<Tid, BTreeSet<CommitId>> = BTreeMap::new();
    for (c, m) in nameable(tx, &p, v, &v.closed_by(r), true)? {
        for t in things_of(&m.view) {
            names.entry(t).or_default().insert(c);
        }
    }
    if names.is_empty() {
        return Ok(true);
    }
    let mut m = Mutation::new();
    m.sign_as(p);
    m.unchecked();
    for (t, ids) in names {
        let set = Value::Set(ids.iter().map(|c| Value::bytes(&c.0)).collect());
        m.op(t, &ct::LISTING, PathOp { path: vec![PathSeg::Key(Value::bytes(&r.0))], op: Op::Put(set) })?;
    }
    Engine::commit_tx(tx, m)?;
    Ok(true)
}

/// A writer of a thing answers another account's rotation `r` with an addendum on each thing it
/// writes: the account's plain-content commits there it names by the cutoff (spec/permissions.md
/// §5.5, Addenda against a rotation), one addendum per thing, so none crosses a label. Waits for a
/// thing whose delete keys are not here yet.
fn witness(tx: &mut Tx<'_>, p: Tid, v: &super::account::AccountView, r: &CommitId) -> Result<bool> {
    let Some(me) = tx.core.member().filter(|_| tx.core.addenda_on) else { return Ok(true) };
    let mut out: BTreeMap<Tid, BTreeSet<CommitId>> = BTreeMap::new();
    for (c, m) in nameable(tx, &p, v, &v.closed_by(r), false)? {
        let w = &m.view;
        if w.purges || w.kind != osis_commit::Kind::Content {
            continue;
        }
        for t in w.aspects.iter().filter(|a| super::addenda::plain_ak(&a.ak)).map(|a| a.tid).chain((w.actor != w.author).then_some(w.actor)) {
            if tx.core.role_now(&me, &t) >= Some(osis_base::Role::Write) {
                out.entry(t).or_default().insert(c);
            }
        }
    }
    for n in out.keys() {
        let created = Default::default();
        let published = crate::engine::secrets::published_keys(tx, &created, [*n])?;
        if !crate::engine::secrets::holds_listed_keys(tx.core, &created, &published, n) {
            return Ok(false);
        }
    }
    for (n, lists) in out {
        let mut mu = Mutation::new();
        mu.op(n, &ct::ADDENDA, PathOp { path: vec![PathSeg::Key(Value::bytes(&r.0))], op: Op::Put(ct::Frontier { commits: lists }.to_value()) })?;
        Engine::commit_tx(tx, mu)?;
    }
    Ok(true)
}

/// A node removed from its account's devices actor (a counting removal of it applied) is no
/// node of the account any more: it drops the account's seeds, so it signs and opens nothing as
/// it, and everything it read only as the account is lost (spec/permissions.md §3, Lost access;
/// an account's retain default does not reach its nodes, §2): every held actor is judged again.
pub(crate) fn leave_if_removed(tx: &mut Tx<'_>) -> Result<()> {
    let Some((p, d)) = tx.core.account_devices() else { return Ok(()) };
    if tx.core.of_devices(&d) {
        return Ok(());
    }
    leave(tx, p, d)
}

/// `leave_if_removed` of account `p` with devices actor `d`.
pub(crate) fn leave(tx: &mut Tx<'_>, p: Tid, d: Tid) -> Result<()> {
    tx.core.accounts.remove(&p);
    tx.core.left.insert(p);
    tx.core.role_changed();
    let held: Vec<Tid> = tx.core.ix.secrets.keys().copied().chain([d]).collect();
    crate::rotation::mark_lost_due(tx, held)
}

/// What a node of this node's account owes its signing chain (spec/permissions.md §3, §5.5),
/// made now: in a fork, the merge of the heads, by one node (`merger`); and the
/// rotation a counting removal from D requires that no counting rotation's list names (one made
/// beside another rotation it did not hold, or by a node that did not rotate), naming it. Looked
/// at when the account's commits moved (`Core::signing_due`); D's role history is its device
/// count's.
pub(crate) fn rotations_due(tx: &mut Tx<'_>) -> Result<Option<CommitId>> {
    if !std::mem::take(&mut tx.core.signing_due) {
        return Ok(None);
    }
    let Some(p) = tx.core.member() else { return Ok(None) };
    let Some(d) = tx.core.accounts.get(&p).map(|a| a.devices) else { return Ok(None) };
    let Some(v) = tx.core.account_view(&p) else { return Ok(None) };
    let roles = osis_base::Ak::new("roles.0").map_err(|_| Error::Misuse("ak"))?;
    let removals: Vec<CommitId> = tx.core.ix.by_aspect.get(&(d, roles)).into_iter().flatten().map(|(_, c)| *c).filter(|c| {
        let core = &*tx.core;
        core.ix.held.edge_commit(c).is_some_and(|rc| rc.author == p && rc.ops.iter().any(|o| o.target == d && o.edge.is_none() && core.is_key_actor(&o.holder)))
            && core.ix.commits.get(c).is_some_and(|m| core.standing(c, &m.view) == osis_perm::EpochStanding::Counts)
    }).collect();
    let mut unnamed = Vec::new();
    for c in removals {
        if !super::lists::names_of(tx, &c)?.iter().any(|(t, s)| *t == d && v.rotation_counts(s)) {
            unnamed.push(c);
        }
    }
    let merging = v.heads().len() > 1;
    if merging && !merger(tx, &v) || !merging && unnamed.is_empty() {
        return Ok(None);
    }
    rotate_in(tx, p, &unnamed)
}

/// Whether this node merges the heads (one merger, so the merges do not fork again): the node
/// whose rotation is the lowest head D's roster authorizes (`AccountView::authorized_by`, the
/// rule this node's side follows too).
fn merger(tx: &Tx<'_>, v: &super::account::AccountView) -> bool {
    v.heads().iter().find_map(|h| v.authorized_by(h)) == Some(tx.core.id.tid())
}

impl Engine {
    /// What this node owes its account's signing chain (`rotations_due`), decided at the end
    /// of a complete pass of its devices actor's labels (node-sync), so a removal and its
    /// rotation that arrive apart, or two forks and the merge of another node, are both in.
    pub fn signing_due(&mut self) -> Result<Done> {
        let c = self.run(rotations_due)?;
        let mut done = Done::default();
        done.add(c);
        if let (Some(r), Some((_, d))) = (c, self.core.account_devices()) {
            done.deliveries.push(self.run(|tx| super::owe(tx, super::Delivery::First { commits: vec![r], under: vec![d] }))?);
        }
        Ok(done)
    }
}
