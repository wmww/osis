//! What a node of account P writes of P's signing chain (spec/permissions.md §3, §5.5,
//! spec/crypto.md §9): the rotation a removal from P's devices actor D requires, with its thing
//! lists; its take-up of the seeds D's `account.0` holds.
//!
//! Principle: closing an epoch ends the standing of what was signed at it, so a rotation names
//! what its rotator holds there (its thing lists), as a demotion's frontier names what its
//! demoter holds.

use super::account::things_of;
use super::Done;
use crate::engine::write::writable_now;
use crate::engine::{Engine, Step, Tx, records};
use crate::error::{Error, Result};
use crate::events::{Diagnostic, DiagnosticKind};
use crate::Mutation;
use osis_base::format::CHUNK_THRESHOLD;
use osis_base::{CommitId, Tid, Value};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_store::Shred;
use osis_commit::RotationHeader;
use osis_commit::thing_list::{ListIds, ThingCert, ThingList};
use osis_crypto::{AccountEpochKeys, Secret32, SigningSecret, VerifyingKey};
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
    pub at: Option<(CommitId, Arc<AccountEpochKeys>)>,
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
pub(crate) fn rotate_in(tx: &mut Tx<'_>, p: Tid, also: &[CommitId], done: &mut Done) -> Result<Option<CommitId>> {
    let held = tx.core.accounts.get(&p).cloned().ok_or(Error::Misuse("not an account held here"))?;
    let v = tx.core.account_view(&p).ok_or(Error::Misuse("no signing chain for the account"))?;
    let signing = tx.core.account_signing(&p).ok().flatten();
    let mut names = Vec::new();
    // a removed node's rotation no authorized one supersedes yet: superseded unnamed, rejected
    let reject = unanswered(tx, &p, &v)?;
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
                let Some(k) = v.keys_of(&h, &held) else { return Ok(None) };
                named.push((h, k));
            }
            let Some((first, k)) = named.first().cloned() else { return Ok(None) };
            names = named.iter().skip(1).map(|x| x.0).collect();
            (Some((first, k)), heads.clone(), named.into_iter().skip(1).map(|x| x.1.signing.clone()).collect(), heads)
        }
    };
    let (mut supersedes, mut closes) = (supersedes, closes);
    for r in reject {
        if !supersedes.contains(&r) {
            supersedes.push(r);
            closes.push(r);
        }
    }
    // after the heads' seeds are known held: rotating D first signs as the account
    let Some(under) = seed_under(tx, &p, &held.devices, done)? else { return Ok(None) };
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
        // inline lists only (linked thing lists are not written yet: issues/linked-thing-lists.md)
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
    acct.seeds.insert(signing.to_bytes().to_vec(), ct::AccountSeed { seed: seed.expose().to_vec(), under: osis_keys::aspects::to_schema(&under) });
    m.set(held.devices, &ct::ACCOUNT, &acct)?;
    let lists = leaves.into_iter().zip(paths).map(|((i, l), path)| (i, path.siblings, l)).collect();
    let mut sup = supersedes;
    sup.sort();
    m.rotation = Some(AccountRotation { header: RotationHeader { signing_key: signing, kem_key: keys.kem.public().clone(), supersedes: sup, names, list_root: root }, merge_keys, lists, at });
    // the new seed is taken up from `account.0` as the commit applies (`take_seeds`)
    Engine::commit_tx(tx, m)
}

/// D's read epoch the seed of a rotation of account `p` by this node goes under: the one it
/// encrypts D's content under (`wrap_epoch`), so a node taking the seed up holds the removals
/// from D this node held (`usable_seeds`). Encrypting under D, it rotates D first where due
/// (`ensure_rotated`: a removal from D it knows that D's epoch does not cover, so the removed
/// node would open the seed); `None` while D's read stays blocked.
fn seed_under(tx: &mut Tx<'_>, p: &Tid, d: &Tid, done: &mut Done) -> Result<Option<osis_crypto::Epoch>> {
    if crate::rotation::ensure_rotated(tx, *p, *d, done)?.contains(&osis_base::Role::Read) {
        return Ok(None);
    }
    Ok(tx.core.epochs(d).and_then(|e| osis_keys::wrap_epoch(&e.read)))
}

/// An `account.0` entry's epoch keys, by their signing key: `None` when the entry is not that
/// key's seed.
pub(crate) fn epoch_keys(key: &[u8], seed: &[u8]) -> Option<(VerifyingKey, Arc<AccountEpochKeys>)> {
    let keys = AccountEpochKeys::from_seed(&Secret32::from_bytes(seed.try_into().ok()?));
    let pk = keys.signing.verifying_key();
    (pk.as_bytes()[..] == *key).then(|| (pk, Arc::new(keys)))
}

/// The seeds of `acct`, on devices actor `d`, this node takes up besides those in `have`
/// (spec/crypto.md §9): each entry that is its epoch's seed and whose D read epoch (`under`) is
/// established here with its secret held for use, its names met. A node uses only established
/// epochs: so it holds every removal from D the entry's writer held before it signs at, or
/// rotates from, that epoch, and a line it extends names no removal it does not hold. An entry
/// that is not its epoch's seed opens and signs nothing.
pub(crate) fn usable_seeds(core: &crate::engine::Core, d: &Tid, acct: ct::Account, have: &BTreeMap<VerifyingKey, Arc<AccountEpochKeys>>) -> BTreeMap<VerifyingKey, Arc<AccountEpochKeys>> {
    // D's epochs, judged only when an entry is new here
    let epochs = std::cell::OnceCell::new();
    let usable = |e: &ct::Epoch| {
        let Some(epochs) = epochs.get_or_init(|| core.epochs(d)) else { return false };
        osis_keys::aspects::from_schema(e).is_ok_and(|e| epochs.read.is_established(&e) && epochs.read.secret(&e).is_some())
    };
    let mut out = BTreeMap::new();
    for (k, v) in acct.seeds {
        if let Ok(pk) = VerifyingKey::from_slice(&k)
            && !have.contains_key(&pk)
            && usable(&v.under)
            && let Some((pk, e)) = epoch_keys(&k, &v.seed)
        {
            out.insert(pk, e);
        }
    }
    out
}

/// Takes up the seeds D's `account.0` holds as it now reads (`usable_seeds`), where D is the
/// devices actor of an account held here: when `account.0` moves (a rotation of it applied) and
/// at the end of a pass (`rotations_due`: D's epochs established may have moved with a removal
/// or secret that arrived).
pub(crate) fn take_seeds(tx: &mut Tx<'_>, d: &Tid) -> Result<()> {
    let Some((p, a)) = tx.core.accounts.iter().find(|(_, a)| a.devices == *d).map(|(p, a)| (*p, a.clone())) else { return Ok(()) };
    if !tx.core.of_devices(d) {
        return Ok(());
    }
    let ak = osis_base::Ak::new("account.0").map_err(|_| Error::Misuse("ak"))?;
    let Some(acct) = tx.state(d, &ak)?.and_then(osis_crdt::Fragment::read).and_then(|x| <ct::Account as osis_schema::Codec>::from_value(&x).ok()) else { return Ok(()) };
    let mut keys = a.keys.clone();
    keys.extend(usable_seeds(tx.core, d, acct, &a.keys));
    if keys.len() != a.keys.len() {
        let mut n = (*a).clone();
        n.keys = keys;
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
/// pending, while the open epoch's seed is not here to sign at, or while a thing it writes on may
/// be written only later (`write::MayWrite::Later`: its minting or delete keys are not here); a
/// void one is answered by nothing. Each answer is one step (`Tx::step`): one that fails leaves
/// nothing, is reported (`DiagnosticKind::OwnWriteFailed`) and stays due, and the transaction
/// goes on, so a receive never fails for this node's own answer.
pub(crate) fn answer_rotations(tx: &mut Tx<'_>) -> Result<()> {
    let due: Vec<CommitId> = tx.core.ix.rotations_due.iter().copied().collect();
    for r in due {
        let answered = tx.step(Step::Rotation, |tx| {
            if answer_rotation(tx, &r)? {
                tx.core.ix.rotations_due.remove(&r);
                tx.txn.remove_local(&[records::ROTATIONS_DUE, &r.0[..]].concat(), Shred::No)?;
            }
            Ok(())
        });
        if let Err(e) = answered {
            let now = tx.now();
            tx.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::OwnWriteFailed, tids: Vec::new(), commit: Some(r), peer: None, detail: e.to_string() }, now);
        }
    }
    Ok(())
}

/// The commits of account `p` at `epochs` the cutoff lets this node name (spec/permissions.md
/// §5.5, Cutoff) that no word held names: received before the earliest closer of their epoch held
/// that ends it (`ends`; at an epoch with none, every one received), or (`own`, a node of `p`)
/// made by this node, per its inner signature. Rotations count by the chain; ephemeral commits
/// are named as durable ones.
fn nameable(tx: &mut Tx<'_>, p: &Tid, v: &super::account::AccountView, epochs: &[CommitId], own: bool) -> Result<Vec<(CommitId, crate::engine::Meta)>> {
    let me = tx.core.id.tid();
    let departures = if own { Some(departures(tx, p, v)?) } else { None };
    let mut out = Vec::new();
    for e in epochs {
        let closers: BTreeSet<CommitId> = v.closers(e).into_iter().filter(|c| ends(v, departures.as_ref(), e, c)).collect();
        let earliest = closers.iter().filter_map(|c| tx.core.ix.commits.get(c).map(|m| m.received)).min();
        let open = v.is_open(e);
        let at: Vec<CommitId> = tx.core.ix.by_epoch.get(&(*p, *e)).into_iter().flatten().copied().collect();
        for c in at {
            let Some(m) = tx.core.ix.commits.get(&c).cloned() else { continue };
            if v.is_rotation(&c) || !open && tx.core.standing(&c, &m.view) == osis_perm::EpochStanding::Counts {
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
        // a rotation D's roster does not authorize (a removed node's fork) is answered by the
        // rotation superseding it, which closes all it closes: a removed node re-forking costs
        // no listing per fork
        if v.authorized_by(r).is_none() {
            return Ok(true);
        }
        return listing(tx, p, &v, r);
    }
    witness(tx, p, &v, r)
}

/// A node of account `p` answers its rotation `r` with a listing: per thing, the commits of `p`
/// at the epochs `r` closes that no word held names, this node's own (by inner signature) and
/// others' by the cutoff (spec/permissions.md §5.5, Listings). A listing needs no role on a thing;
/// one it may write on only later waits whole, one that is gone here is left out.
fn listing(tx: &mut Tx<'_>, p: Tid, v: &super::account::AccountView, r: &CommitId) -> Result<bool> {
    if tx.core.accounts.get(&p).is_none_or(|a| !tx.core.of_devices(&a.devices)) {
        return Ok(true);
    }
    if tx.core.account_signing(&p).ok().flatten().is_none() {
        return Ok(false);
    }
    let mut names: BTreeMap<Tid, BTreeSet<CommitId>> = BTreeMap::new();
    // an open epoch's commits count unnamed: they are named once a rotation closes it
    let closed: Vec<CommitId> = v.closed_by(r).into_iter().filter(|e| !v.is_open(e)).collect();
    for (c, m) in nameable(tx, &p, v, &closed, true)? {
        for t in things_of(&m.view) {
            names.entry(t).or_default().insert(c);
        }
    }
    let Some(on) = writable_now(tx, p, names, "listing.0", None)? else { return Ok(false) };
    if on.is_empty() {
        return Ok(true);
    }
    let mut m = Mutation::new();
    m.sign_as(p);
    m.unchecked();
    for (t, ids) in on {
        let set = Value::Set(ids.iter().map(|c| Value::bytes(&c.0)).collect());
        m.op(t, &ct::LISTING, PathOp { path: vec![PathSeg::Key(Value::bytes(&r.0))], op: Op::Put(set) })?;
    }
    Engine::commit_tx(tx, m)?;
    Ok(true)
}

/// A writer of a thing answers another account's rotation `r` with an addendum on each thing it
/// writes: the account's plain-content commits there it names by the cutoff (spec/permissions.md
/// §5.5, Addenda against a rotation), one addendum per thing, so none crosses a label. Waits whole
/// for a thing it may write on only later (`write::may_write`).
fn witness(tx: &mut Tx<'_>, p: Tid, v: &super::account::AccountView, r: &CommitId) -> Result<bool> {
    let Some(me) = tx.core.member().filter(|_| tx.core.addenda_on) else { return Ok(true) };
    let mut out: BTreeMap<Tid, BTreeSet<CommitId>> = BTreeMap::new();
    let closed: Vec<CommitId> = v.closed_by(r).into_iter().filter(|e| !v.is_open(e)).collect();
    for (c, m) in nameable(tx, &p, v, &closed, false)? {
        let w = &m.view;
        if w.purges || w.kind != osis_commit::Kind::Content {
            continue;
        }
        for t in w.aspects.iter().filter(|a| super::addenda::plain_ak(&a.ak)).map(|a| a.tid).chain((w.actor != w.author).then_some(w.actor)) {
            out.entry(t).or_default().insert(c);
        }
    }
    let Some(on) = writable_now(tx, me, out, ct::ADDENDA_AK, Some(osis_base::Role::Write))? else { return Ok(false) };
    for (n, lists) in on {
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

/// The counting removals from account `p`'s devices actor D of a node of D, with that node.
fn removals(tx: &mut Tx<'_>, p: &Tid, d: &Tid) -> Result<Vec<(CommitId, Tid)>> {
    let roles = osis_base::Ak::new("roles.0").map_err(|_| Error::Misuse("ak"))?;
    let core = &*tx.core;
    Ok(core.ix.by_aspect.get(&(*d, roles)).into_iter().flatten().filter_map(|(_, c)| {
        let rc = core.ix.held.edge_commit(c).filter(|rc| rc.author == *p)?;
        let o = rc.ops.iter().find(|o| o.target == *d && o.edge.is_none() && core.is_key_actor(&o.holder))?;
        core.ix.commits.get(c).filter(|m| core.standing(c, &m.view) == osis_perm::EpochStanding::Counts).map(|_| (*c, o.holder))
    }).collect())
}

/// The departures of this node's account `p` that rotations D's roster authorizes cover: per held
/// counting such rotation, the counting removals from D its thing list for D names, each with
/// the node it removes.
#[derive(Default)]
struct Departures {
    named: BTreeMap<CommitId, BTreeSet<CommitId>>,
    node: BTreeMap<CommitId, Tid>,
    /// Removed nodes D's roster holds again.
    back: BTreeSet<Tid>,
}

impl Departures {
    /// Every removal some such rotation names.
    fn all(&self) -> BTreeSet<CommitId> {
        self.named.values().flatten().copied().collect()
    }

    /// The removals rotations on held rotation `r`'s line name; none for the first epoch.
    fn covered(&self, v: &super::account::AccountView, r: &CommitId) -> BTreeSet<CommitId> {
        v.line(r).into_iter().flatten().filter_map(|s| self.named.get(s)).flatten().copied().collect()
    }

    /// The nodes those removals remove that D's roster does not hold again (a re-added node's
    /// removal ends nothing).
    fn removed(&self, v: &super::account::AccountView, r: &CommitId) -> BTreeSet<Tid> {
        self.covered(v, r).iter().filter_map(|c| self.node.get(c)).filter(|n| !self.back.contains(n)).copied().collect()
    }
}

fn departures(tx: &mut Tx<'_>, p: &Tid, v: &super::account::AccountView) -> Result<Departures> {
    let mut out = Departures::default();
    let Some(d) = tx.core.accounts.get(p).map(|a| a.devices) else { return Ok(out) };
    let roster: BTreeSet<Tid> = tx.core.key_holders(&d).into_iter().map(|(m, _)| m).collect();
    for (c, n) in removals(tx, p, &d)? {
        if roster.contains(&n) {
            out.back.insert(n);
        }
        out.node.insert(c, n);
        for (t, s) in super::lists::names_of(tx, &c)? {
            if t == d && v.rotation_counts(&s) && v.authorized_by(&s).is_some() {
                out.named.entry(s).or_default().insert(c);
            }
        }
    }
    Ok(out)
}

/// Whether closer `c` of held epoch `e` ends it for the cutoff (spec/permissions.md §5.5,
/// Cutoff): `c` descends from `e`, or (`departures`, a node of the account reading D's lists)
/// `c`'s line names the removal of a node `e`'s line names none of, so `e` may be boxed to it.
/// A rotation beside `e` naming no one more (a concurrent rotation of the same heads, or one
/// removing the same node) ends nothing: forks stand. Without D's lists (a witness) every closer
/// ends it.
fn ends(v: &super::account::AccountView, departures: Option<&Departures>, e: &CommitId, c: &CommitId) -> bool {
    let Some(dep) = departures else { return true };
    if *e == osis_commit::FIRST_EPOCH || v.line(c).is_some_and(|l| l.contains(e)) {
        return true;
    }
    let mine = dep.removed(v, e);
    dep.removed(v, c).iter().any(|x| !mine.contains(x))
}

/// The held rotations of this node's account `p` beside a removal of their minter whose
/// epoch no counting rotation D's roster authorizes supersedes, once an authorized rotation
/// held names that node's removal (so the removal's line is held: rejecting earlier would
/// reject what it is signed at): a removed node's forks, each a head wherever the roster is not
/// read until a rotation of the account supersedes it unnamed.
fn unanswered(tx: &mut Tx<'_>, p: &Tid, v: &super::account::AccountView) -> Result<Vec<CommitId>> {
    let Some(d) = tx.core.accounts.get(p).map(|a| a.devices) else { return Ok(Vec::new()) };
    let named = departures(tx, p, v)?.all();
    let removed: BTreeSet<Tid> = removals(tx, p, &d)?.into_iter().filter(|(c, _)| named.contains(c)).map(|(_, n)| n).collect();
    Ok(v.rotation_ids().into_iter().filter(|r| v.holds(r) && v.removed_minter(r).is_some_and(|n| removed.contains(&n)) && !v.superseded_by_authorized(r)).collect())
}

/// What a node of this node's account owes its signing chain (spec/permissions.md §3, §5.5),
/// made now. Any node of the account makes it, none designated: forks stand, so a fork alone
/// owes nothing, and two nodes' rotations made at once fork and stand. One rotation
/// superseding every head (`rotate_in`) is owed when a removed node's fork stands unanswered
/// (`unanswered`), a head is blocked here (its line lacks a departure an authorized rotation
/// held names: it may be boxed to the departed node), or a counting removal from D no
/// authorized rotation names may be named by this node by the cutoff (its own, or received
/// before the earliest closer ending its epoch), or is named by a rotation that stands (made by
/// a node since removed, before its removal: its word from then stands), which the rotation
/// names. A removal named only by a rotation beside its maker's removal (a removed node's fork)
/// falls with that fork unless the cutoff lets this node name it: a removed node removes no one
/// for good. Looked at when the account's commits
/// moved (`Core::signing_due`); D's role history is its device count's.
pub(crate) fn rotations_due(tx: &mut Tx<'_>, done: &mut Done) -> Result<Option<CommitId>> {
    if !std::mem::take(&mut tx.core.signing_due) {
        return Ok(None);
    }
    let Some(p) = tx.core.member() else { return Ok(None) };
    let Some(d) = tx.core.accounts.get(&p).map(|a| a.devices) else { return Ok(None) };
    take_seeds(tx, &d)?;
    // a seed taken up moves what the account's epochs judge
    crate::apply::rejudged(tx, false)?;
    let Some(v) = tx.core.account_view(&p) else { return Ok(None) };
    let dep = departures(tx, &p, &v)?;
    let named = dep.all();
    let mut unnamed = Vec::new();
    for (c, _) in removals(tx, &p, &d)? {
        if named.contains(&c) {
            continue;
        }
        let standing = super::lists::names_of(tx, &c)?.iter().any(|(t, s)| *t == d && v.rotation_counts(s) && v.stands(s));
        let Some(e) = tx.core.ix.commits.get(&c).and_then(|m| m.view.epoch) else { continue };
        if standing || nameable(tx, &p, &v, &[e], true)?.iter().any(|x| x.0 == c) {
            unnamed.push(c);
        }
    }
    let blocked = v.heads().iter().any(|h| {
        let line = dep.covered(&v, h);
        named.iter().any(|c| !line.contains(c))
    });
    if unnamed.is_empty() && !blocked && unanswered(tx, &p, &v)?.is_empty() {
        return Ok(None);
    }
    rotate_in(tx, p, &unnamed, done)
}

impl Engine {
    /// What this node owes its account's signing chain (`rotations_due`), decided at the end
    /// of a complete pass of its devices actor's labels (node-sync), so a removal and its
    /// rotation that arrive apart, or two forks and the merge of another node, are both in.
    pub fn signing_due(&mut self) -> Result<Done> {
        let mut done = Done::default();
        let c = self.run(|tx| rotations_due(tx, &mut done))?;
        done.add(c);
        if let (Some(r), Some((_, d))) = (c, self.core.account_devices()) {
            done.deliveries.push(self.run(|tx| super::owe(tx, super::Delivery::First { commits: vec![r], under: vec![d] }))?);
        }
        Ok(done)
    }
}
