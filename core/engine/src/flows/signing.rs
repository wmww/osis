//! What a node of account P writes of P's signing chain (spec/permissions.md §3, §5.5,
//! spec/crypto.md §9): the rotation a removal from P's devices actor D requires, with its thing
//! lists; its take-up of the seeds D's `account.0` holds.
//!
//! Principle: a revocation ends the standing of what was signed at the epochs it closes, so a
//! rotation names what its rotator holds there (its thing lists), as a demotion's frontier names
//! what its demoter holds; every rotation names, as a later removal revokes earlier epochs.

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
    pub at: Option<(CommitId, Arc<AccountEpochKeys>)>,
}

impl AccountRotation {
    pub(crate) fn certs(&self, rotation: CommitId) -> Vec<ThingCert> {
        self.lists.iter().map(|(index, siblings, list)| ThingCert { rotation, index: *index, siblings: siblings.clone(), list: list.clone() }).collect()
    }
}

/// A thing's listed commits: role-class and purge-request ones, then plain ones by receipt.
type PerThing = (BTreeSet<CommitId>, Vec<(osis_base::WallMs, CommitId)>);

/// The membership changes of D a rotation carries (spec/permissions.md §1, §5.4): the devices it
/// adds (a pairing) and those it removes. No addition or removal exists apart from its rotation.
#[derive(Clone, Debug, Default)]
pub(crate) struct Members {
    pub adds: Vec<Tid>,
    pub removes: Vec<Tid>,
}

/// Rotates account `p`'s epoch (spec/permissions.md §3, §5.5; spec/crypto.md §9): a role commit
/// signed at the open epoch, minting one whose seed its header boxes to each device on D's roster
/// (`custody::seed_boxes`) and whose public keys go into P's `keys.0`, re-keying D to that
/// roster in the same commit. In a
/// fork (several heads) it is a merge of the heads D's roster authorizes whose seeds are held
/// here (`mergeable`): superseding each, signed at the preferred one and naming the others with
/// a signature by each one's key. A removed node's rotation no authorized one supersedes
/// (`unanswered`) is superseded unnamed, so the merge rejects it.
/// Its thing lists name the commits of P this node holds at the epochs it closes that no word
/// names, by the cutoff (`nameable`: at an open epoch every one received), cut per thing it has
/// a delta on or acts for; within the bound, plain content past it left to this node's listings.
/// `None`: an authorized head's seed is not held here, or no head is authorized.
pub(crate) fn rotate_in(tx: &mut Tx<'_>, p: Tid, also: &[CommitId], done: &mut Done) -> Result<Option<CommitId>> {
    rotate_with(tx, p, also, &Members::default(), done)
}

/// `rotate_in` carrying membership changes `members`: its header seals them (spec/crypto.md §9,
/// Roster); a device it adds is boxed every seed this node holds besides the new one (Custody),
/// one it removes nothing.
pub(crate) fn rotate_with(tx: &mut Tx<'_>, p: Tid, also: &[CommitId], members: &Members, done: &mut Done) -> Result<Option<CommitId>> {
    let held = tx.core.accounts.get(&p).cloned().ok_or(Error::Misuse("not an account held here"))?;
    let v = tx.core.account_view(&p).ok_or(Error::Misuse("no signing chain for the account"))?;
    let signing = tx.core.account_signing(&p).ok().flatten();
    let mut names = Vec::new();
    // a removed node's rotation no authorized one supersedes yet: superseded unnamed, rejected
    let reject = unanswered(&v, &tx.core.id.tid());
    let heads = mergeable(&v, &held);
    let (at, supersedes, merge_keys, closes) = match signing {
        Some((e, _)) if heads.len() < 2 => (None, vec![e], Vec::new(), vec![e]),
        // an open epoch whose seed is not here yet (its removal has not arrived): nothing to act at
        None if heads.len() < 2 => return Ok(None),
        _ => {
            // the merge supersedes and names (accepts) the heads D's roster authorizes whose
            // seeds are held here, signed at the preferred one; a head whose seed is not here is
            // left to a node that holds it (superseding it unnamed would reject a line this
            // node follows); a removed node's fork is superseded unnamed below (`unanswered`),
            // so it is rejected with its lists (spec/permissions.md §5.4)
            let Some((first, k)) = heads.first().cloned() else { return Ok(None) };
            names = heads.iter().skip(1).map(|x| x.0).collect();
            let sup: Vec<CommitId> = heads.iter().map(|x| x.0).collect();
            (Some((first, k)), sup.clone(), heads.iter().skip(1).map(|x| x.1.signing.clone()).collect(), sup)
        }
    };
    // the revocations this node took off the new rotation's line: it stands with them
    // (spec/permissions.md §5.4), so a node that took another revocation reads it as that side
    let on_line = |t: &CommitId| supersedes.iter().any(|b| b == t || v.line(b).is_some_and(|l| l.contains(t)));
    let mut takes: Vec<CommitId> = v.taken().iter().copied().filter(|t| !on_line(t)).collect();
    takes.sort();
    let (mut supersedes, mut closes) = (supersedes, closes);
    for r in reject {
        if !supersedes.contains(&r) {
            supersedes.push(r);
            closes.push(r);
        }
    }
    let _ = done;
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
    // D's deposit seed is the account's: fresh with each rotation carrying a removal (someone
    // leaves, spec/crypto.md §3); one carrying none (a pairing, a merge) keeps it
    if !members.removes.is_empty() || k.deposit_seed.is_none() {
        let mut dep = [0u8; 32];
        tx.rng.fill_bytes(&mut dep);
        k.deposit_seed = Some(dep);
    }
    m.set(p, &ct::KEYS, &k)?;
    // on D: the epoch whose seed it boxes, and D re-keyed to its roster after this rotation's
    // membership changes (spec/permissions.md §3: D's keys move only with the account's)
    let d = held.devices;
    m.op(d, &ct::ACCOUNT, PathOp { path: vec![], op: Op::Add(Value::bytes(&signing.to_bytes())) })?;
    let skip: Vec<(Tid, Option<osis_base::Role>)> = members.removes.iter().map(|x| (*x, None)).collect();
    let mut boxing = crate::rotation::recipients(tx, &p, &d, &skip)?;
    for n in &members.adds {
        if !boxing.holders.iter().any(|h| h.holder == *n) {
            boxing.holders.push(super::recipient(tx, *n, osis_base::Role::Admin)?);
        }
    }
    let held_d = tx.core.epochs(&d).map(Arc::unwrap_or_clone).ok_or(Error::Misuse("D's epochs not held"))?;
    let departs = if members.removes.is_empty() { crate::rotation::Departs::No } else { crate::rotation::Departs::Holder };
    let d_rot = crate::rotation::rotation_into(tx, &mut m, d, &osis_keys::ROLES.into_iter().collect(), &held_d, &boxing, departs)?;
    let seeds = super::custody::seed_boxes(tx, &p, &held.devices, &seed, members)?;
    let at_keys = match &at {
        Some((_, k)) => k.clone(),
        None => tx.core.account_signing(&p)?.ok_or(Error::Misuse("the account's open epoch is not held"))?.1,
    };
    let (mut adds, mut removes) = (members.adds.clone(), members.removes.clone());
    adds.sort();
    removes.sort();
    let devices = if adds.is_empty() && removes.is_empty() { Vec::new() } else { osis_crypto::seal_devices(&at_keys.inner, &signing, &adds, &removes) };
    let lists = leaves.into_iter().zip(paths).map(|((i, l), path)| (i, path.siblings, l)).collect();
    let mut sup = supersedes;
    sup.sort();
    m.rotation = Some(AccountRotation { header: RotationHeader { signing_key: signing, kem_key: keys.kem.public().clone(), supersedes: sup, names, takes, revokes: !removes.is_empty(), devices, list_root: root, seeds }, merge_keys, lists, at });
    // the new seed is kept as the commit applies: its box to this node opens (`custody::take_boxes`)
    let c = Engine::commit_tx(tx, m)?;
    crate::rotation::record(tx, d, &d_rot)?;
    Ok(c)
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
/// void one is answered by nothing, until it comes to count (`account::refresh_epochs` notes it
/// due again). Each answer is one step (`Tx::step`): one that fails leaves
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
    let departures = own.then(|| departures(v));
    let mut out = Vec::new();
    for e in epochs {
        let closers: BTreeSet<CommitId> = v.closers(e).into_iter().filter(|c| ends(v, departures.as_ref(), e, c)).collect();
        let earliest = closers.iter().filter_map(|c| tx.core.ix.commits.get(c).map(|m| m.received)).min();
        let open = v.is_open(e);
        let at: Vec<CommitId> = tx.core.ix.by_epoch.get(&(*p, *e)).into_iter().flatten().copied().collect();
        for c in at {
            let Some(m) = tx.core.ix.commits.get(&c).cloned() else { continue };
            // a word is owed whether or not the epoch is revoked yet (one counting unrevoked, or
            // only while it waits for D's list, may be revoked later): only a held word naming it
            // spares it
            if v.is_rotation(&c) || !open && named_by_a_word(tx, v, &c, &m.view)? {
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

/// Whether a counting word held here names account commit `c` (`view`, its view): a counting
/// rotation's thing list or a counting listing, on a thing `c` has a delta on or acts for
/// (spec/permissions.md §5.5, Epoch rule).
fn named_by_a_word(tx: &mut Tx<'_>, v: &super::account::AccountView, c: &CommitId, view: &crate::engine::View) -> Result<bool> {
    let things = things_of(view);
    for (t, s) in super::lists::names_of(tx, c)? {
        if !things.contains(&t) {
            continue;
        }
        let counts = match tx.core.ix.commits.get(&s) {
            _ if v.is_rotation(&s) => v.rotation_counts(&s),
            Some(m) => m.view.author == view.author && tx.core.standing(&s, &m.view) == osis_perm::EpochStanding::Counts,
            None => false,
        };
        if counts {
            return Ok(true);
        }
    }
    Ok(false)
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
/// others' by the cutoff (spec/permissions.md §5.5, Listings), one commit per thing: a commit
/// goes whole under the sync IDs of every thing it touches, so one over every thing would ship
/// each thing's listing wherever any other thing goes. A listing needs no role on a thing; one
/// it may write on only later waits whole, one that is gone here is left out.
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
    for (t, ids) in on {
        let mut m = Mutation::new();
        m.sign_as(p);
        m.unchecked();
        let set = Value::Set(ids.iter().map(|c| Value::bytes(&c.0)).collect());
        m.op(t, &ct::LISTING, PathOp { path: vec![PathSeg::Key(Value::bytes(&r.0))], op: Op::Put(set) })?;
        Engine::commit_tx(tx, m)?;
    }
    Ok(true)
}

/// A writer of a thing answers another account's rotation `r` with an addendum on each thing it
/// writes: the account's plain-content commits there it names by the cutoff (spec/permissions.md
/// §5.5, Addenda against a rotation), one addendum per thing, so none crosses a sync ID. Waits whole
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

/// Judges account `p` (devices actor `d`) again now that this node took it up or left it
/// (`Engine::take_up`): the epoch rule reads D only at a node holding the account, so every
/// standing may move (spec/permissions.md §5.4, Following, at a node of P and outside it), the
/// account's commits on D among them, whose standing may move with no epoch's (Waiting counts
/// them only at a node of P). Nothing else notes it: `Core::judged_from` tracks what moves while
/// the account is held, not holding it.
pub(crate) fn judge_account_again(tx: &mut Tx<'_>, p: Tid, d: Tid) -> Result<()> {
    tx.core.ix.epochs_due.insert(p);
    let on_d: Vec<CommitId> = tx.core.ix.role_on.get(&(d, p)).into_iter().flatten().copied().collect();
    tx.core.ix.names_due.extend(on_d);
    crate::apply::atomic::rejudged(tx, false).map(drop)
}

/// A node of account `p` leaves it only when no held line keeps it a node (spec/crypto.md §9,
/// Custody), read from the seed boxes alone: of the held rotations that count here or whose seed
/// it holds, every tip (one on no other's line) is boxed to other devices only (with none, the
/// first epoch keeps it). So it leaves on a counting rotation boxing it nothing past every line
/// boxing it; a rotation it neither follows nor holds the seed of (a forgery boxing no one, a line
/// it disregards) moves nothing. Leaving, it drops the account's seeds, so it signs and opens
/// nothing as it, and everything it read only as the account is lost (spec/permissions.md §3, Lost
/// access; an account's retain default does not reach its nodes, §2): every held actor is judged
/// again. D's roster decides nothing here: a grant unnamed at a node is no removal of it, and a
/// node a removal took off the line it follows stays while another held line keeps it, so its
/// user's switch to that line takes.
pub(crate) fn leave_if_removed(tx: &mut Tx<'_>) -> Result<()> {
    let Some((p, d)) = tx.core.account_devices() else { return Ok(()) };
    let (Some(v), Some(held)) = (tx.core.account_view(&p), tx.core.accounts.get(&p).cloned()) else { return Ok(()) };
    if kept(&v, &held) {
        return Ok(());
    }
    leave(tx, p, d)
}

/// Whether some held line keeps this node a node of its account (`leave_if_removed`).
pub(crate) fn kept(v: &super::account::AccountView, held: &super::account::HeldAccount) -> bool {
    let rots: Vec<CommitId> = v.rotation_ids().into_iter().filter(|r| v.holds(r) && (v.rotation_counts(r) || v.keys_of(r, held).is_some())).collect();
    let below: BTreeSet<CommitId> = rots.iter().flat_map(|r| v.line(r).into_iter().flatten().filter(move |x| *x != r)).copied().collect();
    let mut tips = rots.iter().filter(|r| !below.contains(*r)).peekable();
    tips.peek().is_none() || tips.any(|t| v.keys_of(t, held).is_some())
}

/// `leave_if_removed` of account `p` with devices actor `d`.
pub(crate) fn leave(tx: &mut Tx<'_>, p: Tid, d: Tid) -> Result<()> {
    tx.core.accounts.remove(&p);
    super::custody::shred(tx, &p)?;
    tx.core.left.insert(p);
    judge_account_again(tx, p, d)?;
    let held: Vec<Tid> = tx.core.ix.secrets.keys().copied().chain([d]).collect();
    crate::rotation::touch_held(tx, held);
    Ok(())
}

/// The departures of this node's account that counting rotations carry: per such rotation, the
/// nodes it removes.
#[derive(Default)]
struct Departures {
    named: BTreeMap<CommitId, BTreeSet<Tid>>,
    /// Removed nodes D's roster holds again.
    back: BTreeSet<Tid>,
}

impl Departures {
    /// The nodes the rotations on held rotation `r`'s line remove that D's roster does not hold
    /// again (a re-added node's removal ends nothing); none for the first epoch.
    fn removed(&self, v: &super::account::AccountView, r: &CommitId) -> BTreeSet<Tid> {
        v.line(r).into_iter().flatten().filter_map(|s| self.named.get(s)).flatten().filter(|n| !self.back.contains(n)).copied().collect()
    }
}

fn departures(v: &super::account::AccountView) -> Departures {
    let mut out = Departures::default();
    for r in v.rotation_ids().into_iter().filter(|r| v.rotation_counts(r)) {
        let ns = v.removes(&r);
        if ns.is_empty() {
            continue;
        }
        out.back.extend(ns.iter().filter(|n| v.roster().contains(*n)));
        out.named.insert(r, ns);
    }
    out
}

/// Whether closer `c` of held epoch `e` ends it for the cutoff (spec/permissions.md §5.5,
/// Cutoff): `c` descends from `e`, or (`departures`, a node of the account reading D's lists)
/// `c`'s line names the removal of a node `e`'s line names none of, so `e` may be boxed to it.
/// A rotation beside `e` naming no one more (a concurrent rotation of the same heads, or one
/// removing the same node) ends nothing, so writes at a head stay nameable until a merge. Without
/// D's lists (a witness) every closer ends it.
fn ends(v: &super::account::AccountView, departures: Option<&Departures>, e: &CommitId, c: &CommitId) -> bool {
    let Some(dep) = departures else { return true };
    if *e == osis_commit::FIRST_EPOCH || v.line(c).is_some_and(|l| l.contains(e)) {
        return true;
    }
    let mine = dep.removed(v, e);
    dep.removed(v, c).iter().any(|x| !mine.contains(x))
}

/// The heads of `v` a merge by this node names: those whose seeds are held here, the preferred
/// one first.
fn mergeable(v: &super::account::AccountView, held: &super::account::HeldAccount) -> Vec<(CommitId, Arc<AccountEpochKeys>)> {
    let mut heads = v.heads();
    heads.sort_by_key(|h| *h != v.preferred());
    heads.into_iter().filter_map(|h| Some((h, v.keys_of(&h, held)?))).collect()
}

/// The held rotations of this node's account this node disregards (placed in conflict with the
/// line it follows: a removed node's fork, one no node of the account minted, another side's)
/// with no rotation on their line a counting one rejects, that no rotation of this node's
/// supersedes: superseded unnamed by its next rotation, so every reader that followed one is told
/// (spec/permissions.md §5.4, Warning). Another node's rotation superseding it may reject nothing
/// (signed at its epoch: contested from below), so only a rejection answers it, and each node
/// answers once (its own answer may be so contested too). One answer per line: a reader following
/// it holds that rejection already, so two sides never answer each other's answers; a rotation
/// signed at the answer's epoch that puts the rejected one on a line through it ends that
/// rejection, and is answered in turn.
fn unanswered(v: &super::account::AccountView, me: &Tid) -> Vec<CommitId> {
    v.rotation_ids().into_iter().filter(|r| v.disregarded(r) && !v.superseded_by(r, me) && !v.line(r).into_iter().flatten().any(|q| v.rejected(q))).collect()
}

/// What a node of the account owes its signing chain (spec/permissions.md §5.5), made now. Any
/// node of the account makes it, none designated. One rotation (`rotate_in`) is owed when the
/// heads fork (readers outside the account follow one head only, so the heads it can sign at are
/// merged), a rotation it disregards stands unanswered (`unanswered`: superseded unnamed, so
/// every reader that followed it is told), or a revocation it took is on no line of its
/// preferred head (taken by no rotation on it) while it cannot merge. A removal or addition is
/// made with its own rotation (`Engine::remove_device`, `Engine::pair`). Looked at when the
/// account's commits moved (`Core::signing_due`).
pub(crate) fn rotations_due(tx: &mut Tx<'_>, done: &mut Done) -> Result<Option<CommitId>> {
    if !std::mem::take(&mut tx.core.signing_due) {
        return Ok(None);
    }
    let Some(p) = tx.core.member() else { return Ok(None) };
    let Some(d) = tx.core.accounts.get(&p).map(|a| a.devices) else { return Ok(None) };
    let Some(v) = tx.core.account_view(&p) else { return Ok(None) };
    if !signs_for(tx.core, &d, &v) {
        return Ok(None);
    }
    let held = tx.core.accounts.get(&p).cloned().ok_or(Error::Misuse("not an account held here"))?;
    let fork = mergeable(&v, &held).len() > 1;
    let pref = v.preferred();
    let line: BTreeSet<CommitId> = v.line(&pref).cloned().unwrap_or_default();
    let carried = |t: &CommitId| line.contains(t) || line.iter().any(|q| v.takes_of(q).contains(t));
    let untaken = !fork && v.taken().iter().any(|t| !carried(t));
    if !fork && !untaken && unanswered(&v, &tx.core.id.tid()).is_empty() {
        return Ok(None);
    }
    rotate_in(tx, p, &[], done)
}

/// Whether this node writes its account's chain (rotations, seed re-seals): it is on D's
/// roster (a node off it would mint a seed it boxes to none but itself), and it took no
/// revocation of itself.
pub(crate) fn signs_for(core: &crate::engine::Core, d: &Tid, v: &super::account::AccountView) -> bool {
    let me = core.id.tid();
    core.of_devices(d) && !v.taken().iter().any(|r| v.removes(r).contains(&me))
}

impl Engine {
    /// What this node owes its account's signing chain, decided at the end of a complete pass
    /// of its devices actor's sync IDs (node-sync), so two forks and the merge of another node
    /// are both in: the rotation due (`rotations_due`), then the seed re-seals of its heads
    /// (`custody::reseal_seeds`).
    pub fn signing_due(&mut self) -> Result<Done> {
        let mut done = Done::default();
        let c = self.run(|tx| rotations_due(tx, &mut done))?;
        done.add(c);
        done.commits.extend(self.run(super::custody::reseal_seeds)?);
        Ok(done)
    }
}
