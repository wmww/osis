//! Custody of an account's seeds (spec/crypto.md §9, Custody). Principle: custody follows
//! holding. A rotation boxes its new seed to each device on its maker's roster (its header's seed
//! boxes); a node holds a seed iff it opened a box to its own device key, whoever wrote the box
//! and whether or not its rotation counts. Judgment decides only where a node signs and what it
//! boxes, never what it holds, so the chain is a function of held commits alone.

use crate::engine::{Core, Tx, records};
use crate::error::{Error, Result};
use osis_base::{Role, Tid};
use osis_commit::{Header, SeedBox, SeedReseal};
use osis_schema::core_types as ct;
use osis_schema::{Codec, RawKey};
use osis_base::Value;
use osis_crdt::{Op, PathOp, PathSeg};
use super::account::AccountView;
use osis_crypto::{AccountEpochKeys, Secret32, VerifyingKey};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Every seed of account `p` in this node's custody, by epoch signing key.
pub(crate) type Seeds = BTreeMap<VerifyingKey, Arc<AccountEpochKeys>>;

fn row(p: &Tid, key: &VerifyingKey) -> Vec<u8> {
    [records::SEEDS, p.as_bytes().as_slice(), &key.to_bytes()].concat()
}

/// Opens the seed boxes of header `h` (a rotation's of the epoch it mints, a re-seal's of the
/// epoch it names) addressed to this node's device key, at a node holding the account or of no
/// account yet (a pairing hands a new node its seeds so), counting or not, and keeps every seed
/// found (`keep`).
pub(crate) fn take_boxes(tx: &mut Tx<'_>, h: &Header) -> Result<()> {
    let Some((key, boxes)) = seed_boxes_of(h) else { return Ok(()) };
    let p = h.author;
    let ours = tx.core.accounts.contains_key(&p) || tx.core.account.get().is_none_or(|a| a == p);
    if !ours || held(tx, &p, key)? {
        return Ok(());
    }
    let kem = tx.core.id.keys().kem.clone();
    let Some(seeds) = boxes.iter().find_map(|b| osis_crypto::open_seeds(&kem, &p, key, &b.sealed)) else { return Ok(()) };
    for s in seeds {
        keep(tx, &p, &s)?;
    }
    Ok(())
}

/// Header `h`'s seed boxes with the signing key of the epoch whose seed they carry: a rotation's
/// (the epoch it mints) or a re-seal's.
pub(crate) fn seed_boxes_of(h: &Header) -> Option<(&VerifyingKey, &[SeedBox])> {
    match (&h.rotation, &h.reseal) {
        (Some(r), _) => Some((&r.signing_key, &r.seeds)),
        (None, Some(r)) => Some((&r.signing_key, &r.seeds)),
        (None, None) => None,
    }
}

/// Whether the seed of account `p`'s epoch with signing key `key` is in custody here: recorded,
/// and taken up where the account is held. (Memory alone is not custody: a transaction rolled
/// back, a trial among them, keeps no record.)
fn held(tx: &mut Tx<'_>, p: &Tid, key: &VerifyingKey) -> Result<bool> {
    Ok(tx.txn.get_local(&row(p, key))?.is_some() && tx.core.accounts.get(p).is_none_or(|a| a.keys.contains_key(key)))
}

/// Keeps seed `s` of account `p` in custody: recorded, and taken up at once where the account is
/// held (its chain is judged again: inner signatures it opens may move what counts).
pub(crate) fn keep(tx: &mut Tx<'_>, p: &Tid, s: &Secret32) -> Result<()> {
    let keys = AccountEpochKeys::from_seed(s);
    let pk = keys.signing.verifying_key();
    tx.txn.put_local(&row(p, &pk), s.expose(), Shred::Yes)?;
    if let Some(a) = tx.core.accounts.get(p).filter(|a| !a.keys.contains_key(&pk)) {
        let mut n = (**a).clone();
        n.keys.insert(pk, Arc::new(keys));
        tx.core.accounts.insert(*p, Arc::new(n));
        tx.core.ix.epochs_due.insert(*p);
        // a part on the account itself sealed under an epoch whose seed came only now opens now:
        // its stored entries are opened again
        let lacking: Vec<osis_base::CommitId> = tx.core.aspects_of(p).flat_map(|(_, cs)| cs.iter().map(|x| x.1)).filter(|c| tx.core.ix.commits.get(c).is_some_and(|m| m.view.aspects_on(p).any(|ai| m.missing(ai)))).collect();
        tx.core.redeliver.extend(lacking);
    }
    Ok(())
}

/// The seeds of account `p` in custody here.
pub(crate) fn seeds(tx: &mut Tx<'_>, p: &Tid) -> Result<Seeds> {
    let mut out = Seeds::new();
    let prefix = [records::SEEDS, p.as_bytes().as_slice()].concat();
    tx.scan(&prefix, |_, v| {
        let s = Secret32::from_bytes(v.as_slice().try_into().map_err(|_| Error::Corrupt("seed record"))?);
        let keys = AccountEpochKeys::from_seed(&s);
        out.insert(keys.signing.verifying_key(), Arc::new(keys));
        Ok(())
    })?;
    Ok(out)
}

/// Drops every seed of account `p` in custody here: the node left it.
pub(crate) fn shred(tx: &mut Tx<'_>, p: &Tid) -> Result<()> {
    tx.remove_scanned(&[records::SEEDS, p.as_bytes().as_slice()].concat(), |_| Ok(true))
}

/// The devices on D's roster as this node reads it: the key actors holding D (D's first admin,
/// the account, holds it by its record and is no device).
pub(crate) fn roster(core: &Core, d: &Tid) -> Vec<Tid> {
    core.key_holders(d).into_iter().map(|(m, _)| m).filter(|m| core.is_key_actor(m) && !core.is_account(m)).collect()
}

/// The seed boxes of a rotation of account `p` minting the epoch with seed `seed`: one to each
/// device on D's roster here, carrying the new seed, and to each of `adds` (devices it adds)
/// also every seed this node holds (spec/crypto.md §9, Custody). Ascending by tag.
pub(crate) fn seed_boxes(tx: &mut Tx<'_>, p: &Tid, d: &Tid, seed: &Secret32, adds: &[Tid]) -> Result<Vec<SeedBox>> {
    let epoch = AccountEpochKeys::from_seed(seed).signing.verifying_key();
    let held: Vec<Secret32> = tx.core.accounts.get(p).map(|a| a.keys.values().map(|k| k.seed().clone()).collect()).unwrap_or_default();
    let mut devices = roster(tx.core, d);
    for a in adds {
        if !devices.contains(a) {
            devices.push(*a);
        }
    }
    let mut out = Vec::new();
    for m in devices {
        let mut payload: Vec<&Secret32> = vec![seed];
        if adds.contains(&m) {
            payload.extend(held.iter().filter(|s| s.expose() != seed.expose()));
        }
        out.push(seed_box(tx, p, &epoch, &m, &payload)?);
    }
    out.sort_by_key(|b| b.tag);
    Ok(out)
}

/// A seed box of account `p`'s epoch with signing key `epoch` to device `m`: `payload`, that
/// epoch's seed first, sealed to `m`'s KEM key, tagged by that seed and `m`.
fn seed_box(tx: &mut Tx<'_>, p: &Tid, epoch: &VerifyingKey, m: &Tid, payload: &[&Secret32]) -> Result<SeedBox> {
    let kem = match super::recipient(tx, *m, Role::Admin)?.keys {
        osis_keys::HolderKeys::KeyActor { kem, .. } => kem,
        _ => return Err(Error::Misuse("a device holds no key actor's KEM key")),
    };
    let first = payload.first().ok_or(Error::Misuse("an empty seed box"))?;
    let sealed = osis_crypto::seal_seeds(&kem, p, epoch, payload, &mut *tx.rng).map_err(|_| Error::Misuse("seed box"))?;
    Ok(SeedBox { tag: osis_crypto::seed_tag(first, m), sealed })
}

/// Seed re-seals (spec/crypto.md §9, Custody), at the end of a complete pass of D's sync IDs:
/// for each head of this node's account whose seed it holds and whose line it holds whole, the
/// devices on D's roster no counting box of that seed is tagged for are boxed it, with the seeds
/// of its line held here, one commit per head. Bounded by structure: once held, a re-seal is a
/// counting box, so each (head, device) is re-sealed once per node that sees it lacking before it
/// holds another's. A box counts only in a commit that counts here, so a holder of an old seed (a
/// removed node) cannot hold a re-seal back with a tag over a box that opens for no one.
pub(crate) fn reseal_seeds(tx: &mut Tx<'_>) -> Result<Vec<osis_base::CommitId>> {
    let Some((p, d)) = tx.core.account_devices() else { return Ok(Vec::new()) };
    let (Some(v), Some(held)) = (tx.core.account_view(&p), tx.core.accounts.get(&p).cloned()) else { return Ok(Vec::new()) };
    if !super::signing::signs_for(tx.core, &d, &v) {
        return Ok(Vec::new());
    }
    let roster = roster(tx.core, &d);
    let boxed = counting_tags(tx.core, &v, &d);
    let mut out = Vec::new();
    for h in v.heads() {
        let Some(keys) = v.keys_of(&h, &held) else { continue };
        if !v.whole(&h, |c| tx.core.ix.commits.contains_key(c)) {
            continue;
        }
        let seed = keys.seed().clone();
        let lacking: Vec<Tid> = roster.iter().filter(|m| !boxed.contains(&osis_crypto::seed_tag(&seed, m))).copied().collect();
        if lacking.is_empty() {
            continue;
        }
        let epoch = keys.signing.verifying_key();
        // Interim (issues/account-removal-before-its-rotation.md): replaced by custody phase 2.
        // The re-seal writes the epoch's entry in D's `account.0` again (the record its rotation
        // put on D), as a re-seal of a thing writes its boxes again: a new entry, so it travels
        // under D's sync IDs to every device.
        let acct = tx.state(&d, &ct::ACCOUNT.name())?.and_then(osis_crdt::Fragment::read).and_then(|x| ct::ACCOUNT.decode(&x).ok()).unwrap_or_default();
        let Some(under) = acct.under.get(epoch.to_bytes().as_slice()) else { continue };
        // the head's seed, then the seeds of its line held here: a device reads who minted each
        // rotation on the line with the seed of the epoch it is signed at
        let line: Vec<Secret32> = v.line(&h).into_iter().flatten().chain([&osis_commit::FIRST_EPOCH]).filter(|r| **r != h).filter_map(|r| v.keys_of(r, &held)).map(|k| k.seed().clone()).collect();
        let payload: Vec<&Secret32> = std::iter::once(&seed).chain(line.iter()).collect();
        let mut seeds = Vec::new();
        for m in &lacking {
            seeds.push(seed_box(tx, &p, &epoch, m, &payload)?);
        }
        seeds.sort_by_key(|b| b.tag);
        let mut m = crate::Mutation::new();
        m.sign_as(p);
        let k = Value::bytes(&epoch.to_bytes());
        m.op(d, &ct::ACCOUNT, PathOp { path: vec![PathSeg::Field(0)], op: Op::Remove(k.clone()) })?;
        m.op(d, &ct::ACCOUNT, PathOp { path: vec![PathSeg::Field(0), PathSeg::Key(k)], op: Op::Set(under.to_value()) })?;
        m.reseal = Some(SeedReseal { signing_key: epoch, seeds });
        out.extend(crate::Engine::commit_tx(tx, m)?);
    }
    Ok(out)
}

/// The tags of every seed box in a commit of account `p` on D that counts here: a counting
/// rotation's, a counting re-seal's (both write D's `account.0`).
fn counting_tags(core: &Core, v: &AccountView, d: &Tid) -> BTreeSet<[u8; osis_crypto::SEED_TAG_LEN]> {
    let Ok(ak) = osis_base::Ak::new("account.0") else { return BTreeSet::new() };
    let mut out = BTreeSet::new();
    for (_, c) in core.ix.by_aspect.get(&(*d, ak)).into_iter().flatten() {
        let Some(m) = core.ix.commits.get(c) else { continue };
        let counts = if v.is_rotation(c) { v.rotation_counts(c) } else { core.standing(c, &m.view) == osis_perm::EpochStanding::Counts };
        let h = m.header.arc();
        if counts && let Some((_, boxes)) = seed_boxes_of(&h) {
            out.extend(boxes.iter().map(|b| b.tag));
        }
    }
    out
}
