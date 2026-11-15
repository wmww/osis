//! Custody of an account's seeds (spec/crypto.md §9, Custody). Principle: custody follows
//! holding. A rotation boxes its new seed to each device on its maker's roster (its header's seed
//! boxes); a node holds a seed iff it opened a box to its own device key, whoever wrote the box
//! and whether or not its rotation counts. Judgment decides only where a node signs and what it
//! boxes, never what it holds, so the chain is a function of held commits alone.

use crate::engine::{Core, Tx, records};
use crate::error::{Error, Result};
use osis_base::{Role, Tid};
use osis_commit::{Header, SeedBox};
use osis_crypto::{AccountEpochKeys, Secret32, VerifyingKey};
use osis_store::Shred;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Every seed of account `p` in this node's custody, by epoch signing key.
pub(crate) type Seeds = BTreeMap<VerifyingKey, Arc<AccountEpochKeys>>;

fn row(p: &Tid, key: &VerifyingKey) -> Vec<u8> {
    [records::SEEDS, p.as_bytes().as_slice(), &key.to_bytes()].concat()
}

/// Opens the seed boxes of rotation header `h` addressed to this node's device key, at a node
/// holding the rotation's account or of no account yet (a pairing hands a new node its seeds so),
/// counting or not, and keeps every seed found (`keep`).
pub(crate) fn take_boxes(tx: &mut Tx<'_>, h: &Header) -> Result<()> {
    let Some(rot) = h.rotation.as_ref() else { return Ok(()) };
    let p = h.author;
    let ours = tx.core.accounts.contains_key(&p) || tx.core.account.get().is_none_or(|a| a == p);
    if !ours || held(tx, &p, &rot.signing_key)? {
        return Ok(());
    }
    let kem = tx.core.id.keys().kem.clone();
    let Some(seeds) = rot.seeds.iter().find_map(|b| osis_crypto::open_seeds(&kem, &p, &rot.signing_key, &b.sealed)) else { return Ok(()) };
    for s in seeds {
        keep(tx, &p, &s)?;
    }
    Ok(())
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
        let kem = match super::recipient(tx, m, Role::Admin)?.keys {
            osis_keys::HolderKeys::KeyActor { kem, .. } => kem,
            _ => return Err(Error::Misuse("a device holds no key actor's KEM key")),
        };
        let mut payload: Vec<&Secret32> = vec![seed];
        if adds.contains(&m) {
            payload.extend(held.iter().filter(|s| s.expose() != seed.expose()));
        }
        let sealed = osis_crypto::seal_seeds(&kem, p, &epoch, &payload, &mut *tx.rng).map_err(|_| Error::Misuse("seed box"))?;
        out.push(SeedBox { tag: osis_crypto::seed_tag(seed, &m), sealed });
    }
    out.sort_by_key(|b| b.tag);
    Ok(out)
}
