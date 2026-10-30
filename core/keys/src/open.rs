//! Opening `/secrets` (spec/crypto.md §4): a member's boxes with any key it holds, then older
//! epochs through history boxes.

use crate::aspects::{from_schema, observe_secrets};
use crate::epoch::{ActorEpochs, Unchecked};
use crate::Error;
use osis_base::{Role, Tid};
use osis_crypto::{BoxForm, BoxSlot, Epoch, KeyActorKeys, KemSecret, Secret32, key_actor_role_secret, open_box, open_history, open_symmetric_box, role_kem};
use osis_schema::core_types::{BoxKey, HistoryKey, Sealed, SecretBox, Secrets};
use std::collections::BTreeMap;

/// Who opens: a key actor by its seed, or an actor member by the role secrets it holds.
pub enum Opener<'a> {
    KeyActor { member: Tid, seed: &'a Secret32 },
    Actor { member: Tid, epochs: &'a ActorEpochs },
}

impl Opener<'_> {
    pub fn member(&self) -> Tid {
        match self {
            Opener::KeyActor { member, .. } | Opener::Actor { member, .. } => *member,
        }
    }
}

/// One role secret recovered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub role: Role,
    pub epoch: Epoch,
    pub secret: Secret32,
}

/// Opens every box of `actor`'s `/secrets` addressed to the opener. Boxes it cannot open (a key
/// it does not hold, bad bytes) are returned with the reason; they are not fatal.
pub fn open_boxes(actor: &Tid, secrets: &Secrets, opener: &Opener) -> (Vec<Opened>, Vec<(BoxKey, Error)>) {
    let member = opener.member();
    let mut kem_cache: Option<KemSecret> = None;
    let mut out = Vec::new();
    let mut failed = Vec::new();
    for (k, b) in secrets.boxes.iter().filter(|(k, _)| k.member == member) {
        match open_one(actor, k, b, opener, &mut kem_cache) {
            Ok(Some(items)) => out.extend(items),
            Ok(None) => {}
            Err(e) => failed.push((k.clone(), e)),
        }
    }
    (out, failed)
}

/// `Ok(None)`: the opener holds no key for this box.
fn open_one(actor: &Tid, k: &BoxKey, b: &SecretBox, opener: &Opener, kem_cache: &mut Option<KemSecret>) -> Result<Option<Vec<Opened>>, Error> {
    let epoch = from_schema(&k.epoch)?;
    let slot = BoxSlot::Secrets { actor: *actor, member: k.member, role: k.role, epoch };
    match b {
        SecretBox::Sealed(sb) => {
            let keyset = sb.keyset.as_ref().map(from_schema).transpose()?;
            let kem = match (opener, keyset) {
                (Opener::KeyActor { seed, .. }, None) => kem_cache.get_or_insert_with(|| KeyActorKeys::from_seed(seed).kem).clone(),
                (Opener::Actor { epochs, .. }, Some(ks)) => match epochs.role(k.role).secret(&ks) {
                    Some(s) => role_kem(s),
                    None => return Ok(None),
                },
                _ => return Err(Error::Mismatch("sealed form does not fit the member kind")),
            };
            let Sealed::X25519MlKem768(bytes) = &sb.sealed;
            let items = open_box(&kem, &slot, BoxForm::Sealed { keyset, suite: sb.suite }, bytes)?;
            let key_actor = keyset.is_none();
            // An actor's box carries its key's (role, epoch) only; a key actor's, one secret per
            // role at or below its key's role, the key's role at the key's epoch.
            let fits = items.iter().any(|i| i.role == k.role && i.epoch == epoch)
                && items.iter().all(|i| i.role <= k.role)
                && (key_actor || items.len() == 1);
            if !fits {
                return Err(Error::Mismatch("box items"));
            }
            Ok(Some(items.into_iter().map(|i| Opened { role: i.role, epoch: i.epoch, secret: i.secret }).collect()))
        }
        SecretBox::Symmetric(sym) => {
            let epoch_s = from_schema(&sym.epoch)?;
            let s = match opener {
                Opener::KeyActor { seed, .. } if epoch_s == Epoch::ZERO => key_actor_role_secret(seed, k.role),
                Opener::KeyActor { .. } => return Ok(None),
                Opener::Actor { epochs, .. } => match epochs.role(k.role).secret(&epoch_s) {
                    Some(s) => s.clone(),
                    None => return Ok(None),
                },
            };
            let secret = open_symmetric_box(&s, &slot, epoch_s, &sym.wrap)?;
            Ok(Some(vec![Opened { role: k.role, epoch, secret }]))
        }
    }
}

/// Ciphertexts of the live entries of a history key that holds several (puts by different
/// writers): readers try each, not only the merged read (spec/crypto.md §4).
pub type HistoryAlts = BTreeMap<HistoryKey, Vec<Vec<u8>>>;

/// Opens the history boxes of every epoch whose secret `epochs` holds, repeatedly. Every live
/// entry of a key (`alts`: each live entry of keys with several) is tried with every secret
/// held for its epoch, since any writer of the key may put one (spec/crypto.md §4): an entry
/// listing a secret its epoch's recorded keyset refutes is a lie and ignored whole; an entry of
/// the bytes the epoch's applied rotation commit wrote (`RoleEpochs::is_rotation_history`)
/// lists checked secrets; from the others each earlier secret is checked against its epoch's
/// keyset when one is recorded and kept as an unverified reading-only candidate when not
/// (`RoleEpochs::learn_unverified`). The epochs listed are marked superseded by the opening one
/// (counted once it is established).
/// `from`: the source when `secrets` is a pending commit's: what its history boxes list is
/// reading-only even when opened with a checked secret (an ex-holder of it can forge them).
pub fn open_histories(actor: &Tid, secrets: &Secrets, alts: &HistoryAlts, epochs: &mut ActorEpochs, from: Option<Unchecked>) -> Vec<(HistoryKey, Error)> {
    let mut failed: BTreeMap<HistoryKey, Error> = BTreeMap::new();
    // (key, secret) pairs tried: a secret learned later for an epoch tries its entries again
    let mut done: BTreeMap<HistoryKey, Vec<Secret32>> = BTreeMap::new();
    loop {
        let mut progress = false;
        for (k, ct) in &secrets.history {
            let Ok(e) = from_schema(&k.epoch) else {
                failed.insert(k.clone(), Error::Mismatch("history epoch"));
                continue;
            };
            let candidates: Vec<Secret32> = epochs.role(k.role).reading_secrets(&e).into_iter().filter(|s| !done.get(k).is_some_and(|d| d.contains(s))).cloned().collect();
            if candidates.is_empty() {
                continue;
            }
            let unchecked = from.is_some() || epochs.role(k.role).is_reading_only(&e);
            progress = true;
            let cts: Vec<&Vec<u8>> = std::iter::once(ct).chain(alts.get(k).into_iter().flatten()).collect();
            let mut opened_any = false;
            for s in &candidates {
                done.entry(k.clone()).or_default().push(s.clone());
                // a reading-only secret's source passes on to what it opens
                let source = from.or_else(|| epochs.role(k.role).reading_source(&e, s));
                for c in &cts {
                    let Ok(earlier) = open_history(s, actor, k.role, &e, c) else { continue };
                    opened_any = true;
                    let re = epochs.role_mut(k.role);
                    if earlier.iter().any(|(x, sx)| re.get(x).and_then(|i| i.derives(x, sx)) == Some(false)) {
                        continue;
                    }
                    // the bytes e's applied rotation commit wrote: checked as that commit is,
                    // whatever secret of e opened them
                    let genuine = from.is_none() && re.is_rotation_history(&e, c);
                    // what an unchecked box lists supersedes nothing; reopened once e is checked
                    if !unchecked || genuine {
                        re.rotation(e, earlier.iter().map(|(x, _)| *x));
                    }
                    for (x, sx) in earlier {
                        match (genuine, unchecked, source) {
                            (true, ..) => re.set_box_secret(x, sx),
                            // what a pending commit's box or its secrets open is reading-only too
                            (false, true, Some(u)) => re.set_reading_secret(x, sx, u),
                            _ => re.learn_unverified(x, sx),
                        }
                    }
                }
            }
            if opened_any {
                failed.remove(k);
            } else if !failed.contains_key(k) {
                failed.insert(k.clone(), Error::Mismatch("history box"));
            }
        }
        if !progress {
            break;
        }
    }
    failed.into_iter().collect()
}

/// Everything a node learns from `actor`'s `/secrets`: the epochs named, its boxes' secrets,
/// then older ones by history. Establishes nothing (spec/crypto.md §4): the caller runs
/// `SecretsWrite::applied` per applied rotation commit and `snapshot_keyed` per held snapshot.
/// `unchecked`: `None` when `secrets` is the applied valid state (its boxes replace
/// reading-only secrets); the source for boxes of a pending commit, whose secrets are kept for
/// reading only and never replace one (spec/crypto.md §4). Returns what could not be opened.
pub fn ingest(actor: &Tid, secrets: &Secrets, opener: &Opener, epochs: &mut ActorEpochs, unchecked: Option<Unchecked>) -> Result<Vec<Error>, Error> {
    ingest_with(actor, secrets, &HistoryAlts::new(), opener, epochs, unchecked)
}

/// `ingest` trying every live entry of the history keys in `alts`.
pub fn ingest_with(actor: &Tid, secrets: &Secrets, alts: &HistoryAlts, opener: &Opener, epochs: &mut ActorEpochs, unchecked: Option<Unchecked>) -> Result<Vec<Error>, Error> {
    // an unchecked source records no epoch beyond its bounded reading-only candidates
    if unchecked.is_none() {
        observe_secrets(secrets, epochs)?;
    }
    let (opened, failed) = open_boxes(actor, secrets, opener);
    for o in opened {
        let re = epochs.role_mut(o.role);
        match unchecked {
            Some(u) => re.set_reading_secret(o.epoch, o.secret, u),
            None => re.set_box_secret(o.epoch, o.secret),
        }
    }
    let mut errs: Vec<Error> = failed.into_iter().map(|(_, e)| e).collect();
    errs.extend(open_histories(actor, secrets, alts, epochs, unchecked).into_iter().map(|(_, e)| e));
    Ok(errs)
}
