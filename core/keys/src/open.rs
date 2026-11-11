//! Opening `secrets.0` (spec/crypto.md §4): a holder's boxes with any key it holds, then older
//! epochs through history boxes.

use crate::aspects::{from_schema, observe_secrets};
use crate::epoch::{ActorEpochs, Unchecked};
use crate::names::Names;
use crate::Error;
use osis_base::{Role, Tid};
use osis_crypto::{AccountEpochKeys, BoxForm, BoxSlot, Epoch, KeyActorKeys, Secret32, key_actor_role_secret, open_box, open_history, open_symmetric_box, role_kem};
use osis_schema::core_types::{BoxKey, HistoryKey, Sealed, SecretBox, Secrets};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Who opens: a key actor by its keys, or an actor holder by the role secrets it holds.
pub enum Opener<'a> {
    KeyActor { holder: Tid, keys: &'a KeyActorKeys },
    Actor { holder: Tid, epochs: &'a ActorEpochs },
    /// An account by the epoch keys it holds, by epoch name (spec/crypto.md §3).
    Account { holder: Tid, keys: &'a BTreeMap<Epoch, Arc<AccountEpochKeys>> },
}

impl Opener<'_> {
    pub fn holder(&self) -> Tid {
        match self {
            Opener::KeyActor { holder, .. } | Opener::Actor { holder, .. } | Opener::Account { holder, .. } => *holder,
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

/// Opens every box of `actor`'s `secrets.0` addressed to the opener. Boxes it cannot open (a key
/// it does not hold, bad bytes) are returned with the reason; they are not fatal.
pub fn open_boxes(actor: &Tid, secrets: &Secrets, opener: &Opener) -> (Vec<Opened>, Vec<(BoxKey, Error)>) {
    let holder = opener.holder();
    let mut out = Vec::new();
    let mut failed = Vec::new();
    for (k, b) in secrets.boxes.iter().filter(|(k, _)| k.holder == holder) {
        match open_one(actor, k, b, opener) {
            Ok(Some(o)) => out.push(o),
            Ok(None) => {}
            Err(e) => failed.push((k.clone(), e)),
        }
    }
    (out, failed)
}

/// `Ok(None)`: the opener holds no key for this box.
fn open_one(actor: &Tid, k: &BoxKey, b: &SecretBox, opener: &Opener) -> Result<Option<Opened>, Error> {
    let epoch = from_schema(&k.epoch)?;
    let slot = BoxSlot::Secrets { actor: *actor, holder: k.holder, role: k.role, epoch };
    match b {
        SecretBox::Sealed(sb) => {
            let keyset = sb.keyset.as_ref().map(from_schema).transpose()?;
            let role;
            let kem = match (opener, keyset) {
                (Opener::KeyActor { keys, .. }, None) => &keys.kem,
                (Opener::Actor { epochs, .. }, Some(ks)) => match epochs.role(k.role).secret(&ks) {
                    Some(s) => {
                        role = role_kem(s);
                        &role
                    }
                    None => return Ok(None),
                },
                (Opener::Account { keys, .. }, Some(ks)) => match keys.get(&ks) {
                    Some(e) => &e.kem,
                    None => return Ok(None),
                },
                _ => return Err(Error::Mismatch("sealed form does not fit the holder kind")),
            };
            let Sealed::X25519MlKem768(bytes) = &sb.sealed;
            // osis-crypto checks the item is the key's (role, epoch)
            let i = open_box(kem, &slot, BoxForm::Sealed { keyset, suite: sb.suite }, bytes)?;
            Ok(Some(Opened { role: i.role, epoch: i.epoch, secret: i.secret }))
        }
        SecretBox::Symmetric(sym) => {
            let epoch_s = from_schema(&sym.epoch)?;
            let s = match opener {
                Opener::KeyActor { keys, .. } if epoch_s == Epoch::ZERO => key_actor_role_secret(keys.seed(), k.role),
                Opener::KeyActor { .. } => return Ok(None),
                Opener::Actor { epochs, .. } => match epochs.role(k.role).secret(&epoch_s) {
                    Some(s) => s.clone(),
                    None => return Ok(None),
                },
                Opener::Account { keys, .. } => match keys.get(&epoch_s) {
                    Some(e) => key_actor_role_secret(e.seed(), k.role),
                    None => return Ok(None),
                },
            };
            let secret = open_symmetric_box(&s, &slot, epoch_s, &sym.wrap)?;
            Ok(Some(Opened { role: k.role, epoch, secret }))
        }
    }
}

/// Ciphertexts of the live entries of a history key that holds several (puts by different
/// writers): readers try each, not only the merged read (spec/crypto.md §4).
pub type HistoryAlts = BTreeMap<HistoryKey, Vec<Vec<u8>>>;

/// Opens the history boxes of every epoch whose secret `epochs` holds, repeatedly. Every live
/// entry of a key (`alts`: each live entry of keys with several) is tried, since any writer of
/// the key may put one (spec/crypto.md §4); each secret an entry lists names its own epoch
/// (osis-crypto recomputes it), so a lying entry only names an epoch of its own. The epochs
/// listed are marked superseded by the opening one (counted once it is established), and its
/// names recorded (spec/crypto.md §4: what establishes it once met).
/// `from`: the source when `secrets` is a pending commit's: what its history boxes list is
/// reading-only, and so is what a reading-only secret opens (it inherits that secret's sources);
/// neither supersedes anything.
pub fn open_histories(actor: &Tid, secrets: &Secrets, alts: &HistoryAlts, epochs: &mut ActorEpochs, from: Option<Unchecked>) -> Vec<(HistoryKey, Error)> {
    let mut failed: BTreeMap<HistoryKey, Error> = BTreeMap::new();
    // keys tried, and whether with a secret not reading-only (one that becomes so tries again)
    let mut done: BTreeMap<HistoryKey, bool> = BTreeMap::new();
    loop {
        let mut progress = false;
        for (k, ct) in &secrets.history {
            let Ok(e) = from_schema(&k.epoch) else {
                failed.insert(k.clone(), Error::Mismatch("history epoch"));
                continue;
            };
            let re = epochs.role(k.role);
            let Some(s) = re.reading_secret(&e).cloned() else { continue };
            let sources: Vec<Unchecked> = match from {
                Some(u) => vec![u],
                None => re.reading_sources(&e).into_iter().collect(),
            };
            let checked = sources.is_empty();
            if done.get(k).is_some_and(|was| *was || !checked) {
                continue;
            }
            done.insert(k.clone(), checked);
            progress = true;
            let mut opened_any = false;
            for c in std::iter::once(ct).chain(alts.get(k).into_iter().flatten()) {
                let Ok((earlier, names)) = open_history(&s, actor, k.role, &e, c) else { continue };
                // an entry whose names do not parse opens nothing
                let Some(names) = Names::from_value(&names) else { continue };
                opened_any = true;
                let re = epochs.role_mut(k.role);
                if checked {
                    re.rotation(e, earlier.iter().map(|(x, _)| *x));
                    re.add_names(e, names);
                }
                for (x, sx) in earlier {
                    if checked {
                        re.set_secret(x, sx);
                    } else {
                        for u in &sources {
                            re.set_reading_secret(x, sx.clone(), *u);
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

/// Everything a node learns from `actor`'s `secrets.0`: the epochs named, its boxes' secrets,
/// then older ones by history. Establishes nothing (spec/crypto.md §4): the caller records
/// `SecretsWrite::rotated` per held valid rotation commit and `snapshot_keyed` per held snapshot,
/// and its view establishes (`ActorEpochs::establish`).
/// `unchecked`: `None` when `secrets` is the applied valid state; the source for boxes of a
/// pending commit, whose secrets are kept for reading only (spec/crypto.md §4). Returns what
/// could not be opened.
pub fn ingest(actor: &Tid, secrets: &Secrets, opener: &Opener, epochs: &mut ActorEpochs, unchecked: Option<Unchecked>) -> Result<Vec<Error>, Error> {
    ingest_with(actor, secrets, &HistoryAlts::new(), opener, epochs, unchecked)
}

/// `ingest` trying every live entry of the history keys in `alts`.
pub fn ingest_with(actor: &Tid, secrets: &Secrets, alts: &HistoryAlts, opener: &Opener, epochs: &mut ActorEpochs, unchecked: Option<Unchecked>) -> Result<Vec<Error>, Error> {
    // an unchecked source records no epoch beyond its bounded reading-only secrets
    if unchecked.is_none() {
        observe_secrets(secrets, epochs)?;
    }
    let (opened, failed) = open_boxes(actor, secrets, opener);
    for o in opened {
        let re = epochs.role_mut(o.role);
        match unchecked {
            Some(u) => re.set_reading_secret(o.epoch, o.secret, u),
            None => re.set_secret(o.epoch, o.secret),
        }
    }
    let mut errs: Vec<Error> = failed.into_iter().map(|(_, e)| e).collect();
    errs.extend(open_histories(actor, secrets, alts, epochs, unchecked).into_iter().map(|(_, e)| e));
    Ok(errs)
}
