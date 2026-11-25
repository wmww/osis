//! Opening `secrets.0` (spec/crypto.md §4): a holder's boxes with any key it holds, then older
//! epochs through history boxes.

use crate::aspects::{from_schema, observe_secrets};
use crate::epoch::{ActorEpochs, Unchecked};
use crate::names::Names;
use crate::Error;
use osis_base::{Role, Tid};
use osis_crypto::{BoxForm, BoxSlot, Epoch, Secret32, open_box, open_history, open_joint_box, open_symmetric_box, read_open_box, role_kem};
use osis_schema::core_types::{BoxKey, HistoryKey, Sealed, SecretBox, Secrets};
use std::collections::{BTreeMap, BTreeSet};

/// Who opens: a holder by the role secrets it holds.
pub struct Opener<'a> {
    pub holder: Tid,
    pub epochs: &'a ActorEpochs,
}

impl Opener<'_> {
    pub fn holder(&self) -> Tid {
        self.holder
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
    open_boxes_where(actor, secrets, opener, |_| true)
}

/// `open_boxes` over the boxes whose key `try_key` takes.
fn open_boxes_where(actor: &Tid, secrets: &Secrets, opener: &Opener, try_key: impl Fn(&BoxKey) -> bool) -> (Vec<Opened>, Vec<(BoxKey, Error)>) {
    let holder = opener.holder();
    let mut out = Vec::new();
    let mut failed = Vec::new();
    for (k, b) in secrets.boxes.iter().filter(|(k, _)| k.holder.0 == holder && try_key(k)) {
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
    let slot = BoxSlot::Secrets { actor: *actor, holder: k.holder.0, role: k.role, epoch };
    // the open form is the public's alone, and the public's boxes are of it alone (spec/crypto.md
    // §4 Boxes): any other pairing is ignored
    if k.holder.0.is_public() != matches!(b, SecretBox::Open(_)) {
        return Ok(None);
    }
    match b {
        SecretBox::Open(payload) => {
            let i = read_open_box(&slot, payload)?;
            Ok(Some(Opened { role: i.role, epoch: i.epoch, secret: i.secret }))
        }
        SecretBox::Sealed(sb) => {
            let keyset = sb.keyset.as_ref().map(from_schema).transpose()?;
            let role;
            let Some(ks) = keyset else { return Err(Error::Mismatch("a sealed box names no keyset")) };
            let kem = match opener.epochs.role(k.role).secret(&ks) {
                Some(s) => {
                    role = role_kem(s);
                    &role
                }
                None => return Ok(None),
            };
            let Sealed::X25519MlKem768(bytes) = &sb.sealed;
            // osis-crypto checks the item is the key's (role, epoch)
            let i = open_box(kem, &slot, BoxForm::Sealed { keyset, suite: sb.suite }, bytes)?;
            Ok(Some(Opened { role: i.role, epoch: i.epoch, secret: i.secret }))
        }
        SecretBox::Joint(jb) => {
            let keysets: Vec<Epoch> = jb.keysets.iter().map(from_schema).collect::<Result<_, _>>()?;
            let mut roles = Vec::new();
            let mut kems = Vec::new();
            for ks in &keysets {
                match opener.epochs.role(k.role).secret(ks) {
                    Some(s) => roles.push(role_kem(s)),
                    None => return Ok(None),
                }
            }
            kems.extend(roles.iter());
            let Sealed::X25519MlKem768(bytes) = &jb.sealed;
            let i = open_joint_box(&kems, &slot, &keysets, jb.suite, bytes)?;
            Ok(Some(Opened { role: i.role, epoch: i.epoch, secret: i.secret }))
        }
        SecretBox::Symmetric(sym) => {
            let epoch_s = from_schema(&sym.epoch)?;
            let Some(s) = opener.epochs.role(k.role).secret(&epoch_s).cloned() else { return Ok(None) };
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
/// (osis-crypto recomputes it), so a lying entry only names an epoch of its own. What the live
/// entries of a key opened with a secret not reading-only list and name replaces what its epoch
/// had (`RoleEpochs::set_history`: superseded once it is established, established once some
/// entry's names are met, spec/crypto.md §4), so `secrets` must hold every live entry of each
/// history key it holds. A key not opened so leaves its epoch's record alone: the caller first
/// clears the epochs of the keys its read stands for (`clear_history`).
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
            let (mut named, mut listed, mut floor) = (BTreeSet::new(), BTreeSet::new(), None);
            for c in std::iter::once(ct).chain(alts.get(k).into_iter().flatten()) {
                let Ok(h) = open_history(&s, actor, k.role, &e, c) else { continue };
                // an entry whose names do not parse opens nothing
                let Some(names) = Names::from_value(&h.names) else { continue };
                opened_any = true;
                named.insert(names);
                floor = floor.max(Some(h.floor));
                listed.extend(h.earlier.iter().map(|(x, _)| *x));
                let re = epochs.role_mut(k.role);
                for (x, sx) in h.earlier {
                    if checked {
                        re.set_secret(x, sx);
                    } else {
                        for u in &sources {
                            re.set_reading_secret(x, sx.clone(), *u);
                        }
                    }
                }
                // a roles secret opens role parts only; from a pending commit's entry, for opening
                // alone, as a reading-only secret
                for (x, rx) in h.roles {
                    if checked {
                        re.set_roles(x, rx);
                    } else {
                        for u in &sources {
                            re.set_reading_roles(x, rx.clone(), *u);
                        }
                    }
                }
            }
            if checked {
                epochs.role_mut(k.role).set_history(e, named, listed, floor);
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

/// `ingest_with` with no box to open: what the secrets `epochs` holds already learn from
/// `actor`'s `secrets.0` by history (a thing minted with a key, its secrets the minter's alone,
/// boxed to nobody).
pub fn ingest_held(actor: &Tid, secrets: &Secrets, alts: &HistoryAlts, epochs: &mut ActorEpochs, unchecked: Option<Unchecked>) -> Result<Vec<Error>, Error> {
    if unchecked.is_none() {
        observe_secrets(secrets, epochs)?;
    }
    Ok(open_histories(actor, secrets, alts, epochs, unchecked).into_iter().map(|(_, e)| e).collect())
}

/// `ingest` trying every live entry of the history keys in `alts`.
pub fn ingest_with(actor: &Tid, secrets: &Secrets, alts: &HistoryAlts, opener: &Opener, epochs: &mut ActorEpochs, unchecked: Option<Unchecked>) -> Result<Vec<Error>, Error> {
    // an unchecked source records no epoch beyond its bounded reading-only secrets
    if unchecked.is_none() {
        observe_secrets(secrets, epochs)?;
    }
    // Invariant: a box at an epoch whose checked secret `epochs` holds, naming it, is not opened.
    // Opening it could only set that same secret again, a no-op: a `secrets.0` box opens only to
    // a secret naming its key's (role, epoch) (osis-crypto checks the item, or for the symmetric
    // form the secret, against the key, spec/crypto.md §4), and the epoch's nonce is a 32-byte
    // KDF of that secret's roles secret, so a second secret naming it is a KDF collision; given
    // the same secret, `set_secret` keeps it and `set_reading_secret` returns at a checked one.
    // The held secret is checked against the epoch here rather than trusted. What is lost: the open error of a malformed box at such an epoch,
    // which reads nothing (spec/crypto.md §4: a box proves itself by what it opens).
    let held = |k: &BoxKey| {
        from_schema(&k.epoch).is_ok_and(|e| epochs.role(k.role).secret(&e).is_some_and(|s| e.names(actor, k.role, s)))
    };
    let (opened, failed) = open_boxes_where(actor, secrets, opener, |k| !held(k));
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
