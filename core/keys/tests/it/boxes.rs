//! Grants, re-seals, history re-writes, box checks and sizes (spec/crypto.md §4, spec/wire.md §7).

use crate::common::*;
use osis_base::Role;
use osis_crypto::{BoxItem, BoxSlot, Secret32, seal_box};
use osis_keys::aspects::{box_key, history_key, to_schema};
use osis_keys::{ActorEpochs, Error, Holder, HolderKeys, Opener, Recipient, ROLES, box_holder, ingest, open_boxes, reseal_missing, reseal_needed, roles_up_to, rotate};
use osis_schema::core_types::{Sealed, SealedBox, SecretBox, Secrets};
use std::collections::BTreeSet;

/// An unchecked source: a pending commit by node `n`.
fn from(n: u8) -> osis_keys::Unchecked {
    osis_keys::Unchecked { author: osis_base::Tid::from_bytes([n; 15]), commit: osis_base::CommitId([n; 32]) }
}

struct Forked {
    a: osis_base::Tid,
    view: ActorEpochs,
    s: Secrets,
    forks: [osis_crypto::Epoch; 2],
    rng: osis_crypto::SeededRng,
}

/// Actor A (mint admin P, symmetric) after its own-secrets switch and a read fork.
fn forked() -> Forked {
    let (a, p) = (tid(1), tid(2));
    let mut g = rng(0);
    let pe = actor_epochs(0x20);
    let admin = admin_rcpt(p, &pe);
    let mut view = ActorEpochs::derived(&pe, &a);
    let mut s = Secrets::default();
    let r1 = rotate(&a, &roles_up_to(Role::Admin), &view, &s, std::slice::from_ref(&admin), &osis_keys::Names::default(), &mut g).unwrap();
    r1.secrets.apply(&mut s);
    view = r1.preview(&view).unwrap();
    let read: BTreeSet<Role> = [Role::Read].into_iter().collect();
    let x = rotate(&a, &read, &view, &s, std::slice::from_ref(&admin), &osis_keys::Names::default(), &mut g).unwrap();
    let y = rotate(&a, &read, &view, &s, std::slice::from_ref(&admin), &osis_keys::Names::default(), &mut g).unwrap();
    x.secrets.apply(&mut s);
    y.secrets.apply(&mut s);
    view = x.preview(&view).unwrap();
    view = y.preview(&view).unwrap();
    Forked { a, view, s, forks: [x.role(Role::Read).unwrap().epoch, y.role(Role::Read).unwrap().epoch], rng: g }
}

impl Forked {
    /// Reader G granted read: G, its epochs, and the state holding its boxes.
    fn grant_reader(&mut self) -> (osis_base::Tid, ActorEpochs, Secrets) {
        let (g, ge) = (tid(5), actor_epochs(0x50));
        let w = box_holder(&self.a, &self.view, &hist(&self.a, &self.view, &self.s), &actor_rcpt(g, Role::Read, &ge), &roles_up_to(Role::Read), &mut self.rng).unwrap().unwrap();
        let mut s = self.s.clone();
        w.apply(&mut s);
        (g, ge, s)
    }
}

// spec/crypto.md §4: a grant writes the grantee's boxes for every granted role at each current
// epoch (forks included) and re-writes those epochs' history boxes unchanged; the grantee then
// reads every earlier epoch.
#[test]
fn grant_boxes_every_current_epoch() {
    let mut f = forked();
    let (g, ge) = (tid(5), actor_epochs(0x50));
    let w = box_holder(&f.a, &f.view, &hist(&f.a, &f.view, &f.s), &actor_rcpt(g, Role::Write, &ge), &roles_up_to(Role::Write), &mut f.rng).unwrap().unwrap();
    let keys: BTreeSet<_> = w.boxes.keys().cloned().collect();
    let (es, ew) = (f.view.sync.newest().unwrap(), f.view.write.newest().unwrap());
    let want: BTreeSet<_> = [box_key(g, Role::Sync, &es), box_key(g, Role::Read, &f.forks[0]), box_key(g, Role::Read, &f.forks[1]), box_key(g, Role::Write, &ew)].into_iter().collect();
    assert_eq!(keys, want);
    for (r, e) in [(Role::Sync, es), (Role::Read, f.forks[0]), (Role::Read, f.forks[1]), (Role::Write, ew)] {
        assert_eq!(w.history[&history_key(r, &e)], f.s.history[&history_key(r, &e)]);
    }
    // removes nothing; supersedes nothing (it writes no keyset)
    assert!(w.removed.is_empty());
    let mut s = f.s.clone();
    w.apply(&mut s);
    let mut gv = ActorEpochs::default();
    assert!(ingest(&f.a, &s, &Opener { holder: g, epochs: &ge }, &mut gv, None).unwrap().is_empty());
    // the boxed epochs and, by history, the older ones
    for (e, s) in f.view.read.held() {
        assert_eq!(gv.read.secret(&e), Some(s), "{e:?}");
    }
    assert!(gv.admin.held().next().is_none());
}

// spec/crypto.md §4: a grantee gets a box per granted role and current epoch (read's forks
// each get one).
#[test]
fn grant_box_per_role_and_epoch() {
    let mut f = forked();
    let (k, ke) = (tid(6), actor_epochs(0x60));
    let w = box_holder(&f.a, &f.view, &hist(&f.a, &f.view, &f.s), &actor_rcpt(k, Role::Write, &ke), &roles_up_to(Role::Admin), &mut f.rng).unwrap().unwrap();
    let ew = f.view.write.newest().unwrap();
    let mut want: Vec<_> = f.view.read.current().iter().map(|e| box_key(k, Role::Read, e)).collect();
    assert_eq!(want.len(), 2, "read forked");
    want.push(box_key(k, Role::Write, &ew));
    want.push(box_key(k, Role::Sync, &f.view.sync.newest().unwrap()));
    want.sort();
    assert_eq!(w.boxes.keys().cloned().collect::<Vec<_>>(), want);
    let mut s = f.s.clone();
    w.apply(&mut s);
    let mut kv = ActorEpochs::default();
    ingest(&f.a, &s, &Opener { holder: k, epochs: &ke }, &mut kv, None).unwrap();
    // Establishment from the state as a snapshot (the grantee's commits elided).
    osis_keys::snapshot_keyed(&s, osis_base::CommitId([1; 32]), &mut kv).unwrap();
    kv.establish(&osis_keys::AllHeld);
    assert_eq!(kv.write.newest_held().map(|x| x.0), Some(ew));
    assert!(f.view.read.current().iter().all(|e| kv.read.secret(e).is_some()), "every read fork held");
    // A writer holding its secrets writes symmetric boxes instead.
    let sym = Recipient { holder: k, role: Role::Read, keys: HolderKeys::from_keys(&keys_of(&ke)).unwrap().with_own(&ke), floor: 0 };
    let w = box_holder(&f.a, &f.view, &hist(&f.a, &f.view, &f.s), &sym, &roles_up_to(Role::Read), &mut f.rng).unwrap().unwrap();
    assert_eq!(w.boxes.len(), 3, "sync and both read forks");
    assert!(w.boxes.values().all(|b| matches!(b, SecretBox::Symmetric(x) if x.wrap.len() == 49)));
    let mut s = f.s.clone();
    w.apply(&mut s);
    let mut kv = ActorEpochs::default();
    ingest(&f.a, &s, &Opener { holder: k, epochs: &ke }, &mut kv, None).unwrap();
    assert!(f.forks.iter().all(|e| kv.read.secret(e).is_some()));
}

// spec/crypto.md §4, spec/permissions.md §3 (re-seal; the other roles keep their epochs): a rotation of one role removes and
// writes boxes of that role only, so a holder's write rotation leaves its boxes at
// both read forks, and the trigger finds nothing to re-seal.
#[test]
fn rotation_keeps_other_roles_boxes() {
    let mut f = forked();
    let (p, pe) = (tid(2), actor_epochs(0x20));
    let admin = Recipient { holder: p, role: Role::Admin, keys: HolderKeys::from_keys(&keys_of(&pe)).unwrap().with_own(&pe), floor: 0 };
    let (k, ke) = (tid(6), actor_epochs(0x60));
    let mut s = f.s.clone();
    box_holder(&f.a, &f.view, &hist(&f.a, &f.view, &s), &actor_rcpt(k, Role::Write, &ke), &roles_up_to(Role::Write), &mut f.rng).unwrap().unwrap().apply(&mut s);
    let rot = rotate(&f.a, &[Role::Write].into_iter().collect(), &f.view, &s, &[admin, actor_rcpt(k, Role::Write, &ke)], &osis_keys::Names::default(), &mut f.rng).unwrap();
    let mut v = f.view.clone();
    rot.secrets.apply(&mut s);
    v = rot.preview(&v).unwrap();
    let mut want: Vec<_> = f.forks.iter().map(|e| box_key(k, Role::Read, e)).collect();
    want.push(box_key(k, Role::Write, &rot.rotated[0].epoch));
    want.push(box_key(k, Role::Sync, &f.view.sync.newest().unwrap()));
    want.sort();
    assert_eq!(s.boxes.keys().filter(|b| b.holder == osis_base::Weak(k)).cloned().collect::<Vec<_>>(), want);
    let holders = [Holder { holder: k, role: Role::Write }];
    assert!(reseal_missing(&f.a, &s, &v, &k, Role::Read).is_empty());
    assert!(reseal_needed(&f.a, &s, &v, &holders).is_empty());
    let mut kv = ActorEpochs::default();
    ingest(&f.a, &s, &Opener { holder: k, epochs: &ke }, &mut kv, None).unwrap();
    assert!(f.forks.iter().all(|e| kv.read.secret(e).is_some()), "both read forks held");
}

// spec/permissions.md §3: a re-seal goes to the holder's newest keyset the node holds.
#[test]
fn reseal_to_newest_keyset() {
    let mut f = forked();
    let m = tid(3);
    let mut me = actor_epochs(0x30);
    for (i, r) in ROLES.into_iter().enumerate() {
        me.role_mut(r).set_history(ep(2, 0x31), BTreeSet::new(), [ep(1, 0x30)], None);
        me.role_mut(r).set_established(ep(2, 0x31), osis_keys::Provenance::Fixed);
        me.role_mut(r).set_secret(ep(2, 0x31), Secret32::from_bytes([0x70 + i as u8; 32]));
    }
    let read: BTreeSet<Role> = [Role::Read].into_iter().collect();
    let w = box_holder(&f.a, &f.view, &hist(&f.a, &f.view, &f.s), &actor_rcpt(m, Role::Read, &me), &read, &mut f.rng).unwrap().unwrap();
    for b in w.boxes.values() {
        let SecretBox::Sealed(b) = b else { panic!() };
        assert_eq!(b.keyset, Some(to_schema(&ep(2, 0x31))));
    }
    // Opening with only the old keyset's secret fails to find a key; the new one opens.
    let mut s = f.s.clone();
    w.apply(&mut s);
    let old = actor_epochs(0x30);
    let (got, _) = open_boxes(&f.a, &s, &Opener { holder: m, epochs: &old });
    assert!(got.is_empty());
    let (got, failed) = open_boxes(&f.a, &s, &Opener { holder: m, epochs: &me });
    assert_eq!((got.len(), failed.len()), (2, 0));
    // No keyset known: nothing is boxed.
    let none = Recipient { holder: m, role: Role::Read, keys: HolderKeys::default(), floor: 0 };
    assert!(box_holder(&f.a, &f.view, &hist(&f.a, &f.view, &f.s), &none, &read, &mut f.rng).unwrap().is_none());
    // A granter holding no current secret of a role cannot grant it.
    let mut stale = f.view.clone();
    stale.read = Default::default();
    assert_eq!(box_holder(&f.a, &stale, &hist(&f.a, &stale, &f.s), &actor_rcpt(m, Role::Read, &me), &read, &mut f.rng).unwrap_err(), Error::NoSecret(Role::Read));
}

// spec/wire.md §7: a box opens only at its own key; its payload must name the key's epoch.
#[test]
fn box_checks() {
    let mut f = forked();
    let (m, me) = (tid(3), actor_epochs(0x30));
    let read: BTreeSet<Role> = [Role::Read].into_iter().collect();
    let w = box_holder(&f.a, &f.view, &hist(&f.a, &f.view, &f.s), &actor_rcpt(m, Role::Read, &me), &read, &mut f.rng).unwrap().unwrap();
    // Moved to another key: decryption fails.
    let (k, b) = w.boxes.iter().next().unwrap();
    let mut moved = Secrets::default();
    let mut k2 = k.clone();
    k2.epoch = to_schema(&ep(9, 9));
    moved.boxes.insert(k2, b.clone());
    let (got, failed) = open_boxes(&f.a, &moved, &Opener { holder: m, epochs: &me });
    assert!(got.is_empty() && matches!(failed[0].1, Error::Crypto(_)));
    // A payload whose secret names another epoch than its key (a lying grant): refused on open.
    let kem = osis_crypto::role_kem(me.read.secret(&ep(1, 0x30)).unwrap());
    let bad = lying_box(&mut f, m, Some((ep(1, 0x30), kem.public())));
    let (got, failed) = open_boxes(&f.a, &bad, &Opener { holder: m, epochs: &me });
    assert!(got.is_empty());
    assert!(matches!(failed[0].1, Error::Crypto(osis_crypto::Error::Malformed(_))), "{:?}", failed[0].1);
    // An item naming its own epoch but not the key's is refused by the sealer.
    let slot = BoxSlot::Secrets { actor: f.a, holder: m, role: Role::Read, epoch: f.forks[0] };
    let other = Secret32::from_bytes([1; 32]);
    let item = BoxItem { role: Role::Read, epoch: osis_crypto::Epoch::derive(&f.a, Role::Read, 7, &other).unwrap(), secret: other };
    assert!(seal_box(kem.public(), &slot, Some(ep(1, 0x30)), &item, &mut f.rng).is_err());
}

/// A sealed box keyed (holder, read, fork 0) of `f` carrying a secret that is not the fork's
/// (built by hand: the sealer refuses it), to the KEM key of `keyset`.
fn lying_box(f: &mut Forked, holder: osis_base::Tid, keyset: Option<(osis_crypto::Epoch, &osis_crypto::KemPublicKey)>) -> Secrets {
    let (ks, pk) = keyset.unwrap();
    let slot = BoxSlot::Secrets { actor: f.a, holder, role: Role::Read, epoch: f.forks[0] };
    let form = osis_crypto::BoxForm::Sealed { keyset: Some(ks), suite: 1 };
    let payload = osis_base::cbor::encode(&osis_base::Value::List(vec![
        osis_base::Value::Int(0),
        osis_base::Value::Int(f.forks[0].n() as i64),
        osis_base::Value::Bytes(vec![0x66; 32]),
    ]));
    let raw = osis_crypto::seal(pk, &slot.ad(form).unwrap(), &payload, &mut f.rng).unwrap();
    let mut s = Secrets::default();
    s.boxes.insert(box_key(holder, Role::Read, &f.forks[0]), SecretBox::Sealed(SealedBox { keyset: Some(to_schema(&ks)), suite: 1, sealed: Sealed::X25519MlKem768(raw) }));
    s
}

// notes/crypto.md, Costs (spec/crypto.md §1, spec/wire.md §7): a sealed box is about 1.2 KB, a
// symmetric one 49 bytes plus its epoch.
#[test]
fn sizes() {
    let mut f = forked();
    let (m, me) = (tid(3), actor_epochs(0x30));
    let w = box_holder(&f.a, &f.view, &hist(&f.a, &f.view, &f.s), &actor_rcpt(m, Role::Read, &me), &roles_up_to(Role::Read), &mut f.rng).unwrap().unwrap();
    for b in w.boxes.values() {
        let enc = osis_base::cbor::encode(&osis_schema::Codec::to_value(b));
        assert!((1200..1300).contains(&enc.len()), "{}", enc.len());
    }
    for (k, b) in f.s.boxes.iter().filter(|(k, _)| k.holder == osis_base::Weak(tid(2))) {
        let enc = osis_base::cbor::encode(&osis_schema::Codec::to_value(b));
        assert!(enc.len() < 180, "{k:?} {}", enc.len());
    }
}

// spec/crypto.md §4: "a secret learned only from a pending or invalid commit is kept for reading
// and never encrypted under until an applied valid box carries it". A pending grant's boxes
// yield reading-only secrets; no encrypting getter returns them, even once the epochs are
// established; the applied valid box makes them checked, and a later pending box changes
// nothing.
#[test]
fn unchecked_boxes_are_reading_only() {
    let mut f = forked();
    let (g, ge, s) = f.grant_reader();
    let mut gv = ActorEpochs::default();
    ingest(&f.a, &s, &Opener { holder: g, epochs: &ge }, &mut gv, Some(from(1))).unwrap();
    for e in f.forks {
        assert_eq!(gv.read.reading_secret(&e), f.view.read.secret(&e));
        assert!(gv.read.secret(&e).is_none() && gv.read.is_reading_only(&e));
        gv.read.set_established(e, osis_keys::Provenance::Rotated);
    }
    assert!(gv.read.newest_held().is_none() && gv.read.newest_secret().is_none() && gv.read.held_established().next().is_none());
    assert_eq!(osis_keys::wrap_epoch(&gv.read), None);
    assert!(gv.read.held_newest_first().len() >= 2, "still tried for reading");
    // the grant applies: checked
    ingest(&f.a, &s, &Opener { holder: g, epochs: &ge }, &mut gv, None).unwrap();
    for e in f.forks {
        assert_eq!(gv.read.secret(&e), f.view.read.secret(&e));
    }
    assert_eq!(gv.read.newest_held().map(|x| x.0), f.view.read.newest());
    // a pending box arriving later changes nothing
    let before = gv.clone();
    ingest(&f.a, &s, &Opener { holder: g, epochs: &ge }, &mut gv, Some(from(2))).unwrap();
    assert_eq!(gv, before);
}

// spec/crypto.md §4: what a reading-only secret opens through history boxes is reading-only too,
// with the same sources, until the applied state carries it.
#[test]
fn reading_only_through_history() {
    let mut f = forked();
    let (g, ge, s) = f.grant_reader();
    let mut gv = ActorEpochs::default();
    ingest(&f.a, &s, &Opener { holder: g, epochs: &ge }, &mut gv, Some(from(2))).unwrap();
    let older: Vec<_> = gv.read.held_newest_first().into_iter().map(|x| x.0).filter(|e| !f.forks.contains(e)).collect();
    assert!(!older.is_empty());
    assert!(older.iter().all(|e| gv.read.is_reading_only(e) && gv.read.reading_sources(e) == [from(2)].into_iter().collect()));
    assert!(f.forks.iter().all(|e| gv.read.get(e).unwrap().supersedes.is_empty()), "supersedes nothing");
    // applied: the history boxes open again with checked secrets
    ingest(&f.a, &s, &Opener { holder: g, epochs: &ge }, &mut gv, None).unwrap();
    assert!(older.iter().all(|e| gv.read.secret(e) == f.view.read.secret(e)));
    // the pending commit goes: nothing it gave is lost
    assert!(!gv.drop_reading_from(&from(2).commit));
}

// spec/crypto.md §4: a box carrying a secret that is not its key's epoch's (a lying grant by an
// may-grant holder, pending or applied) is ignored on sight, before or after the genuine box: the
// genuine secret is held either way.
#[test]
fn lying_box_ignored_in_either_order_spec_crypto_4() {
    let mut f = forked();
    let (g, ge) = (tid(5), actor_epochs(0x50));
    let kem = osis_crypto::role_kem(ge.read.secret(&ep(1, 0x50)).unwrap());
    let lie = lying_box(&mut f, g, Some((ep(1, 0x50), kem.public())));
    let grant = box_holder(&f.a, &f.view, &hist(&f.a, &f.view, &f.s), &actor_rcpt(g, Role::Read, &ge), &roles_up_to(Role::Read), &mut f.rng).unwrap().unwrap();
    let mut s = f.s.clone();
    grant.apply(&mut s);
    let opener = Opener { holder: g, epochs: &ge };
    for unchecked in [None, Some(from(3))] {
        let mut lie_first = ActorEpochs::default();
        ingest(&f.a, &lie, &opener, &mut lie_first, unchecked).unwrap();
        assert!(!lie_first.read.holds_any());
        ingest(&f.a, &s, &opener, &mut lie_first, None).unwrap();
        let mut lie_last = ActorEpochs::default();
        ingest(&f.a, &s, &opener, &mut lie_last, None).unwrap();
        ingest(&f.a, &lie, &opener, &mut lie_last, unchecked).unwrap();
        assert_eq!(lie_first, lie_last);
        assert_eq!(lie_first.read.secret(&f.forks[0]), f.view.read.secret(&f.forks[0]));
    }
}

// spec/crypto.md §4: epochs known only from pending commits are bounded: at most
// `MAX_READING_PER_AUTHOR` per author and `MAX_READING` per role; a second source of one adds
// no epoch; a source commit that applies or is dropped takes its secrets with it.
#[test]
fn reading_epochs_bounded_spec_crypto_4() {
    let a = osis_base::Tid::from_bytes([1; 15]);
    let at = |n: u64, b: u8| {
        let s = Secret32::from_bytes([b; 32]);
        (osis_crypto::Epoch::derive(&a, Role::Read, n, &s).unwrap(), s)
    };
    let mut v = ActorEpochs::default();
    for n in 1..200 {
        let (e, s) = at(n, 3);
        v.read.set_reading_secret(e, s, from(1));
    }
    let count = |v: &ActorEpochs| v.read.held_newest_first().len();
    assert_eq!(count(&v), osis_keys::MAX_READING_PER_AUTHOR);
    // another author's source for a held epoch adds none; a new epoch of its own does
    let (e1, s1) = at(1, 3);
    v.read.set_reading_secret(e1, s1, from(2));
    assert_eq!(count(&v), osis_keys::MAX_READING_PER_AUTHOR);
    let (e9, s9) = at(1, 9);
    v.read.set_reading_secret(e9, s9, from(2));
    assert_eq!(count(&v), osis_keys::MAX_READING_PER_AUTHOR + 1);
    // a total cap over authors
    for n in 10..40u8 {
        for k in 0..64 {
            let (e, s) = at(1000 + k, n);
            v.read.set_reading_secret(e, s, from(n));
        }
    }
    assert_eq!(count(&v), osis_keys::MAX_READING);
    // a source commit goes: an epoch it alone gave goes, one another source gave stays
    assert!(v.drop_reading_from(&from(2).commit));
    assert!(v.read.get(&e9).is_none() && v.read.is_reading_only(&e1));
}

// spec/crypto.md §4: authors whose chain the node does not know share one budget (throwaway
// identities gain nothing).
#[test]
fn unknown_authors_share_one_budget_spec_crypto_4() {
    let a = osis_base::Tid::from_bytes([1; 15]);
    let unknown = |n: u8| osis_keys::Unchecked { author: osis_keys::UNKNOWN_AUTHOR, commit: osis_base::CommitId([n; 32]) };
    let mut v = ActorEpochs::default();
    for n in 0..200u8 {
        let s = Secret32::from_bytes([n; 32]);
        v.read.set_reading_secret(osis_crypto::Epoch::derive(&a, Role::Read, 1, &s).unwrap(), s, unknown(n));
    }
    assert_eq!(v.read.held_newest_first().len(), osis_keys::MAX_READING_PER_AUTHOR);
    // a known author still has its own
    let s = Secret32::from_bytes([0xaa; 32]);
    v.read.set_reading_secret(osis_crypto::Epoch::derive(&a, Role::Read, 1, &s).unwrap(), s, from(7));
    assert_eq!(v.read.held_newest_first().len(), osis_keys::MAX_READING_PER_AUTHOR + 1);
}

// spec/crypto.md §4, spec/permissions.md §2: a history key may hold several live entries (an
// may-grant holder's put next to the genuine one); a newer garbage entry wins the merged read, so
// readers try each entry and still open the older epochs.
#[test]
fn history_alternatives_tried_spec_crypto_4() {
    let mut f = forked();
    let (g, ge, s) = f.grant_reader();
    let older: Vec<_> = f.view.read.held().map(|x| x.0).filter(|e| !f.forks.contains(e)).collect();
    assert!(!older.is_empty());
    let mut bad = s.clone();
    let mut alts = osis_keys::HistoryAlts::new();
    for (k, ct) in bad.history.iter_mut() {
        alts.insert(k.clone(), vec![vec![0x5a; ct.len()], ct.clone()]);
        *ct = vec![0x5a; ct.len()];
    }
    let mut plain = ActorEpochs::default();
    osis_keys::ingest(&f.a, &bad, &Opener { holder: g, epochs: &ge }, &mut plain, None).unwrap();
    assert!(older.iter().all(|e| plain.read.reading_secret(e).is_none()), "the merged read alone hides them");
    let mut gv = ActorEpochs::default();
    osis_keys::ingest_with(&f.a, &bad, &alts, &Opener { holder: g, epochs: &ge }, &mut gv, None).unwrap();
    assert!(older.iter().all(|e| gv.read.secret(e) == f.view.read.secret(e)), "each entry tried");
}

/// `f` granted to a reader G, plus a lying entry next to each fork's genuine history box: put by
/// a may-grant holder of the fork's secret, merged read first, listing a made-up secret at each
/// older n (each names an epoch of its own). Returns G, its epochs, the state, the alternatives,
/// the older epochs and the planted ones.
fn poisoned(f: &mut Forked) -> (osis_base::Tid, ActorEpochs, Secrets, osis_keys::HistoryAlts, Vec<osis_crypto::Epoch>, Vec<osis_crypto::Epoch>) {
    let (g, ge, mut s) = f.grant_reader();
    let older: Vec<_> = f.view.read.held().map(|x| x.0).filter(|e| !f.forks.contains(e)).collect();
    assert!(!older.is_empty());
    let junk = Secret32::from_bytes([0x66; 32]);
    let garbage: Vec<_> = older.iter().map(|e| (osis_crypto::Epoch::derive(&f.a, Role::Read, e.n(), &junk).unwrap(), junk.clone())).collect();
    let mut alts = osis_keys::HistoryAlts::new();
    for e in f.forks {
        let k = history_key(Role::Read, &e);
        let lie = osis_crypto::seal_history(f.view.read.secret(&e).unwrap(), &f.a, Role::Read, &e, &osis_crypto::HistoryEntry { earlier: garbage.to_vec(), names: osis_keys::Names::default().to_value(), floor: 0, roles: Vec::new() }).unwrap();
        let genuine = std::mem::replace(s.history.get_mut(&k).unwrap(), lie.clone());
        alts.insert(k, vec![lie, genuine]);
    }
    let planted = garbage.into_iter().map(|(e, _)| e).collect();
    (g, ge, s, alts, older, planted)
}

// spec/crypto.md §4: a may-grant holder's extra history entry listing made-up secrets cannot
// name the older epochs (each secret names its own), so the genuine entry gives every older
// secret whatever the order of arrival or of the entries; what the lie lists is a planted
// epoch: never established, so never encrypted under or put in a history box.
#[test]
fn history_box_poison_refused_spec_crypto_4() {
    let mut f = forked();
    let (g, ge, s, alts, older, planted) = poisoned(&mut f);
    let opener = Opener { holder: g, epochs: &ge };
    let mut gv = ActorEpochs::default();
    osis_keys::ingest_with(&f.a, &s, &alts, &opener, &mut gv, None).unwrap();
    for e in &older {
        assert_eq!(gv.read.secret(e), f.view.read.secret(e), "{e:?}");
    }
    // the entries in the other order
    let mut swapped = alts.clone();
    swapped.values_mut().for_each(|v| v.reverse());
    let mut s2 = s.clone();
    for (k, v) in &swapped {
        *s2.history.get_mut(k).unwrap() = v[0].clone();
    }
    let mut gv2 = ActorEpochs::default();
    osis_keys::ingest_with(&f.a, &s2, &swapped, &opener, &mut gv2, None).unwrap();
    assert_eq!(gv, gv2);
    // the planted epochs: held, never established, never in a history box
    osis_keys::snapshot_keyed(&s, osis_base::CommitId([1; 32]), &mut gv).unwrap();
    gv.establish(&osis_keys::AllHeld);
    for e in &planted {
        assert!(gv.read.reading_secret(e).is_some() && !gv.read.is_established(e));
    }
    assert!(gv.read.held_established().all(|(e, _)| !planted.contains(&e)));
}

/// KEM decapsulations `f` runs.
fn decaps(f: impl FnOnce()) -> u64 {
    osis_base::costs::take();
    f();
    osis_base::costs::take().into_iter().filter(|c| c.0 == "kem: decapsulate").map(|c| c.2).sum()
}

// spec/crypto.md §4 (Reading-only secrets: a box proves itself by what it opens): a box at an
// epoch whose checked secret the opener's view holds can only give that secret again, so it is
// not opened, nor one whose reading-only secret is known from the same pending commit (read
// again at each retry); a box at an epoch not held, or held for reading from another source or
// none, is, and one that does not open there is reported.
#[test]
fn a_held_epochs_box_is_not_opened_again_spec_crypto_4() {
    let mut f = forked();
    let (g, ge, s) = f.grant_reader();
    let opener = Opener { holder: g, epochs: &ge };
    let boxes = s.boxes.keys().filter(|k| k.holder.0 == g).count() as u64;
    assert!(boxes >= 2);
    // unheld: every box of G opened
    let mut gv = ActorEpochs::default();
    assert_eq!(decaps(|| assert!(ingest(&f.a, &s, &opener, &mut gv, None).unwrap().is_empty())), boxes);
    // held: none opened again, the view unchanged
    let before = gv.clone();
    assert_eq!(decaps(|| assert!(ingest(&f.a, &s, &opener, &mut gv, None).unwrap().is_empty())), 0);
    assert_eq!(decaps(|| assert!(ingest(&f.a, &s, &opener, &mut gv, Some(from(1))).unwrap().is_empty())), 0);
    assert_eq!(gv, before);
    // held for reading only: opened again, and the applied boxes make the secrets checked
    let mut rv = ActorEpochs::default();
    ingest(&f.a, &s, &opener, &mut rv, Some(from(1))).unwrap();
    assert!(rv.read.held().next().is_none());
    let read = rv.clone();
    assert_eq!(decaps(|| assert!(ingest(&f.a, &s, &opener, &mut rv, Some(from(1))).unwrap().is_empty())), 0);
    assert_eq!(rv, read);
    assert_eq!(decaps(|| assert!(ingest(&f.a, &s, &opener, &mut rv, Some(from(2))).unwrap().is_empty())), boxes);
    assert_eq!(decaps(|| assert!(ingest(&f.a, &s, &opener, &mut rv, None).unwrap().is_empty())), boxes);
    assert_eq!(rv, before);
    // a box that does not open at an epoch not held is reported; at one held it is not opened
    let mut bad = s.clone();
    let k = bad.boxes.keys().find(|k| k.holder.0 == g && k.role == Role::Read).unwrap().clone();
    let SecretBox::Sealed(sb) = bad.boxes.get_mut(&k).unwrap() else { panic!("a sealed box") };
    let Sealed::X25519MlKem768(bytes) = &mut sb.sealed;
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let mut fresh = ActorEpochs::default();
    assert_eq!(ingest(&f.a, &bad, &opener, &mut fresh, None).unwrap().len(), 1);
    let e = osis_keys::aspects::from_schema(&k.epoch).unwrap();
    assert!(fresh.read.secret(&e).is_none());
    assert!(ingest(&f.a, &bad, &opener, &mut gv, None).unwrap().is_empty());
    assert_eq!(gv, before);
}

// spec/crypto.md §3: a held role secret's KEM key pair is derived once, kept with the secret:
// opening every box of G three times derives one key pair per keyset they are sealed to, at
// the first open
#[test]
fn opens_derive_each_held_key_pair_once_spec_crypto_3() {
    let mut f = forked();
    let (g, granted, s) = f.grant_reader();
    // G's secrets held afresh: the grant derived the key pairs of `granted`'s
    let mut ge = ActorEpochs::default();
    for r in ROLES {
        for (e, x) in granted.role(r).held() {
            ge.role_mut(r).set_secret(e, x.secret().clone());
        }
    }
    let opener = Opener { holder: g, epochs: &ge };
    let sealed: Vec<_> = s.boxes.iter().filter(|(k, _)| k.holder.0 == g).filter_map(|(k, b)| match b {
        SecretBox::Sealed(sb) => Some((k.role, sb.keyset.clone())),
        _ => None,
    }).collect();
    let keysets: BTreeSet<_> = sealed.iter().cloned().collect();
    assert!(sealed.len() > keysets.len(), "several boxes under one secret");
    osis_base::costs::take();
    for _ in 0..3 {
        let (got, failed) = open_boxes(&f.a, &s, &opener);
        assert!(failed.is_empty());
        assert_eq!(got.len(), sealed.len());
    }
    let counted = |name: &str, c: &[(&str, std::time::Duration, u64)]| c.iter().filter(|x| x.0 == name).map(|x| x.2).sum::<u64>();
    let c = osis_base::costs::take();
    assert_eq!(counted("kem: decapsulate", &c), 3 * sealed.len() as u64);
    assert_eq!(counted("kem: keygen", &c), keysets.len() as u64);
}
