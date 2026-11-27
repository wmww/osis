//! Holders across rotations, wrap epochs, supersession read from the commits alone
//! (spec/crypto.md §4, §5; spec/permissions.md §3).

use crate::common::*;
use osis_base::Role;
use osis_crypto::Epoch;
use osis_keys::aspects::box_key;
use osis_keys::{ActorEpochs, Holder, Opener, Recipient, SecretsWrite, box_holder, ingest, reseal_needed, roles_up_to, rotate};
use osis_schema::core_types::Secrets;
use std::collections::BTreeSet;

// spec/permissions.md §3: a grant raced by a read-only rotation (made unaware of it) keeps its
// box at the superseded read epoch only: the re-seal trigger asks for the new one.
#[test]
fn grant_raced_by_read_rotation() {
    let rg = &mut rng(0);
    let (a, p, pe, view, base) = switched(&[], rg);
    let (k, ke) = (tid(6), actor_epochs(0x60));
    let grant = box_holder(&a, &view, &hist(&a, &view, &base), &actor_rcpt(k, Role::Write, &ke), &roles_up_to(Role::Write), &mut *rg).unwrap().unwrap();
    let rot = rotate(&a, &roles(&[Role::Read]), &view, &base, &[admin_rcpt(p, &pe)], &osis_keys::Names::default(), &mut *rg).unwrap();
    let mut s = base.clone();
    grant.apply(&mut s);
    rot.secrets.apply(&mut s);
    let mut v = view.clone();
    v = rot.preview(&v).unwrap();
    let er2 = rot.role(Role::Read).unwrap().epoch;
    let holders = [Holder { holder: k, role: Role::Write }];
    assert_eq!(reseal_needed(&a, &s, &v, &holders), vec![(k, roles(&[Role::Read]))]);
    let w = box_holder(&a, &v, &hist(&a, &v, &s), &actor_rcpt(k, Role::Write, &ke), &roles(&[Role::Read]), &mut *rg).unwrap().unwrap();
    w.apply(&mut s);
    assert!(reseal_needed(&a, &s, &v, &holders).is_empty());
    let mut kv = ActorEpochs::default();
    ingest(&a, &s, &Opener { holder: k, epochs: &ke }, &mut kv, None).unwrap();
    assert!(kv.read.secret(&er2).is_some());
}

// spec/crypto.md §4: a rotation of admin demoting a holder to write removes its admin box
// only; its read and write boxes stay.
#[test]
fn demoted_keeps_lower_roles() {
    let rg = &mut rng(0);
    let (k, ke) = (tid(6), actor_epochs(0x60));
    let (a, p, pe, view, s0) = switched(&[actor_rcpt(k, Role::Admin, &ke)], rg);
    let ea = view.admin.newest().unwrap();
    assert!(s0.boxes.contains_key(&box_key(k, Role::Admin, &ea)));
    let rot = rotate(&a, &roles(&[Role::Admin]), &view, &s0, &[admin_rcpt(p, &pe), actor_rcpt(k, Role::Write, &ke)], &osis_keys::Names::default(), &mut *rg).unwrap();
    let mut s = s0.clone();
    rot.secrets.apply(&mut s);
    let mut v = view.clone();
    v = rot.preview(&v).unwrap();
    let (es, er, ew) = (v.sync.newest().unwrap(), v.read.newest().unwrap(), v.write.newest().unwrap());
    let mut want = vec![box_key(k, Role::Sync, &es), box_key(k, Role::Read, &er), box_key(k, Role::Write, &ew)];
    want.sort();
    assert_eq!(s.boxes.keys().filter(|b| b.holder == osis_base::Weak(k)).cloned().collect::<Vec<_>>(), want);
    let mut kv = ActorEpochs::default();
    ingest(&a, &s, &Opener { holder: k, epochs: &ke }, &mut kv, None).unwrap();
    assert!(kv.read.secret(&er).is_some());
    assert!(kv.write.secret(&ew).is_some());
    assert!(kv.admin.secret(&rot.role(Role::Admin).unwrap().epoch).is_none());
}

// spec/crypto.md §5: a rotation commit wraps under the newest read epoch it supersedes whose
// secret the rotator holds.
#[test]
fn wrap_under_held_superseded() {
    let rg = &mut rng(0);
    let (a, p, pe, mut view, s) = switched(&[], rg);
    let e1 = view.read.newest().unwrap();
    // A fork the rotator knows (its box to P held) but holds no secret of, newer than its own.
    let fork = Epoch::new(e1.n(), [0; 32]).unwrap();
    view.read.set_history(fork, BTreeSet::new(), view.read.get(&e1).unwrap().supersedes.clone(), None);
    view.read.set_established(fork, osis_keys::Provenance::Fixed);
    assert_eq!(view.read.newest(), Some(fork));
    let mut s = s;
    let p_box = s.boxes[&box_key(p, Role::Read, &e1)].clone();
    s.boxes.insert(box_key(p, Role::Read, &fork), p_box);
    let rot = rotate(&a, &roles(&[Role::Read]), &view, &s, &[admin_rcpt(p, &pe)], &osis_keys::Names::default(), &mut *rg).unwrap();
    // it supersedes the epochs its keyset lists and those its history box lists
    let held: BTreeSet<Epoch> = view.read.held_established().map(|x| x.0).collect();
    assert_eq!(rot.role(Role::Read).unwrap().supersedes, held.iter().copied().chain([fork]).collect());
    assert!(held.contains(&e1) && !held.contains(&fork));
    assert_eq!(rot.wrap_epoch(), Some(e1));
}

// spec/crypto.md §4 (Boxes: rotating needs no secret), §5: a rotator holding no
// current read secret (another's epoch superseded its own) lists that epoch, carries the
// secrets it holds in the history box, and wraps under the newest of those.
#[test]
fn wrap_without_current_secret() {
    let rg = &mut rng(0);
    let (a, p, pe, mut view, s) = switched(&[], rg);
    let e1 = view.read.newest().unwrap();
    let ew = Epoch::new(e1.n() + 1, [7; 32]).unwrap();
    view.read.set_history(ew, BTreeSet::new(), [e1], None);
    view.read.set_established(ew, osis_keys::Provenance::Fixed);
    assert_eq!(view.read.newest_held(), None);
    let rot = rotate(&a, &roles(&[Role::Read]), &view, &s, &[admin_rcpt(p, &pe)], &osis_keys::Names::default(), &mut *rg).unwrap();
    assert_eq!(rot.role(Role::Read).unwrap().epoch.n(), ew.n() + 1);
    assert!(rot.role(Role::Read).unwrap().supersedes.contains(&ew) && rot.role(Role::Read).unwrap().supersedes.contains(&e1));
    assert_eq!(rot.wrap_epoch(), Some(e1));
    assert_eq!(rot.preview(&view).unwrap().read.current(), vec![rot.role(Role::Read).unwrap().epoch]);
}

// spec/crypto.md §4: what a rotation supersedes is read from its commit alone, so every node
// holding the same commits agrees on the current epochs, in whatever order they arrived. X and
// Y fork read; Z rotates read unaware of Y. A non-holder applying them in any order counts Y and
// Z current, as do the rotators.
#[test]
fn supersession_independent_of_arrival_order() {
    let rg = &mut rng(0);
    let (a, p, pe, view, s) = switched(&[], rg);
    let holders = [admin_rcpt(p, &pe)];
    let x = rotate(&a, &roles(&[Role::Read]), &view, &s, &holders, &osis_keys::Names::default(), &mut *rg).unwrap();
    let y = rotate(&a, &roles(&[Role::Read]), &view, &s, &holders, &osis_keys::Names::default(), &mut *rg).unwrap();
    let (mut sx, mut vx) = (s.clone(), view.clone());
    x.secrets.apply(&mut sx);
    vx = applied(&x, &vx, 2);
    let z = rotate(&a, &roles(&[Role::Read]), &vx, &sx, &holders, &osis_keys::Names::default(), &mut *rg).unwrap();
    // `switched`'s rotation again (same inputs and randomness: a fresh `rng(0)`)
    let r0 = rotate(&a, &roles_up_to(Role::Admin), &ActorEpochs::derived(&pe, &a), &Secrets::default(), &holders, &osis_keys::Names::default(), &mut rng(0)).unwrap();
    assert_eq!(view.read.newest(), Some(r0.role(Role::Read).unwrap().epoch));
    let commits = [(&x, 2u8), (&y, 3), (&z, 4)];
    let mut want = vec![y.role(Role::Read).unwrap().epoch, z.role(Role::Read).unwrap().epoch];
    want.sort();
    for order in [[0, 1, 2], [1, 0, 2], [1, 2, 0], [2, 1, 0], [0, 2, 1], [2, 0, 1]] {
        let mut v = ActorEpochs::default();
        r0.secrets.applied(&mut v, osis_base::CommitId([1; 32]), &r0.keys).unwrap();
        for i in order {
            let (rot, c) = commits[i];
            rot.secrets.applied(&mut v, osis_base::CommitId([c; 32]), &rot.keys).unwrap();
        }
        assert_eq!(v.read.current(), want, "{order:?}");
    }
    // the rotators' own views agree
    let mut vz = vx.clone();
    vz = z.preview(&vz).unwrap();
    y.secrets.applied(&mut vz, osis_base::CommitId([3; 32]), &y.keys).unwrap();
    assert_eq!(vz.read.current(), want);
}

// spec/crypto.md §4: an epoch first seen in a commit is not established until its rotation commit
// is applied (`Chain`); a grant re-writing a history box establishes nothing; joining writes, a
// later removal wins over an earlier put.
#[test]
fn observe_and_extend() {
    let rg = &mut rng(0);
    let (a, p, pe, view, s) = switched(&[], rg);
    let rot = rotate(&a, &roles(&[Role::Read]), &view, &s, &[admin_rcpt(p, &pe)], &osis_keys::Names::default(), &mut *rg).unwrap();
    let mut v = view.clone();
    rot.secrets.observe(&mut v).unwrap();
    let e2 = rot.role(Role::Read).unwrap().epoch;
    assert!(!v.read.is_current(&e2));
    // The rotated view re-sealing someone at e2: applying that re-seal establishes nothing.
    let mut rv = view.clone();
    rv = rot.preview(&rv).unwrap();
    let mut s2 = s.clone();
    rot.secrets.apply(&mut s2);
    let (k, ke) = (tid(6), actor_epochs(0x60));
    let reseal = osis_keys::box_holder(&a, &rv, &hist(&a, &rv, &s2), &actor_rcpt(k, Role::Read, &ke), &roles(&[Role::Read]), &mut *rg).unwrap().unwrap();
    assert!(!reseal.history.is_empty());
    assert!(!reseal.applied(&mut v, osis_base::CommitId([3; 32]), &osis_keys::KeysWrite::default()).unwrap());
    assert!(!v.read.is_current(&e2));
    assert!(rot.secrets.applied(&mut v, osis_base::CommitId([2; 32]), &rot.keys).unwrap());
    assert_eq!(v.read.current(), vec![e2]);
    assert_eq!(v.read.provenance(&e2), Some(osis_keys::Provenance::Rotated));
    let key = box_key(p, Role::Read, &e2);
    let mut w = rot.secrets.clone();
    w.extend(SecretsWrite { removed: [key.clone()].into(), ..SecretsWrite::default() });
    assert!(!w.boxes.contains_key(&key) && w.removed.contains(&key));
}

/// Boxes and their encoded bytes per role that rotation `rot` writes.
fn boxes_by_role(rot: &osis_keys::Rotation) -> std::collections::BTreeMap<Role, (usize, usize)> {
    use osis_schema::Codec as _;
    let mut out = std::collections::BTreeMap::new();
    for (k, b) in &rot.secrets.boxes {
        let e: &mut (usize, usize) = out.entry(k.role).or_default();
        e.0 += 1;
        e.1 += osis_base::encode(&b.to_value()).len();
    }
    out
}

// spec/permissions.md §3, spec/crypto.md §4 (a rotation writes new boxes for every current holder): counted, not timed: with n readers and n holders of
// only sync besides the admin, removing a sync holder rotates only sync, one box per holder
// (2n + 1); removing a reader rotates sync and read, the sync secret's share every holder's box
// (2n + 1) beside the readers' read boxes (n + 1). At 10n each count is 10x the holders' part:
// linear in the holders, about 1.2 KB a sealed box.
#[test]
fn rotation_boxes_per_role_at_n_and_10n_spec_permissions_3() {
    let mut seen = Vec::new();
    for n in [4usize, 40] {
        let rg = &mut rng(n as u64);
        let mut extra = Vec::new();
        for i in 0..n {
            let b = u8::try_from(3 + 2 * i).unwrap();
            extra.push(actor_rcpt(tid(b), Role::Read, &actor_epochs(b)));
            extra.push(actor_rcpt(tid(b + 1), Role::Sync, &actor_epochs(b + 1)));
        }
        let (a, p, pe, view, s) = switched(&extra, rg);
        let holders: Vec<Recipient> = std::iter::once(admin_rcpt(p, &pe)).chain(extra.iter().cloned()).collect();
        // a sync holder removed: only sync
        let sync_only = rotate(&a, &roles(&[Role::Sync]), &view, &s, &holders[..holders.len() - 1], &osis_keys::Names::default(), &mut *rg).unwrap();
        let by = boxes_by_role(&sync_only);
        assert_eq!(by.keys().copied().collect::<Vec<_>>(), vec![Role::Sync]);
        assert_eq!(by[&Role::Sync].0, 2 * n, "every holder left but the removed one: {by:?}");
        // a reader removed: sync and read
        let readers: Vec<Recipient> = holders.iter().filter(|h| h.holder != tid(3)).cloned().collect();
        let reader = rotate(&a, &roles(&[Role::Sync, Role::Read]), &view, &s, &readers, &osis_keys::Names::default(), &mut *rg).unwrap();
        let by = boxes_by_role(&reader);
        assert_eq!((by[&Role::Sync].0, by[&Role::Read].0), (2 * n, n), "{by:?}");
        let (sb, rb) = (by[&Role::Sync].1, by[&Role::Read].1);
        eprintln!("n {n}: sync-holder removal {} boxes {} B; reader removal sync {} boxes {sb} B, read {} boxes {rb} B (sync share {:.0}%)", 2 * n, boxes_by_role(&sync_only)[&Role::Sync].1, 2 * n, n, 100.0 * sb as f64 / (sb + rb) as f64);
        seen.push((boxes_by_role(&sync_only)[&Role::Sync], by[&Role::Sync], by[&Role::Read]));
    }
    // the holders' part grows 10x: (2n - 1) + admin and n - 1 + admin boxes at each size
    let [(s4, r4s, r4r), (s40, r40s, r40r)] = [seen[0], seen[1]];
    assert_eq!((s40.0 - 1, r40s.0 - 1, r40r.0 - 1), (10 * (s4.0 - 1) + 9, 10 * (r4s.0 - 1) + 9, 10 * (r4r.0 - 1) + 9));
}

// spec/crypto.md §3 (Genesis seed), §4 (History box): a rotation from none carries its first
// admin secret as the genesis seed; a dependent thing's derived view carries
// kdf("sync genesis", g(mint admin), tid), its making independent writes that into its admin
// history box, and an admin granted later opens it; an admin entry without it is a history add.
#[test]
fn admin_history_carries_the_genesis_seed() {
    let rg = &mut rng(0);
    let names = osis_keys::Names::default();
    let (t, p, k, ke) = (tid(7), tid(2), tid(6), actor_epochs(0x60));
    // minted with a key: from none
    let first = rotate(&t, &roles_up_to(Role::Admin), &ActorEpochs::default(), &Secrets::default(), &[], &names, &mut *rg).unwrap();
    let admin1 = first.role(Role::Admin).unwrap();
    assert_eq!(first.genesis.as_ref(), Some(admin1.secret.secret()));
    // dependent on P: derived from P's genesis seed
    let mut pe = actor_epochs(0x20);
    let g = osis_crypto::Secret32::from_bytes([0x33; 32]);
    let pa = pe.admin.newest().unwrap();
    pe.admin.set_genesis(pa, Some(g.clone()));
    let a = tid(1);
    let view = ActorEpochs::derived(&pe, &a);
    let ga = osis_crypto::genesis_seed(&g, &a);
    assert_eq!(view.genesis(), Some(&ga));
    let r = rotate(&a, &roles_up_to(Role::Admin), &view, &Secrets::default(), &[admin_rcpt(p, &pe), actor_rcpt(k, Role::Admin, &ke)], &names, &mut *rg).unwrap();
    assert_eq!(r.genesis.as_ref(), Some(&ga));
    let mut s = Secrets::default();
    r.secrets.apply(&mut s);
    let mut kv = ActorEpochs::default();
    ingest(&a, &s, &Opener { holder: k, epochs: &ke }, &mut kv, None).unwrap();
    assert_eq!(kv.genesis(), Some(&ga), "an admin opens it from the history box");
    // an admin entry carrying none is a history add for a holder of the seed
    let v = applied(&r, &view, 1);
    let ea = v.admin.newest().unwrap();
    let bare = osis_crypto::seal_history(v.admin.secret(&ea).unwrap(), &a, Role::Admin, &ea, &osis_crypto::HistoryEntry { earlier: Vec::new(), names: names.to_value(), floor: 0, roles: Vec::new(), genesis: None }).unwrap();
    let mut s2 = s.clone();
    s2.history.insert(osis_keys::aspects::history_key(Role::Admin, &ea), bare);
    assert!(hist(&a, &v, &s2).get(&(Role::Admin, ea)).is_some_and(osis_keys::HistoryBox::adds));
    assert!(!hist(&a, &v, &s).get(&(Role::Admin, ea)).is_some_and(osis_keys::HistoryBox::adds));
}
