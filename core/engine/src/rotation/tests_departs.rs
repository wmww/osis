//! What covers a departure (spec/crypto.md §4, Covers): a rotation commit's own names (bound to
//! it by the digest its keyset publishes) and the departures it makes itself, while its author
//! holds the role. A writer leaving by self-removal (which carries no rotation,
//! spec/permissions.md §3) holds the current epochs' secrets and may put history entries there,
//! backdate commits (it was a writer then) and rotate; none of it may cover its own departure,
//! or no node rotates and it keeps reading new content. Also which write takes a departed holder
//! down (spec/crypto.md §4, Covers) and the self-removal reading (spec/permissions.md §2).

#![allow(clippy::unwrap_used)]
use super::tests::{edge, independent_thing, newest_read, send_skipping, synced};
use crate::flows::Demotion;
use crate::Mutation;
use crate::local_peer::LocalPeer;
use osis_base::{Role, Tid};
use osis_crypto::Epoch;
use osis_keys::{Names, Own};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

const A: usize = 0;
const W: usize = 1;
const X: usize = 2;

/// Peers A (mint admin of `g`), W (a `w_role` holder), X (an admin), all synced (built once per
/// role, a copy each call). Returns `g` and the tids.
fn shape(w_role: Role) -> (LocalPeer, Tid, Vec<Tid>) {
    let (lp, (g, tids)) = LocalPeer::cached(&format!("rotation::tests_departs::shape/{w_role:?}"), || {
        let mut lp = synced(3);
        let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
        let g = independent_thing(&mut lp, A);
        lp.peers[A].engine.grant(&g, &tids[W], &edge(w_role)).unwrap();
        lp.peers[A].engine.grant(&g, &tids[X], &edge(Role::Admin)).unwrap();
        lp.sync_all().unwrap();
        (lp, (g, tids))
    });
    (lp, g, tids)
}

/// Puts into `m` (each as a live entry beside the others) a history entry at each current read
/// epoch of `g` whose secret this node holds, listing nothing and naming `names`.
fn forged_entry(tx: &mut crate::engine::Tx<'_>, m: &mut Mutation, g: Tid, names: &Names) -> crate::Result<()> {
    let held = tx.core.epochs(&g).unwrap();
    let mut history = std::collections::BTreeMap::new();
    for e in held.read.current() {
        let Some(s) = held.read.secret(&e) else { continue };
        let ct = osis_crypto::seal_history(s, &g, Role::Read, &e, &osis_crypto::HistoryEntry { earlier: Vec::new(), names: names.to_value(), floor: 0, roles: Vec::new() }).unwrap();
        history.insert(ct::HistoryKey { role: Role::Read, epoch: ct::Epoch { n: e.n(), nonce: *e.nonce() } }, ct);
    }
    if history.is_empty() {
        return Err(crate::Error::Misuse("no current read secret held"));
    }
    crate::flows::put_secrets(m, g, &osis_keys::SecretsWrite { history, ..Default::default() }, true)
}

/// How the leaver forges.
#[derive(Clone, Copy, Debug)]
pub(super) enum Forge {
    /// Nothing: a plain self-removal.
    None,
    /// Its self-removal commit puts an entry at the current read epoch naming itself by its mark.
    Mark,
    /// After its self-removal, a commit backdated before it puts an entry listing the
    /// self-removal by its key.
    Listed,
    /// Its self-removal commit also rotates read and write to fresh epochs boxed to the others,
    /// its names carrying its own mark (it made those secrets).
    Rotating,
    /// After its self-removal, a commit backdated before it rotates read and write, its names
    /// listing the self-removal by its key (a rotation commit of its own, boxing the others).
    Backdated,
}

/// Peer `i` leaves `g` by a self-removal, forging as `how`. Returns the (role, epoch) secrets it
/// held or made (`Rotating`'s and `Backdated`'s are in no record of its own).
pub(super) fn leave(lp: &mut LocalPeer, i: usize, g: Tid, how: Forge) -> crate::Result<BTreeSet<(Role, Epoch)>> {
    lp.peers[i].engine.run(|tx| {
        let me = tx.core.me();
        let held = tx.core.epochs(&g).unwrap_or_default();
        let mut out: BTreeSet<(Role, Epoch)> = osis_keys::ROLES.into_iter().flat_map(|r| held.role(r).epochs().filter(|(_, x)| x.secret.is_some()).map(move |(e, _)| (r, *e)).collect::<Vec<_>>()).collect();
        let t1 = tx.core.hlc.next();
        let ts = tx.core.hlc.next();
        let mut m = Mutation::new();
        m.ts = Some(ts);
        crate::flows::edges::removal(tx, &mut m, g, me)?;
        match how {
            Forge::Mark => {
                let blind = *m.blind.get_or_insert_with(|| crate::engine::write::draw_blind(&mut *tx.rng));
                forged_entry(tx, &mut m, g, &Names { departs: Some(Own { ts: ts.to_u64(), author: me, blind }), ..Names::default() })?
            }
            Forge::Rotating => {
                let holders = super::recipients(tx, &me, &g, &[(me, None)])?;
                let rot = super::rotation_into(tx, &mut m, g, &[Role::Read, Role::Write].into(), &held, &holders, crate::rotation::Departs::Holder)?;
                assert!(rot.names.departs.is_some());
                out.extend(rot.rotated.iter().map(|r| (r.role, r.epoch)));
            }
            Forge::None | Forge::Listed | Forge::Backdated => {}
        }
        m.unchecked();
        // past this node's own refusal (a reader writing `secrets.0`): receivers judge it
        tx.core.skip_writer_rules = true;
        let c = crate::engine::Engine::commit_tx(tx, m);
        tx.core.skip_writer_rules = false;
        let c = c?;
        if let Forge::Listed | Forge::Backdated = how {
            let mut m = Mutation::new();
            m.ts = Some(t1);
            match how {
                Forge::Listed => {
                    let name = osis_keys::Name::applied(osis_keys::Key { ts: ts.to_u64(), node: me, commit: c.unwrap() }, me);
                    forged_entry(tx, &mut m, g, &Names { list: [name].into(), departs: None })?;
                }
                _ => {
                    // its names list the self-removal: an applied write lowering its edge
                    let holders = super::recipients(tx, &me, &g, &[])?;
                    let rot = super::rotation_into(tx, &mut m, g, &[Role::Read, Role::Write].into(), &held, &holders, crate::rotation::Departs::No)?;
                    if !rot.names.list.iter().any(|n| n.key.commit == c.unwrap()) {
                        return Err(crate::Error::Misuse("the backdated rotation does not name the self-removal"));
                    }
                    out.extend(rot.rotated.iter().map(|r| (r.role, r.epoch)));
                }
            }
            m.unchecked();
            tx.core.skip_writer_rules = true;
            let c = crate::engine::Engine::commit_tx(tx, m);
            tx.core.skip_writer_rules = false;
            c?;
        }
        Ok(out)
    })
}

/// W, holding `role`, leaves as `how`; A and X get everything. Each must see its read role due
/// for rotation, and after `ensure_rotated` encrypt under a read epoch W never held.
fn leaver_uncovered(role: Role, how: Forge) {
    let (mut lp, g, tids) = shape(role);
    let w_held: BTreeSet<Epoch> = leave(&mut lp, W, g, how).unwrap().into_iter().filter(|(r, _)| *r == Role::Read).map(|(_, e)| e).collect();
    for i in [A, X] {
        for pk in lp.packages_for(W, i).unwrap() {
            let _ = lp.peers[i].receive(&pk.bytes, pk.blobs.clone());
        }
    }
    for i in [A, X] {
        assert!(lp.peers[i].engine.departures(&g).unwrap().iter().any(|d| d.holder == tids[W]), "peer {i} knows W left ({role:?} {how:?})");
        if role == Role::Write {
            let e = lp.peers[i].engine.epochs(&g).unwrap();
            let opened = match how {
                Forge::Mark => e.read.epochs().any(|(_, x)| x.names.iter().any(|n| n.departs.is_some_and(|o| o.author == tids[W]))),
                Forge::Listed | Forge::Backdated => e.read.epochs().any(|(_, x)| x.names.iter().any(|n| n.list.iter().any(|m| m.key.node == tids[W]))),
                Forge::None | Forge::Rotating => true,
            };
            assert!(opened, "peer {i} opened W's entry ({role:?} {how:?})");
        }
        assert!(super::tests::blocked_at(&mut lp, i, g).contains(&Role::Read), "peer {i}: W's departure covered ({role:?} {how:?})");
        lp.peers[i].engine.ensure_rotated(&g).unwrap();
        let now = newest_read(&lp, i, g).unwrap();
        assert!(!w_held.contains(&now), "peer {i} encrypts under {now:?}, which W held ({role:?} {how:?})");
    }
}

// spec/crypto.md §4 (covers): a plain self-removal stays uncovered (the baseline). W's
// self-removal by its own writes covers nothing:
// - spec/crypto.md §4 (Covers; Met; Departs mark): it puts an entry at the current read epoch
//   naming its own mark; the mark establishes, never covers.
// - spec/crypto.md §4 (covers: an entry counts only as the rotation commit whose keyset publishes
//   its digest): after it, W backdates a commit before it putting an entry at the current read
//   epoch that lists the self-removal by its key. No keyset commits to the entry.
// - spec/crypto.md §4 (covers: a rotation commit counts while its author holds the role),
//   spec/permissions.md §3 (self-removal; carries no rotation): it rotates to fresh epochs boxed
//   to the others. W made those secrets and holds nothing now.
// - spec/crypto.md §4 (covers: a rotation commit counts while its author holds the role): after
//   it W backdates a rotation commit (valid: a writer then) whose names list the self-removal.
//   Its own commit, bound to its own entry; W holds nothing now.
// - spec/permissions.md §3 (a `secrets.0` delta needs; at least write): a reader's backdated
//   entry listing its self-removal writes nothing there.
#[test]
fn self_removal_uncovered_spec_crypto_4() {
    for how in [Forge::None, Forge::Mark, Forge::Listed, Forge::Rotating, Forge::Backdated] {
        leaver_uncovered(Role::Write, how);
    }
    leaver_uncovered(Role::Read, Forge::Listed);
}

// spec/crypto.md §4 (Holds; Departure; maker; Covers): over grants with key access; the departs mark's author holds r, spec/requirements.md Permissions (a keyless grant gives no read through
// it): W writes G and is mint admin of H; G reads H, then H reads G (closing the cycle:
// keyless). W's self-removal rotates read and write, its departs mark naming itself. W still
// holds read on G through H, but keyless: it reads nothing through it, so its rotation covers
// nothing and it left the epochs it made: A and X rotate before encrypting.
#[test]
fn leaver_through_keyless_grant_spec_crypto_4() {
    let mut lp = synced(3);
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, A);
    lp.peers[A].engine.grant(&g, &tids[W], &edge(Role::Write)).unwrap();
    lp.peers[A].engine.grant(&g, &tids[X], &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let h = independent_thing(&mut lp, W);
    lp.peers[W].engine.grant(&h, &g, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[A].clock.advance(1);
    lp.peers[A].engine.grant(&g, &h, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    assert!(super::members::key_access(&lp.peers[A].engine.core).contains(&(g, h)), "H's grant on G is keyless");
    let w_held: BTreeSet<Epoch> = leave(&mut lp, W, g, Forge::Rotating).unwrap().into_iter().filter(|(r, _)| *r == Role::Read).map(|(_, e)| e).collect();
    lp.sync_all().unwrap();
    for i in [A, X] {
        assert_eq!(lp.peers[i].engine.core.timelines().get(&g).unwrap().role(&tids[W], &g, osis_perm::At::KEYS), Some(Role::Read), "peer {i}: W holds read on G through H (a role all the same)");
        assert!(super::tests::blocked_at(&mut lp, i, g).contains(&Role::Read), "peer {i}: W's departure covered");
        lp.peers[i].engine.ensure_rotated(&g).unwrap();
        let now = newest_read(&lp, i, g).unwrap();
        assert!(!w_held.contains(&now), "peer {i} encrypts under {now:?}, which W held");
    }
}

// spec/crypto.md §4 (Covers; tail): the tail write taking the holder below the role is one that applies; a dropped write lowering it applies nothing and pins nothing. Admin P4 demotes admin P1 to read (K); P1, not knowing,
// self-removes (S); the mint admin, not knowing K, demotes P4 to read (D), whose audit drops K. Admin
// Q holds K and D but not S: P1 is admin again there, and Q's rotation for P4 boxes P1, naming D.
// At the mint admin P1's departure is S's, which Q's epochs do not name: the mint admin rotates.
#[test]
fn dropped_lowering_takes_nothing_spec_crypto_4() {
    let (o, p1, p4, q) = (0, 1, 2, 3);
    let none = BTreeSet::new();
    let mut lp = synced(4);
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, o);
    for t in &tids[1..] {
        lp.peers[o].engine.grant(&g, t, &edge(Role::Admin)).unwrap();
    }
    lp.sync_all().unwrap();
    lp.peers[p4].engine.demote(&g, &Demotion { holder: tids[p1], new: Some(edge(Role::Read)), retain: None }).unwrap();
    let p1_held = leave(&mut lp, p1, g, Forge::None).unwrap();
    lp.peers[o].clock.advance(1_000);
    lp.peers[o].engine.demote(&g, &Demotion { holder: tids[p4], new: Some(edge(Role::Read)), retain: None }).unwrap();
    // Q gets K after D's `ts`
    lp.peers[q].clock.advance(2_000);
    send_skipping(&mut lp, p4, q, &none);
    send_skipping(&mut lp, o, q, &none);
    assert_eq!(lp.peers[q].engine.core.role_now(&tids[p1], &g), Some(Role::Admin), "K dropped at Q: P1 admin again");
    lp.peers[q].engine.ensure_rotated(&g).unwrap();
    let qe = lp.peers[q].engine.epochs(&g).unwrap();
    assert!(qe.write.newest_held().is_some() && qe.admin.newest_held().is_some());
    send_skipping(&mut lp, q, o, &none);
    send_skipping(&mut lp, p4, o, &none);
    send_skipping(&mut lp, p1, o, &none);
    assert!(lp.peers[o].engine.core.role_now(&tids[p1], &g).is_none(), "P1 left");
    let deps = lp.peers[o].engine.departures(&g).unwrap();
    let d = deps.iter().find(|d| d.holder == tids[p1] && d.edge.is_some()).unwrap();
    let last = d.edge.as_ref().and_then(|e| e.writes.iter().rev().find(|w| w.applied));
    assert!(last.is_some_and(|w| w.key.node == tids[p1] && w.role.is_none()), "shown by P1's self-removal: {d:?}");
    lp.peers[o].engine.ensure_rotated(&g).unwrap();
    let now = lp.peers[o].engine.epochs(&g).unwrap();
    let opens = super::tests::openable(&mut lp, o, &[g], tids[p1], p1_held.into_iter().map(|(r, e)| (g, r, e)).collect());
    for r in Role::ALL {
        let e = now.role(r).newest().unwrap();
        assert!(!opens.contains(&(g, r, e)), "mint admin encrypts under {r:?} epoch {e:?}, which P1 opens");
    }
}

// spec/permissions.md §2 (self-removal: authority through the holder does not count),
// spec/crypto.md §4 (covers: a rotation commit counts while its author holds the role): holder M
// holds admin on A; P1, M's mint admin, holds admin on A only through M. P1 demotes M to write in a
// commit carrying a frontier and a rotation of admin and read (boxing M). It applies as a self-removal; P1 made the new admin secret and holds only
// write after, so the mint admin rotates admin again.
#[test]
fn holder_actor_demoted_by_its_own_admin_spec_crypto_4() {
    let mut lp = synced(3);
    let p2 = lp.peers[2].engine.me();
    let a = independent_thing(&mut lp, 0);
    let m = independent_thing(&mut lp, 1);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&a, &p2, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let made = lp.peers[1]
        .engine
        .run(|tx| {
            let held = tx.core.epochs(&a).unwrap();
            let me = tx.core.me();
            let mut m_ = Mutation::new();
            m_.ts = Some(tx.core.hlc.next());
            crate::flows::put_edge(&mut m_, a, m, &edge(Role::Write))?;
            m_.frontier(osis_perm::Frontier::default());
            let holders = super::recipients(tx, &me, &a, &[(m, Some(Role::Write))])?;
            let rot = super::rotation_into(tx, &mut m_, a, &[Role::Read, Role::Admin].into(), &held, &holders, crate::rotation::Departs::Holder)?;
            assert!(rot.names.departs.is_some());
            tx.core.skip_writer_rules = true;
            let c = crate::engine::Engine::commit_tx(tx, m_);
            tx.core.skip_writer_rules = false;
            c?;
            Ok(rot.rotated.iter().filter(|r| r.role == Role::Admin).map(|r| r.epoch).collect::<BTreeSet<Epoch>>())
        })
        .unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[0].engine.core.key_holders(&a).into_iter().find(|h| h.0 == m).map(|h| h.1), Some(Role::Write), "M demoted to write");
    assert!(super::tests::blocked_at(&mut lp, 0, a).contains(&Role::Admin), "M's departure from admin covered by P1's epoch");
    lp.peers[0].engine.ensure_rotated(&a).unwrap();
    let now = lp.peers[0].engine.epochs(&a).unwrap().admin.newest_held().map(|x| x.0).unwrap();
    assert!(!made.contains(&now), "mint admin's admin epoch {now:?} is one P1 made");
}

// spec/permissions.md §2 (self-removal: authority through the holder does not count): holder M
// holds admin on A; P1, M's mint admin, has admin on A only through M. Its removal of M (no frontier,
// no rotation) is a self-removal at every node: it applies. Likewise node N of account U removing
// U's admin grant on A (U's only path to A); N has admin on U and no other authority on A.
#[test]
fn a_mint_admins_removal_of_its_holder_is_a_self_removal_spec_permissions_2() {
    for account in [false, true] {
        let mut lp = synced(2);
        let a = independent_thing(&mut lp, 0);
        let m = if account { lp.peers[1].engine.me() } else { independent_thing(&mut lp, 1) };
        lp.sync_all().unwrap();
        lp.peers[0].engine.grant(&a, &m, &edge(Role::Admin)).unwrap();
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[1].engine.core.role_now(&m, &a), Some(Role::Admin), "account {account}");
        lp.peers[1].engine.demote(&a, &Demotion { holder: m, new: None, retain: None }).unwrap();
        lp.sync_all().unwrap();
        for i in 0..2 {
            assert!(!lp.peers[i].engine.core.key_holders(&a).iter().any(|h| h.0 == m), "peer {i}: removed (account {account})");
        }
    }
}

/// What `x`'s epochs of each role are established and superseded by (spec/crypto.md §4): per
/// epoch, its live history entries' names and what it supersedes; and the role's current epochs.
type Inputs = Vec<(Role, Vec<(Epoch, BTreeSet<Names>, BTreeSet<Epoch>)>, Vec<Epoch>)>;

fn inputs(x: &osis_keys::ActorEpochs) -> Inputs {
    osis_keys::ROLES.into_iter().map(|r| (r, x.role(r).epochs().map(|(e, i)| (*e, i.names.clone(), i.superseded_epochs())).collect(), x.role(r).current())).collect()
}

// spec/crypto.md §4 (Established: some *live* entry; Supersedes: what its history box lists):
// W puts a history entry with names of its own at the current read epoch, unaware A is removing
// it, so the entry's commit is invalid once the removal is held. X applies it before the removal
// (the entry joins, then is stripped), A after (it never joins). Holding the same commits, both
// read the epochs alike: the stripped entry names and supersedes nothing at X.
#[test]
fn stripped_history_entry_leaves_nothing_spec_crypto_4() {
    let (mut lp, g, tids) = shape(Role::Write);
    let removal = lp.peers[A].engine.demote(&g, &Demotion { holder: tids[W], new: None, retain: None }).unwrap().commits;
    assert!(!removal.is_empty());
    lp.advance(1000);
    let name = osis_keys::Name::applied(osis_keys::Key { ts: 1, node: tids[W], commit: osis_base::CommitId([0x5a; 32]) }, tids[W]);
    let odd = Names { list: [name].into(), departs: None };
    let entry = lp.peers[W]
        .engine
        .run(|tx| {
            let mut m = Mutation::new();
            forged_entry(tx, &mut m, g, &odd)?;
            crate::engine::Engine::commit_tx(tx, m)
        })
        .unwrap()
        .unwrap();
    let pk = lp.peers[W].engine.package(&entry).unwrap().unwrap();
    // X: the entry, then the removal; A: the removal (its own), then the entry
    lp.peers[X].receive(&pk.bytes, pk.blobs.clone()).unwrap();
    let opened = lp.peers[X].engine.epochs(&g).unwrap();
    assert!(opened.read.epochs().any(|(_, i)| i.names.contains(&odd)), "X opened W's entry while it was live");
    send_skipping(&mut lp, A, X, &BTreeSet::new());
    lp.peers[A].receive(&pk.bytes, pk.blobs.clone()).unwrap();
    lp.sync(A, X).unwrap();
    lp.sync(X, A).unwrap();
    let (x, a) = (lp.peers[X].engine.epochs(&g).unwrap(), lp.peers[A].engine.epochs(&g).unwrap());
    assert!(!x.read.epochs().any(|(_, i)| i.names.contains(&odd)), "the stripped entry names nothing at X");
    assert_eq!(inputs(&x), inputs(&a), "X and A read the epochs alike");
}

// spec/sync-opens.md §4 (Departed: toward a departed peer a credential counts only at an epoch
// covering every departure), spec/crypto.md §4 (Covers): a sync key's epoch is judged as the sync
// epoch it is. W, a sync holder, is removed: the sync epoch it held covers nothing of its
// departure, the one the removal's rotation made covers it, as does the read epoch W never held.
#[test]
fn a_sync_epoch_covers_a_departure_only_once_rotated_spec_sync_opens_4() {
    let (mut lp, g, tids) = shape(Role::Sync);
    let a = &mut lp.peers[A].engine;
    let s = a.sync_id_of(&g).unwrap().unwrap();
    let sync0 = a.epochs(&g).unwrap().role(Role::Sync).current();
    a.demote(&g, &Demotion { holder: tids[W], new: None, retain: None }).unwrap();
    let after = a.epochs(&g).unwrap();
    let (sync1, read) = (after.role(Role::Sync).current(), after.role(Role::Read).current());
    assert!(sync1 != sync0, "the removal rotated sync");
    for e in &sync0 {
        assert!(!a.covers_departures(&s, *e).unwrap(), "{e:?}, held by W, covers its departure");
    }
    for e in sync1.iter().chain(&read) {
        assert!(a.covers_departures(&s, *e).unwrap(), "{e:?} does not cover W's departure");
    }
}

// spec/permissions.md §2 Self-removal (a removal of an absent grant lowers): W, reading
// `g` only through a holder actor H it administers, removes its own grant on `g`, which it never
// held (the rotation property's forged leave): the path ends at W, the empty path, with no
// frontier and nothing named. Stated as an explicit removal through [H] (H's write grant), it
// would need admin there and apply in no pass of the walk by path, where today's walk applies it.
#[test]
fn a_removal_of_ones_own_absent_grant_states_the_empty_path_spec_permissions_2() {
    let mut lp = synced(3);
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = independent_thing(&mut lp, A);
    let h = independent_thing(&mut lp, A);
    lp.peers[A].engine.grant(&g, &h, &edge(Role::Write)).unwrap();
    lp.peers[A].engine.grant(&h, &tids[W], &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let before = super::tests::commit_ids(&mut lp, W);
    leave(&mut lp, W, g, Forge::None).unwrap();
    let new: Vec<_> = super::tests::commit_ids(&mut lp, W).difference(&before).copied().collect();
    let e = &lp.peers[W].engine;
    let leave = new.iter().filter_map(|id| e.header(id)).find(|hd| hd.kind.is_role()).unwrap();
    let osis_commit::Paths::One(p) = &leave.path else { panic!("one path") };
    assert!(p.things.is_empty() && leave.frontier.is_none(), "{p:?}");
    lp.sync_all().unwrap();
    for i in 0..3 {
        assert_eq!(lp.peers[i].engine.roster(&g).get(&tids[W]), None, "peer {i}");
    }
}
