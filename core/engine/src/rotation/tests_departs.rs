//! What covers a departure (spec/crypto.md §4, Covers): a rotation commit's own names (bound to
//! it by the digest its keyset publishes) and the departures it makes itself, while its author
//! holds the role. A writer leaving by self-removal (which carries no rotation,
//! spec/permissions.md §3) holds the current epochs' secrets and may put history entries there,
//! backdate commits (it was a writer then) and rotate; none of it may cover its own departure,
//! or no node rotates and it keeps reading new content. Also the attribution of a departure
//! (spec/crypto.md §4, Attributes) and the self-removal reading (spec/permissions.md §2).

#![allow(clippy::unwrap_used)]
use super::tests::{edge, group, newest_read, send_skipping};
use crate::flows::Demotion;
use crate::Mutation;
use crate::local_peer::LocalPeer;
use osis_base::{Role, Tid, WallMs};
use osis_crypto::Epoch;
use osis_keys::{Names, Own};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

const A: usize = 0;
const W: usize = 1;
const X: usize = 2;

/// Peers A (first admin of `g`), W (a writer), X (an admin), all synced. Returns `g` and the tids.
fn shape(seed: u64, w_role: Role) -> (LocalPeer, Tid, Vec<Tid>) {
    let mut lp = LocalPeer::new(3, seed, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.tid()).collect();
    let g = group(&mut lp, A);
    lp.peers[A].engine.grant(&g, &tids[W], &edge(w_role)).unwrap();
    lp.peers[A].engine.grant(&g, &tids[X], &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    (lp, g, tids)
}

/// Puts into `m` (each as a live entry beside the others) a history entry at each current read
/// epoch of `g` whose secret this node holds, listing nothing and naming `names`.
fn forged_entry(tx: &mut crate::engine::Tx<'_>, m: &mut Mutation, g: Tid, names: &Names) -> crate::Result<()> {
    let held = tx.core.epochs(&g).unwrap();
    let mut history = std::collections::BTreeMap::new();
    for e in held.read.current() {
        let Some(s) = held.read.secret(&e) else { continue };
        let ct = osis_crypto::seal_history(s, &g, Role::Read, &e, &[], &names.to_value()).unwrap();
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
        let me = tx.core.id.tid();
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
                let holders = super::recipients(tx, &me, &g, &[(me, None)])?.ok_or(super::SEAL_WAITS)?;
                let rot = super::rotation_into(tx, &mut m, g, &[Role::Read, Role::Write].into(), &held, &holders, true)?;
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
                    let name = osis_keys::Name { thing: g, key: osis_keys::Key { ts: ts.to_u64(), node: me, commit: c.unwrap() } };
                    forged_entry(tx, &mut m, g, &Names { list: [name].into(), departs: None })?;
                }
                _ => {
                    // its names list the self-removal: the newest lowering write on its edge
                    let holders = super::recipients(tx, &me, &g, &[])?.ok_or(super::SEAL_WAITS)?;
                    let rot = super::rotation_into(tx, &mut m, g, &[Role::Read, Role::Write].into(), &held, &holders, false)?;
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

/// W leaves as `how`; A and X get everything. Each must see its read role due for rotation, and
/// after `ensure_rotated` encrypt under a read epoch W never held.
fn leaver_uncovered(seed: u64, how: Forge) {
    leaver_uncovered_as(seed, Role::Write, how)
}

/// `leaver_uncovered` with the leaver holding `role`.
fn leaver_uncovered_as(seed: u64, role: Role, how: Forge) {
    let (mut lp, g, tids) = shape(seed, role);
    let w_held: BTreeSet<Epoch> = leave(&mut lp, W, g, how).unwrap().into_iter().filter(|(r, _)| *r == Role::Read).map(|(_, e)| e).collect();
    for pk in lp.packages(W).unwrap() {
        for i in [A, X] {
            let _ = lp.peers[i].engine.ingest(&pk.bytes, pk.blobs.clone());
        }
    }
    for i in [A, X] {
        assert!(lp.peers[i].engine.departures(&g).unwrap().iter().any(|d| d.holder == tids[W]), "peer {i} knows W left ({how:?})");
        if role == Role::Write {
            let e = lp.peers[i].engine.epochs(&g).unwrap();
            let opened = match how {
                Forge::Mark => e.read.epochs().any(|(_, x)| x.names.iter().any(|n| n.departs.is_some_and(|o| o.author == tids[W]))),
                Forge::Listed | Forge::Backdated => e.read.epochs().any(|(_, x)| x.names.iter().any(|n| n.list.iter().any(|m| m.key.node == tids[W]))),
                Forge::None | Forge::Rotating => true,
            };
            assert!(opened, "peer {i} opened W's entry ({how:?})");
        }
        assert!(super::tests::blocked_at(&mut lp, i, g).contains(&Role::Read), "peer {i}: W's departure covered ({how:?})");
        lp.peers[i].engine.ensure_rotated(&g).unwrap();
        let now = newest_read(&lp, i, g).unwrap();
        assert!(!w_held.contains(&now), "peer {i} encrypts under {now:?}, which W held ({how:?})");
    }
}

// spec/crypto.md §4 (covers): a plain self-removal stays uncovered (the baseline).
#[test]
fn self_removal_uncovered_spec_crypto_4() {
    leaver_uncovered(5_101, Forge::None);
}

// spec/crypto.md §4 (covers; Met, departs mark): W's self-removal puts an entry at the current
// read epoch naming its own mark; the mark establishes, never covers.
#[test]
fn self_removal_own_mark_entry_spec_crypto_4() {
    leaver_uncovered(5_102, Forge::Mark);
}

// spec/crypto.md §4 (covers: an entry counts only as the rotation commit whose keyset publishes
// its digest): after its self-removal, W backdates a commit before it putting an entry at the
// current read epoch that lists the self-removal by its key. No keyset commits to the entry.
#[test]
fn self_removal_listed_by_backdated_entry_spec_crypto_4() {
    leaver_uncovered(5_108, Forge::Listed);
}

// spec/crypto.md §4 (covers: a rotation commit counts while its author holds the role),
// spec/permissions.md §3 (a self-removal carries no rotation): W's self-removal rotates to fresh
// epochs boxed to the others. W made those secrets and holds nothing now.
#[test]
fn self_removal_rotating_spec_crypto_4() {
    leaver_uncovered(5_104, Forge::Rotating);
}

// spec/crypto.md §4 (covers: a rotation commit counts while its author holds the role): after
// its self-removal W backdates a rotation commit (valid: a writer then) whose names list the
// self-removal. Its own commit, bound to its own entry; W holds nothing now.
#[test]
fn self_removal_backdated_rotation_spec_crypto_4() {
    leaver_uncovered(5_110, Forge::Backdated);
}

// spec/permissions.md §3 (a `secrets.0` delta needs write): a reader's backdated entry listing
// its self-removal writes nothing there.
#[test]
fn reader_self_removal_listed_entry_spec_crypto_4() {
    leaver_uncovered_as(5_106, Role::Read, Forge::Listed);
}

// spec/crypto.md §4 (attributes: a departure goes to the newest commit at whose point the holder
// was lowered for keys; an audit drop that raises it is no event). Admin P4 demotes admin P1 to read (K); P1, not knowing,
// self-removes (S); the first admin, not knowing K, demotes P4 to read (D), whose audit drops K. Admin
// Q holds K and D but not S: P1 is admin again there, and Q's rotation for P4 boxes P1, naming D.
// At the first admin P1's departure is S's, which Q's epochs do not name: the first admin rotates.
#[test]
fn departure_attributed_to_its_lowering_not_a_later_drop_spec_crypto_4() {
    let (o, p1, p4, q) = (0, 1, 2, 3);
    let none = BTreeSet::new();
    let mut lp = LocalPeer::new(4, 1_336, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.tid()).collect();
    let g = group(&mut lp, o);
    for t in &tids[1..] {
        lp.peers[o].engine.grant(&g, t, &edge(Role::Admin)).unwrap();
    }
    lp.sync_all().unwrap();
    lp.peers[p4].engine.demote(&g, &Demotion { holder: tids[p1], new: Some(edge(Role::Read)), retain: None }).unwrap();
    let p1_held = leave(&mut lp, p1, g, Forge::None).unwrap();
    // D is the newest event on P1's edge
    lp.peers[o].clock.advance(1_000);
    lp.peers[o].engine.demote(&g, &Demotion { holder: tids[p4], new: Some(edge(Role::Read)), retain: None }).unwrap();
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
    let d = deps.iter().find(|d| d.holder == tids[p1]).unwrap();
    assert_eq!(d.at.map(|n| n.key.node), Some(tids[p1]), "attributed to P1's self-removal");
    lp.peers[o].engine.ensure_rotated(&g).unwrap();
    let now = lp.peers[o].engine.epochs(&g).unwrap();
    let opens = super::tests::openable(&mut lp, o, &[g], tids[p1], p1_held.into_iter().map(|(r, e)| (g, r, e)).collect());
    for r in [Role::Read, Role::Write, Role::Admin] {
        let e = now.role(r).newest().unwrap();
        assert!(!opens.contains(&(g, r, e)), "first admin encrypts under {r:?} epoch {e:?}, which P1 opens");
    }
}

// spec/permissions.md §2 (self-removal: authority through the holder does not count),
// spec/crypto.md §4 (covers: a rotation commit counts while its author holds the role): group M
// holds admin on A; P1, M's first admin, holds admin on A only through M. P1 demotes M to write in a
// commit carrying a frontier and a rotation of admin and read (boxing M, which shows M:
// Authority holds). It applies as a self-removal; P1 made the new admin secret and holds only
// write after, so the first admin rotates admin again.
#[test]
fn holder_actor_demoted_by_its_own_admin_spec_crypto_4() {
    let mut lp = LocalPeer::new(3, 5_107, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let p2 = lp.peers[2].engine.tid();
    let a = group(&mut lp, 0);
    let m = group(&mut lp, 1);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&a, &p2, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let made = lp.peers[1]
        .engine
        .run(|tx| {
            let held = tx.core.epochs(&a).unwrap();
            let me = tx.core.id.tid();
            let mut m_ = Mutation::new();
            m_.ts = Some(tx.core.hlc.next());
            crate::flows::put_edge(&mut m_, a, m, &edge(Role::Write))?;
            m_.frontier(osis_schema::Codec::to_value(&ct::Frontier::default()));
            let holders = super::recipients(tx, &me, &a, &[(m, Some(Role::Write))])?.ok_or(super::SEAL_WAITS)?;
            let rot = super::rotation_into(tx, &mut m_, a, &[Role::Read, Role::Admin].into(), &held, &holders, true)?;
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
    assert!(!made.contains(&now), "first admin's admin epoch {now:?} is one P1 made");
}

// spec/permissions.md §2 (self-removal: authority through the holder does not count): group M
// holds admin on A; P1, M's first admin, has admin on A only through M. Its removal of M (no frontier,
// no rotation) is a self-removal at every node: it applies.
#[test]
fn own_group_removal_is_a_self_removal_spec_permissions_2() {
    let mut lp = LocalPeer::new(2, 5_109, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let a = group(&mut lp, 0);
    let m = group(&mut lp, 1);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[1].engine.demote(&a, &Demotion { holder: m, new: None, retain: None }).unwrap();
    lp.sync_all().unwrap();
    for i in 0..2 {
        assert!(!lp.peers[i].engine.core.key_holders(&a).iter().any(|h| h.0 == m), "peer {i}: M removed");
    }
}

// spec/permissions.md §2 (self-removal: authority through the holder does not count): node N of
// account U removes U's admin grant on group G (U's only path to G); N has admin on U and no
// other authority on G. A self-removal at every node: it applies without a frontier.
#[test]
fn account_leaving_a_group_it_administers_spec_permissions_2() {
    let mut lp = LocalPeer::new(2, 5_111, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let g = group(&mut lp, 0);
    let u = lp.peers[1].engine.create_person(&[]).unwrap().0.person;
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&g, &u, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(lp.peers[1].engine.core.role_now(&lp.peers[1].engine.tid(), &g), Some(Role::Admin));
    lp.peers[1].engine.demote(&g, &Demotion { holder: u, new: None, retain: None }).unwrap();
    lp.sync_all().unwrap();
    for i in 0..2 {
        assert!(!lp.peers[i].engine.core.key_holders(&g).iter().any(|h| h.0 == u), "peer {i}: U removed");
    }
}
