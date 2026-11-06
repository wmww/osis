//! Departs marks (spec/crypto.md §4, Names): a history entry's departs mark covers only the
//! departures of a rotation commit that is no self-removal. A writer leaving by self-removal
//! (which carries no rotation, spec/permissions.md §3) holds the current epochs' secrets and may
//! put history entries there until it leaves; none of them may cover its own departure, or no
//! node rotates and it keeps reading new content.

#![allow(clippy::unwrap_used)]
use super::tests::{edge, group, newest_read, rotate_leaving_out, send_skipping};
use crate::flows::{Demotion, PreSync};
use crate::Mutation;
use crate::local_peer::LocalPeer;
use osis_base::{Role, Tid, Ts, WallMs};
use osis_crypto::Epoch;
use osis_keys::{Names, Own};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

const A: usize = 0;
const W: usize = 1;
const X: usize = 2;

/// Peers A (owner of `g`), W (a writer), X (an admin), all synced. Returns `g` and the tids.
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
    assert!(!history.is_empty());
    crate::flows::put_secrets(m, g, &osis_keys::SecretsWrite { history, ..Default::default() }, true)
}

/// A mark naming the commit at `ts` by `node`.
fn mark(ts: Ts, node: Tid) -> Names {
    Names { departs: Some(Own { ts: ts.to_u64(), node }), ..Names::default() }
}

/// How the leaver forges.
#[derive(Clone, Copy, Debug)]
enum Forge {
    /// Nothing: a plain self-removal.
    None,
    /// Its self-removal commit puts an entry at the current read epoch naming itself by its mark.
    Same,
    /// An earlier commit (still a writer) puts that entry, naming the self-removal it makes next.
    Earlier,
    /// Its self-removal commit also rotates read and write to fresh epochs boxed to the others,
    /// its names carrying its own mark (it made those secrets).
    Rotating,
    /// Its self-removal commit puts an entry naming the mark of an earlier rotation commit that
    /// departed another holder (`Mark`).
    Replayed(Ts, Tid),
    /// After its self-removal, a commit backdated before it puts an entry listing the
    /// self-removal by its key (not a mark).
    Listed,
}

/// Peer `i` leaves `g` by a self-removal, forging as `how`. Returns the (role, epoch) secrets it
/// held or made (`Rotating`'s are in no record of its own).
fn leave(lp: &mut LocalPeer, i: usize, g: Tid, how: Forge) -> crate::Result<BTreeSet<(Role, Epoch)>> {
    lp.peers[i].engine.run(|tx| {
        let me = tx.core.id.tid();
        let held = tx.core.epochs(&g).unwrap_or_default();
        let mut out: BTreeSet<(Role, Epoch)> = osis_keys::ROLES.into_iter().flat_map(|r| held.role(r).epochs().filter(|(_, x)| x.secret.is_some()).map(move |(e, _)| (r, *e)).collect::<Vec<_>>()).collect();
        let t1 = tx.core.hlc.next();
        let ts = tx.core.hlc.next();
        if let Forge::Earlier = how {
            let mut m = Mutation::new();
            m.ts = Some(t1);
            forged_entry(tx, &mut m, g, &mark(ts, me))?;
            crate::engine::Engine::commit_tx(tx, m)?;
        }
        let mut m = Mutation::new();
        m.ts = Some(ts);
        crate::flows::edges::removal(tx, &mut m, g, me)?;
        match how {
            Forge::Same => forged_entry(tx, &mut m, g, &mark(ts, me))?,
            Forge::Replayed(t, node) => forged_entry(tx, &mut m, g, &mark(t, node))?,
            Forge::Rotating => {
                let holders = super::recipients(tx, &me, &g, &[(me, None)])?.ok_or(super::SEAL_WAITS)?;
                let dep = osis_keys::Departure::holder(me, Role::Read).upto(Role::Write);
                let rot = super::rotation_into(tx, &mut m, g, &[Role::Read, Role::Write].into(), &held, &holders, &[dep])?;
                assert!(rot.names.departs.is_some());
                out.extend(rot.rotated.iter().map(|r| (r.role, r.epoch)));
            }
            Forge::None | Forge::Earlier | Forge::Listed => {}
        }
        m.unchecked();
        // past this node's own refusal (a reader writing `secrets.0`): receivers judge it
        tx.core.skip_writer_rules = true;
        let c = crate::engine::Engine::commit_tx(tx, m);
        tx.core.skip_writer_rules = false;
        let c = c?;
        if let Forge::Listed = how {
            let name = osis_keys::Name { thing: g, key: osis_keys::Key { ts: ts.to_u64(), node: me, commit: c.unwrap() } };
            let mut m = Mutation::new();
            m.ts = Some(t1);
            forged_entry(tx, &mut m, g, &Names { list: [name].into(), departs: None })?;
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

/// `leaver_uncovered` with the leaver holding `role`; `Replayed` names the rotation commit of X's
/// demotion to write by A, made first.
fn leaver_uncovered_as(seed: u64, role: Role, how: Forge) {
    let (mut lp, g, tids) = shape(seed, role);
    let how = match how {
        Forge::Replayed(..) => {
            let c = lp.peers[A].engine.demote(&g, &Demotion { holder: tids[X], new: Some(edge(Role::Write)), presync: PreSync::Synced, retain: None }).unwrap().commits;
            lp.sync_all().unwrap();
            let h = &lp.peers[A].engine.core.ix.commits[&c[0]];
            Forge::Replayed(h.header.ts, h.view.author)
        }
        how => how,
    };
    let w_held: BTreeSet<Epoch> = leave(&mut lp, W, g, how).unwrap().into_iter().filter(|(r, _)| *r == Role::Read).map(|(_, e)| e).collect();
    for pk in lp.packages(W).unwrap() {
        for i in [A, X] {
            let _ = lp.peers[i].engine.ingest(&pk.bytes, pk.blobs.clone());
        }
    }
    for i in [A, X] {
        assert!(lp.peers[i].engine.departures(&g).unwrap().iter().any(|d| d.holder == tids[W]), "peer {i} knows W left ({how:?})");
        if role == Role::Write && matches!(how, Forge::Same | Forge::Earlier | Forge::Replayed(..)) {
            let e = lp.peers[i].engine.epochs(&g).unwrap();
            let forged = |o: &Own| match how {
                Forge::Replayed(t, node) => o.ts == t.to_u64() && o.node == node,
                _ => o.node == tids[W],
            };
            assert!(e.read.epochs().any(|(_, x)| x.names.iter().any(|n| n.departs.is_some_and(|o| forged(&o)))), "peer {i} opened W's entry ({how:?})");
        }
        if let Forge::Listed = how {
            let e = lp.peers[i].engine.epochs(&g).unwrap();
            assert!(e.read.epochs().any(|(_, x)| x.names.iter().any(|n| n.list.iter().any(|m| m.key.node == tids[W]))), "peer {i} opened W's entry ({how:?})");
        }
        assert!(super::tests::blocked_at(&mut lp, i, g).contains(&Role::Read), "peer {i}: W's departure covered ({how:?})");
        lp.peers[i].engine.ensure_rotated(&g).unwrap();
        let now = newest_read(&lp, i, g).unwrap();
        assert!(!w_held.contains(&now), "peer {i} encrypts under {now:?}, which W held ({how:?})");
    }
}

// spec/crypto.md §4 (Names, departs mark): a plain self-removal stays uncovered (the baseline).
#[test]
fn self_removal_uncovered_spec_crypto_4() {
    leaver_uncovered(5_101, Forge::None);
}

// spec/crypto.md §4 (Names, departs mark): W's self-removal puts an entry at the current read
// epoch naming its own mark; that epoch must not cover W's departure.
#[test]
fn self_removal_own_mark_entry_spec_crypto_4() {
    leaver_uncovered(5_102, Forge::Same);
}

// spec/crypto.md §4 (Names, departs mark): the entry comes in W's earlier commit, naming the
// (`ts`, node) its self-removal then takes: a mark is predictable by its author.
#[test]
fn self_removal_predicted_mark_entry_spec_crypto_4() {
    leaver_uncovered(5_103, Forge::Earlier);
}

/// issues/own-departure-named-by-own-entry.md: after its self-removal, W backdates a commit
/// before it putting an entry at the current read epoch that lists the self-removal by its key
/// (a list name, not a mark): the epoch covers W's departure.
#[test]
#[ignore = "issues/own-departure-named-by-own-entry.md"]
fn repro_self_removal_listed_by_backdated_entry() {
    leaver_uncovered(5_108, Forge::Listed);
}

// spec/crypto.md §4 (Names, departs mark), spec/permissions.md §3 (a self-removal carries no
// rotation): W's self-removal rotates to fresh epochs boxed to the others, marked as departing W.
// W made those secrets: they must not cover its departure.
#[test]
fn self_removal_rotating_spec_crypto_4() {
    leaver_uncovered(5_104, Forge::Rotating);
}

// spec/crypto.md §4 (Names, departs mark: only a commit writing a keyset of the actor),
// spec/permissions.md §3 (a removal goes alone while Seal waits): as
// `removal_goes_alone_while_seal_waits_spec_permissions_3`, A forked over M's two keysets, so
// a1's removal of admin a2 carries no rotation. Before it, a2 puts entries at A's current read
// epochs naming the (`ts`, node) a1's removal then takes (a guess; exact here). That removal
// rotates nothing: its mark names no rotation, and A's read rotation stays due at a1.
#[test]
fn guessed_mark_of_removal_alone_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let none = BTreeSet::new();
    let mut lp = LocalPeer::new(5, 964, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let (d, m2, a1, a2) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid(), lp.peers[3].engine.tid(), lp.peers[4].engine.tid());
    let m = group(&mut lp, 0);
    let a = group(&mut lp, 3);
    lp.peers[0].engine.grant(&m, &m2, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&m, &d, &edge(Role::Read)).unwrap();
    lp.peers[3].engine.grant(&a, &a2, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[3].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    rotate_leaving_out(&mut lp, 0, m, &read, &[]);
    lp.peers[2].clock.advance(1_000);
    rotate_leaving_out(&mut lp, 2, m, &read, &[]);
    send_skipping(&mut lp, 0, 3, &none);
    send_skipping(&mut lp, 2, 4, &none);
    lp.peers[3].engine.ensure_rotated(&a).unwrap();
    lp.peers[4].engine.ensure_rotated(&a).unwrap();
    send_skipping(&mut lp, 4, 3, &none);
    send_skipping(&mut lp, 2, 3, &none);
    send_skipping(&mut lp, 3, 4, &none);
    assert_eq!(lp.peers[3].engine.epochs(&a).unwrap().read.current().len(), 2, "A forked over M's two keysets");
    // a2's guess: a1's next `ts` once a2's commit (at `tf`) reached it
    let (w, last) = (lp.peers[3].engine.core.hlc.wall(), lp.peers[3].engine.core.hlc.last());
    let guess = lp.peers[4]
        .engine
        .run(|tx| {
            let tf = tx.core.hlc.next();
            let l = last.max(tf);
            let guess = if w > l.wall_ms() { Ts::make(w, 0) } else { Ts::make(l.wall_ms(), l.logical() + 1) }.unwrap();
            let mut mu = Mutation::new();
            mu.ts = Some(tf);
            forged_entry(tx, &mut mu, a, &mark(guess, a1))?;
            crate::engine::Engine::commit_tx(tx, mu)?;
            Ok(guess)
        })
        .unwrap();
    send_skipping(&mut lp, 4, 3, &none);
    let before = lp.peers[3].engine.epochs(&a).unwrap().read.current();
    assert!(before.iter().all(|e| lp.peers[3].engine.epochs(&a).unwrap().read.get(e).unwrap().names.iter().any(|n| n.departs.is_some())), "a1 opened a2's entries");
    let c = lp.peers[3].engine.demote(&a, &Demotion { holder: a2, new: None, presync: PreSync::Synced, retain: None }).unwrap().commits;
    assert_eq!(c.len(), 1, "the removal is written alone");
    assert_eq!(lp.peers[3].engine.core.ix.commits[&c[0]].header.ts, guess, "a2 guessed the removal's ts");
    assert_eq!(lp.peers[3].engine.epochs(&a).unwrap().read.current(), before, "no rotation of A");
    let (done, still) = lp.peers[3].engine.ensure_rotated(&a).unwrap();
    assert!(done.commits.is_empty() && still.contains(&Role::Read), "a2's departure covered by its guessed mark");
}

// spec/crypto.md §4 (Names, departs mark): W's self-removal puts an entry naming the mark of A's
// earlier rotation commit (X demoted to write): that mark covers only X's departure.
#[test]
fn self_removal_replayed_mark_entry_spec_crypto_4() {
    leaver_uncovered(5_105, Forge::Replayed(Ts::default(), Tid::from_bytes([0; 15])));
}

// spec/permissions.md §3 (a `secrets.0` delta needs write): a reader's self-removal putting an
// entry naming its own mark writes nothing there.
#[test]
fn reader_self_removal_own_mark_entry_spec_crypto_4() {
    leaver_uncovered_as(5_106, Role::Read, Forge::Same);
}

/// Seeds: OSIS_FORGED_DEPARTS_START, OSIS_FORGED_DEPARTS_SEEDS (default 0..200).
#[test]
#[ignore = "tier 2"]
fn forged_departs_leak_nothing_large() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_FORGED_DEPARTS_START", "OSIS_FORGED_DEPARTS_SEEDS", osis_base::testenv::large(0..200));
    let replay = |s: u64| format!("OSIS_FORGED_DEPARTS_START={s} OSIS_FORGED_DEPARTS_SEEDS=1 cargo test -p osis-engine --lib rotation::tests_departs::forged_departs_leak_nothing_large -- --ignored --exact");
    s.run("rotation::tests_departs::forged_departs_leak_nothing_large", replay, forged_departs);
}

// spec/crypto.md §4 (Names, departs mark; Encrypting under): random removals and demotions by
// admins, self-removals (writers forging departs-mark entries as `Forge` says, or not),
// rotations and partial syncs on a group of five peers; then everything synced and the owner
// rotating what is due. The owner encrypts under no epoch that a peer now below its role held or
// made at any point, or opens from the final boxes with what it held. These seeds leak with
// departs marks met by any held commit of that `ts` and author.
#[test]
fn forged_departs_leak_nothing() {
    for seed in [9, 16, 22, 44] {
        forged_departs(seed);
    }
}

fn forged_departs(seed: u64) {
    const N: usize = 5;
    let roles = osis_keys::ROLES;
    let mut rng = super::tests::Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut lp = LocalPeer::new(N, 8_000 + seed, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..N).map(|i| lp.peers[i].engine.tid()).collect();
    let g = group(&mut lp, 0);
    for t in &tids[1..] {
        lp.peers[0].engine.grant(&g, t, &edge(roles[rng.next(3) as usize])).unwrap();
    }
    lp.sync_all().unwrap();
    // every (thing, role, epoch) secret each peer held or made
    let mut ever: Vec<BTreeSet<(Tid, Role, Epoch)>> = vec![BTreeSet::new(); N];
    let note = |lp: &LocalPeer, ever: &mut Vec<BTreeSet<(Tid, Role, Epoch)>>| {
        for (p, set) in ever.iter_mut().enumerate() {
            let Some(e) = lp.peers[p].engine.epochs(&g) else { continue };
            for r in roles {
                set.extend(e.role(r).epochs().filter(|(_, x)| x.secret.is_some()).map(|(x, _)| (g, r, *x)));
            }
        }
    };
    note(&lp, &mut ever);
    for _ in 0..3 + rng.next(3) {
        for i in 0..N {
            let Some(ri) = lp.peers[i].engine.core.role_now(&tids[i], &g) else { continue };
            if rng.next(2) == 0 {
                continue;
            }
            match rng.next(4) {
                0 if ri == Role::Admin => {
                    let j = 1 + rng.next(N as u64 - 1) as usize;
                    let new = (rng.next(2) == 0).then_some(Role::Read);
                    if j != i && lp.peers[i].engine.core.role_now(&tids[j], &g) > new {
                        let _ = lp.peers[i].engine.demote(&g, &Demotion { holder: tids[j], new: new.map(edge), presync: PreSync::Synced, retain: None });
                    }
                }
                1 if i != 0 => {
                    let how = if ri >= Role::Write { [Forge::None, Forge::Same, Forge::Earlier, Forge::Rotating][rng.next(4) as usize] } else { Forge::None };
                    if let Ok(held) = leave(&mut lp, i, g, how) {
                        ever[i].extend(held.into_iter().map(|(r, e)| (g, r, e)));
                    }
                }
                _ if ri >= Role::Write => {
                    let rot: BTreeSet<Role> = roles.into_iter().filter(|r| *r <= ri && rng.next(2) == 0).collect();
                    if !rot.is_empty() {
                        rotate_leaving_out(&mut lp, i, g, &rot, &[]);
                    }
                }
                _ => {}
            }
            note(&lp, &mut ever);
        }
        for _ in 0..3 {
            let (a, b) = (rng.next(N as u64) as usize, rng.next(N as u64) as usize);
            if a != b {
                lp.sync(a, b).unwrap();
            }
        }
        note(&lp, &mut ever);
    }
    lp.sync_all().unwrap();
    note(&lp, &mut ever);
    let Ok((_, blocked)) = lp.peers[0].engine.ensure_rotated(&g) else { return };
    let now = lp.peers[0].engine.epochs(&g).unwrap();
    for d in 1..N {
        let role_d = lp.peers[0].engine.core.key_holders(&g).into_iter().find(|h| h.0 == tids[d]).map(|h| h.1);
        let opens = super::tests::openable(&mut lp, 0, &[g], tids[d], ever[d].clone());
        for r in roles.into_iter().filter(|r| role_d < Some(*r) && !blocked.contains(r)) {
            if let Some(e) = now.role(r).newest() {
                assert!(!opens.contains(&(g, r, e)), "seed {seed}: owner encrypts under {r:?} epoch {e:?}, held by peer {d} (now {role_d:?})");
            }
        }
    }
}

/// issues/own-departure-named-by-own-entry.md: group M holds admin on A; P1, M's owner, holding
/// admin on A only through M, demotes M to write as an explicit demotion (perm judges it one:
/// it has edge-admin authority through M) rotating admin (the role M left) and read (boxing M,
/// which shows M: Authority holds). Its mark names M's departure from admin; P1 made the new
/// admin secret and holds only write after, yet the owner keeps that admin epoch.
#[test]
#[ignore = "issues/own-departure-named-by-own-entry.md"]
fn repro_holder_actor_demoted_by_its_own_admin() {
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
            let holders = super::recipients(tx, &me, &a, &[(m, Some(Role::Write))])?.ok_or(super::SEAL_WAITS)?;
            let dep = osis_keys::Departure::holder(m, Role::Admin).upto(Role::Admin);
            let rot = super::rotation_into(tx, &mut m_, a, &[Role::Read, Role::Admin].into(), &held, &holders, &[dep])?;
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
    lp.peers[0].engine.ensure_rotated(&a).unwrap();
    let now = lp.peers[0].engine.epochs(&a).unwrap().admin.newest_held().map(|x| x.0).unwrap();
    assert!(!made.contains(&now), "owner's admin epoch {now:?} is one P1 made");
}

/// issues/self-removal-through-holder-disagrees.md: group M holds admin on A; P1, M's owner, has
/// admin on A only through M. Its honest removal of M is written as a self-removal (no frontier,
/// no rotation: `validity::self_removal` reads P1's authority with M's edge left out), but the
/// perm judge counts edge-admin authority through M, so it is no self-removal, no finalize either,
/// and applies nothing: M stays.
#[test]
#[ignore = "issues/self-removal-through-holder-disagrees.md"]
fn repro_own_group_removal_applies_nothing() {
    let mut lp = LocalPeer::new(2, 5_109, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let a = group(&mut lp, 0);
    let m = group(&mut lp, 1);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[1].engine.demote(&a, &Demotion { holder: m, new: None, presync: PreSync::Synced, retain: None }).unwrap();
    lp.sync_all().unwrap();
    for i in 0..2 {
        assert!(!lp.peers[i].engine.core.key_holders(&a).iter().any(|h| h.0 == m), "peer {i}: M removed");
    }
}
