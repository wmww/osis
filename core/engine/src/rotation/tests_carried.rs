//! Carried demotions (spec/crypto.md §4, Carried demotions; model core/test/tla/rotation
//! Depth0.tla `Travel`, `D0_rm_*_travel*`): a keyset of a holder actor carries the demotions of
//! writers and admins of it and below it that its rotator held, a node holds the keyset only
//! with them, and so a parent's node learns a removal below its holder actor exactly when the
//! keyset that excludes it arrives. Shape: G <- X1 <- .. <- Xd <- {W (write), R (read)}; A
//! administers G and syncs only G, B administers every X and syncs no G. B removes W from Xd and
//! rotates up to X1; W never learns it.
//!
//! Invariant (the requirement as written, spec/requirements.md Permissions; model
//! `NoLeakKnowing`): once A holds a keyset of X1 made knowing W's removal, nothing A writes on G
//! from then on is under an epoch W opens, whatever W writes with what it holds (a rotation of
//! X1 past the knowing keyset, a proof at a keyset nobody holds, a backdated rotation of G).
//! It holds because A holds the removal with the keyset, so every commit of W on X1 or G that
//! the removal's frontier does not list is invalid at A (spec/permissions.md §5.2), backdated
//! ones too.

#![allow(clippy::unwrap_used)]
use super::tests::{commit_ids, edge, group, held_by, newest_read, openable, synced};
use crate::Mutation;
use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use osis_base::{CommitId, Role, Tid, Ts, WallMs};
use osis_crypto::{Epoch, Secret32};
use osis_keys::{HolderKeys, Recipient};
use std::collections::BTreeSet;

const A: usize = 0;
const B: usize = 1;
const W: usize = 2;
const R: usize = 3;

type Key = (Tid, Role, Epoch);

struct Shape {
    lp: LocalPeer,
    g: Tid,
    /// X1 (holding write on G) first, Xd (holding W and R) last; each Xi+1 holds write on Xi.
    xs: Vec<Tid>,
}

impl Shape {
    fn x1(&self) -> Tid {
        self.xs[0]
    }
    fn xd(&self) -> Tid {
        *self.xs.last().unwrap()
    }
    fn all(&self) -> Vec<Tid> {
        std::iter::once(self.g).chain(self.xs.iter().copied()).collect()
    }
    fn me(&self, i: usize) -> Tid {
        self.lp.peers[i].engine.me()
    }
}

/// The shape at depth `d` (`d` holder actors between G and W), all synced (built once, a copy
/// each call).
fn shape(d: usize) -> Shape {
    let (lp, (g, xs)) = LocalPeer::cached(&format!("rotation::tests_carried::shape/{d}"), || {
        let mut lp = synced(4);
        let (w, r) = (lp.peers[W].engine.me(), lp.peers[R].engine.me());
        let mut xs: Vec<Tid> = (0..d).map(|_| group(&mut lp, B)).collect();
        lp.sync_all().unwrap();
        let xd = *xs.last().unwrap();
        lp.peers[B].engine.grant(&xd, &w, &edge(Role::Write)).unwrap();
        lp.peers[B].engine.grant(&xd, &r, &edge(Role::Read)).unwrap();
        for i in (0..d - 1).rev() {
            lp.peers[B].engine.grant(&xs[i], &xs[i + 1], &edge(Role::Write)).unwrap();
        }
        lp.sync_all().unwrap();
        let g = group(&mut lp, A);
        lp.peers[A].engine.grant(&g, &xs[0], &edge(Role::Write)).unwrap();
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[W].engine.core.role_now(&w, &g), Some(Role::Write));
        assert!(held_by(&lp, W, &[g]).contains(&(g, Role::Read, newest_read(&lp, A, g).unwrap())), "W reads G");
        xs.shrink_to_fit();
        (lp, (g, xs))
    });
    Shape { lp, g, xs }
}

/// Delivers parts `parts` of commit `c` of peer `from` to peer `to`, and what a verifier needs
/// beside them as `from` judges it (`Engine::author_chain`: for a `keys.0` part, the demotions
/// its keysets carry), each projected to the parts listed: a certificate, as a node placing
/// `c`'s keyset under a label of G places it.
fn deliver_certified(lp: &mut LocalPeer, from: usize, to: usize, c: CommitId, parts: BTreeSet<usize>) {
    deliver_certified_in(lp, from, to, c, parts, None);
}

/// `deliver_certified`, shuffled by `order` when given (any arrival order: a keyset arriving
/// before what it carries is held once that comes).
fn deliver_certified_in(lp: &mut LocalPeer, from: usize, to: usize, c: CommitId, parts: BTreeSet<usize>, order: Option<&mut super::tests::Rng>) {
    let chain = lp.peers[from].engine.author_chain(&c, &parts).unwrap();
    let mut send: Vec<(CommitId, BTreeSet<usize>)> = chain.commits.into_iter().collect();
    send.push((c, parts));
    let pks = lp.packages(from).unwrap();
    // (the projected bytes, its package)
    let mut cuts: Vec<(Vec<u8>, usize)> = Vec::new();
    for (i, pk) in pks.iter().enumerate() {
        for (x, keep) in send.iter().filter(|(x, _)| *x == pk.id) {
            let b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
            let cut = osis_commit::rewrite(&b, |ai| !keep.contains(&ai));
            assert_eq!(cut.header.id(), *x);
            cuts.push((cut.encode(), i));
        }
    }
    if let Some(rng) = order {
        for k in (1..cuts.len()).rev() {
            cuts.swap(k, rng.next(k as u64 + 1) as usize);
        }
    }
    // twice: a part whose chain came after it is taken the second time
    for _ in 0..2 {
        for (bytes, i) in &cuts {
            let _ = lp.peers[to].receive(bytes, pks[*i].blobs.clone());
        }
    }
}

/// The `keys.0` part of commit `c` on `t` at peer `i`.
fn keys_part(lp: &LocalPeer, i: usize, c: &CommitId, t: Tid) -> BTreeSet<usize> {
    let m = lp.peers[i].engine.core.ix.commits.get(c).unwrap();
    m.view.aspects.iter().enumerate().filter(|(_, a)| a.tid == t && a.ak.as_str() == "keys.0").map(|(ai, _)| ai).collect()
}

/// What B's removal of `who` from Xd made.
struct Removal {
    /// The removal commit (with Xd's rotation).
    rm: CommitId,
    /// B's rotation of X1 (knowing the removal).
    x1_rot: CommitId,
    /// The secrets W held before.
    start: BTreeSet<Key>,
}

/// How B's rotation of X1 carries the removal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Carry {
    /// As B's engine writes it.
    Honest,
    /// Carrying nothing, and placed at A alone (planted fault: the model's `Travel = FALSE`).
    Nothing,
}

/// B removes `who` (W or R) from Xd, then rotates every X up to X1 (each box to the one below
/// stale); W gets all of B's commits but the removal; A gets X1's rotation as a certificate with
/// what travels with it (`deliver_certified`), or alone for `Carry::Nothing`.
fn removed(s: &mut Shape, who: usize, carry: Carry) -> Removal {
    removed_with(s, who, carry, 0, Some(None))
}

/// `removed`, with `again` more rotations of X1 by B after the knowing one (each as `carry`
/// says), A getting the newest as a certificate in the order `order` draws (`Some(None)`: as
/// made), or bare (`None`, as for `Carry::Nothing`: the keyset alone, its carried commits not).
fn removed_with(s: &mut Shape, who: usize, carry: Carry, again: usize, order: Option<Option<&mut super::tests::Rng>>) -> Removal {
    let start = held_by(&s.lp, W, &s.all());
    let (x, xd, x1) = (s.me(who), s.xd(), s.x1());
    // later than every grant by more than the backdating (`Attack::Backdated`)
    s.lp.advance(1000);
    let before = commit_ids(&mut s.lp, B);
    s.lp.peers[B].engine.demote(&xd, &Demotion { holder: x, new: None, retain: None }).unwrap();
    let rm = *commit_ids(&mut s.lp, B).difference(&before).next().unwrap();
    // up to X2 as B's engine does it, then X1 as `carry` says
    for i in (1..s.xs.len()).rev() {
        s.lp.peers[B].engine.ensure_rotated(&s.xs[i]).unwrap();
    }
    let b = s.me(B);
    let roles: BTreeSet<Role> = if who == W { [Role::Read, Role::Write].into() } else { [Role::Read].into() };
    let mut x1_rot = None;
    for _ in 0..=again {
    let before = commit_ids(&mut s.lp, B);
    match carry {
        Carry::Honest => {
            s.lp.peers[B].engine.run(|tx| super::rotate_now(tx, b, x1, &roles)).unwrap();
        }
        Carry::Nothing => {
            s.lp.peers[B]
                .engine
                .run(|tx| {
                    let held = tx.core.epochs(&x1).unwrap();
                    let holders = super::recipients(tx, &b, &x1, &[])?;
                    let secrets = crate::flows::secrets_in(tx, &x1)?;
                    let names = super::departures::names(tx.core, &x1, None);
                    let rot = osis_keys::rotate_leaving_out(&x1, &roles, &held, &secrets, &holders.holders, &holders.left_out, &osis_keys::Carried::default(), &names, &mut *tx.rng).unwrap();
                    let mut m = Mutation::new();
                    crate::flows::put_secrets(&mut m, x1, &rot.secrets, false)?;
                    crate::flows::put_keysets(&mut m, x1, &rot.keys)?;
                    crate::engine::Engine::commit_tx(tx, m)?;
                    super::record(tx, x1, &rot)
                })
                .unwrap();
        }
    }
    x1_rot = Some(*commit_ids(&mut s.lp, B).difference(&before).next().unwrap());
    }
    let x1_rot = x1_rot.unwrap();
    let carried: BTreeSet<CommitId> = s.lp.peers[B].engine.core.keysets_of(&x1).flat_map(|(_, _, k)| k.demotions.iter().copied()).collect();
    assert_eq!(carried.contains(&rm), carry == Carry::Honest && who == W, "X1's keysets carry a writer's removal, never a reader's");
    super::tests::send_skipping(&mut s.lp, B, W, &BTreeSet::from([rm]));
    let parts = keys_part(&s.lp, B, &x1_rot, x1);
    match order.filter(|_| carry == Carry::Honest) {
        Some(order) => deliver_certified_in(&mut s.lp, B, A, x1_rot, parts, order),
        None => {
            for pk in s.lp.packages(B).unwrap().into_iter().filter(|p| p.id == x1_rot) {
                let b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
                s.lp.peers[A].receive(&osis_commit::rewrite(&b, |ai| !parts.contains(&ai)).encode(), pk.blobs).unwrap();
            }
        }
    }
    Removal { rm, x1_rot, start }
}

/// How W, removed where it does not know it, acts on G.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Attack {
    /// Rotates G sealing X1 at the knowing keyset, which it cannot open (sealed to its KEM key).
    Plain,
    /// Rotates X1 itself past the knowing keyset (listing it), then G sealing X1 there.
    Rogue,
    /// Rotates G boxing X1 at a keyset of X1 nobody holds.
    MadeUp,
    /// Rotates G stamped before the removal, sealing X1 at the knowing keyset.
    Backdated,
    /// Re-seals X1 at G's current epochs (which it holds) at the knowing keyset, over the stale
    /// boxes: no rotation, so A would find those epochs fresh.
    Reseal,
}

const ATTACKS: [Attack; 5] = [Attack::Plain, Attack::Rogue, Attack::MadeUp, Attack::Backdated, Attack::Reseal];

/// W rotates `a`'s read and write as a party removed where it does not know it may: boxing every
/// holder its engine would, holder actor `m` at `to` (its keyset) instead, signed past its own
/// writer rules, stamped `ts` when given. The commit and the epochs it made.
fn forged(s: &mut Shape, a: Tid, m: Tid, to: Option<(Epoch, osis_crypto::KemPublicKey)>, ts: Option<Ts>) -> (CommitId, BTreeSet<Key>) {
    let w = s.me(W);
    let before = commit_ids(&mut s.lp, W);
    let made = s.lp.peers[W]
        .engine
        .run(|tx| {
            let held = tx.core.epochs(&a).unwrap();
            let secrets = crate::flows::secrets_in(tx, &a)?;
            let mut holders = super::recipients(tx, &w, &a, &[])?.holders;
            if let Some((k, kem)) = &to {
                holders.retain(|h| h.holder != m);
                holders.push(Recipient { holder: m, role: Role::Write, keys: HolderKeys::Actor { keysets: [Role::Read, Role::Write].into_iter().map(|r| (r, vec![(*k, kem.clone())])).collect(), own: Default::default() } });
            }
            let names = super::departures::names(tx.core, &a, None);
            let roles = BTreeSet::from([Role::Read, Role::Write]);
            let rot = osis_keys::rotate(&a, &roles, &held, &secrets, &holders, &names, &mut *tx.rng).unwrap();
            let mut mu = Mutation::new();
            mu.ts = ts;
            mu.unchecked();
            crate::flows::put_secrets(&mut mu, a, &rot.secrets, false)?;
            crate::flows::put_keysets(&mut mu, a, &rot.keys)?;
            tx.core.skip_writer_rules = true;
            let c = crate::engine::Engine::commit_tx(tx, mu);
            tx.core.skip_writer_rules = false;
            c?;
            super::record(tx, a, &rot)?;
            Ok(rot.rotated.iter().map(|x| (a, x.role, x.epoch)).collect::<BTreeSet<_>>())
        })
        .unwrap();
    (*commit_ids(&mut s.lp, W).difference(&before).next().unwrap(), made)
}

/// X1's knowing keyset (B's newest read keyset of X1) and its KEM key, as B holds it.
fn knowing(s: &Shape) -> (Epoch, osis_crypto::KemPublicKey) {
    let x1 = s.x1();
    let (r, e, k) = s.lp.peers[B].engine.core.keysets_of(&x1).filter(|x| x.0 == Role::Write).max_by_key(|x| x.1.n()).unwrap();
    assert_eq!(r, Role::Write);
    (e, k.kem.clone().unwrap())
}

/// W attacks as `how`; its commits reach A. Returns the secrets W holds, its own new epochs
/// included.
fn attack(s: &mut Shape, how: Attack, rm: &Removal) -> BTreeSet<Key> {
    let (g, x1) = (s.g, s.x1());
    let mut known = rm.start.clone();
    match how {
        Attack::Plain => {
            let k = knowing(s);
            known.extend(forged(s, g, x1, Some(k), None).1);
        }
        Attack::Rogue => {
            // W's rotation of X1 lists every keyset of X1 it holds, the knowing one included
            let (c, made) = forged(s, x1, s.xs.get(1).copied().unwrap_or(x1), None, None);
            known.extend(made);
            let ks = keys_part(&s.lp, W, &c, x1);
            let k = s.lp.peers[W].engine.core.keysets_of(&x1).filter(|x| x.0 == Role::Write).max_by_key(|x| x.1.n()).map(|x| (x.1, x.2.kem.clone().unwrap())).unwrap();
            assert!(!ks.is_empty());
            known.extend(forged(s, g, x1, Some(k), None).1);
        }
        Attack::MadeUp => {
            let sec = Secret32::from_bytes([77; 32]);
            let e = Epoch::derive(&x1, Role::Write, 99, &sec).unwrap();
            known.extend(forged(s, g, x1, Some((e, osis_crypto::role_kem(&sec).public().clone())), None).1);
        }
        Attack::Backdated => {
            let at = s.lp.peers[B].engine.core.ix.commits.get(&rm.rm).unwrap().view.ts;
            let ts = Ts::make(WallMs(at.wall_ms().0 - 1), 0).unwrap();
            let k = knowing(s);
            known.extend(forged(s, g, x1, Some(k), Some(ts)).1);
        }
        Attack::Reseal => {
            let (k, kem) = knowing(s);
            s.lp.peers[W]
                .engine
                .run(|tx| {
                    let held = tx.core.epochs(&g).unwrap();
                    let hist = super::history_boxes(tx, &tx.core.writer().unwrap(), &g)?;
                    let keys = HolderKeys::Actor { keysets: [Role::Read, Role::Write].into_iter().map(|r| (r, vec![(k, kem.clone())])).collect(), own: Default::default() };
                    let rcpt = Recipient { holder: x1, role: Role::Write, keys };
                    // (none where W holds no current epoch of G: B's cascade rotated G past it)
                    let Ok(Some(w)) = osis_keys::box_holder(&g, &held, &hist, &rcpt, &BTreeSet::from([Role::Read, Role::Write]), &mut *tx.rng) else { return Ok(()) };
                    let mut m = Mutation::new();
                    m.unchecked();
                    crate::flows::put_secrets(&mut m, g, &w, false)?;
                    tx.core.skip_writer_rules = true;
                    let c = crate::engine::Engine::commit_tx(tx, m);
                    tx.core.skip_writer_rules = false;
                    c.map(|_| ())
                })
                .unwrap();
        }
    }
    known.extend(held_by(&s.lp, W, &s.all()));
    super::tests::send_skipping(&mut s.lp, W, A, &BTreeSet::new());
    known
}

/// A writes G (rotating first as due). Whether W, holding `known`, opens the epoch A writes
/// under.
fn a_writes_opened(s: &mut Shape, known: BTreeSet<Key>) -> bool {
    let (_, still) = s.lp.peers[A].engine.ensure_rotated(&s.g).unwrap();
    assert!(still.is_empty(), "A blocked on G: {still:?}");
    let w = s.me(W);
    let all = s.all();
    let opened = openable(&mut s.lp, A, &all, w, known);
    let e = newest_read(&s.lp, A, s.g).unwrap();
    opened.contains(&(s.g, Role::Read, e))
}

// spec/crypto.md §4 (Carried demotions), spec/requirements.md Permissions: for each way W, removed
// from Xd unknown to it, acts on G after X1's knowing keyset reached A (plain, rotating X1 past the
// knowing keyset, a made-up keyset, a backdated rotation), A writes nothing W opens. Depth 1 and 3.
#[test]
fn removed_member_reads_nothing_after_the_knowing_keyset_spec_crypto_4() {
    for d in [1, 3] {
        for how in ATTACKS {
            let mut s = shape(d);
            let rm = removed(&mut s, W, Carry::Honest);
            let w = s.me(W);
            assert_eq!(s.lp.peers[A].engine.core.role_now(&w, &s.g), None, "depth {d}: A holds W's removal with X1's keyset");
            let known = attack(&mut s, how, &rm);
            assert!(!a_writes_opened(&mut s, known), "depth {d}, {how:?}: W opens what A writes");
        }
    }
}

// The planted fault (the model's `Travel = FALSE`): B's rotation of X1 carries nothing, so A
// holds the knowing keyset without the removal and counts W a writer of G. Then each way W acts
// makes A write under an epoch W opens: the test above sees each leak.
#[test]
fn keyset_carrying_nothing_leaks_spec_crypto_4() {
    for how in ATTACKS {
        let mut s = shape(2);
        let rm = removed(&mut s, W, Carry::Nothing);
        let w = s.me(W);
        assert_eq!(s.lp.peers[A].engine.core.role_now(&w, &s.g), Some(Role::Write), "A does not know W left");
        let known = attack(&mut s, how, &rm);
        assert!(a_writes_opened(&mut s, known), "{how:?}: the planted fault is seen");
    }
}

// spec/crypto.md §4 (Held keyset): a keyset is held only with the demotions it carries. A holds
// X1's knowing rotation without the removal it lists: X1's new keyset is not held there (no
// anchor, nothing stale by it), and is once the removal arrives, whatever the order.
#[test]
fn keyset_held_only_with_its_demotions_spec_crypto_4() {
    let mut s = shape(2);
    let x1 = s.x1();
    let rm = removed(&mut s, W, Carry::Honest);
    let k = knowing(&s).0;
    let held = |s: &Shape| s.lp.peers[A].engine.core.keyset(&x1, Role::Write, &k).is_some();
    assert!(held(&s), "with what travels");
    // a peer holding X1's rotation alone
    let mut lp = s.lp.copy().unwrap();
    let c = lp.peers.len();
    let now = lp.peers[A].engine.now();
    lp.peers.push(crate::local_peer::Peer::new(91, now).unwrap());
    for pk in lp.packages(A).unwrap().into_iter().filter(|p| p.id != rm.rm) {
        let _ = lp.peers[c].receive(&pk.bytes, pk.blobs);
    }
    assert!(lp.peers[c].engine.core.ix.keysets.contains_key(&(x1, Role::Write, k)), "its body noted");
    assert!(lp.peers[c].engine.core.keyset(&x1, Role::Write, &k).is_none(), "not held without the removal");
    for pk in lp.packages(A).unwrap().into_iter().filter(|p| p.id == rm.rm) {
        lp.peers[c].receive(&pk.bytes, pk.blobs).unwrap();
    }
    assert!(lp.peers[c].engine.core.keyset(&x1, Role::Write, &k).is_some(), "held once it arrives");
    assert!(s.lp.peers[A].engine.core.ix.commits.contains_key(&rm.x1_rot));
}

// spec/requirements.md Permissions (a parent never depends on who reads through its members);
// spec/crypto.md §4 (Carried demotions): a reader's removal from Xd travels nowhere above it. A
// holds X1's keysets made knowing R's removal, but not the removal: R still reads Xd as A sees
// it, X1's keysets carry nothing, and A holds no edge write of Xd it did not hold before.
#[test]
fn reader_removal_stays_below_spec_crypto_4() {
    let mut s = shape(2);
    let (r, xd, x1) = (s.me(R), s.xd(), s.x1());
    let before: BTreeSet<CommitId> = s.lp.peers[A].engine.core.ix.held.commits_on(&xd).iter().map(|c| c.id).collect();
    let rm = removed(&mut s, R, Carry::Honest);
    // (A may hold the removal commit's `keys.0` part: Xd's keyset on a chain)
    assert!(s.lp.peers[A].engine.core.ix.held.edge_commit(&rm.rm).is_none(), "A holds R's removal");
    assert_eq!(s.lp.peers[A].engine.core.role_now(&r, &xd), Some(Role::Read), "A learns R left Xd");
    let now: BTreeSet<CommitId> = s.lp.peers[A].engine.core.ix.held.commits_on(&xd).iter().map(|c| c.id).collect();
    assert_eq!(now, before, "A learns an edge write of Xd");
    assert!(s.lp.peers[A].engine.core.keysets_of(&x1).all(|(_, _, k)| k.demotions.is_empty() && !k.demotes), "X1's keysets carry a reader's removal");
}

/// A {a1 (peer 0), M (read)}, M {m1 (peer 1), S (write)}, S {f (peer 2)}: f reaches M only
/// through S, and reads A through M. Returns (A, M, S). Built once, a copy each call.
fn route_shape() -> (LocalPeer, Tid, Tid, Tid) {
    let (lp, (a, m, s)) = LocalPeer::cached("rotation::tests_carried::route_shape", || {
        let mut lp = synced(3);
        let s = group(&mut lp, 2);
        let m = group(&mut lp, 1);
        lp.sync_all().unwrap();
        lp.peers[1].engine.grant(&m, &s, &edge(Role::Write)).unwrap();
        let a = group(&mut lp, 0);
        lp.sync_all().unwrap();
        lp.peers[0].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        assert!(held_by(&lp, 2, &[a]).contains(&(a, Role::Read, newest_read(&lp, 0, a).unwrap())), "f reads A through M");
        (lp, (a, m, s))
    });
    (lp, a, m, s)
}

// spec/requirements.md Permissions (a removal nobody stamps cuts off nothing by itself),
// spec/permissions.md §5.1 (a write never demotes its own author): f removes its own route S
// from M in a commit that also rotates M leaving S out (model `D0_half`). The rotation is valid
// (f held write on M just before it), so f keeps the epoch it made; a1, holding M's keysets as
// certificates only, seals M at f's keyset. Once m1, who knows S left, rotates M (listing f's
// keyset), a1 seals M there and nothing a1 writes on A after is under an epoch f opens.
#[test]
fn rotation_removing_its_own_route_leaks_nothing_spec_crypto_4() {
    let (mut lp, a, m, s) = route_shape();
    let mut known = held_by(&lp, 2, &[a, m]);
    let made = lp.peers[2]
        .engine
        .run(|tx| {
            let me = tx.core.writer().unwrap();
            let held = tx.core.epochs(&m).unwrap();
            let holders = super::recipients(tx, &me, &m, &[(s, None)])?;
            let mut mu = Mutation::new();
            crate::flows::edges::removal(tx, &mut mu, m, s)?;
            let rot = super::rotation_into(tx, &mut mu, m, &[Role::Read, Role::Write].into(), &held, &holders, super::Departs::Holder)?;
            mu.unchecked();
            tx.core.skip_writer_rules = true;
            let c = crate::engine::Engine::commit_tx(tx, mu);
            tx.core.skip_writer_rules = false;
            c?;
            super::record(tx, m, &rot)?;
            Ok(rot.rotated.iter().map(|r| (m, r.role, r.epoch)).collect::<BTreeSet<_>>())
        })
        .unwrap();
    known.extend(made);
    super::tests::deliver_without_secrets(&mut lp, 2, 0, m);
    super::tests::send_skipping(&mut lp, 2, 1, &BTreeSet::new());
    lp.peers[0].engine.ensure_rotated(&a).unwrap();
    lp.peers[1].engine.ensure_rotated(&m).unwrap();
    super::tests::deliver_without_secrets(&mut lp, 1, 0, m);
    let (_, still) = lp.peers[0].engine.ensure_rotated(&a).unwrap();
    assert!(still.is_empty(), "a1 blocked on A: {still:?}");
    known.extend(held_by(&lp, 2, &[a]));
    let f = lp.peers[2].engine.me();
    let (e, em) = (newest_read(&lp, 0, a).unwrap(), newest_read(&lp, 1, m).unwrap());
    assert!(!openable(&mut lp, 0, &[a, m], f, known.clone()).contains(&(a, Role::Read, e)), "f opens a1's newest epoch of A");
    assert!(!openable(&mut lp, 1, &[m], f, known).contains(&(m, Role::Read, em)), "f opens m1's newest epoch of M");
}

// spec/crypto.md §4 (Carried demotions: below write too): B demotes W on Xd to read and rotates
// up to X1's write; X1's keysets carry the demotion, so A counts W a reader of G. W's read and
// write rotation of G (sealing X1's write at its new keyset, which W cannot open) is invalid at
// A, and A writes under no write epoch W opens.
#[test]
fn demoted_member_writes_nothing_after_the_knowing_keyset_spec_crypto_4() {
    let mut s = shape(2);
    let (w, g, x1, xd, b) = (s.me(W), s.g, s.x1(), s.xd(), s.me(B));
    let mut known = held_by(&s.lp, W, &s.all());
    s.lp.advance(1000);
    let before = commit_ids(&mut s.lp, B);
    s.lp.peers[B].engine.demote(&xd, &Demotion { holder: w, new: Some(edge(Role::Read)), retain: None }).unwrap();
    let rm = *commit_ids(&mut s.lp, B).difference(&before).next().unwrap();
    s.lp.peers[B].engine.ensure_rotated(&s.xs[1]).unwrap();
    let before = commit_ids(&mut s.lp, B);
    s.lp.peers[B].engine.run(|tx| super::rotate_now(tx, b, x1, &BTreeSet::from([Role::Write]))).unwrap();
    let x1_rot = *commit_ids(&mut s.lp, B).difference(&before).next().unwrap();
    super::tests::send_skipping(&mut s.lp, B, W, &BTreeSet::from([rm]));
    let parts = keys_part(&s.lp, B, &x1_rot, x1);
    deliver_certified(&mut s.lp, B, A, x1_rot, parts);
    assert_eq!(s.lp.peers[A].engine.core.role_now(&w, &g), Some(Role::Read), "A holds W's demotion with X1's keyset");
    let k = s.lp.peers[B].engine.core.keysets_of(&x1).filter(|x| x.0 == Role::Write).max_by_key(|x| x.1.n()).map(|x| (x.1, x.2.kem.clone().unwrap())).unwrap();
    known.extend(forged(&mut s, g, x1, Some(k), None).1);
    super::tests::send_skipping(&mut s.lp, W, A, &BTreeSet::new());
    let (_, still) = s.lp.peers[A].engine.ensure_rotated(&g).unwrap();
    assert!(still.is_empty(), "{still:?}");
    known.extend(held_by(&s.lp, W, &s.all()));
    let all = s.all();
    let opened = openable(&mut s.lp, A, &all, w, known);
    let ew = s.lp.peers[A].engine.epochs(&g).unwrap().write.newest_held().unwrap().0;
    assert!(!opened.contains(&(g, Role::Write, ew)), "W opens A's newest write epoch of G");
}

// Randomized differential (spec/crypto.md §4, Carried demotions; the invariant at the top): over
// depth 1-3, each way W acts, more rotations of X1 after the knowing one (a keyset carrying the
// demotion on), and the order X1's newest keyset and what it carries reach A (or the keyset alone),
// A writes nothing W opens while that keyset is held there. With every keyset of X1 carrying
// nothing (the fix disabled), some case leaks.
#[test]
fn removed_member_reads_nothing_randomized_spec_crypto_4() {
    // whether A held X1's newest keyset (made knowing) when it wrote, and W opened what it wrote
    let run = |seed: u64, carry: Carry| -> (bool, bool) {
        let mut rng = super::tests::Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let d = 1 + rng.next(3) as usize;
        let how = ATTACKS[rng.next(ATTACKS.len() as u64) as usize];
        let again = rng.next(2) as usize;
        let bare = rng.next(3) == 0;
        let mut s = shape(d);
        let rm = removed_with(&mut s, W, carry, again, (!bare).then_some(Some(&mut rng)));
        let k = knowing(&s).0;
        let x1 = s.x1();
        let known = attack(&mut s, how, &rm);
        let held = s.lp.peers[A].engine.core.keyset(&x1, Role::Write, &k).is_some();
        (held, a_writes_opened(&mut s, known))
    };
    for seed in 0..16 {
        let (held, opened) = run(seed, Carry::Honest);
        assert!(!(held && opened), "seed {seed}: W opens what A writes holding X1's knowing keyset");
    }
    assert!((0..16).any(|seed| run(seed, Carry::Nothing) == (true, true)), "with the fix disabled nothing leaks: the test reaches no attack");
}
