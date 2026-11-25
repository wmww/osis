//! Connection proofs judged (spec/sync-opens.md §2, §4 J; spec/permissions.md §4 Stranded): a
//! claim's path judged with the proof's copies taken in as a trial, the guard, and the proven role.
//! The model: roles-model `paths::proofs` (notes/accounts-switch-brief.md, Models).

use crate::disputes::{admins, fight};
use crate::flows::{edge_of, people, send_carried, thing_of};
use osis_base::{Role, Tid};
use osis_engine::local_peer::LocalPeer;
use osis_engine::sync::{Claim, J, ProvenThing};

/// Peer `i`'s node thing's claim, signed by its key, claiming `path`.
fn claim(lp: &mut LocalPeer, i: usize, path: &[Tid]) -> Claim {
    let mut c = lp.peers[i].engine.proving().unwrap().provers[0].claim();
    c.path = path.to_vec();
    c
}

/// The role `proven` gives `t` (`None`: not proven, or proven at none now).
fn role_of(proven: &[ProvenThing], t: &Tid) -> Option<Role> {
    proven.iter().find(|p| p.thing == *t).and_then(|p| p.role)
}

// spec/sync-opens.md §2 (judged with the sides taking them in would record; A proof proves
// nothing where the reading it is judged on undoes a lowering): b removed a (w) and peer 3
// holds it; a carries as a copy its own removal of b, stamped earlier (r). Judged beside what
// peer 3 holds with no side recorded, r leaves w no right and a is t's admin again. Taken in, peer
// 3 sides with w (held first); the guard denies it too. And the trial keeps nothing.
#[test]
fn a_removed_nodes_counter_removal_proves_nothing_spec_sync_opens_2() {
    let mut f = fight(4);
    let (t, a, w, r) = (f.t, f.a, f.w.clone(), f.r.clone());
    send_carried(&mut f.lp, 1, 3, &w);
    assert_eq!(admins(&f, 3), (false, true));
    let c = claim(&mut f.lp, 0, &[t]);
    let copies = f.lp.peers[0].engine.copies_of(&r.iter().map(|x| (*x, t)).collect::<Vec<_>>(), &[a]).unwrap();
    assert!(!copies.commits.is_empty());
    let held = f.lp.peers[3].engine.commit_ids();
    let e = &mut f.lp.peers[3].engine;
    assert_eq!(role_of(&e.proven(std::slice::from_ref(&c), &Default::default()).unwrap(), &t), None, "its own reading: removed");
    let p = e.proven(&[c], &copies).unwrap();
    assert_eq!(role_of(&p, &t), None, "the copy proves nothing");
    assert_eq!(e.commit_ids(), held, "the trial keeps nothing");
    assert_eq!(admins(&f, 3), (false, true));
}

/// Peer 2 makes `t` and `s` (admin peer 2) with `t` holding write on `s` and peer 3 read on `s`,
/// all spread; then grants peer 0 `on_t` on `t`, which only peer 0 gets: peer 3 reads `s` and
/// holds no grant of peer 0's on `t`.
fn contact(on_t: Role) -> (LocalPeer, Tid, Tid) {
    let (mut lp, ps) = people(4);
    let t = thing_of(&mut lp, 2, ps[2]);
    let s = thing_of(&mut lp, 2, ps[2]);
    lp.peers[2].engine.grant(&s, &t, &edge_of(Role::Write)).unwrap();
    lp.peers[2].engine.grant(&s, &ps[3], &edge_of(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[2].engine.grant(&t, &ps[0], &edge_of(on_t)).unwrap();
    lp.sync(2, 0).unwrap();
    (lp, t, s)
}

// spec/sync-opens.md §2 (records taken as received evidence): peer 3 holds none of t's
// grants; peer 0 proves its node thing claiming [t] with copies of its grant on t, and proves t at
// the role the grant gives. With no copies it proves t nothing.
#[test]
fn honest_copies_prove_a_path_the_verifier_lacks_spec_sync_opens_2() {
    let (mut lp, t, _) = contact(Role::Write);
    let pr = lp.peers[0].engine.proving().unwrap();
    assert_eq!(pr.provers[0].path, vec![t], "the node thing claims the thing it holds a grant on");
    let c = pr.provers[0].claim();
    let e = &mut lp.peers[3].engine;
    assert_eq!(role_of(&e.proven(std::slice::from_ref(&c), &Default::default()).unwrap(), &t), None, "no copies: the path is not held here");
    assert_eq!(role_of(&e.proven(&[c], &pr.copies).unwrap(), &t), Some(Role::Write));
}

// spec/sync-opens.md §2 (proven role: the least of the path's and the claimed thing's role on S),
// §4 J, spec/permissions.md §4 (Stranded): peer 0 holds read on t and t
// write on s. Peer 0 proving [t] is s's reader, never its writer, though t writes s.
#[test]
fn the_proven_role_is_capped_by_the_path_spec_sync_opens_2() {
    let (mut lp, t, s) = contact(Role::Read);
    let pr = lp.peers[0].engine.proving().unwrap();
    let c = pr.provers[0].claim();
    let e = &mut lp.peers[3].engine;
    let sid = e.sync_id_of(&s).unwrap().expect("s's sync ID");
    let p = e.proven(&[c], &pr.copies).unwrap();
    assert_eq!(role_of(&p, &t), Some(Role::Read));
    assert_eq!(e.judge_peer(&sid, &p).unwrap(), J::Reader);
    assert_eq!(e.writer_of(&sid, &p).unwrap(), None, "read on t: no writer of s");
}

/// Peer `i` removes `holder` from `t`; the commits it made.
fn remove(lp: &mut LocalPeer, i: usize, t: Tid, holder: Tid) -> Vec<osis_base::CommitId> {
    let before: std::collections::BTreeSet<_> = lp.peers[i].engine.commit_ids().into_iter().collect();
    lp.peers[i].engine.demote(&t, &osis_engine::flows::Demotion { holder, new: None, retain: None }).unwrap();
    lp.peers[i].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect()
}

// spec/sync-opens.md §2 (A proof proves nothing where the reading it is judged on undoes a lowering), roles-model `a_cherry_picked_removal_of_the_remover_proves_
// nothing`: admins a, b, d of t (mint admin c, peer 3); a removes d first, d (not knowing it)
// removes b, then b (knowing neither) removes a. Peer 4 holds b's removal of a alone. a carries
// d's removal of b and not its own of d: read with it, b's removal has no right and a is admin
// again, which nothing will ever bring peer 4 to read (the copy is kept with the connection
// alone). It undoes a lowering peer 4's reading applies: it proves nothing.
#[test]
fn a_cherry_picked_removal_of_the_remover_proves_nothing_spec_sync_opens_2() {
    let (mut lp, ps) = people(5);
    let (a, b, d, c) = (ps[0], ps[1], ps[2], ps[3]);
    let t = thing_of(&mut lp, 3, c);
    for x in [a, b, d] {
        lp.peers[3].engine.grant(&t, &x, &edge_of(Role::Admin)).unwrap();
    }
    lp.peers[3].engine.grant(&t, &ps[4], &edge_of(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].clock.advance(1_000);
    remove(&mut lp, 0, t, d);
    lp.peers[2].clock.advance(2_000);
    let z = remove(&mut lp, 2, t, b);
    lp.peers[1].clock.advance(4_000);
    let r = remove(&mut lp, 1, t, a);
    send_carried(&mut lp, 1, 4, &r);
    let c0 = claim(&mut lp, 0, &[t]);
    let copies = lp.peers[2].engine.copies_of(&z.iter().map(|x| (*x, t)).collect::<Vec<_>>(), &[a]).unwrap();
    let e = &mut lp.peers[4].engine;
    assert!(!e.roster(&t).contains_key(&a), "peer 4 reads a removed");
    assert_eq!(role_of(&e.proven(&[c0], &copies).unwrap(), &t), None, "the cherry-picked copy proves nothing");
}

// spec/sync-opens.md §2 (judged with the sides taking them in would record), roles-model
// `honest_copies_are_judged_with_the_sides_their_receipt_records`: peer 3 holds b's removal of a
// (w). Reader e (peer 4) proves [t] carrying a's earlier-stamped removal of b (r), a seed of w.
// Taken in, peer 3 would side with w (held first), so w stays applied and e's read stands; judged
// under the trust set as it stands, r voids w, the guard sees w undone, and e proves nothing.
#[test]
fn copies_are_judged_with_the_sides_their_receipt_records_spec_sync_opens_2() {
    let mut f = fight(5);
    let (t, a, w, r) = (f.t, f.a, f.w.clone(), f.r.clone());
    send_carried(&mut f.lp, 1, 3, &w);
    let c4 = claim(&mut f.lp, 4, &[t]);
    let copies = f.lp.peers[0].engine.copies_of(&r.iter().map(|x| (*x, t)).collect::<Vec<_>>(), &[a]).unwrap();
    let e = &mut f.lp.peers[3].engine;
    assert_eq!(role_of(&e.proven(&[c4], &copies).unwrap(), &t), Some(Role::Read));
}

/// Runs of `Engine::proven`'s judgement since the last `costs::take`.
fn proven_runs() -> u64 {
    osis_base::costs::take().into_iter().filter(|(k, _, _)| *k == "sync: proven").map(|(_, _, n)| n).sum()
}

/// `k` proofs (one per connection) peer 3 judges, each peer 0's node claiming its grant on a
/// thing of its own with a copy of that grant, which peer 3 lacks: each a trial.
fn proofs(k: usize) -> (LocalPeer, Vec<(Claim, osis_blob::Certificates)>) {
    let (mut lp, ps) = people(4);
    let mut out = Vec::new();
    let mut grants = Vec::new();
    for _ in 0..k {
        let t = thing_of(&mut lp, 2, ps[2]);
        let before: std::collections::BTreeSet<_> = lp.peers[2].engine.commit_ids().into_iter().collect();
        lp.peers[2].engine.grant(&t, &ps[0], &edge_of(Role::Write)).unwrap();
        grants.push((t, lp.peers[2].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect::<Vec<_>>()));
    }
    lp.sync(2, 0).unwrap();
    for (t, cs) in grants {
        let c = claim(&mut lp, 0, &[t]);
        let copies = lp.peers[0].engine.copies_of(&cs.iter().map(|x| (*x, t)).collect::<Vec<_>>(), &[ps[0]]).unwrap();
        assert!(!copies.commits.is_empty());
        out.push((c, copies));
    }
    (lp, out)
}

// spec: none (internal: notes/engine.md, Derived values; spec/sync-opens.md §2 trials). A trial
// leaves no mark on what reads the node's state: each connection's proof, judged with copies
// the verifier lacks, is judged once however often each is asked, at k and 10k connections, and
// no trial moves another's answer.
#[test]
fn a_proofs_trial_moves_no_proofs_answer() {
    for k in [2, 20] {
        let (mut lp, ps) = proofs(k);
        let e = &mut lp.peers[3].engine;
        proven_runs();
        for _ in 0..3 {
            for (c, copies) in &ps {
                assert_eq!(role_of(&e.proven(std::slice::from_ref(c), copies).unwrap(), &c.path[0]), Some(Role::Write));
            }
        }
        assert_eq!(proven_runs(), k as u64, "each of {k} proofs judged once");
    }
}
