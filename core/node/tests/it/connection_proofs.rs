#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Connection proofs (spec/sync.md §10, Connection proofs; issues/net-shared-set.md step 2): what
//! `SyncEngine::proven` reports comes from the connection's own exchange and nothing else.

use crate::net::local_nodes;
use crate::net;
use net::*;
use crate::peers::reach_ed;
use osis_base::{Role, Tid};
use osis_crypto::{Secret32, SigningSecret};
use osis_node::sync::ConnId;
use osis_proto::{ActorProof, ClientConfig, ClientEvent, ClientInput, ClientOutput, ClientSession, Code, Command, Message, Prover, encode_frame};
use std::collections::BTreeSet;

/// The key dialed in these tests: the listener's static key.
pub(crate) const LISTENER: [u8; 32] = [0x42; 32];
/// A's hello challenge in `dial`.
pub(crate) const CHALLENGE: [u8; 32] = [7; 32];

pub(crate) struct Dialer {
    /// The served session at the node (its engine's ID) and its hub connection.
    pub(crate) conn: ConnId,
    pub(crate) hc: ConnId,
    pub(crate) cs: ClientSession,
    /// The listener's Hello challenge.
    pub(crate) hello: [u8; 32],
}

/// One round of the session: frames to node `n`'s hub, its answers back; the events gathered.
pub(crate) fn pump(net: &mut Net, n: usize, p: &mut Dialer, outs: Vec<ClientOutput>) -> Vec<ClientEvent> {
    net.hand_exchange(n, p.hc, &mut p.cs, Vec::new(), outs, false)
}

fn dial(net: &mut Net, n: usize) -> Dialer {
    dial_with(net, n, CHALLENGE)
}

/// A dialer's own Hello challenge, chosen by the dialer: a hostile one picks it.
pub(crate) fn dial_with(net: &mut Net, n: usize, challenge: [u8; 32]) -> Dialer {
    let (hc, sent) = net.hand_accept(n, LISTENER, osis_transport::Peer::Key([0x43; 32]));
    let hello = sent.iter().find_map(|b| osis_proto::Hello::decode(&b[4..]).ok()).unwrap().challenge;
    let mut p = Dialer { conn: 0, hc, cs: ClientSession::new(ClientConfig { peer_static_key: LISTENER, challenge }), hello };
    let now = net.now();
    let mut outs = p.cs.handle(now, ClientInput::Start);
    for f in sent {
        outs.extend(p.cs.handle(now, ClientInput::Bytes(f)));
    }
    pump(net, n, &mut p, outs);
    p.conn = net.served(n, hc);
    p
}

pub(crate) fn prove(net: &mut Net, n: usize, p: &mut Dialer, provers: Vec<Prover>) -> Vec<ClientEvent> {
    let now = net.now();
    let outs = p.cs.handle(now, ClientInput::Command(Command::Prove(provers)));
    pump(net, n, p, outs)
}

/// Sends `proofs` raw, as a dialer that made them itself would.
fn prove_raw(net: &mut Net, n: usize, p: &Dialer, id: u32, proofs: Vec<ActorProof>) -> Vec<Message> {
    net.hand_input(n, p.hc, encode_frame(&Message::Prove { id, proofs }.encode())).iter().filter_map(|b| Message::decode(&b[4..]).ok()).collect()
}

pub(crate) fn proved_by(evs: &[ClientEvent]) -> Vec<ActorProof> {
    evs.iter().find_map(|e| if let ClientEvent::Proved { proofs } = e { Some(proofs.clone()) } else { None }).expect("a Proved answer")
}

/// A node with an account of its own: (node, account).
pub(crate) fn account_node(net: &mut Net, seed: u64, host: usize) -> (usize, Tid) {
    let n = net.node(seed, &[host]);
    let addr = net.address(host);
    let (p, done) = net.engine(n).create_account(std::slice::from_ref(&addr)).unwrap();
    let acts = net.sync(n).carry_out(done).unwrap();
    net.actions(n, acts);
    net.run();
    (n, p.account)
}

/// A second node of `first`'s account: admin on it, chain and all.
pub(crate) fn paired_node(net: &mut Net, seed: u64, host: usize, first: usize, account: Tid) -> usize {
    let n = net.joining_node(seed, &[host]);
    net.pair(n, first);
    let nt = net.node_tid(n);
    let done = net.engine(first).pair(&nt).unwrap();
    let grant = done.commits[0];
    let acts = net.sync(first).carry_out(done).unwrap();
    net.actions(first, acts);
    for (_, pks) in net.sync(first).take_direct() {
        for pk in pks {
            let _ = net.engine(n).ingest(&pk.bytes, pk.blobs);
        }
    }
    let done = net.engine(n).paired(&account, &grant).unwrap();
    let acts = net.sync(n).carry_out(done).unwrap();
    net.actions(n, acts);
    net.run();
    n
}

fn proven(net: &mut Net, n: usize, p: &Dialer) -> BTreeSet<Tid> {
    net.sync(n).proven(p.conn).unwrap().clone()
}

fn set(tids: &[Tid]) -> BTreeSet<Tid> {
    tids.iter().copied().collect()
}

// spec/sync.md §10: a dialer's proof shows its node and its account by the epoch's key; the
// listener answers with its own proofs to a dialer that proved an actor it knows
#[test]
fn dialer_proves_then_known_listener_answers_spec_sync_10() {
    let (mut net, _host, a, b, account) = net::account_pair();
    let (ta, tb) = (net.node_tid(a), net.node_tid(b));
    let mut p = dial(&mut net, a);
    let provers = net.sync(b).provers(true).unwrap();
    let evs = prove(&mut net, a, &mut p, provers);
    assert_eq!(proven(&mut net, a, &p), set(&[tb, account]), "the node and its account");
    let back = proved_by(&evs);
    assert_eq!(actors(&back), set(&[ta, account]), "the listener's proof: {back:?}");
    assert!(back.iter().all(|x| x.verify(true, &CHALLENGE, &LISTENER)), "signed for this dialer and this listener");
}

// spec/sync.md §10 (identity only to known actors): a dialer proving only actors the listener
// holds no record of gets no proof back, though what it proved stands
#[test]
fn listener_proves_nothing_to_a_stranger_spec_sync_10() {
    let (mut net, _host, [(a, _), (s, account)]) = net::account_nodes([1, 3]);
    let ts = net.node_tid(s);
    assert!(net.engine(a).core.created(&ts).is_none() && net.engine(a).core.created(&account).is_none(), "strangers to a");
    let mut p = dial(&mut net, a);
    let provers = net.sync(s).provers(false).unwrap();
    let evs = prove(&mut net, a, &mut p, provers);
    assert_eq!(proved_by(&evs), Vec::new(), "no identity to a stranger");
    assert_eq!(proven(&mut net, a, &p), set(&[account]), "its account still proves itself; its node key goes to its own nodes only");
    assert!(!proven(&mut net, a, &p).contains(&ts));
}

// spec/sync.md §10: a key actor (a link key) proves itself by its signing key, no chain
#[test]
fn key_actor_proved_by_its_signing_key_spec_sync_10() {
    let (mut net, [a]) = local_nodes::<1>();
    let key = SigningSecret::from_seed(&Secret32::from_bytes([9; 32]));
    let record = osis_base::CreationRecord::KeyActor { alg: 1, public_key: key.verifying_key().to_bytes().to_vec(), nonce: [9; 32], account: false };
    let actor = record.tid();
    let mut p = dial(&mut net, a);
    prove(&mut net, a, &mut p, vec![Prover { key, record }]);
    assert_eq!(proven(&mut net, a, &p), set(&[actor]));
}

// spec/sync.md §10: a proof by a key that is not the record's proves nothing
#[test]
fn forged_key_proves_nothing_spec_sync_10() {
    let (mut net, [a]) = local_nodes::<1>();
    let real = SigningSecret::from_seed(&Secret32::from_bytes([9; 32]));
    let record = osis_base::CreationRecord::KeyActor { alg: 1, public_key: real.verifying_key().to_bytes().to_vec(), nonce: [9; 32], account: false };
    let thief = SigningSecret::from_seed(&Secret32::from_bytes([8; 32]));
    let mut p = dial(&mut net, a);
    let evs = prove(&mut net, a, &mut p, vec![Prover { key: thief, record }]);
    assert_eq!(proven(&mut net, a, &p), set(&[]));
    assert_eq!(proved_by(&evs), Vec::new());
}

// spec/sync.md §10, spec/wire.md §11.2: a proof signed for another connection's challenge, or for
// another listener, proves nothing here: replay across connections fails
#[test]
fn proof_for_another_session_or_listener_proves_nothing_spec_sync_10() {
    let (mut net, _host, a, b, _) = net::account_pair();
    let tb = net.node_tid(b);
    let provers = net.sync(b).provers(true).unwrap();
    // proved honestly on one connection
    let mut first = dial(&mut net, a);
    prove(&mut net, a, &mut first, provers.clone());
    assert!(proven(&mut net, a, &first).contains(&tb));
    let captured_good = provers.iter().map(|x| x.sign(false, &first.hello, &LISTENER)).collect::<Vec<_>>();
    assert!(captured_good.iter().all(|x| x.verify(false, &first.hello, &LISTENER)), "made for the first connection");
    // the same bytes replayed on a second connection, whose challenge differs
    let second = dial(&mut net, a);
    let answers = prove_raw(&mut net, a, &second, 7, captured_good);
    assert!(answers.iter().any(|m| matches!(m, Message::Proved { proofs, .. } if proofs.is_empty())), "{answers:?}");
    assert_eq!(proven(&mut net, a, &second), set(&[]), "a replayed proof");
    // over this connection's challenge, but for another listener
    let third = dial(&mut net, a);
    let elsewhere: Vec<ActorProof> = provers.iter().map(|x| x.sign(false, &third.hello, &[0xee; 32])).collect();
    let _ = prove_raw(&mut net, a, &third, 8, elsewhere);
    assert_eq!(proven(&mut net, a, &third), set(&[]), "a proof for another listener");
}

// spec/wire.md §11.2: one Prove per connection, a second is an error and changes nothing
#[test]
fn second_prove_refused_spec_wire_11_2() {
    let (mut net, [a]) = local_nodes::<1>();
    let key = SigningSecret::from_seed(&Secret32::from_bytes([9; 32]));
    let record = osis_base::CreationRecord::KeyActor { alg: 1, public_key: key.verifying_key().to_bytes().to_vec(), nonce: [9; 32], account: false };
    let mut p = dial(&mut net, a);
    let first = prove(&mut net, a, &mut p, vec![Prover { key: key.clone(), record: record.clone() }]);
    assert_eq!(proved_by(&first), vec![], "unknown to a");
    let answers = prove_raw(&mut net, a, &p, 99, Vec::new());
    assert!(answers.contains(&Message::Error { id: 99, code: Code::MALFORMED }), "{answers:?}");
    assert_eq!(proven(&mut net, a, &p), set(&[record.tid()]), "the first stands");
}

// spec/sync.md §10: an account proof by a key that is no open epoch of that account proves it not;
// the node's own key still stands
#[test]
fn an_account_is_proved_only_by_its_own_epoch_key_spec_sync_10() {
    let (mut net, _host, [(a, account), (s, other)]) = net::account_nodes([1, 3]);
    let ts = net.node_tid(s);
    // as made for s's own nodes: its node key first, so the forged account proof can borrow it
    let provers = net.sync(s).provers(true).unwrap();
    let record = net.engine(a).core.created(&account).unwrap().clone();
    // s signs for a's account with its own node key
    let mut forged = provers.clone();
    forged[1] = Prover { key: provers[0].key.clone(), record };
    let mut p = dial(&mut net, a);
    prove(&mut net, a, &mut p, forged);
    assert_eq!(proven(&mut net, a, &p), set(&[ts]), "another's account, by a key of no epoch of it");
    // s's real account still works
    let mut p = dial(&mut net, a);
    prove(&mut net, a, &mut p, provers);
    assert_eq!(proven(&mut net, a, &p), set(&[ts, other]));
}

// spec/sync.md §10: group data never proves anything: b's roster entry held at a in full, a Prove
// without the account's proof proves the node alone
#[test]
fn held_group_data_proves_nothing_spec_sync_10() {
    let (mut net, _host, a, b, _) = net::account_pair();
    let tb = net.node_tid(b);
    let provers: Vec<Prover> = net.sync(b).provers(true).unwrap().into_iter().filter(|x| x.record.tid() == tb).collect();
    let mut p = dial(&mut net, a);
    prove(&mut net, a, &mut p, provers);
    assert_eq!(proven(&mut net, a, &p), set(&[tb]), "the account was not proved on this connection");
}

// spec/sync.md §10: a connection whose peer sent no Prove proved nothing, and the listener shows
// nothing of its own unasked
#[test]
fn a_session_with_no_prove_proves_nothing_spec_sync_10() {
    let (mut net, [a]) = local_nodes::<1>();
    let p = dial(&mut net, a);
    assert_eq!(proven(&mut net, a, &p), set(&[]));
    assert_eq!(net.sync(a).proven(ConnId::MAX), None, "no such connection");
}

// spec/sync.md §10: connection proofs run over real dials (no hand driver): the dialing node's
// `proven` gets the listener's actors, the listener's the dialer's, and neither depends on
// which side dialed
#[test]
fn proofs_run_on_a_real_connection_either_way_spec_sync_10() {
    let (mut net, _host, a, b, account) = net::account_pair();
    let (ta, tb) = (net.node_tid(a), net.node_tid(b));
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    net.group_at(a, &[], vec![]);
    net.run();
    net.advance(70_000);
    net.run();
    let saw = |net: &mut Net, n: usize, peer: Tid| net.sync(n).proven_connections().iter().any(|(_, p)| p.contains(&peer) && p.contains(&account));
    assert!(saw(&mut net, a, tb), "a saw b prove");
    assert!(saw(&mut net, b, ta), "b saw a prove");
}

/// The actors `proofs` name.
fn actors(proofs: &[ActorProof]) -> BTreeSet<Tid> {
    proofs.iter().map(ActorProof::actor).collect()
}

// spec/sync.md §10 (a connection's proven actors are only what its peer proved on it): adversary
// M runs other sessions in parallel, choosing every Hello challenge it controls (it reads a peer's
// Hello before sending its own), and presents any proof it collected on any session. Honest parties
// a (a listener, M dials it twice) and h (a dialer, dials M) never prove anything to each other:
// no session they run may report an actor of theirs, however M mixes what it collected.
#[test]
fn no_session_reports_an_actor_it_did_not_prove_spec_sync_10() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, _) = account_node(&mut net, 1, host);
    let (h, _) = account_node(&mut net, 2, host);
    let (m, _) = account_node(&mut net, 3, host);
    let (ta, th) = (net.node_tid(a), net.node_tid(h));
    // M is known to a, so a answers it (its best position)
    reach_ed(&mut net, a);
    reach_ed(&mut net, m);
    net.group_at(a, &[(m, Role::Read)], vec![]);
    net.run();
    net.advance(70_000);
    net.run();
    let h_provers = net.sync(h).provers(false).unwrap();
    let m_provers = net.sync(m).provers(false).unwrap();
    let h_set: BTreeSet<Tid> = actors(&h_provers.iter().map(|x| x.sign(false, &[0; 32], &[0; 32])).collect::<Vec<_>>());
    const KM: [u8; 32] = [0x77; 32];
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut pick = |n: usize| { x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9).wrapping_add(0x94d0_49bb_1331_11eb); ((x >> 32) as usize) % n };
    for round in 0..64 {
        // the listener-side target: a's second session, whose challenge M reads first
        let target = dial(&mut net, a);
        // a answers M on a session whose dialer challenge M chose (often equal to the target's)
        let c1 = if pick(4) == 0 { [round as u8; 32] } else { target.hello };
        let mut src = dial_with(&mut net, a, c1);
        let evs = prove(&mut net, a, &mut src, m_provers.clone());
        let a_listener = proved_by(&evs);
        assert!(!a_listener.is_empty(), "a knows m and answers");
        // h dials M: signs whatever challenge M's Hello chose, over M's key
        let c2 = if pick(4) == 0 { target.hello } else { [round as u8 + 100; 32] };
        let h_dialer: Vec<ActorProof> = h_provers.iter().map(|x| x.sign(false, &c2, &KM)).collect();
        // into the listener target: everything M collected, in a random order and subset
        let mut pool: Vec<ActorProof> = a_listener.iter().chain(&h_dialer).cloned().collect();
        if pick(2) == 0 { pool.reverse(); }
        pool.truncate(1 + pick(pool.len()));
        let _ = prove_raw(&mut net, a, &target, 900 + round, pool);
        let seen = proven(&mut net, a, &target);
        assert!(!seen.contains(&ta), "round {round}: a's own actor on a connection M dialed: {seen:?}");
        assert!(!seen.contains(&th), "round {round}: h's actor on a connection M dialed: {seen:?}");
        // the dialer target: honest h dialing M, which echoes h's own Hello challenge at it
        let ch = [round as u8 + 50; 32];
        let mut cs = ClientSession::new(ClientConfig { peer_static_key: KM, challenge: ch });
        let now = net.now();
        cs.handle(now, ClientInput::Start);
        cs.handle(now, ClientInput::Bytes(encode_frame(&osis_proto::Hello::new(now, ch).encode())));
        let out = cs.handle(now, ClientInput::Command(Command::Prove(h_provers.clone())));
        let (id, sent) = out.iter().find_map(|o| if let ClientOutput::Send(f) = o { match Message::decode(&f[4..]) { Ok(Message::Prove { id, proofs }) => Some((id, proofs)), _ => None } } else { None }).expect("h proves");
        // M answers with h's own proof as made, or as re-signed by it over h's challenge
        let reply: Vec<ActorProof> = if pick(2) == 0 { sent } else { h_provers.iter().map(|x| x.sign(false, &ch, &KM)).collect() };
        let out = cs.handle(now, ClientInput::Bytes(encode_frame(&Message::Proved { id, proofs: reply }.encode())));
        let got = out.iter().find_map(|o| if let ClientOutput::Event(ClientEvent::Proved { proofs }) = o { Some(proofs.clone()) } else { None }).expect("an answer");
        assert!(actors(&got).is_disjoint(&h_set), "round {round}: h proved to itself by its own reflected proof");
    }
}

// spec/wire.md §11.2 (MAX_PROOFS): a node holding more key actors than fit proves its own key and
// account, then the first key actors by tid, and the message fits and is accepted
#[test]
fn many_key_actors_prove_the_first_by_tid_spec_wire_11_2() {
    use osis_proto::MAX_PROOFS;
    let mut net = Net::new();
    let host = net.add_host();
    let (a, _) = account_node(&mut net, 1, host);
    let held: BTreeSet<Tid> = (0..MAX_PROOFS + 10).map(|i| net.engine(a).hold_key_actor(Secret32::from_bytes([(i & 255) as u8, (i >> 8) as u8, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7])).unwrap()).collect();
    assert_eq!(held.len(), MAX_PROOFS + 10);
    let provers = net.sync(a).provers(true).unwrap();
    assert_eq!(provers.len(), MAX_PROOFS);
    let tids: Vec<Tid> = provers.iter().map(|p| p.record.tid()).collect();
    assert_eq!(tids[0], net.node_tid(a), "this node's own key first");
    assert_eq!(tids[2..], held.iter().copied().take(MAX_PROOFS - 2).collect::<Vec<_>>()[..], "then the key actors, by tid");
    let (s, _) = account_node(&mut net, 2, host);
    let mut p = dial(&mut net, s);
    let want: BTreeSet<Tid> = tids.iter().copied().collect();
    prove(&mut net, s, &mut p, provers);
    let got = proven(&mut net, s, &p);
    assert!(want.is_subset(&got), "every proof sent was accepted");
}

// spec/wire.md §11.2 (MAX_PROOFS): a Prove past the cap is refused whole: no Proved, nothing proved
#[test]
fn prove_past_its_caps_is_refused_whole_spec_wire_11_2() {
    use osis_proto::MAX_PROOFS;
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let signer = |i: u32| {
        let mut seed = [3u8; 32];
        seed[..4].copy_from_slice(&i.to_le_bytes());
        let key = SigningSecret::from_seed(&Secret32::from_bytes(seed));
        let record = osis_base::CreationRecord::KeyActor { alg: 1, public_key: key.verifying_key().to_bytes().to_vec(), nonce: seed, account: false };
        Prover { key, record }
    };
    let many: Vec<Prover> = (0..=MAX_PROOFS as u32).map(signer).collect();
    for (case, provers, refused) in [
        ("MAX_PROOFS", many[..MAX_PROOFS].to_vec(), false),
        ("past MAX_PROOFS", many, true),
    ] {
        let p = dial(&mut net, a);
        let proofs: Vec<ActorProof> = provers.iter().map(|x| x.sign(false, &p.hello, &LISTENER)).collect();
        let want = actors(&proofs);
        let answers = prove_raw(&mut net, a, &p, 5, proofs);
        let answered = answers.iter().any(|m| matches!(m, Message::Proved { .. }));
        assert_eq!(answered, !refused, "{case}: {answers:?}");
        assert_eq!(proven(&mut net, a, &p).is_superset(&want), !refused, "{case}");
    }
}
