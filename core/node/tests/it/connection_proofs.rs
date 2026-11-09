#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Connection proofs (spec/sync.md §10, Connection proofs; issues/net-shared-set.md step 2): what
//! `SyncEngine::proven` reports comes from the connection's own exchange and nothing else.

use crate::net;
use net::*;
use crate::peers::reach_ed;
use osis_base::{Role, Tid};
use osis_crypto::{Secret32, SigningSecret};
use osis_node::ACCOUNT_RECORD;
use osis_node::sync::{Action, ConnId, Event};
use osis_proto::{ActorProof, ClientConfig, ClientEvent, ClientInput, ClientOutput, ClientSession, Code, Command, Message, Prover, encode_frame};
use std::collections::BTreeSet;

/// The key dialed in these tests: the listener's static key.
const LISTENER: [u8; 32] = [0x42; 32];
/// A's hello challenge in `dial`.
const CHALLENGE: [u8; 32] = [7; 32];

struct Dialer {
    conn: ConnId,
    cs: ClientSession,
    /// The listener's Hello challenge.
    hello: [u8; 32],
}

/// One round of the session: frames to node `n`, its answers back; the events gathered.
fn pump(net: &mut Net, n: usize, p: &mut Dialer, mut acts: Vec<Action>, mut outs: Vec<ClientOutput>) -> Vec<ClientEvent> {
    let mut evs = Vec::new();
    loop {
        let mut moved = false;
        for o in std::mem::take(&mut outs) {
            match o {
                ClientOutput::Send(b) => {
                    acts.extend(net.sync(n).handle(Event::Bytes { conn: p.conn, bytes: b }));
                    moved = true;
                }
                ClientOutput::Event(e) => evs.push(e),
                _ => {}
            }
        }
        for a in std::mem::take(&mut acts) {
            match a {
                Action::Send { conn, bytes } if conn == p.conn => {
                    let now = net.now();
                    outs.extend(p.cs.handle(now, ClientInput::Bytes(bytes)));
                    moved = true;
                }
                a => net.actions(n, vec![a]),
            }
        }
        if !moved {
            return evs;
        }
    }
}

fn dial(net: &mut Net, n: usize) -> Dialer {
    let (conn, acts) = net.sync(n).accept(LISTENER, [0x43; 32]);
    let hello = acts.iter().find_map(|a| if let Action::Send { bytes, .. } = a { osis_proto::Hello::decode(&bytes[4..]).ok() } else { None }).unwrap().challenge;
    let mut p = Dialer { conn, cs: ClientSession::new(ClientConfig { peer_static_key: LISTENER, challenge: CHALLENGE }), hello };
    let now = net.now();
    let outs = p.cs.handle(now, ClientInput::Start);
    pump(net, n, &mut p, acts, outs);
    p
}

fn prove(net: &mut Net, n: usize, p: &mut Dialer, provers: Vec<Prover>) -> Vec<ClientEvent> {
    let now = net.now();
    let outs = p.cs.handle(now, ClientInput::Command(Command::Prove(provers)));
    pump(net, n, p, Vec::new(), outs)
}

/// Sends `proofs` raw, as a dialer that made them itself would.
fn prove_raw(net: &mut Net, n: usize, p: &Dialer, id: u32, proofs: Vec<ActorProof>) -> Vec<Message> {
    let acts = net.sync(n).handle(Event::Bytes { conn: p.conn, bytes: encode_frame(&Message::Prove { id, proofs }.encode()) });
    acts.iter().filter_map(|a| if let Action::Send { bytes, .. } = a { Message::decode(&bytes[4..]).ok() } else { None }).collect()
}

fn proved_by(evs: &[ClientEvent]) -> Vec<ActorProof> {
    evs.iter().find_map(|e| if let ClientEvent::Proved { proofs } = e { Some(proofs.clone()) } else { None }).expect("a Proved answer")
}

/// A node with an account of its own: (node, account).
fn account_node(net: &mut Net, seed: u64, host: usize) -> (usize, Tid) {
    let n = net.node(seed, &[host]);
    let addr = net.address(host);
    let (p, done) = net.engine(n).create_person(std::slice::from_ref(&addr)).unwrap();
    net.engine(n).set_app_record(ACCOUNT_RECORD, p.person.as_bytes()).unwrap();
    let acts = net.sync(n).carry_out(done).unwrap();
    net.actions(n, acts);
    net.run();
    (n, p.person)
}

/// A second node of `first`'s account: admin on it, chain and all.
fn paired_node(net: &mut Net, seed: u64, host: usize, first: usize, account: Tid) -> usize {
    let n = net.node(seed, &[host]);
    net.pair(n, first);
    let nt = net.tid(n);
    let done = net.engine(first).pair(&account, &nt).unwrap();
    let grant = done.commits[0];
    let acts = net.sync(first).carry_out(done).unwrap();
    net.actions(first, acts);
    for (_, pks) in net.sync(first).take_direct() {
        for pk in pks {
            let _ = net.engine(n).ingest(&pk.bytes, pk.blobs);
        }
    }
    let done = net.engine(n).paired(&account, &grant).unwrap();
    net.engine(n).set_app_record(ACCOUNT_RECORD, account.as_bytes()).unwrap();
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

// spec/sync.md §10: a dialer's proof shows its node and, through its chain, its account; the
// listener answers with its own proofs to a dialer that proved an actor it knows
#[test]
fn dialer_proves_then_known_listener_answers_spec_sync_10() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, account) = account_node(&mut net, 1, host);
    let b = paired_node(&mut net, 2, host, a, account);
    let (ta, tb) = (net.tid(a), net.tid(b));
    let mut p = dial(&mut net, a);
    let provers = net.sync(b).provers().unwrap();
    let evs = prove(&mut net, a, &mut p, provers);
    assert_eq!(proven(&mut net, a, &p), set(&[tb, account]), "the node and its account");
    let back = proved_by(&evs);
    assert!(back.iter().any(|x| x.actor() == ta && x.accounts == [account]), "the listener's proof: {back:?}");
    assert!(back.iter().all(|x| x.verify(&CHALLENGE, &LISTENER)), "signed for this dialer and this listener");
}

// spec/sync.md §10 (identity only to known actors): a dialer proving only actors the listener
// holds no record of gets no proof back, though what it proved stands
#[test]
fn listener_proves_nothing_to_a_stranger_spec_sync_10() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, _) = account_node(&mut net, 1, host);
    let (s, account) = account_node(&mut net, 3, host);
    let ts = net.tid(s);
    assert!(net.engine(a).core.created(&ts).is_none() && net.engine(a).core.created(&account).is_none(), "strangers to a");
    let mut p = dial(&mut net, a);
    let provers = net.sync(s).provers().unwrap();
    let evs = prove(&mut net, a, &mut p, provers);
    assert_eq!(proved_by(&evs), Vec::new(), "no identity to a stranger");
    assert_eq!(proven(&mut net, a, &p), set(&[ts, account]), "its own chain still proves what it claims");
}

// spec/sync.md §10: a key actor (a link key) proves itself by its signing key, no chain
#[test]
fn key_actor_proved_by_its_signing_key_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let key = SigningSecret::from_seed(&Secret32::from_bytes([9; 32]));
    let record = osis_base::CreationRecord::KeyActor { alg: 1, public_key: key.verifying_key().to_bytes().to_vec(), nonce: [9; 32] };
    let actor = record.tid();
    let mut p = dial(&mut net, a);
    prove(&mut net, a, &mut p, vec![Prover { key, record, accounts: vec![], chain: vec![] }]);
    assert_eq!(proven(&mut net, a, &p), set(&[actor]));
}

// spec/sync.md §10: a proof by a key that is not the record's proves nothing
#[test]
fn forged_key_proves_nothing_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let real = SigningSecret::from_seed(&Secret32::from_bytes([9; 32]));
    let record = osis_base::CreationRecord::KeyActor { alg: 1, public_key: real.verifying_key().to_bytes().to_vec(), nonce: [9; 32] };
    let thief = SigningSecret::from_seed(&Secret32::from_bytes([8; 32]));
    let mut p = dial(&mut net, a);
    let evs = prove(&mut net, a, &mut p, vec![Prover { key: thief, record, accounts: vec![], chain: vec![] }]);
    assert_eq!(proven(&mut net, a, &p), set(&[]));
    assert_eq!(proved_by(&evs), Vec::new());
}

// spec/sync.md §10, spec/wire.md §11.2: a proof signed for another connection's challenge, or for
// another listener, proves nothing here: replay across connections fails
#[test]
fn proof_for_another_session_or_listener_proves_nothing_spec_sync_10() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, account) = account_node(&mut net, 1, host);
    let b = paired_node(&mut net, 2, host, a, account);
    let tb = net.tid(b);
    let provers = net.sync(b).provers().unwrap();
    // proved honestly on one connection
    let mut first = dial(&mut net, a);
    prove(&mut net, a, &mut first, provers.clone());
    assert!(proven(&mut net, a, &first).contains(&tb));
    let captured_good = provers.iter().map(|x| x.sign(&first.hello, &LISTENER)).collect::<Vec<_>>();
    assert!(captured_good.iter().all(|x| x.verify(&first.hello, &LISTENER)), "made for the first connection");
    // the same bytes replayed on a second connection, whose challenge differs
    let second = dial(&mut net, a);
    let answers = prove_raw(&mut net, a, &second, 7, captured_good);
    assert!(answers.iter().any(|m| matches!(m, Message::Proved { proofs, .. } if proofs.is_empty())), "{answers:?}");
    assert_eq!(proven(&mut net, a, &second), set(&[]), "a replayed proof");
    // over this connection's challenge, but for another listener
    let third = dial(&mut net, a);
    let elsewhere: Vec<ActorProof> = provers.iter().map(|x| x.sign(&third.hello, &[0xee; 32])).collect();
    let _ = prove_raw(&mut net, a, &third, 8, elsewhere);
    assert_eq!(proven(&mut net, a, &third), set(&[]), "a proof for another listener");
}

// spec/wire.md §11.2: one Prove per connection, a second is an error and changes nothing
#[test]
fn second_prove_refused_spec_wire_11_2() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let key = SigningSecret::from_seed(&Secret32::from_bytes([9; 32]));
    let record = osis_base::CreationRecord::KeyActor { alg: 1, public_key: key.verifying_key().to_bytes().to_vec(), nonce: [9; 32] };
    let mut p = dial(&mut net, a);
    let first = prove(&mut net, a, &mut p, vec![Prover { key: key.clone(), record: record.clone(), accounts: vec![], chain: vec![] }]);
    assert_eq!(proved_by(&first), vec![], "unknown to a");
    let answers = prove_raw(&mut net, a, &p, 99, Vec::new());
    assert!(answers.contains(&Message::Error { id: 99, code: Code::MALFORMED }), "{answers:?}");
    assert_eq!(proven(&mut net, a, &p), set(&[record.tid()]), "the first stands");
}

// spec/sync.md §10: a chain that does not lead from the proving node to the account proves the
// node alone: an unrelated account's chain, a chain of another node of the account, no chain
#[test]
fn chain_that_does_not_chain_proves_only_the_node_spec_sync_10() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, account) = account_node(&mut net, 1, host);
    let b = paired_node(&mut net, 2, host, a, account);
    let (s, other) = account_node(&mut net, 3, host);
    let ts = net.tid(s);
    // s claims a's account with its own (other account's) chain
    let mut provers = net.sync(s).provers().unwrap();
    provers[0].accounts = vec![account];
    let mut p = dial(&mut net, a);
    prove(&mut net, a, &mut p, provers.clone());
    assert_eq!(proven(&mut net, a, &p), set(&[ts]), "another account's chain");
    // s claims a's account with b's genuine chain: it is b's, not s's
    provers[0].chain = net.engine(b).account_chain(&account).unwrap();
    let mut p = dial(&mut net, a);
    prove(&mut net, a, &mut p, provers.clone());
    assert_eq!(proven(&mut net, a, &p), set(&[ts]), "a chain of another node");
    // no chain at all
    provers[0].chain = Vec::new();
    let mut p = dial(&mut net, a);
    prove(&mut net, a, &mut p, provers.clone());
    assert_eq!(proven(&mut net, a, &p), set(&[ts]), "no chain");
    // garbage chain does not break the exchange
    provers[0].chain = vec![vec![1, 2, 3]];
    let mut p = dial(&mut net, a);
    prove(&mut net, a, &mut p, provers.clone());
    assert_eq!(proven(&mut net, a, &p), set(&[ts]), "bytes that are no commit");
    // and the claim of s's real account still works
    provers[0].accounts = vec![other];
    provers[0].chain = net.engine(s).account_chain(&other).unwrap();
    let mut p = dial(&mut net, a);
    prove(&mut net, a, &mut p, provers);
    assert_eq!(proven(&mut net, a, &p), set(&[ts, other]));
}

// spec/sync.md §10: group data never proves anything: b's chain held at a in full, a Prove
// that shows no chain proves the node alone
#[test]
fn held_group_data_proves_nothing_spec_sync_10() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, account) = account_node(&mut net, 1, host);
    let b = paired_node(&mut net, 2, host, a, account);
    let tb = net.tid(b);
    assert_eq!(net.engine(a).core.timelines.get(&account).unwrap().role(&tb, &account, osis_perm::At::KEYS), Some(Role::Admin), "a holds b's chain");
    let mut provers = net.sync(b).provers().unwrap();
    provers[0].chain = Vec::new();
    let mut p = dial(&mut net, a);
    prove(&mut net, a, &mut p, provers);
    assert_eq!(proven(&mut net, a, &p), set(&[tb]), "the chain was not shown on this connection");
}

// spec/sync.md §10: a removal this node holds closes the proof, though the chain alone shows
// the node (issues/net-shared-set.md Adversaries; until accounts sign)
#[test]
fn removal_held_closes_the_proof_spec_sync_10() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, account) = account_node(&mut net, 1, host);
    let b = paired_node(&mut net, 2, host, a, account);
    let (ta, tb) = (net.tid(a), net.tid(b));
    // the chain as b holds it before its removal
    let provers = net.sync(b).provers().unwrap();
    let rec = recipients_of(net.engine(a), &[(ta, Role::Admin)]);
    remove_holder(net.engine(a), account, tb, &rec, 79);
    let mut p = dial(&mut net, a);
    prove(&mut net, a, &mut p, provers);
    assert_eq!(proven(&mut net, a, &p), set(&[tb]), "b's old chain: its key, not the account");
}

// spec/sync.md §10: a connection whose peer sent no Prove proved nothing, and the listener shows
// nothing of its own unasked
#[test]
fn a_session_with_no_prove_proves_nothing_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let p = dial(&mut net, a);
    assert_eq!(proven(&mut net, a, &p), set(&[]));
    assert_eq!(net.sync(a).proven(ConnId::MAX), None, "no such connection");
}

// spec/sync.md §10: connection proofs run over real dials (no hand driver): the dialing node's
// `proven` gets the listener's actors, the listener's the dialer's, and neither depends on
// which side dialed
#[test]
fn proofs_run_on_a_real_connection_either_way_spec_sync_10() {
    let mut net = Net::new();
    let host = net.add_host();
    let (a, account) = account_node(&mut net, 1, host);
    let b = paired_node(&mut net, 2, host, a, account);
    let (ta, tb) = (net.tid(a), net.tid(b));
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    net.group_at(a, &[(b, Role::Read)], vec![]);
    net.run();
    net.advance(70_000);
    net.run();
    let saw = |net: &mut Net, n: usize, peer: Tid| net.sync(n).proven_connections().iter().any(|(_, p)| p.contains(&peer) && p.contains(&account));
    assert!(saw(&mut net, a, tb), "a saw b prove");
    assert!(saw(&mut net, b, ta), "b saw a prove");
}
