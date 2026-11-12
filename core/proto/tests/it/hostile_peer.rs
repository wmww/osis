//! A misbehaving peer against a `ClientSession` (spec/requirements.md: "Peer input never causes
//! unbounded allocation, work, storage or diagnostics"): replies scripted frame by frame.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_proto::*;

const T0: u64 = 1_700_000_000_000;

fn ready() -> ClientSession {
    let mut c = ClientSession::new(ClientConfig { peer_static_key: [1; 32], challenge: [2; 32] });
    c.handle(T0, ClientInput::Start);
    c.handle(T0, ClientInput::Bytes(encode_frame(&Hello::new(T0, [3; 32]).encode())));
    c
}

fn sent(out: &[ClientOutput]) -> Vec<Message> {
    out.iter().filter_map(|o| if let ClientOutput::Send(f) = o { Message::decode(&f[4..]).ok() } else { None }).collect()
}

fn reply(c: &mut ClientSession, m: Message) -> Vec<ClientOutput> {
    c.handle(T0, ClientInput::Bytes(encode_frame(&m.encode())))
}

fn prover(seed: u8) -> Prover {
    let key = osis_crypto::SigningSecret::from_seed(&osis_crypto::Secret32::from_bytes([seed; 32]));
    let record = osis_base::CreationRecord::KeyActor { alg: 1, public_key: key.verifying_key().to_bytes().to_vec(), nonce: [seed; 32], account: false };
    Prover { key, record }
}

fn prove(c: &mut ClientSession) -> u32 {
    let out = c.handle(T0, ClientInput::Command(Command::Prove(vec![prover(1)])));
    sent(&out).iter().find_map(|m| if let Message::Prove { id, .. } = m { Some(*id) } else { None }).unwrap()
}

fn proved_of(out: &[ClientOutput]) -> Vec<ActorProof> {
    out.iter().find_map(|o| if let ClientOutput::Event(ClientEvent::Proved { proofs }) = o { Some(proofs.clone()) } else { None }).expect("a Proved event")
}

// spec/sync.md §10, spec/wire.md §11.2 (Prove): the dialer's first frames sign the listener's Hello
// challenge and the key it dialed; `Prove` goes only after that Hello
#[test]
fn prove_signs_the_listeners_challenge_spec_sync_10() {
    let mut c = ClientSession::new(ClientConfig { peer_static_key: [1; 32], challenge: [2; 32] });
    c.handle(T0, ClientInput::Start);
    let queued = c.handle(T0, ClientInput::Command(Command::Prove(vec![prover(1)])));
    assert!(sent(&queued).is_empty(), "no proof before the listener's Hello: it has no challenge to sign");
    let out = c.handle(T0, ClientInput::Bytes(encode_frame(&Hello::new(T0, [3; 32]).encode())));
    let proofs = sent(&out).into_iter().find_map(|m| if let Message::Prove { proofs, .. } = m { Some(proofs) } else { None }).expect("sent once ready");
    assert!(proofs[0].verify(false, &[3; 32], &[1; 32]), "over the listener's challenge and static key");
    assert!(!proofs[0].verify(false, &[2; 32], &[1; 32]), "not over this side's own");
}

// spec/sync.md §10: the listener's proofs must sign this side's challenge and the key it dialed,
// so a proof made for another connection (a replay), another dialer's challenge or another
// listener (a relaying peer's) proves nothing here, and a proof that does counts
#[test]
fn listener_proof_binds_this_connection_spec_sync_10() {
    let good = prover(5).sign(true, &[2; 32], &[1; 32]);
    for (case, bad) in [("replayed", prover(6).sign(true, &[0xaa; 32], &[1; 32])), ("another listener", prover(7).sign(true, &[2; 32], &[0xbb; 32])), ("reflected role", prover(8).sign(false, &[2; 32], &[1; 32]))] {
        for (proofs, want) in [(vec![good.clone(), bad.clone()], vec![good.clone()]), (vec![bad, good.clone()], vec![])] {
            let mut c = ready();
            let rid = prove(&mut c);
            let out = reply(&mut c, Message::Proved { id: rid, proofs });
            assert_eq!(proved_of(&out), want, "{case}: checking stops at the first bad proof (spec/wire.md §11.2)");
        }
    }
}

// spec/wire.md §11.2 (Prove): an empty Proved (a listener proving nothing to this dialer) is
// an answer like any other, not an error
#[test]
fn empty_proved_is_an_answer_spec_wire_11_2() {
    let mut c = ready();
    let rid = prove(&mut c);
    let out = reply(&mut c, Message::Proved { id: rid, proofs: vec![] });
    assert_eq!(proved_of(&out), vec![]);
    assert!(!out.iter().any(|o| matches!(o, ClientOutput::Close)));
}
