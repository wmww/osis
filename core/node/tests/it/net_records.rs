#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Records and the pair key on connections (spec/sync.md §10, Pair key; issues/net-reconnect.md,
//! Resume), and `changed_at` (issues/net-reconnect.md, Changes).

use crate::connection_proofs::{CHALLENGE, Dialer, LISTENER, dial_with, prove, pump};
use crate::net;
use crate::peers::reach_ed;
use net::*;
use osis_base::{LabelId, Role, Tid};
use osis_crypto::kdf::{pair_key, resume_tag, resumed_tag};
use osis_node::sync::ConnId;
use osis_node::sync::records::ConnRecord;
use osis_proto::{ClientEvent, ClientInput, Command, Code, Message, Request};
use std::collections::BTreeSet;
use osis_store::{Record, RecordId};

fn records(net: &mut Net, n: usize, actor: Tid) -> Vec<Record> {
    net.engine(n).run(|tx| Ok(tx.txn.records_of_actors(&[actor])?)).unwrap()
}

/// Node `a` and `b`, co-holders of one group, only `b` dialable: `a` dials `b` alone.
fn dialing_pair(net: &mut Net) -> (usize, usize) {
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach_ed(net, b);
    net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    (a, b)
}

/// Resume on a hand-driven dialer: the events back.
fn resume(net: &mut Net, n: usize, p: &mut Dialer, nonce: [u8; 32], tags: Vec<[u8; 32]>) -> Vec<ClientEvent> {
    let now = net.now();
    let outs = p.cs.handle(now, ClientInput::Command(Command::Resume { nonce, tags }));
    pump(net, n, p, Vec::new(), outs)
}

fn refused(evs: &[ClientEvent]) -> bool {
    evs.iter().any(|e| matches!(e, ClientEvent::Refused { kind: Request::Resume, .. }))
}

fn resumed_tag_of(evs: &[ClientEvent]) -> (Option<[u8; 32]>, [u8; 32]) {
    evs.iter().find_map(|e| if let ClientEvent::Resumed { tag, nonce } = e { Some((*tag, *nonce)) } else { None }).expect("a Resumed answer")
}

// spec/sync.md §10 (Pair key): each side keeps one record of the other, holding the same r, which
// a reconnect finds again rather than making another
#[test]
fn a_reconnect_finds_the_same_record_and_r_spec_sync_10() {
    let mut net = Net::new();
    let (a, b) = dialing_pair(&mut net);
    let (ta, tb) = (net.node_tid(a), net.node_tid(b));
    let at_a = records(&mut net, a, tb);
    let at_b = records(&mut net, b, ta);
    assert_eq!((at_a.len(), at_b.len()), (1, 1), "one record each side");
    assert_eq!(at_a[0].r, at_b[0].r, "both hold the same r");
    assert!(at_a[0].actors.contains(&tb), "the record names the proven key actors");
    net.restart(a, 11);
    net.run();
    let again = records(&mut net, a, tb);
    assert_eq!(again.len(), 1, "no second record after a restart");
    assert_eq!(again[0].r, at_a[0].r, "the same pair key");
    assert_eq!(records(&mut net, b, ta).len(), 1);
}

/// Dials `b` by hand proving `a`'s node key, with a's own provers.
fn dial_as(net: &mut Net, a: usize, b: usize, challenge: [u8; 32]) -> Dialer {
    let mut p = dial_with(net, b, challenge);
    let provers = net.sync(a).provers().unwrap();
    prove(net, b, &mut p, provers);
    p
}

fn the_record(net: &mut Net, n: usize, actor: Tid) -> RecordId {
    let r = records(net, n, actor);
    assert_eq!(r.len(), 1);
    r[0].id
}

// spec/sync.md §10 (Pair key): the listener answers a tag it holds with one only r's holder can
// make, and that record's connection is this one
#[test]
fn a_matching_tag_is_answered_and_takes_the_record_spec_sync_10() {
    let mut net = Net::new();
    let (a, b) = dialing_pair(&mut net);
    let ta = net.node_tid(a);
    let r = records(&mut net, b, ta)[0].r;
    // a's own connection goes first: of two on one record, the hash of their nonces picks which lives
    net.set_online(a, false);
    net.run();
    let mut p = dial_as(&mut net, a, b, CHALLENGE);
    let tag = resume_tag(&r, &LISTENER, &CHALLENGE, &p.hello);
    let (answer, _) = resumed_tag_of(&resume(&mut net, b, &mut p, [5; 32], vec![[1; 32], tag]));
    assert_eq!(answer, Some(resumed_tag(&r, &LISTENER, &CHALLENGE, &p.hello)), "the answer shows it holds r");
    assert_ne!(answer, Some(tag), "an echo of the dialer's own tag would prove nothing");
    assert_eq!(net.sync(b).connection_record(p.conn), Some(the_record(&mut net, b, ta)));
    assert_eq!(records(&mut net, b, ta).len(), 1, "no new record");
}

// spec/sync.md §10 (Pair key): a tag the listener does not hold makes a new record from the two
// nonces on this side alone; the old one stays, for LRU
#[test]
fn a_pair_key_mismatch_makes_a_new_record_from_the_nonces_spec_sync_10() {
    let mut net = Net::new();
    let (a, b) = dialing_pair(&mut net);
    let ta = net.node_tid(a);
    let old = records(&mut net, b, ta)[0].r;
    let mut p = dial_as(&mut net, a, b, CHALLENGE);
    let (answer, theirs) = resumed_tag_of(&resume(&mut net, b, &mut p, [5; 32], vec![[1; 32]]));
    assert_eq!(answer, None, "no tag it holds");
    let held: Vec<[u8; 32]> = records(&mut net, b, ta).iter().map(|r| r.r).collect();
    assert_eq!(held.len(), 2, "the orphan stays for LRU");
    assert!(held.contains(&old));
    assert!(held.contains(pair_key(&[5; 32], &theirs).expose()), "the new r is the nonces' kdf");
}

// spec/sync.md §10 (Pair key): at most one Resume per connection, and only after Prove
#[test]
fn resume_is_once_a_connection_and_only_after_a_prove_spec_sync_10() {
    let mut net = Net::new();
    let (a, b) = dialing_pair(&mut net);
    let ta = net.node_tid(a);
    let mut unproved = dial_with(&mut net, b, [3; 32]);
    assert!(refused(&resume(&mut net, b, &mut unproved, [5; 32], vec![])), "no Prove yet");
    let mut p = dial_as(&mut net, a, b, CHALLENGE);
    let evs = resume(&mut net, b, &mut p, [5; 32], vec![]);
    assert!(resumed_tag_of(&evs).0.is_none());
    let before = records(&mut net, b, ta).len();
    assert!(refused(&resume(&mut net, b, &mut p, [6; 32], vec![])), "a second is an error");
    assert_eq!(records(&mut net, b, ta).len(), before, "and makes nothing");
    let code = resume(&mut net, b, &mut p, [7; 32], vec![]).into_iter().find_map(|e| if let ClientEvent::Refused { code, .. } = e { Some(code) } else { None });
    assert_eq!(code, Some(Code::MALFORMED));
}

// issues/net-reconnect.md, Resume: a connection that proved no known actor gets no record: it is
// refused and leaves nothing
#[test]
fn a_stranger_gets_no_record_spec_sync_10() {
    let mut net = Net::new();
    let (_a, b) = dialing_pair(&mut net);
    let stranger = net.node(9, &[]);
    let ts = net.node_tid(stranger);
    let mut p = dial_as(&mut net, stranger, b, [4; 32]);
    assert!(refused(&resume(&mut net, b, &mut p, [5; 32], vec![])));
    assert!(records(&mut net, b, ts).is_empty());
    assert_eq!(net.sync(b).connection_record(p.conn), None);
}

// issues/net-shared-set.md step 3: a chain-proved account resumes nothing: only a key actor
// proved by its own key counts, so a node whose only tie to the verifier is its account chain
// makes and finds no record, even for a record naming that account
#[test]
fn a_chain_proved_account_resumes_nothing_spec_sync_10() {
    let mut net = Net::new();
    let host = net.add_host();
    let (x, account) = crate::connection_proofs::account_node(&mut net, 11, host);
    let b = net.node(2, &[host]);
    // b holds nothing of x: the account stands by the chain in the proof alone
    let r = [8; 32];
    let id = net.engine(b).run(|tx| Ok(tx.txn.record_create(r, &[account])?)).unwrap();
    let mut p = dial_as(&mut net, x, b, [4; 32]);
    let proved = net.sync(b).proven(p.conn).unwrap();
    assert!(proved.contains(&account), "the chain did prove the account");
    let tag = resume_tag(&r, &LISTENER, &[4; 32], &p.hello);
    assert!(refused(&resume(&mut net, b, &mut p, [5; 32], vec![tag])), "not known by its own key");
    assert_eq!(net.sync(b).connection_record(p.conn), None);
    assert_eq!(records(&mut net, b, account).len(), 1, "the account's record is untouched");
    assert_eq!(records(&mut net, b, account)[0].id, id);
}

// issues/net-reconnect.md, Adversaries: a node removed from every roster held here no longer
// resumes its record
#[test]
fn a_removed_node_no_longer_resumes_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach_ed(&mut net, b);
    let g = net.group_at(b, &[(a, Role::Write)], vec![]);
    net.run();
    let ta = net.node_tid(a);
    assert_eq!(records(&mut net, b, ta).len(), 1);
    let r = records(&mut net, b, ta)[0].r;
    let holder = net.tid(a);
    let recipients = recipients_of(net.engine(b), &[]);
    remove_holder(net.engine(b), g, holder, &recipients, 3);
    net.run();
    let mut p = dial_as(&mut net, a, b, CHALLENGE);
    let tag = resume_tag(&r, &LISTENER, &CHALLENGE, &p.hello);
    assert!(refused(&resume(&mut net, b, &mut p, [5; 32], vec![tag])), "a removed node resumes nothing");
    assert_eq!(net.sync(b).connection_record(p.conn), None);
}

// issues/net-reconnect.md, Resume: two connections of one dialer are one record, the smaller
// `connection_order` keeps it and the other closes, on one end, whatever order they arrive
#[test]
fn two_connections_of_one_dialer_are_one_record_one_closing_spec_sync_10() {
    let mut net = Net::new();
    let (a, b) = dialing_pair(&mut net);
    let ta = net.node_tid(a);
    let r = records(&mut net, b, ta)[0].r;
    net.set_online(a, false);
    net.run();
    let mut first = dial_as(&mut net, a, b, [3; 32]);
    let tag = resume_tag(&r, &LISTENER, &[3; 32], &first.hello);
    resume(&mut net, b, &mut first, [5; 32], vec![tag]);
    let id = the_record(&mut net, b, ta);
    assert_eq!(net.sync(b).connection_record(first.conn), Some(id));
    let mut second = dial_as(&mut net, a, b, [4; 32]);
    let tag = resume_tag(&r, &LISTENER, &[4; 32], &second.hello);
    let evs = resume(&mut net, b, &mut second, [6; 32], vec![tag]);
    assert_eq!(resumed_tag_of(&evs).0, Some(resumed_tag(&r, &LISTENER, &[4; 32], &second.hello)));
    assert_eq!(records(&mut net, b, ta).len(), 1, "one record");
    let (kept, gone) = if osis_crypto::kdf::connection_order(&r, &[3; 32], &first.hello) < osis_crypto::kdf::connection_order(&r, &[4; 32], &second.hello) { (first.conn, second.conn) } else { (second.conn, first.conn) };
    assert_eq!(net.sync(b).connection_record(kept), Some(id), "the smaller has it");
    assert!(net.sync(b).proven(gone).is_none(), "the other closed");
}

fn peer_routes_up(net: &mut Net, n: usize) -> Vec<ConnId> {
    net.sync(n).proven_connections().into_iter().filter(|(_, p)| !p.is_empty()).map(|(c, _)| c).collect()
}

// spec/sync.md §10 (Shared set): two connections of one pair are one, whoever dialed each:
// crossing dials leave one record on each side and one connection, which stays without a redial
#[test]
fn crossing_dials_leave_one_connection_per_pair_spec_sync_10() {
    let mut net = Net::new();
    let (a, b) = dialing_pair(&mut net);
    let (ta, tb) = (net.node_tid(a), net.node_tid(b));
    reach_ed(&mut net, a);
    net.run();
    assert_eq!(records(&mut net, a, tb).len(), 1, "one record at a");
    assert_eq!(records(&mut net, b, ta).len(), 1, "one record at b");
    assert_eq!(peer_routes_up(&mut net, a).len(), 1, "one connection at a");
    assert_eq!(peer_routes_up(&mut net, b).len(), 1, "one connection at b");
    let dials = net.dialed.len();
    let retry = net.sync(a).config().peer_retry_ms;
    for _ in 0..3 {
        net.advance(retry);
    }
    assert_eq!((peer_routes_up(&mut net, a).len(), peer_routes_up(&mut net, b).len()), (1, 1), "it stays the one");
    assert_eq!(net.dialed.len(), dials, "the side whose connection closed does not dial again");
}

/// (work reading records for Resumes at `n`, others).
fn lookups_with_others(others: u32) -> u64 {
    let mut net = Net::new();
    let (a, b) = dialing_pair(&mut net);
    let ta = net.node_tid(a);
    net.engine(b).run(|tx| {
        for i in 0..others {
            let mut x = [0u8; 15];
            x[..4].copy_from_slice(&i.to_be_bytes());
            tx.txn.record_create([1; 32], &[Tid::from_bytes(x)])?;
        }
        Ok(())
    }).unwrap();
    assert_eq!(records(&mut net, b, ta).len(), 1);
    let start = net.sync(b).record_lookups();
    let mut p = dial_as(&mut net, a, b, CHALLENGE);
    resume(&mut net, b, &mut p, [5; 32], vec![]);
    net.sync(b).record_lookups() - start
}

// the work of a Resume is the records of its actors, not the node's records
#[test]
fn a_resume_costs_the_records_of_its_actors_not_all_records() {
    assert_eq!(lookups_with_others(10), 1);
    assert_eq!(lookups_with_others(100), 1, "10x the records, the same reads");
}

// issues/net-shared-set.md, Testing: acked_pos rises to min(ack, tested), only with no Offer
// unanswered; a re-mark puts tested below the member and the peer's ack stands
#[test]
fn acked_rises_only_past_a_finished_test() {
    let id = [1; 16];
    let mut c = ConnRecord::new(id, 10);
    c.ack = 50;
    c.tested = 40;
    assert_eq!(c.rise_to(), Some(40));
    c.offers_unanswered = 1;
    assert_eq!(c.rise_to(), None, "an Offer unanswered holds it");
    c.offers_unanswered = 0;
    c.remark(30);
    assert_eq!(c.tested, 29);
    assert_eq!(c.ack, 50, "the peer's ack stands");
    assert_eq!(c.rise_to(), Some(29));
}

fn changed(net: &mut Net, n: usize, l: LabelId) -> Option<u64> {
    net.engine(n).run(|tx| Ok(tx.txn.changed_at(&l)?)).unwrap()
}

// issues/net-reconnect.md, Changes: a role change on the thing moves its changed_at; an ordinary
// write and a restart with nothing changed do not, and append nothing
#[test]
fn changed_at_moves_on_a_role_change_only() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Write)], &[host]);
    net.run();
    let l = net.label(a);
    let first = changed(&mut net, a, l).expect("a held label has a changed_at");
    let t = net.item(a, g, g, "x");
    net.run();
    assert_eq!(changed(&mut net, a, l), Some(first), "a write is no change");
    let end = net.engine(a).run(|tx| Ok(tx.txn.log_end()?)).unwrap();
    net.write(a, t, "y");
    net.run();
    assert_eq!(changed(&mut net, a, l), Some(first));
    net.restart(a, 11);
    net.run();
    assert_eq!(changed(&mut net, a, l), Some(first), "a restart with nothing changed");
    let _ = end;
    let c = net.node(3, &[host]);
    let tc = net.node_tid(c);
    set_edge(net.engine(a), g, tc, Role::Read);
    net.run();
    let moved = changed(&mut net, a, l).unwrap();
    assert!(moved > first, "a role change moves it");
    assert!(net.engine(a).run(|tx| Ok(tx.txn.changed_after(first, 10)?)).unwrap().iter().any(|(p, x)| *p == moved && *x == l));
}

// issues/net-reconnect.md, Changes: a role change that reaches a thing through a roster moves it
#[test]
fn changed_at_moves_when_a_holder_reaches_it_through_a_roster() {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let g = net.group(a, &[], &[host]);
    net.run();
    let l = net.label(a);
    let h = net.group(a, &[], &[host]);
    set_edge(net.engine(a), g, h, Role::Read);
    net.run();
    let before = changed(&mut net, a, l).unwrap();
    let x = net.node(3, &[host]);
    let tx_ = net.tid(x);
    set_edge(net.engine(a), h, tx_, Role::Read);
    net.run();
    assert!(changed(&mut net, a, l).unwrap() > before, "x now reaches g through h");
}

// spec/sync.md §10 (Pair key): a tag names the listener it was made for, like a connection proof:
// one made for a connection to another node (a node between relaying it) finds nothing
#[test]
fn a_tag_made_for_another_listener_finds_nothing_spec_sync_10() {
    let mut net = Net::new();
    let (a, b) = dialing_pair(&mut net);
    let ta = net.node_tid(a);
    let r = records(&mut net, b, ta)[0].r;
    let mut p = dial_as(&mut net, a, b, CHALLENGE);
    let relayed = resume_tag(&r, &[0x99; 32], &CHALLENGE, &p.hello);
    let (answer, _) = resumed_tag_of(&resume(&mut net, b, &mut p, [5; 32], vec![relayed]));
    assert_eq!(answer, None, "a tag bound to another listener is no tag here");
    assert_eq!(records(&mut net, b, ta).len(), 2, "the old record untouched, a new one made");
}

// spec/sync.md §10 (Pair key): the dialer checks the answer: its own tag echoed back finds
// nothing, and it makes a new record rather than trusting the claim
#[test]
fn an_echoed_answer_finds_nothing_end_to_end_spec_sync_10() {
    let mut net = Net::new();
    let (a, b) = dialing_pair(&mut net);
    let tb = net.node_tid(b);
    let old = records(&mut net, a, tb)[0].r;
    let listed = std::rc::Rc::new(std::cell::Cell::new(None));
    let seen = listed.clone();
    net.tamper = Some(Box::new(move |m| match m {
        Message::Resume { tags, .. } => {
            seen.set(tags.first().copied());
            None
        }
        Message::Resumed { id, nonce, .. } => Some(Message::Resumed { id: *id, nonce: *nonce, tag: seen.get() }),
        _ => None,
    }));
    net.restart(a, 11);
    net.run();
    assert!(listed.get().is_some(), "the dialer listed its record");
    let held = records(&mut net, a, tb);
    assert_eq!(held.len(), 2, "a new record beside the old one");
    assert!(held.iter().any(|r| r.r == old));
    let conn = peer_routes_up(&mut net, a).pop().expect("connected");
    let bound = net.sync(a).connection_record(conn).expect("a record");
    assert_ne!(net.engine(a).run(|tx| Ok(tx.txn.record(&bound)?)).unwrap().unwrap().r, old, "not the record the echo named");
}

// spec/sync.md §10 (Pair key): a LAN route replacing a running connection resumes the record,
// one record however many routes it ran over
#[test]
fn a_lan_switch_keeps_one_record_spec_sync_10() {
    let mut net = Net::new();
    let a = net.node(1, &[]);
    let b = net.node(2, &[]);
    reach_ed(&mut net, a);
    reach_ed(&mut net, b);
    net.group_at(a, &[(b, Role::Write)], vec![]);
    net.run();
    let (ta, tb) = (net.node_tid(a), net.node_tid(b));
    let rs = |net: &mut Net, n, actor| -> Vec<[u8; 32]> { records(net, n, actor).iter().map(|r| r.r).collect() };
    let (at_a, at_b) = (rs(&mut net, a, tb), rs(&mut net, b, ta));
    let lk = osis_crypto::SigningSecret::from_seed(&net.sync(b).lan_secret()).verifying_key().to_bytes();
    net.lan_keys.insert(lk, b);
    let ann = net.sync(b).lan_announcement(lk, 5000).unwrap();
    let (_, acts) = net.sync(a).lan_seen(&ann, "192.168.3.4:47380".parse().unwrap());
    net.actions(a, acts);
    net.settle(100_000);
    let (mut a2, mut b2) = (rs(&mut net, a, tb), rs(&mut net, b, ta));
    let sorted = |mut v: Vec<[u8; 32]>| { v.sort(); v };
    a2.sort();
    b2.sort();
    assert_eq!(a2, sorted(at_a), "no new record at a");
    assert_eq!(b2, sorted(at_b), "no new record at b");
}

// issues/net-reconnect.md, Restart and loss: a copy of a store running beside the original
// resumes the same record at the live peer, one record there, and each connection's record is r
#[test]
fn a_copied_store_resumes_the_same_record_at_a_live_peer_spec_sync_10() {
    let mut net = Net::new();
    let (a, b) = dialing_pair(&mut net);
    let ta = net.node_tid(a);
    let r = records(&mut net, b, ta)[0].r;
    let copy = net.copy_node(a, 21);
    net.run();
    net.advance(60_000);
    let at_b: Vec<[u8; 32]> = records(&mut net, b, ta).iter().map(|x| x.r).collect();
    assert_eq!(at_b, [r], "one record at the live peer, the copy found it");
    let tb = net.node_tid(b);
    assert_eq!(records(&mut net, copy, tb)[0].r, r, "the copy holds the same r");
}

// issues/net-reconnect.md, Changes: a holder reaching a sync ID through a cycle of rosters is seen
// from every member of the cycle, whichever the pass reached first
#[test]
fn changed_at_moves_through_a_cycle_of_rosters() {
    for grant_on_second in [false, true] {
        let mut net = Net::new();
        let host = net.add_host();
        let a = net.node(1, &[host]);
        let g = net.group(a, &[], &[host]);
        net.run();
        let lg = net.label(a);
        let h = net.group_seeded(a, &[], vec![net.address(host)], 2);
        net.run();
        set_edge(net.engine(a), g, h, Role::Read);
        set_edge(net.engine(a), h, g, Role::Read);
        net.run();
        let labels = net.sync(a).label_status();
        let lof = |t: Tid| labels.iter().find(|s| s.group == t).map(|s| s.label).unwrap();
        let (lg2, lh2) = (lof(g), lof(h));
        assert_eq!(lg, lg2);
        let before = (changed(&mut net, a, lg2).unwrap(), changed(&mut net, a, lh2).unwrap());
        let x = net.node(3, &[host]);
        let tx_ = net.tid(x);
        set_edge(net.engine(a), if grant_on_second { h } else { g }, tx_, Role::Read);
        net.run();
        assert!(changed(&mut net, a, lg2).unwrap() > before.0, "g's sync ID moved (grant on {})", if grant_on_second { "h" } else { "g" });
        assert!(changed(&mut net, a, lh2).unwrap() > before.1, "h's sync ID moved (grant on {})", if grant_on_second { "h" } else { "g" });
    }
}

/// The invariant at every connection: a bound record exists at both ends with one r, and at the
/// moment it was found the connection had proved a known actor on it, named by the record.
fn check_resume_invariant(net: &mut Net, seen: &mut BTreeSet<(usize, u64, ConnId, RecordId)>) -> usize {
    let mut bound = 0;
    let nodes = net.nodes.len();
    for n in 0..nodes {
        let conns: Vec<(ConnId, BTreeSet<Tid>)> = net.sync(n).proven_connections();
        for (c, proved) in conns {
            let Some(id) = net.sync(n).connection_record(c) else { continue };
            bound += 1;
            let rec = net.engine(n).run(|tx| Ok(tx.txn.record(&id)?)).unwrap().unwrap_or_else(|| panic!("{n}: a connection bound to a record it does not hold"));
            let Some((m, pc)) = net.peer_of(n, c) else { continue };
            if let Some(pid) = net.sync(m).connection_record(pc) {
                let prec = net.engine(m).run(|tx| Ok(tx.txn.record(&pid)?)).unwrap().unwrap_or_else(|| panic!("{m}: bound to a record it does not hold"));
                assert_eq!(rec.r, prec.r, "the two ends of connection ({n},{c:?})-({m},{pc:?}) hold different r");
            }
            if seen.insert((n, net.nodes[n].life, c, id)) {
                assert!(rec.actors.iter().any(|a| proved.contains(a)), "{n}: record {:?} names no actor this connection proved", rec.actors);
                for actor in &rec.actors {
                    assert!(proved.contains(actor), "{n}: record names {actor:?}, not proved here");
                    assert!(net.engine(n).core.judge([*actor]).known(), "{n}: record names {actor:?}, not known here");
                }
            }
        }
    }
    bound
}

/// A hand-driven dialer as some node of `all` to `j`, listing that node's records of `j`'s actors,
/// none of them, or a made-up tag: whatever the listener answers must follow the rule.
fn hand_resume(net: &mut Net, j: usize, all: &[usize], x: &mut u64) {
    let i = all[(xorshift(x) as usize) % all.len()];
    if i == j {
        return;
    }
    let (ti, tj) = (net.node_tid(i), net.node_tid(j));
    let mut ch = [0u8; 32];
    ch[..8].copy_from_slice(&xorshift(x).to_be_bytes());
    let mut p = dial_as(net, i, j, ch);
    let held = net.engine(i).run(|tx| Ok(tx.txn.records_of_actors(&[tj])?)).unwrap();
    let tags: Vec<[u8; 32]> = match xorshift(x) % 3 {
        0 => held.iter().map(|r| resume_tag(&r.r, &LISTENER, &ch, &p.hello)).collect(),
        1 => Vec::new(),
        _ => vec![[xorshift(x) as u8; 32]],
    };
    let nonce = [xorshift(x) as u8; 32];
    let evs = resume(net, j, &mut p, nonce, tags.clone());
    let Some(bound) = net.sync(j).connection_record(p.conn) else {
        // unbound: not known, refused, or the connection this one lost to of a record it shares
        assert!(!net.engine(j).core.judge([ti]).known() || refused(&evs) || evs.is_empty() || net.sync(j).proven(p.conn).is_none(), "a known dialer unbound");
        return;
    };
    let (answer, theirs) = resumed_tag_of(&evs);
    let rec = net.engine(j).run(|tx| Ok(tx.txn.record(&bound)?)).unwrap().expect("bound to a held record");
    assert!(net.engine(j).core.judge([ti]).known(), "a stranger's connection took a record");
    assert!(rec.actors.contains(&ti), "the record names no actor this connection proved");
    match answer {
        Some(t) => {
            let listed = held.iter().find(|r| tags.contains(&resume_tag(&r.r, &LISTENER, &ch, &p.hello)) && resumed_tag(&r.r, &LISTENER, &ch, &p.hello) == t);
            assert!(listed.is_some_and(|r| r.r == rec.r), "an answer for a record the dialer did not list");
        }
        None => assert_eq!(&rec.r, pair_key(&nonce, &theirs).expose(), "no answer, yet not a new record from the nonces"),
    }
}

fn xorshift(x: &mut u64) -> u64 {
    *x ^= *x << 13;
    *x ^= *x >> 7;
    *x ^= *x << 17;
    *x
}

/// One randomized history over three nodes: restarts, a side losing its records, a holder removed
/// and granted again. The invariant is checked after each step; returns how many connections were
/// bound.
fn resume_history(seed: u64) -> usize {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut net = Net::new();
    let nodes: Vec<usize> = (0..3).map(|i| net.node(100 * seed + i + 1, &[])).collect();
    // a fourth node in no group: known to nobody, an adversary's dialer
    let mut all = nodes.clone();
    all.push(net.node(100 * seed + 9, &[]));
    for n in &nodes {
        reach_ed(&mut net, *n);
    }
    let mut groups = Vec::new();
    for (i, (p, q)) in [(0, 1), (0, 2), (1, 2)].into_iter().enumerate() {
        let g = net.group_seeded(nodes[p], &[(nodes[q], Role::Write)], vec![], i as u64 + 1);
        groups.push((g, nodes[p], nodes[q]));
    }
    net.run();
    let mut seen = BTreeSet::new();
    let mut bound = check_resume_invariant(&mut net, &mut seen);
    for step in 0..14 {
        let (g, admin, holder) = groups[(xorshift(&mut x) % 3) as usize];
        let n = nodes[(xorshift(&mut x) % 3) as usize];
        match xorshift(&mut x) % 6 {
            0 => net.restart(n, seed * 1000 + step),
            1 => {
                let conns: Vec<ConnId> = net.sync(n).proven_connections().into_iter().map(|(c, _)| c).collect();
                let in_use: BTreeSet<RecordId> = conns.iter().filter_map(|c| net.sync(n).connection_record(*c)).collect();
                net.engine(n).run(|tx| Ok(tx.txn.records_evict(0, &in_use)?)).unwrap();
            }
            2 => {
                let t = net.node_tid(holder);
                let recipients = recipients_of(net.engine(admin), &[]);
                remove_holder(net.engine(admin), g, t, &recipients, seed * 1000 + step);
            }
            3 => {
                let t = net.node_tid(holder);
                set_edge(net.engine(admin), g, t, Role::Write);
            }
            4 => hand_resume(&mut net, nodes[(xorshift(&mut x) % 3) as usize], &all, &mut x),
            _ => net.restart(n, seed * 1000 + step),
        }
        net.run();
        net.advance(60_000);
        bound += check_resume_invariant(&mut net, &mut seen);
    }
    bound
}

fn resume_replay(seed: u64) -> String {
    format!("OSIS_RESUME_START={seed} OSIS_RESUME_SEEDS=1 cargo test -p osis-node --test it -- --ignored net_records::resume_invariant_random_large")
}

// spec/sync.md §10 (Pair key): over restarts, lost records, removed and re-added holders, no
// connection resumes a record unless both ends hold it and it proved a known actor there
#[test]
fn no_connection_resumes_a_record_without_proof_and_a_shared_r_spec_sync_10() {
    let seeds: Vec<u64> = (1..=12).collect();
    let bound: usize = osis_base::testenv::run_seeds("net_records::resume_invariant", &seeds, false, resume_replay, resume_history).into_iter().sum();
    assert!(bound > 0, "the histories bound no connection");
}

// the same at larger size, on a fresh range
#[test]
#[ignore]
fn resume_invariant_random_large() {
    let range = osis_base::testenv::Seeds::from_env("OSIS_RESUME_START", "OSIS_RESUME_SEEDS", osis_base::testenv::large(1..401));
    range.announce("net_records::resume_invariant_random_large");
    let seeds: Vec<u64> = range.range.clone().collect();
    let bound: usize = osis_base::testenv::run_seeds("net_records::resume_invariant", &seeds, true, resume_replay, resume_history).into_iter().sum();
    assert!(bound > 0, "the histories bound no connection");
}

/// (changed_at passes, labels fingerprinted) for one role change at a node holding `n` groups.
fn stamp_work(n: u64) -> (u64, u64) {
    let mut net = Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let addr = net.address(host);
    let mut last = None;
    for i in 0..n {
        last = Some(net.group_seeded(a, &[], vec![addr.clone()], i + 1));
    }
    net.run();
    let t0 = net.sync(a).pass_stats();
    let x = net.node(3, &[host]);
    let tx_ = net.tid(x);
    set_edge(net.engine(a), last.unwrap(), tx_, Role::Read);
    net.run();
    let t1 = net.sync(a).pass_stats();
    (t1.changed_passes - t0.changed_passes, t1.changed_labels - t0.changed_labels)
}

// issues/net-reconnect.md, Changes: a role change is one pass over the node's sync IDs, whatever
// the node holds: linear in sync IDs, never a pass per sync ID
#[test]
fn a_role_change_is_one_pass_over_the_sync_ids() {
    assert_eq!(stamp_work(4), (1, 5));
    assert_eq!(stamp_work(40), (1, 41));
}
