#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Records and the pair key on connections (spec/sync.md §10, Pair key; issues/net-reconnect.md,
//! Resume), and `changed_at` (issues/net-reconnect.md, Changes).

use crate::connection_proofs::{CHALLENGE, Dialer, dial_with, prove, pump};
use crate::net;
use crate::peers::reach_ed;
use net::*;
use osis_base::{LabelId, Role, Tid};
use osis_crypto::kdf::{pair_key, resume_tag, resumed_tag};
use osis_node::sync::ConnId;
use osis_node::sync::records::ConnRecord;
use osis_proto::{ClientEvent, ClientInput, Command, Code, Request};
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
    let (ta, tb) = (net.tid(a), net.tid(b));
    let at_a = records(&mut net, a, tb);
    let at_b = records(&mut net, b, ta);
    assert_eq!((at_a.len(), at_b.len()), (1, 1), "one record each side");
    assert_eq!(at_a[0].r, at_b[0].r, "both hold the same r");
    assert_eq!(at_a[0].actors, [tb], "the record names the proven key actors");
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
    let ta = net.tid(a);
    let r = records(&mut net, b, ta)[0].r;
    let mut p = dial_as(&mut net, a, b, CHALLENGE);
    let tag = resume_tag(&r, &CHALLENGE, &p.hello);
    let (answer, _) = resumed_tag_of(&resume(&mut net, b, &mut p, [5; 32], vec![[1; 32], tag]));
    assert_eq!(answer, Some(resumed_tag(&r, &CHALLENGE, &p.hello)), "the answer shows it holds r");
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
    let ta = net.tid(a);
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
    let ta = net.tid(a);
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
    let ts = net.tid(stranger);
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
    let tag = resume_tag(&r, &[4; 32], &p.hello);
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
    let ta = net.tid(a);
    assert_eq!(records(&mut net, b, ta).len(), 1);
    let r = records(&mut net, b, ta)[0].r;
    let recipients = recipients_of(net.engine(b), &[]);
    remove_holder(net.engine(b), g, ta, &recipients, 3);
    net.run();
    let mut p = dial_as(&mut net, a, b, CHALLENGE);
    let tag = resume_tag(&r, &CHALLENGE, &p.hello);
    assert!(refused(&resume(&mut net, b, &mut p, [5; 32], vec![tag])), "a removed node resumes nothing");
    assert_eq!(net.sync(b).connection_record(p.conn), None);
}

// issues/net-reconnect.md, Resume: two connections of one dialer are one record, the newer takes
// it and the older closes
#[test]
fn two_connections_of_one_dialer_are_one_record_the_older_closing_spec_sync_10() {
    let mut net = Net::new();
    let (a, b) = dialing_pair(&mut net);
    let ta = net.tid(a);
    let r = records(&mut net, b, ta)[0].r;
    let mut first = dial_as(&mut net, a, b, [3; 32]);
    let tag = resume_tag(&r, &[3; 32], &first.hello);
    resume(&mut net, b, &mut first, [5; 32], vec![tag]);
    let id = the_record(&mut net, b, ta);
    assert_eq!(net.sync(b).connection_record(first.conn), Some(id));
    let mut second = dial_as(&mut net, a, b, [4; 32]);
    let tag = resume_tag(&r, &[4; 32], &second.hello);
    let evs = resume(&mut net, b, &mut second, [6; 32], vec![tag]);
    assert_eq!(resumed_tag_of(&evs).0, Some(resumed_tag(&r, &[4; 32], &second.hello)));
    assert_eq!(net.sync(b).connection_record(second.conn), Some(id), "the newer has it");
    assert_eq!(net.sync(b).connection_record(first.conn), None, "the older gave it up");
    assert_eq!(records(&mut net, b, ta).len(), 1, "one record");
    assert!(net.sync(b).proven(first.conn).is_none(), "the older closed");
}

fn peer_routes_up(net: &mut Net, n: usize) -> Vec<ConnId> {
    net.sync(n).proven_connections().into_iter().filter(|(_, p)| !p.is_empty()).map(|(c, _)| c).collect()
}

// the pair of connections two dialers make to each other stays open until one connection record
// carries both directions (issues/net-sync-structure.md (a)): one record, the binding the newer's
#[test]
fn crossing_dials_keep_both_connections_on_one_record() {
    let mut net = Net::new();
    let (a, b) = dialing_pair(&mut net);
    let (ta, tb) = (net.tid(a), net.tid(b));
    reach_ed(&mut net, a);
    net.run();
    assert_eq!(records(&mut net, a, tb).len(), 1, "one record at a");
    assert_eq!(records(&mut net, b, ta).len(), 1, "one record at b");
    assert!(peer_routes_up(&mut net, a).len() >= 2, "both connections stay up");
}

/// (work reading records for Resumes at `n`, others).
fn lookups_with_others(others: u32) -> u64 {
    let mut net = Net::new();
    let (a, b) = dialing_pair(&mut net);
    let ta = net.tid(a);
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
    let tc = net.tid(c);
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
