#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Unjudgeable commits and parts (spec/commits.md §4, notes/expiry-creation-design.md §3): nothing is
//! kept of them but the keys their boxes open and what they await; they are fetched again.

use crate::common::*;
use crate::net;
use net::{Net, s as text};
use osis_base::{Role, Value};
use osis_commit::CommitBlob;
use osis_node::Ingested;
use osis_node::sync::EntryKind;
use osis_schema::core_types as ct;

// spec/commits.md §4 (Unjudgeable), spec/crypto.md (Reading-only secrets): a grant arriving before its
// thing's record is not kept, its box read: the only keys that open the label holding the
// record. Once the record comes the grant is fetched again and applies; the reading-only source goes.
#[test]
fn grant_before_its_record_opens_then_applies_spec_commits_4() {
    let mut lp = net(2, 601);
    lp.sync_all().unwrap();
    let (me, b) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    let mut m = osis_node::Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    m.set(t, &REG, &s("v")).unwrap();
    let rec = lp.peers[0].commit(m).unwrap().unwrap();
    let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
    let g = *lp.peers[0].engine.grant(&t, &b, &edge).unwrap().commits.last().unwrap();
    let pg = lp.peers[0].engine.package(&g).unwrap().unwrap();
    assert!(matches!(lp.deliver(1, &pg).unwrap(), Ingested::Awaits(..)));
    let e = &lp.peers[1].engine;
    assert!(e.pending().is_empty() && !e.commit_ids().contains(&g), "nothing of it kept");
    assert!(e.epochs(&t).is_some_and(|x| x.read.holds_any()), "its box read");
    assert!(!e.reading_sources().is_empty());
    let pr = lp.peers[0].engine.package(&rec).unwrap().unwrap();
    lp.deliver(1, &pr).unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.commit_ids().contains(&g), "fetched again with the record");
    assert_eq!(e.role_on(&t), Some(Role::Read));
    assert!(e.reading_sources().is_empty(), "its last part applied: the reading-only source went");
}

// spec/commits.md §4 (Judged alone): a junk copy under the true commit ID, before the record: nothing
// of it stays, so the true copy is what applies when the record comes.
#[test]
fn junk_before_the_record_keeps_out_nothing_spec_commits_4() {
    let mut lp = net(2, 602);
    let t = new_thing(&mut lp, 0);
    lp.sync_all().unwrap();
    let u = new_thing(&mut lp, 0);
    let mut m = osis_node::Mutation::new();
    m.set(u, &REG, &s("true")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let _ = t;
    let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
    let mut junk = CommitBlob::decode(&pk.bytes).unwrap();
    for p in &mut junk.parts {
        p.delta = osis_base::encode(&Value::List(vec![Value::Bytes(vec![1; 40])]));
    }
    assert!(matches!(lp.peers[1].receive(&junk.encode(), Vec::new()).unwrap(), Ingested::Awaits(..)));
    assert!(matches!(lp.deliver(1, &pk).unwrap(), Ingested::Awaits(..)));
    lp.sync(0, 1).unwrap();
    assert_eq!(lp.peers[1].engine.get(&u, &ak("t:reg.0")).unwrap(), Some(s("true")));
}

// spec/commits.md §4 (Unjudgeable): one pass judges a first sync as a batch, creations first: at n
// and 10n commits nothing is thrown out, so nothing is fetched twice.
#[test]
fn first_sync_batch_throws_nothing_out_spec_commits_4() {
    for n in [20usize, 200] {
        let mut net = Net::new();
        let host = net.add_host();
        let a = net.node(1, &[host]);
        let b = net.node(2, &[host]);
        let g = net.group(a, &[(b, Role::Read)], &[host]);
        let things: Vec<_> = (0..5).map(|i| net.item(a, g, g, &format!("t{i}"))).collect();
        net.set_online(b, false);
        for i in 0..n {
            net.write(a, things[i % things.len()], &format!("v{i}"));
        }
        let before = net.sync(b).pass_stats().awaits;
        net.set_online(b, true);
        net.run();
        assert_eq!(net.read(b, things[(n - 1) % 5]), Some(text(&format!("v{}", n - 1))));
        assert_eq!(net.sync(b).pass_stats().awaits - before, 0, "at {n}");
    }
}

// spec/requirements.md (no unbounded storage from peer input), spec/commits.md §4: an entry
// awaiting a record holds the entry alone: no bytes, no pending row, at n and 10n.
#[test]
fn awaiting_keeps_no_bytes_at_any_size_spec_commits_4() {
    for n in [10u64, 100] {
        let mut x = crate::parts_relay::case();
        let c = x.c;
        let good = crate::parts_relay::plain(&mut x.net, x.a, &c);
        let ids: Vec<_> = (0..n).map(|i| x.give(crate::parts_relay::junk_parts(&good, (i % 251) as u8), c, 1000 + i)).collect();
        let (b, l) = (x.b, x.l);
        let entries = x.net.sync(b).entries(&l);
        let awaiting = entries.iter().filter(|(id, k)| ids.contains(id) && matches!(k, EntryKind::Awaits { .. })).count();
        assert_eq!(awaiting, n as usize, "at {n}");
        assert!(ids.iter().all(|id| !x.net.sync(b).holds_blob(id)), "no bytes kept at {n}");
        assert!(x.net.engine(b).pending().is_empty(), "no pending row at {n}");
    }
}

// spec/requirements.md (no unbounded work from peer input), spec/commits.md §4: a record's arrival wakes
// each entry awaiting it, once and no more, at n and 10n.
#[test]
fn a_record_wakes_each_waiter_once_spec_commits_4() {
    for n in [5u64, 50] {
        let mut x = crate::parts_relay::case();
        let c = x.c;
        let good = crate::parts_relay::plain(&mut x.net, x.a, &c);
        let ids: Vec<_> = (0..n).map(|i| x.give(crate::parts_relay::junk_parts(&good, (i % 251) as u8), c, 1000 + i)).collect();
        let (b, l) = (x.b, x.l);
        let waiting = |x: &mut crate::parts_relay::Case| x.net.sync(b).entries(&l).iter().filter(|(id, k)| ids.contains(id) && matches!(k, EntryKind::Awaits { .. })).count();
        assert_eq!(waiting(&mut x), n as usize, "at {n}");
        let before = x.net.sync(b).pass_stats().awaits;
        x.give_record(9000);
        assert_eq!(waiting(&mut x), 0, "at {n}: woken");
        assert_eq!(x.net.sync(b).pass_stats().awaits, before, "at {n}: none thrown out again");
    }
}

// spec/requirements.md (no unbounded storage from peer input): a commit given directly (an inbox chain,
// a peer) that cannot be judged leaves nothing in memory once no entry holds it.
#[test]
fn awaiting_header_with_no_entry_is_forgotten_spec_commits_4() {
    let mut x = crate::parts_relay::case();
    let c = x.c;
    let good = crate::parts_relay::plain(&mut x.net, x.a, &c);
    let b = x.b;
    assert!(matches!(x.net.engine(b).ingest(&good, Vec::new()).unwrap(), Ingested::Awaits(..)));
    assert_eq!(x.net.engine(b).awaiting_commits(), vec![c]);
    // the record's entry changes the node's state, so the sweep runs; no entry ever held `c`
    x.give_record(600);
    assert!(x.net.engine(b).awaiting_commits().is_empty());
}

// spec/commits.md §4 (Unjudgeable): a commit thrown out whole with parts on two unknown things: either
// record arriving lets its part apply, whichever part the entry names.
#[test]
fn any_awaited_record_applies_its_part_spec_commits_4() {
    for first in [0, 1] {
        let mut lp = net(2, 610 + first as u64);
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let (mut ts, mut recs) = (Vec::new(), Vec::new());
        for _ in 0..2 {
            let mut m = osis_node::Mutation::new();
            ts.push(lp.peers[0].engine.new_thing(&mut m, me));
            m.set(*ts.last().unwrap(), &REG, &s("rec")).unwrap();
            recs.push(lp.peers[0].commit(m).unwrap().unwrap());
        }
        let mut m = osis_node::Mutation::new();
        m.set(ts[0], &REG, &s("both")).unwrap();
        m.set(ts[1], &REG, &s("both")).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        let pc = lp.peers[0].engine.package(&c).unwrap().unwrap();
        assert!(matches!(lp.deliver(1, &pc).unwrap(), Ingested::Awaits(..)));
        let pr = lp.peers[0].engine.package(&recs[first]).unwrap().unwrap();
        lp.deliver(1, &pr).unwrap();
        let e = &mut lp.peers[1].engine;
        assert_eq!(e.get(&ts[first], &ak("t:reg.0")).unwrap(), Some(s("both")), "the part on the thing whose record came");
        assert!(!e.knows(&ts[1 - first]));
    }
}
