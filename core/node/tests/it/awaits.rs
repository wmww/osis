#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Unjudgeable commits and parts (spec/commits.md §4, notes/expiry-creation-design.md §3): nothing is
//! kept of them but the keys their boxes open and what they await; they are fetched again.

use crate::common::*;
use crate::net;
use net::s as text;
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
    let mut lp = net(2, 0);
    lp.sync_all().unwrap();
    let (me, b) = (lp.peers[0].engine.me(), lp.peers[1].engine.me());
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
    let mut lp = net(2, 0);
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
        let (mut net, _, [a, b], _, things) = net::hosted::<2, 5>(&[(1, Role::Read)], ["t0", "t1", "t2", "t3", "t4"], false);
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

// spec/requirements.md (no unbounded storage or work from peer input), spec/commits.md §4: an
// entry awaiting a record holds the entry alone: no bytes, no pending row; a record's arrival
// wakes each entry awaiting it, once and no more; at n and 10n.
#[test]
fn a_record_wakes_each_waiter_once_spec_commits_4() {
    for n in [10u64, 100] {
        let mut x = crate::parts_relay::case();
        let c = x.c;
        let good = crate::parts_relay::plain(&mut x.net, x.a, &c);
        let ids: Vec<_> = (0..n).map(|i| x.give(crate::parts_relay::junk_parts(&good, (i % 251) as u8), c, 1000 + i)).collect();
        let (b, l) = (x.b, x.l);
        let waiting = |x: &mut crate::parts_relay::Case| x.net.sync(b).entries(&l).iter().filter(|(id, k)| ids.contains(id) && matches!(k, EntryKind::Awaits { .. })).count();
        assert_eq!(waiting(&mut x), n as usize, "at {n}");
        assert!(ids.iter().all(|id| !x.net.sync(b).holds_blob(id)), "no bytes kept at {n}");
        assert!(x.net.engine(b).pending().is_empty(), "no pending row at {n}");
        let before = x.net.sync(b).pass_stats().awaits;
        x.give_record(9000);
        assert_eq!(waiting(&mut x), 0, "at {n}: woken");
        assert_eq!(x.net.sync(b).pass_stats().awaits, before, "at {n}: none thrown out again");
    }
}

// spec/commits.md §4 (Unjudgeable): a commit thrown out whole with parts on two unknown things: either
// record arriving lets its part apply, whichever part the entry names.
#[test]
fn any_awaited_record_applies_its_part_spec_commits_4() {
    for first in [0, 1] {
        let mut lp = net(2, 0);
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.me();
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

// spec/commits.md §4 (Unjudgeable): a commit whose every part is unjudgeable is thrown out, never
// pending, though its `ts` is past `MAX_DRIFT` ahead: nothing of it is kept, and it comes again
// with the record it awaits.
#[test]
fn unjudgeable_ahead_is_thrown_out_not_pending_spec_commits_4() {
    let mut lp = net(2, 0);
    lp.sync_all().unwrap();
    let me = lp.peers[0].engine.me();
    let mut m = osis_node::Mutation::new();
    let p = lp.peers[0].engine.new_thing(&mut m, me);
    let rp = lp.peers[0].commit(m).unwrap().unwrap();
    lp.peers[0].clock.advance(3 * osis_base::format::MAX_DRIFT_MS);
    let mut m = osis_node::Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, p);
    m.set(t, &REG, &s("ahead")).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let pc = lp.peers[0].engine.package(&c).unwrap().unwrap();
    assert!(matches!(lp.deliver(1, &pc).unwrap(), Ingested::Awaits(..)), "its chain is unknown");
    assert!(lp.peers[1].engine.pending().is_empty(), "nothing of it kept");
    lp.peers[1].clock.advance(3 * osis_base::format::MAX_DRIFT_MS);
    lp.peers[1].reexamine().unwrap();
    assert!(lp.peers[1].engine.pending().is_empty() && !lp.peers[1].engine.knows(&t));
    let pr = lp.peers[0].engine.package(&rp).unwrap().unwrap();
    lp.deliver(1, &pr).unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("ahead")), "fetched again with the record");
}

// spec/commits.md §4 (Unjudgeable): a commit thrown out whole, one part on a thing whose record is
// unknown, the other on a known thing its author does not reach yet: the grant that reaches it
// lets that part apply, whichever wait the entry names.
#[test]
fn reach_arriving_applies_its_part_spec_commits_4() {
    let mut named = std::collections::BTreeSet::new();
    // the entry names the wait of the part first in the commit's order: t's record before or
    // after u's reach
    for t_first in [false, true] {
        let mut lp = net(3, 0);
        lp.sync_all().unwrap();
        let w = lp.peers[2].engine.me();
        let u = new_thing(&mut lp, 0);
        lp.sync(0, 1).unwrap();
        let edge = ct::Edge { role: Role::Write, until: None, invite: None, tied: None };
        let g = *lp.peers[0].engine.grant(&u, &w, &edge).unwrap().commits.last().unwrap();
        lp.sync(0, 2).unwrap();
        let (m, t) = loop {
            let mut m = osis_node::Mutation::new();
            let t = lp.peers[2].engine.new_thing(&mut m, w);
            if (t < u) == t_first {
                break (m, t);
            }
        };
        lp.peers[2].commit(m).unwrap().unwrap();
        let mut m = osis_node::Mutation::new();
        m.set(t, &REG, &s("both")).unwrap();
        m.set(u, &REG, &s("both")).unwrap();
        let c = lp.peers[2].commit(m).unwrap().unwrap();
        let pc = lp.peers[2].engine.package(&c).unwrap().unwrap();
        let Ingested::Awaits(_, r) = lp.deliver(1, &pc).unwrap() else { panic!("t first {t_first}: thrown out") };
        named.insert(r == osis_node::Reason::UnknownCreated(t));
        let pg = lp.peers[0].engine.package(&g).unwrap().unwrap();
        lp.deliver(1, &pg).unwrap();
        let e = &mut lp.peers[1].engine;
        assert_eq!(e.get(&u, &ak("t:reg.0")).unwrap(), Some(s("both")), "t first {t_first}, entry names {r:?}: the part its author now reaches");
        assert!(!e.knows(&t));
    }
    assert_eq!(named.len(), 2, "entries naming either wait");
}

// spec/sync-judgement.md §3 (dropped bodies), spec/commits.md §4 (Unjudgeable): `x`'s group g is an item
// and subgroup of `team`, so one blob of a commit on `x` and on a new `h` is under both labels.
// Reader b gets it without `h`'s record: it applies without that part, and its copy goes, its
// wraps under both labels with it. The record comes and the part is missing again: b fetches the
// blob again under each label, though the first fetch brings the bytes the other entry names,
// and every entry opens (taking only the bytes, the other stayed unopened for good; a writer
// placed the commit there again, for another to delete, without end).
// spec/sync-judgement.md §3 (reader; a delete stands once it took a body placed again past one): the host
// never lists `r` to b, so b, holding `r` but no entry of it, judges the parts of g's group
// record that `r` covers must-hold and a deposits; a, holding `r`, deletes them as covered. b
// places each again once per label, not once per round trip (a storm of hundreds of fresh blobs,
// cut only by the host's rate limit), and nothing more over later passes.
#[test]
fn a_part_missing_again_is_fetched_under_every_label_spec_sync_6() {
    let mut net = net::Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let b = net.node(2, &[host]);
    let g = net.group(a, &[(b, Role::Read)], &[host]);
    let x = net.item(a, g, g, "x");
    let team = net.group(a, &[(b, Role::Read)], &[host]);
    net.grant(a, g, team, Role::Read);
    let mut grp = net.engine(a).get_typed(&team, &ct::GROUP).unwrap().unwrap_or_default();
    grp.items.insert(g);
    grp.subgroups.insert(g);
    let mut m = osis_node::Mutation::new();
    m.set(team, &ct::GROUP, &grp).unwrap();
    net.engine(a).commit(m).unwrap();
    net.run();
    let labels: Vec<osis_base::LabelId> = [g, team].map(|t| net.group_labels(b).into_iter().find(|(x, _)| *x == t).unwrap().1.id).into();
    let at_host = |net: &mut net::Net| labels.iter().flat_map(|l| net.host_ids(host, l)).collect::<std::collections::BTreeSet<_>>();
    // a creates h (its record in commit r) while b is away; b never hears of what that placed
    net.set_online(b, false);
    let (before, commits) = (at_host(&mut net), net.engine(a).commit_ids());
    let h = net.item(a, g, g, "first");
    let r = net.engine(a).commit_ids().into_iter().find(|c| !commits.contains(c)).unwrap();
    net.run();
    let hide = at_host(&mut net).difference(&before).copied().collect();
    net.hide_blobs.insert(b, hide);
    let mut m = osis_node::Mutation::new();
    m.set(h, &REG, &s("second")).unwrap();
    m.set(x, &REG, &s("both")).unwrap();
    let c = net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    net.set_online(b, true);
    net.run();
    net.advance(15_000);
    let of_c = |net: &mut net::Net, n: usize, l: &osis_base::LabelId| net.sync(n).entries(l).into_iter().filter(|(_, k)| matches!(k, EntryKind::Commit { commit, .. } if *commit == c)).map(|(id, _)| id).collect::<Vec<_>>();
    let blob = of_c(&mut net, a, &labels[0]);
    assert_eq!(blob.len(), 1);
    assert_eq!(of_c(&mut net, a, &labels[1]), blob, "one blob of c under both labels");
    assert!(net.engine(b).commit_ids().contains(&c), "c applied without its part on h");
    assert_eq!((net.read(b, x), net.read(b, h)), (Some(text("both")), None));
    let shredded = |net: &mut net::Net, l: &osis_base::LabelId| net.sync(b).entry_meta(l, &blob[0]).is_some_and(|m| m.0 == [0; osis_crypto::WRAP_LEN]);
    assert!(labels.iter().all(|l| shredded(&mut net, l)), "c's copy went, its wraps with it");
    // the record by hand (as pairing brings it)
    let logged = |net: &mut net::Net, l: &osis_base::LabelId| {
        let (added, removed) = net.logged_at(host, l);
        added.into_iter().chain(removed).collect::<std::collections::BTreeSet<_>>()
    };
    let known: Vec<_> = labels.iter().map(|l| logged(&mut net, l)).collect();
    let pr = net.engine(a).package(&r).unwrap().unwrap();
    net.engine(b).ingest(&pr.bytes, pr.blobs).unwrap();
    net.run();
    net.advance(15_000);
    assert_eq!(net.read(b, h), Some(text("second")), "the part fetched again");
    for l in &labels {
        assert_eq!(of_c(&mut net, b, l), blob, "{l:?}: c's entry opened");
    }
    let placed = |net: &mut net::Net| labels.iter().zip(&known).map(|(l, k)| logged(net, l).difference(k).count()).collect::<Vec<_>>();
    let after = placed(&mut net);
    // g's creation and x's: each placed again once per label
    assert_eq!(after, [2, 2], "fresh blobs per label");
    for _ in 0..5 {
        net.advance(31_000);
    }
    assert_eq!(placed(&mut net), after, "nothing placed over later passes");
}
