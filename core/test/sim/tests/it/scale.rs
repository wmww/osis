//! Scale counts on the sim (spec/requirements.md Scale): a chat with many members (each member a
//! node; one thing, one label, each message one kept write on one aspect) and an app with many
//! individually shared things. Work is counted (engine spans, pass counters), never timed.

use osis::internals::schema::core_types as ct;
use osis::internals::schema::{History, PurgeBy};
use osis::{Ak, GrantOpts, MemStore, Osis, Role, Store, Tid, Value};
use osis_sim::world::World;
use std::collections::BTreeMap;

const MSG: &str = "chat:msg~0";

fn create(a: &Osis) -> Tid {
    let msg_rule = ct::Required::new(osis::internals::schema::Retention { by: PurgeBy::AuthorOrAdmin, history: Some(History::FOREVER) }, None);
    let rest = ct::Required::new(Default::default(), None);
    let rules = ct::RequiredRules { rules: BTreeMap::from([(Ak::new(MSG).unwrap(), msg_rule)]), default: Some(rest), retain: true };
    // the record alone first (`create()` alone is a role commit), as chat's `create` does, so a
    // joiner's pending reads count members' records only
    let mut w = a.write();
    let c = w.create().unwrap();
    w.commit().unwrap();
    a.sync(c, &[]).unwrap();
    let mut w = a.write();
    w.at(c, ct::REQUIRED).set(&rules).unwrap();
    w.commit().unwrap();
    c
}

fn post(a: &Osis, c: Tid, i: usize) {
    let mut w = a.write();
    w.at(c, osis::DynamicAspectKey::untyped(Ak::new(MSG).unwrap())).fire(&Value::Bytes(format!("message number {i:0>180}").into_bytes())).unwrap();
    w.commit().unwrap();
}

fn meet(w: &mut World, a: &Osis, b: &Osis) -> Tid {
    let card = b.contact_card().unwrap();
    w.run();
    w.until(a.import_contact(&card), 1000, 10).unwrap()
}

/// Each span's count over `f`.
fn counted(w: &mut World, f: impl FnOnce(&mut World)) -> BTreeMap<&'static str, u64> {
    osis_node::costs::take();
    f(w);
    osis_node::costs::take().into_iter().map(|(k, _, n)| (k, n)).collect()
}

/// A chat of `m` members, all settled: the world, its host, the first member (admin), the chat, each member's tid.
fn chat_of(m: usize) -> (World, usize, Osis, Vec<Osis>, Tid, Vec<Tid>) {
    let mut w = World::new();
    let host = w.add_host();
    let a = w.account(1, &[host]);
    w.run();
    let c = create(&a);
    w.run();
    let (mut members, mut tids) = (Vec::new(), Vec::new());
    for i in 0..m {
        let b = w.account(100 + i as u64, &[host]);
        w.run();
        let p = meet(&mut w, &a, &b);
        a.grant(c, p, Role::Write, GrantOpts::default()).unwrap();
        w.run();
        members.push(b);
        tids.push(p);
    }
    (w, host, a, members, c, tids)
}

// spec: none (costs, spec/requirements.md Scale): a post in a chat of many re-derives nothing at
// any node: no `secrets.0` decoded, no held-actors view, no departures walked, no head keys
// derived, no holder decoded, no re-seal scan. So a post's cost per node reads
// nothing per member, kicked member or not.
#[test]
fn post_reads_nothing_per_member() {
    let (mut w, _, a, members, c, tids) = chat_of(5);
    let check = |n: &BTreeMap<&'static str, u64>, when: &str| {
        for k in ["secrets: decode", "held actors", "departures: collect", "head keys: derive", "holders named: read", "reseal: scan", "reexamine: read pending"] {
            assert_eq!(n.get(k).copied().unwrap_or(0), 0, "{k} {when}: {n:?}");
        }
    };
    // one settled post first: caches fill
    post(&a, c, 0);
    w.advance(1);
    let n = counted(&mut w, |w| {
        post(&a, c, 1);
        w.advance(1);
        post(&members[0], c, 2);
        w.advance(1);
    });
    check(&n, "in a quiet chat");
    // a pass at each node holding the chat, not one per label per node
    assert!(n.get("pass").copied().unwrap_or(0) <= 2 * 2 * (members.len() as u64 + 1), "passes for two posts: {n:?}");
    a.set_role(c, tids[1], None, osis::SetRoleOpts { retain_copy: None }).unwrap();
    w.run();
    post(&a, c, 3);
    w.advance(1);
    let n = counted(&mut w, |w| {
        post(&a, c, 4);
        w.advance(1);
    });
    check(&n, "after a kick");
    let texts = members[0].at(c, osis::DynamicAspectKey::untyped(Ak::new(MSG).unwrap())).fired(&osis::CommitQuery { from: osis::CommitFrom::Oldest, limit: Some(50), ..Default::default() }).unwrap();
    assert_eq!(texts.commits.len(), 5, "every post arrived");
}

// spec: none (costs, spec/requirements.md Scale): a joiner's pending role commits, one per
// earlier member waiting for that member's records, are not all read again after each that
// applies (`apply::waits`): reads per commit do not grow with the members.
#[test]
fn joiner_reads_each_pending_commit_few_times() {
    let reads = |m: usize| {
        let (mut w, host, a, _, c, _) = chat_of(m);
        let b = w.account(50, &[host]);
        w.run();
        let p = meet(&mut w, &a, &b);
        let n = counted(&mut w, |w| {
            a.grant(c, p, Role::Write, GrantOpts::default()).unwrap();
            w.run();
        });
        assert_eq!(b.grants(c).unwrap().len(), m + 2);
        n.get("reexamine: read pending").copied().unwrap_or(0)
    };
    let m = 5;
    let n = reads(m);
    // (an account is two commits, the key's card first: one more pending read at the joiner)
    assert!(n <= 2 * m as u64 + 1, "{n} reads of pending commits at {m} members");
}

// Costs against the number of labels: an app with thousands of individually shared things. Each
// thing is a group with a label of its own, shared with one other account, two nodes and a host.

const TEXT: &str = "app:text:y1.0";

fn write(a: &Osis, t: Tid, i: usize) {
    let mut w = a.write();
    w.at(t, osis::DynamicAspectKey::untyped(Ak::new(TEXT).unwrap())).overwrite(&Value::Bytes(format!("text {i}").into_bytes())).unwrap();
    w.commit().unwrap();
}

/// The one thing's text, as `b` reads it.
fn read(b: &Osis, t: Tid) -> Option<Value> {
    b.at(t, osis::DynamicAspectKey::untyped(Ak::new(TEXT).unwrap())).get().unwrap()
}

fn node(w: &mut World, seed: u64, host: usize) -> (Osis, MemStore) {
    let store = MemStore::new();
    let mut cfg = w.cfg(seed, &[host]);
    cfg.store = Store::Memory(store.clone());
    let db = osis::internals::create(cfg).unwrap();
    (db, store)
}

/// `n` shared things, settled: the writer, the reader, the reader's tid at the writer.
fn labels_world(n: usize) -> (World, Osis, Osis, Tid, Vec<Tid>) {
    let mut w = World::new();
    let host = w.add_host();
    let (a, _) = node(&mut w, 1, host);
    let (b, _) = node(&mut w, 2, host);
    w.run();
    let card = b.contact_card().unwrap();
    w.run();
    let p = w.until(a.import_contact(&card), 1000, 10).unwrap();
    w.run();
    let things = (0..n).map(|i| share_new(&mut w, &a, p, i)).collect();
    w.advance(61_000);
    w.advance(61_000);
    (w, a, b, p, things)
}

fn share_new(w: &mut World, a: &Osis, p: Tid, i: usize) -> Tid {
    let mut x = a.write();
    let t = x.create().unwrap();
    x.at(t, osis::DynamicAspectKey::untyped(Ak::new(TEXT).unwrap())).overwrite(&Value::Bytes(format!("text {i}").into_bytes())).unwrap();
    x.commit().unwrap();
    a.sync(t, &[]).unwrap();
    a.grant(t, p, Role::Read, GrantOpts::default()).unwrap();
    w.run();
    t
}

/// The work counters of `dbs` over `f`.
fn counted_work(dbs: &[&Osis], f: impl FnOnce()) -> osis_node::sync::PassStats {
    use osis::internals::Internals;
    let stats = |dbs: &[&Osis]| dbs.iter().map(|d| d.sync_engine(|s| s.pass_stats())).collect::<Vec<_>>();
    let before = stats(dbs);
    f();
    let mut out = osis_node::sync::PassStats::default();
    for (x, y) in before.iter().zip(stats(dbs)) {
        out.passes += y.passes - x.passes;
        out.label_reads += y.label_reads - x.label_reads;
        out.vets += y.vets - x.vets;
        out.claim_lists += y.claim_lists - x.claim_lists;
        out.inbox_keys += y.inbox_keys - x.inbox_keys;
        out.examined += y.examined.saturating_sub(x.examined);
    }
    out
}

// spec/sync.md §6, spec/requirements.md (Scale): a new shared thing, a write and a connect
// do work by what changed, not by how many labels there are (counted, not timed).
#[test]
fn label_costs_do_not_grow_with_labels() {
    let measure = |n: usize| {
        let (mut w, a, b, p, things) = labels_world(n);
        let shared = counted_work(&[&a, &b], || {
            share_new(&mut w, &a, p, n);
        });
        let wrote = counted_work(&[&a, &b], || {
            write(&a, things[0], n + 1);
            w.run();
        });
        w.set_online(&b, false);
        w.run();
        let connect = counted_work(&[&b], || {
            w.set_online(&b, true);
            w.advance(61_000);
        });
        assert_eq!(read(&b, things[0]), Some(Value::Bytes(format!("text {}", n + 1).into_bytes())));
        println!("{n} labels: shared {shared:?}, wrote {wrote:?}, connect {connect:?}");
        (shared, wrote, connect)
    };
    let (small, large) = (measure(2), measure(10));
    assert!(large.0.passes <= small.0.passes + 4, "share: {} passes against {}", large.0.passes, small.0.passes);
    assert!(large.0.label_reads <= small.0.label_reads + 8, "share: {} label reads against {}", large.0.label_reads, small.0.label_reads);
    assert!(large.0.inbox_keys <= small.0.inbox_keys, "share: {} inbox keys against {}", large.0.inbox_keys, small.0.inbox_keys);
    assert!(large.1.passes <= small.1.passes, "write: {} passes against {}", large.1.passes, small.1.passes);
    assert_eq!(large.2.claim_lists, 0, "connect: the held sync keys open every label");
    assert!(large.2.label_reads <= small.2.label_reads + 8, "connect: {} label reads against {}", large.2.label_reads, small.2.label_reads);
}

// spec/sync.md §6: resyncs of settled, subscribed labels run no pass, however many there are, a
// day on included: only a mark or a due time passes a label. Counted.
#[test]
fn idle_labels_pass_only_when_due() {
    const N: usize = 6;
    let (mut w, a, b, _, things) = labels_world(N);
    // past the wait for peers (`peer_pass_wait_ms`), which brings a last pass
    w.advance(310_000);
    w.advance(61_000);
    let idle = counted_work(&[&a, &b], || {
        for _ in 0..5 {
            w.advance(61_000);
        }
    });
    assert_eq!(idle.passes, 0, "idle resyncs ran passes");
    // nothing marks another label: a write passes its own alone, and the rest stay quiet after it
    let wrote = counted_work(&[&a, &b], || {
        write(&a, things[0], N + 1);
        w.run();
        w.advance(61_000);
        w.advance(61_000);
    });
    assert!(wrote.passes <= 16, "{} passes for a write with {N} labels", wrote.passes);
    assert_eq!(read(&b, things[0]), Some(Value::Bytes(format!("text {}", N + 1).into_bytes())));
    let idle = counted_work(&[&a, &b], || w.advance(61_000));
    assert_eq!(idle.passes, 0, "resyncs after a write ran passes");
    // a day on, nothing due: no label passes by the clock alone
    let day = counted_work(&[&a, &b], || {
        w.advance(DAY_MS + 61_000);
        w.advance(61_000);
    });
    assert_eq!(day.passes, 0, "a day on, quiet labels passed");
}

const DAY_MS: u64 = 24 * 3_600_000;

// spec/sync.md §6, spec/permissions.md §3: a grant's `until` is a time only the clock brings: the
// label it departs from passes then, though nothing else marks it (counted).
#[test]
fn an_edge_ending_passes_its_quiet_label() {
    let (mut w, a, _, p, things) = labels_world(2);
    // past the wait for peers (`peer_pass_wait_ms`), which brings a last pass
    w.advance(310_000);
    w.advance(61_000);
    let until = w.now() + 300_000;
    a.grant(things[0], p, Role::Read, GrantOpts { until: Some(osis_base::WallMs(until)), ..GrantOpts::default() }).unwrap();
    w.run();
    w.advance(61_000);
    w.advance(61_000);
    let idle = counted_work(&[&a], || w.advance(61_000));
    assert_eq!(idle.passes, 0, "quiet before the edge ends");
    let ended = counted_work(&[&a], || {
        w.advance(120_000);
    });
    assert!(ended.passes >= 1, "the edge ended and no pass came");
}

// spec/sync.md §5: what a label waits for by time (a copy left to its author, a relay wait) brings
// back that label, not every label of the node (counted).
#[test]
fn a_timed_wait_passes_its_label_alone() {
    let measure = |n: usize| {
        let (mut w, a, b, p, _) = labels_world(n);
        // past the wait for peers (`peer_pass_wait_ms`), which brings a last pass
        w.advance(310_000);
        w.advance(61_000);
        share_new(&mut w, &a, p, n);
        let settled = counted_work(&[&a, &b], || {
            for _ in 0..3 {
                w.advance(20_000);
            }
            w.advance(61_000);
        });
        settled.passes
    };
    let (small, large) = (measure(2), measure(10));
    assert!(large <= small + 4, "{large} passes at 10 labels against {small} at 2");
}

// spec/crypto.md §4, spec/sync.md §3: a burst of grants reads each pending one about once, however
// many wait, and a request waiting for the user is opened once, not at each vet (counted).
#[test]
fn a_burst_of_shares_costs_each_about_once() {
    const BURST: usize = 12;
    let (mut w, a, b, p, _) = labels_world(0);
    let burst = |w: &mut World, from: usize| {
        for i in 0..BURST {
            let mut x = a.write();
            let t = x.create().unwrap();
            x.at(t, osis::DynamicAspectKey::untyped(Ak::new(TEXT).unwrap())).overwrite(&Value::Bytes(format!("text {}", from + i).into_bytes())).unwrap();
            x.commit().unwrap();
            a.sync(t, &[]).unwrap();
            a.grant(t, p, Role::Read, GrantOpts::default()).unwrap();
        }
        w.run();
    };
    let held = w.index(&b).unwrap();
    w.holds_invites.insert(held);
    let waiting = counted_work(&[&b], || burst(&mut w, 100));
    assert!(waiting.inbox_keys <= 2 * BURST as u64, "{} inbox keys tried for {BURST} requests waiting", waiting.inbox_keys);
    w.holds_invites.remove(&held);
    let accepted = counted_work(&[&b], || w.run());
    assert!(accepted.examined <= 4 * BURST as u64, "{} pending commits read for {BURST} grants", accepted.examined);
    assert!(accepted.inbox_keys <= 2 * BURST as u64, "{} inbox keys tried for {BURST} accepted", accepted.inbox_keys);
}

// spec/sync.md §5 (Deposit): shares past an inbox's budget wait with the one refused, their bodies
// unsent, and go as it frees, not all at each deposit it takes.
#[test]
#[ignore = "tier 2, minutes in debug"]
fn a_burst_past_the_budget_sends_each_body_about_once() {
    const BURST: usize = 150;
    let (mut w, a, b, p, _) = labels_world(0);
    // each knows the other: a stranger's shares are requests, at most `INBOX_WAITING` of them
    let card = a.contact_card().unwrap();
    w.run();
    w.until(b.import_contact(&card), 1000, 10).unwrap();
    w.run();
    w.start_tally();
    let things: Vec<Tid> = (0..BURST)
        .map(|i| {
            let mut x = a.write();
            let t = x.create().unwrap();
            x.at(t, osis::DynamicAspectKey::untyped(Ak::new(TEXT).unwrap())).overwrite(&Value::Bytes(format!("text {i}").into_bytes())).unwrap();
            x.commit().unwrap();
            a.sync(t, &[]).unwrap();
            a.grant(t, p, Role::Read, GrantOpts::default()).unwrap();
            t
        })
        .collect();
    w.no_storm = true;
    w.run();
    let mut waits = 0;
    while things.iter().any(|t| read(&b, *t).is_none()) {
        assert!(waits < 100, "b lacks {} of {BURST}", things.iter().filter(|t| read(&b, **t).is_none()).count());
        w.advance(61_000);
        waits += 1;
    }
    let deposits = w.tally(&a).get("Deposit").map_or(0, |x| x.0);
    println!("{deposits} deposits for {BURST} shares, {waits} resyncs");
    assert!(deposits <= 2 * BURST as u64, "{deposits} deposits for {BURST} shares");
}

// spec: none (costs, spec/requirements.md Scale): an add judges nothing per message at any node
// that has them (it moves roles only upstream of the new holder, who wrote nothing and reads no
// body for them): no full pass, no more commits judged by a pass or re-judged by the engine; and
// `secrets.0` is not decoded again for it.
#[test]
fn add_judges_nothing_per_message() {
    let judged = |k: usize| {
        let (mut w, host, a, members, c, _) = chat_of(2);
        for i in 0..k {
            post(&a, c, i);
            w.advance(1);
        }
        w.run();
        // one add passes the labels no post did: what they had waiting is a post's cost
        let d = w.account(51, &[host]);
        w.run();
        let p = meet(&mut w, &a, &d);
        a.grant(c, p, Role::Write, GrantOpts::default()).unwrap();
        w.run();
        // the joiner asleep: it has all to judge (its first pass)
        let b = w.account(50, &[host]);
        w.run();
        let p = meet(&mut w, &a, &b);
        w.sleep(&b);
        let n = counted(&mut w, |w| {
            a.grant(c, p, Role::Write, GrantOpts::default()).unwrap();
            w.run();
        });
        assert_eq!(members[0].grants(c).unwrap().len(), 5);
        let of = |k: &str| n.get(k).copied().unwrap_or(0);
        (of("pass: full"), of("pass: bodies of a commit"), of("rejudge: a commit"), of("secrets: decode"))
    };
    let (quiet, busy) = (judged(0), judged(12));
    assert_eq!(busy, quiet, "(full passes, commits judged, re-judged, decodes) with 12 messages, and none");
    assert_eq!((busy.0, busy.3), (0, 0), "no full pass, no decode");
}

// spec/sync.md §6: when the clock goes back, a quiet label passes once at its next resync: its own
// `pass_at` does not wait for the clock to catch up (counted).
#[test]
fn a_clock_gone_back_keeps_a_quiet_labels_bound() {
    const N: usize = 4;
    let (mut w, a, b, _, _) = labels_world(N);
    // past the wait for peers (`peer_pass_wait_ms`), which brings a last pass
    w.advance(310_000);
    w.advance(61_000);
    w.advance(61_000);
    let idle = counted_work(&[&a, &b], || w.advance(61_000));
    assert_eq!(idle.passes, 0, "quiet before the clock moves");
    w.clock.set(osis_base::WallMs(w.now() - 10 * DAY_MS));
    let back = counted_work(&[&a, &b], || {
        w.advance(61_000);
        w.advance(61_000);
    });
    assert!(back.passes >= 2 * N as u64, "{} passes after the clock went back", back.passes);
    w.advance(61_000);
    let idle = counted_work(&[&a, &b], || w.advance(61_000));
    assert_eq!(idle.passes, 0, "quiet again");
}
