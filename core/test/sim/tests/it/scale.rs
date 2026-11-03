//! A chat with many members (design E, notes/chat-designs/e.md), each member a node on the sim:
//! one ownerless thing with one label, members hold write edges, each message one kept write on
//! one aspect. Numbers in notes/testing.md, "Scale checks". By hand, release, one size at a time:
//! `OSIS_SCALE_M=100 OSIS_SCALE_N=200 cargo test --release -p osis-sim --test it -- --ignored --nocapture --test-threads 1 scale::chat_members`
//! Per node: the time inside one database's passes and receives, what one device would spend. The
//! sim's own run time is the sum over M nodes and says little.

use osis::schema::core_types as ct;
use osis::schema::{Bound, PurgeBy};
use osis::{Ak, EdgeOpts, MemStore, Osis, Retention, Role, StoreAt, Tid, Value};
use osis_sim::world::World;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const MSGS: &str = "chat:msgs:y1.0";

fn env(k: &str, or: usize) -> usize {
    std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(or)
}

fn create(a: &Osis) -> Tid {
    let c = a.create_ownerless(a.me()).unwrap();
    let msgs = ct::Required::new(Retention { by: PurgeBy::AuthorOrAdmin, at_least: Bound { abs: Some(i64::MAX as u64), rel: None }, at_most: Bound::default() }, None);
    let rest = ct::Required::new(Retention::default(), None);
    let rules = ct::RequiredRules { rules: BTreeMap::from([("chat:msgs:".to_string(), msgs), (String::new(), rest)]), keep: true };
    a.write_with(|w| {
        w.at(c, ct::REQUIRED).set(&rules)?;
        w.make_group(c)
    })
    .unwrap();
    a.sync(c, &[]).unwrap();
    c
}

fn post(a: &Osis, c: Tid, i: usize) {
    let mut w = a.write();
    w.at(c, Ak::new(MSGS).unwrap()).replace(&Value::Bytes(format!("message number {i:0>180}").into_bytes())).unwrap();
    w.commit().unwrap();
}

fn meet(w: &mut World, a: &Osis, b: &Osis) -> Tid {
    let card = b.contact_card().unwrap();
    w.run();
    w.until(a.import_contact(&card), 1000, 10).unwrap()
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v.get(v.len() / 2).copied().unwrap_or_default()
}

/// Spans (`osis_node::costs`), dearest first, per one of `n`.
fn show_spans(mut s: Vec<(&'static str, Duration, u64)>, n: usize) -> String {
    s.sort_by_key(|x| std::cmp::Reverse(x.1));
    s.iter().take(24).map(|(k, t, c)| format!("{k} {:.1}x {:.2?}", *c as f64 / n.max(1) as f64, *t / n.max(1) as u32)).collect::<Vec<_>>().join(", ")
}

/// Each database's busy time since `before`.
fn since(w: &mut World, before: &[Duration]) -> Vec<Duration> {
    let now = w.busy_all();
    now.iter().enumerate().map(|(i, t)| t.saturating_sub(before.get(i).copied().unwrap_or_default())).collect()
}

/// The last join settling (by name: `valgrind --toggle-collect='*last_settle*'`).
#[inline(never)]
fn last_settle(w: &mut World) {
    w.run();
}

/// `m` members join one by one (by name: `valgrind --toggle-collect='*joins*'`).
#[inline(never)]
fn joins(w: &mut World, a: &Osis, c: Tid, host: usize, m: usize, every: usize, start: Instant) -> (Vec<Osis>, Vec<MemStore>) {
    let active = env("OSIS_SCALE_ACTIVE", m);
    let (mut members, mut stores) = (Vec::new(), Vec::new());
    for i in 0..m {
        let store = MemStore::new();
        stores.push(store.clone());
        let mut cfg = w.cfg(100 + i as u64, &[host]);
        cfg.store = StoreAt::Memory(store);
        let (b, _) = Osis::create(cfg).unwrap();
        w.run();
        let p = meet(w, a, &b);
        // past `active`, a member's node sleeps (the last one's joins): M-node sizes the sim's sum cannot reach
        if i >= active && i + 1 < m {
            w.sleep(&b);
        }
        let (before, hub, up) = (w.busy_all(), w.hub_busy(), w.traffic(a).up);
        let (mine, down) = (w.traffic(&b).down, Instant::now());
        if i + 1 == m {
            osis_node::costs::take();
        }
        a.share(c, p, Role::Write, EdgeOpts::default()).unwrap();
        let local = down.elapsed();
        let t = Instant::now();
        if i + 1 == m {
            println!("SPANS of the last add, the admin's call: {}", show_spans(osis_node::costs::take(), 1));
            last_settle(w);
            println!("SPANS of the last join at all nodes: {}", show_spans(osis_node::costs::take(), 1));
        } else {
            w.run();
        }
        let world = t.elapsed();
        members.push(b);
        if (i + 1) % every == 0 || i + 1 == m {
            let d = since(w, &before);
            let joiner = w.index(members.last().unwrap()).unwrap();
            let others: Vec<Duration> = d.iter().enumerate().filter(|(j, _)| *j != 0 && *j != joiner && *j <= active).map(|(_, t)| *t).collect();
            println!(
                "JOIN m={} local {local:.1?}, adder {:.1?}, joiner {:.1?}, other member median {:.1?}, host {:.1?}, sim {world:.1?}, up {} B, joiner down {} B, total {:.1?}",
                i + 1,
                d[0],
                d[joiner],
                median(others),
                w.hub_busy() - hub,
                w.traffic(a).up - up,
                w.traffic(members.last().unwrap()).down - mine,
                start.elapsed(),
            );
        }
    }
    (members, stores)
}

/// One member posts `n` messages, each settling (by name: `valgrind --toggle-collect='*posts*'`).
#[inline(never)]
fn posts(w: &mut World, a: &Osis, members: &[Osis], c: Tid, m: usize, n: usize) {
    w.start_tally();
    osis_node::costs::take();
    let (before, hub, up) = (w.busy_all(), w.hub_busy(), w.traffic(a).up);
    let (mut local, t) = (Duration::ZERO, Instant::now());
    for i in 0..n {
        let p = Instant::now();
        post(a, c, i);
        local += p.elapsed();
        w.advance(1);
    }
    w.run();
    let busy = since(w, &before);
    let per = |t: Duration| t / n.max(1) as u32;
    println!("SPANS per message at all nodes: {}", show_spans(osis_node::costs::take(), n));
    let tally = |w: &mut World, db: &Osis| w.tally(db).into_iter().map(|(k, (c, b))| format!("{k} {:.1} x {} B", c as f64 / n.max(1) as f64, b / c.max(1))).collect::<Vec<_>>().join(", ");
    println!("SENT per message: sender: {}", tally(w, a));
    println!("SENT per message: the first member: {}", tally(w, &members[0]));
    println!("SENT per message: the last member: {}", tally(w, &members[members.len() - 1]));
    let mut all: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for db in members {
        for (k, (c, b)) in w.tally(db) {
            let e = all.entry(k).or_default();
            e.0 += c;
            e.1 += b;
        }
    }
    println!("SENT per message per member, all: {}", all.iter().map(|(k, (c, b))| format!("{k} {:.2} x {} B", *c as f64 / (n.max(1) * m.max(1)) as f64, b / (*c).max(1))).collect::<Vec<_>>().join(", "));
    let others: Vec<Duration> = busy.iter().skip(1).take(env("OSIS_SCALE_ACTIVE", m)).copied().collect();
    let hub = w.hub_busy() - hub;
    println!(
        "POST m={m} n={n} local {:.2?}, sender passes {:.2?}, receiver median {:.2?}, host per message {:.2?}, host per message per subscriber {:.1?}, sim per message {:.1?}, up {} B",
        per(local),
        per(busy[0]),
        per(median(others)),
        per(hub),
        per(hub) / (m + 1) as u32,
        per(t.elapsed()),
        (w.traffic(a).up - up) / n.max(1) as u64,
    );
    // a plain member's post, in its own call (no admin)
    let (mut mine, k) = (Duration::ZERO, 20usize);
    for i in 0..k {
        let t = Instant::now();
        post(&members[0], c, n + i);
        mine += t.elapsed();
        w.advance(1);
    }
    println!("POST m={m} local, a plain member {:.2?}", mine / k as u32);
    osis_node::costs::take();
    let mut d = Duration::ZERO;
    for i in 0..k {
        let t = Instant::now();
        post(a, c, n + k + i);
        d += t.elapsed();
        let s = osis_node::costs::take();
        if i == k - 1 {
            println!("POST m={m} local, the admin {:.2?}; SPANS in its call: {}", d / k as u32, show_spans(s, 1));
        }
        w.advance(1);
        osis_node::costs::take();
    }
}

// spec: none (a measure, spec/requirements.md Scale): members join, one posts, every node receives.
#[test]
#[ignore = "scale: by hand"]
fn chat_members() {
    let (m, n) = (env("OSIS_SCALE_M", 10), env("OSIS_SCALE_N", 100));
    let every = (m / 10).max(1);
    let mut w = World::new();
    let host = w.add_host();
    let (a, _) = w.person(1, &[host]);
    w.run();
    let c = create(&a);
    w.run();
    let start = Instant::now();
    let (members, stores) = joins(&mut w, &a, c, host, m, every, start);
    let last = members.last().unwrap();
    let held = |w: &World| (stores[0].held_bytes(), w.hosts[host].backend.held_bytes());
    let (member0, host0) = held(&w);
    println!("STORE m={m} after the joins: a member {member0} B ({} B per member), host {host0} B", member0 / m.max(1) as u64);
    assert_eq!(last.roster(c).len(), m + 1);
    posts(&mut w, &a, &members, c, m, n);
    let (member1, host1) = held(&w);
    println!("STORE m={m} n={n} per message: a member {} B, host {} B", (member1 - member0) / n.max(1) as u64, (host1 - host0) / n.max(1) as u64);
    // one more member, with the messages there: a full pass of the label at each node
    let (b, _) = w.person(50, &[host]);
    w.run();
    let p = meet(&mut w, &a, &b);
    let before = w.busy_all();
    let t = Instant::now();
    a.share(c, p, Role::Write, EdgeOpts::default()).unwrap();
    w.run();
    let d = since(&mut w, &before);
    let joiner = w.index(&b).unwrap();
    let others: Vec<Duration> = d.iter().enumerate().filter(|(j, _)| *j != 0 && *j != joiner && *j <= env("OSIS_SCALE_ACTIVE", m)).map(|(_, t)| *t).collect();
    println!("JOIN after the {n} messages m={m}: other member median {:.1?}, joiner {:.1?}, joiner down {} B, sim {:.1?}", median(others), d[joiner], w.traffic(&b).down, t.elapsed());
    let down = w.traffic(last).down;
    println!("TOTAL m={m}: joiner's whole down {down} B, wall {:.1?}", start.elapsed());
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
    let (a, _) = w.person(1, &[host]);
    w.run();
    let c = create(&a);
    w.run();
    let (mut members, mut tids) = (Vec::new(), Vec::new());
    for i in 0..m {
        let (b, _) = w.person(100 + i as u64, &[host]);
        w.run();
        let p = meet(&mut w, &a, &b);
        a.share(c, p, Role::Write, EdgeOpts::default()).unwrap();
        w.run();
        members.push(b);
        tids.push(p);
    }
    (w, host, a, members, c, tids)
}

// spec: none (costs, spec/requirements.md Scale): a post in a chat of many re-derives nothing at
// any node: no `secrets.0` decoded, no held-actors view, no departures walked, no head keys
// derived, no holder decoded, no re-seal scan, no heartbeat read. So a post's cost per node reads
// nothing per member, kicked member or not.
#[test]
fn post_reads_nothing_per_member() {
    let (mut w, _, a, members, c, tids) = chat_of(5);
    let check = |n: &BTreeMap<&'static str, u64>, when: &str| {
        for k in ["secrets: decode", "held actors", "departures: collect", "head keys: derive", "holders named: read", "reseal: scan", "heartbeat: read", "reexamine: read pending"] {
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
    w.until(a.demote(c, tids[1], osis::Lower::Remove, osis::Demotion { sync: osis::WaitForSync::Skip, backdate: None, repudiate: false, keep: None }), 1000, 100).unwrap();
    w.run();
    post(&a, c, 3);
    w.advance(1);
    let n = counted(&mut w, |w| {
        post(&a, c, 4);
        w.advance(1);
    });
    check(&n, "after a kick");
    let texts = members[0].at(c, Ak::new(MSGS).unwrap()).history(osis::HistoryFrom::Oldest, 50).unwrap();
    assert_eq!(texts.entries.len(), 5, "every post arrived");
}

// spec: none (costs, spec/requirements.md Scale): a joiner's pending role commits, one per
// earlier member waiting for that member's records, are not all read again after each that
// applies (`apply::waits`): reads per commit do not grow with the members.
#[test]
fn joiner_reads_each_pending_commit_few_times() {
    let reads = |m: usize| {
        let (mut w, host, a, _, c, _) = chat_of(m);
        let (b, _) = w.person(50, &[host]);
        w.run();
        let p = meet(&mut w, &a, &b);
        let n = counted(&mut w, |w| {
            a.share(c, p, Role::Write, EdgeOpts::default()).unwrap();
            w.run();
        });
        assert_eq!(b.roster(c).len(), m + 2);
        n.get("reexamine: read pending").copied().unwrap_or(0)
    };
    let m = 9;
    let n = reads(m);
    assert!(n <= 2 * m as u64, "{n} reads of pending commits at {m} members");
}
