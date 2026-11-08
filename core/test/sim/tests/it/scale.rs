//! A chat with many members (design E, notes/chat.md), each member a node on the sim:
//! one thing made by its record, with one label, members hold write grants, each message one kept write on
//! one aspect. Numbers in notes/testing.md, "Scale checks". By hand, release, one size at a time:
//! `OSIS_SCALE_M=100 OSIS_SCALE_N=200 cargo test --release -p osis-sim --test it -- --ignored --nocapture --test-threads 1 scale::chat_members`
//! Per node: the time inside one node's passes and receives, what one node would spend. The
//! sim's own run time is the sum over M nodes and says little. `OSIS_SCALE_ACTIVE`: past so many a
//! member sleeps once its join settled; `OSIS_SCALE_CARDS=0`: before it, so no card (an admin's cost
//! at sizes where every joiner reading all before it takes hours).

use osis::internals::MemStoreMeasures as _;
use osis::internals::schema::core_types as ct;
use osis::internals::schema::{History, PurgeBy};
use osis::{Ak, GrantOpts, MemStore, Osis, Role, Store, Tid, Value};
use osis_sim::world::World;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const MSGS: &str = "chat:msgs~0";

fn env(k: &str, or: usize) -> usize {
    std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(or)
}

fn create(a: &Osis) -> Tid {
    let msgs = ct::Required::new(osis::internals::schema::Retention { by: PurgeBy::AuthorOrAdmin, history: Some(History::FOREVER) }, None);
    let rest = ct::Required::new(Default::default(), None);
    let rules = ct::RequiredRules { rules: BTreeMap::from([(Ak::new(MSGS).unwrap(), msgs)]), default: Some(rest), retain: true };
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
    w.at(c, osis::DynamicAspectKey::untyped(Ak::new(MSGS).unwrap())).set(&Value::Bytes(format!("message number {i:0>180}").into_bytes())).unwrap();
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

/// Each node's busy time since `before`.
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
    let cards = env("OSIS_SCALE_CARDS", 1) != 0;
    let (mut members, mut stores) = (Vec::new(), Vec::new());
    for i in 0..m {
        let store = MemStore::new();
        stores.push(store.clone());
        let mut cfg = w.cfg(100 + i as u64, &[host]);
        cfg.store = Store::Memory(store);
        let b = osis::internals::create(cfg).unwrap();
        w.run();
        let p = meet(w, a, &b);
        // `OSIS_SCALE_CARDS=0`: asleep before its join, no card uploaded, so an admin's cost at sizes
        // whose every joiner reading all before it would take hours (the last one still joins)
        if i >= active && i + 1 < m && !cards {
            w.sleep(&b);
        }
        let (before, hub, up) = (w.busy_all(), w.hub_busy(), w.traffic(a).up);
        let (mine, down) = (w.traffic(&b).down, Instant::now());
        if i + 1 == m {
            osis_node::costs::take();
        }
        a.grant(c, p, Role::Write, GrantOpts::default()).unwrap();
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
        // past `active`, a member's node sleeps once its join settled, its card uploaded: M-node
        // sizes the sim's sum cannot reach
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
        if i >= active && cards {
            w.sleep(members.last().unwrap());
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

/// The rest of a joiner's fill (by name: `valgrind --toggle-collect='*fill_rest*'`).
#[inline(never)]
fn fill_rest(w: &mut World) {
    // (not folded into `last_settle`: the same code)
    std::hint::black_box(w.now());
    w.run();
}

/// Runs the world one message at a time until `b` reads a full newest page of the chat, the
/// newest message on top, as a chat opening would (by name: `--toggle-collect='*joiner_reads_newest*'`).
/// The messages' steps taken.
#[inline(never)]
fn joiner_reads_newest(w: &mut World, b: &Osis, c: Tid, newest: &[u8]) -> u64 {
    let k = Ak::new(MSGS).unwrap();
    let want = Value::Bytes(newest.to_vec());
    let (mut steps, mut idle) = (0u64, 0);
    loop {
        steps += 1;
        if w.step(None) {
            idle = 0;
        } else {
            // nothing moves: the user's click on the invite, or a timer's turn
            for r in b.invite_requests().unwrap() {
                b.accept_invite(r).unwrap();
            }
            idle += 1;
            assert!(idle < 200, "the fill stopped: {:?}", b.at(c, osis::DynamicAspectKey::untyped(k.clone())).history(osis::HistoryFrom::Newest, 50).map(|p| p.entries.len()));
            w.tick(1000);
        }
        if steps % 8 == 0 {
            let Ok(p) = b.at(c, osis::DynamicAspectKey::untyped(k.clone())).history(osis::HistoryFrom::Newest, 50) else { continue };
            let held = |e: &osis::HistoryEntry<Value>| matches!(e.body, osis::HistoryBody::Held(Some(_)));
            if p.entries.len() == 50 && p.entries.iter().all(held) && matches!(&p.entries[0].body, osis::HistoryBody::Held(Some(v)) if *v == want) {
                return steps;
            }
        }
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
    let a = w.account(1, &[host]);
    w.run();
    let c = create(&a);
    w.run();
    let start = Instant::now();
    let (members, stores) = joins(&mut w, &a, c, host, m, every, start);
    let last = members.last().unwrap();
    let held = |w: &World| (stores[0].held_bytes(), w.hosts[host].backend.held_bytes());
    let (member0, host0) = held(&w);
    println!("STORE m={m} after the joins: a member {member0} B ({} B per member), host {host0} B", member0 / m.max(1) as u64);
    assert_eq!(last.grants(c).unwrap().len(), m + 1);
    let (rows, blobs, nblobs) = stores[0].held_split();
    println!("STORE a member, per member: rows {} B, {nblobs} blobs {} B", rows / m.max(1) as u64, blobs / m.max(1) as u64);
    for (what, n, bytes) in osis::internals::Internals::engine(&members[0], |e| e.held_report()).unwrap() {
        println!("STORE a member, per member: {:.1} x {what} {} B", n as f64 / m.max(1) as f64, bytes / m.max(1) as u64);
    }
    posts(&mut w, &a, &members, c, m, n);
    let (member1, host1) = held(&w);
    println!("STORE m={m} n={n} per message: a member {} B, host {} B", (member1 - member0) / n.max(1) as u64, (host1 - host0) / n.max(1) as u64);
    // one more member, with the messages there
    let b = w.account(50, &[host]);
    w.run();
    let p = meet(&mut w, &a, &b);
    let before = w.busy_all();
    let joiner0 = w.busy(&b);
    let t = Instant::now();
    osis_node::costs::take();
    a.grant(c, p, Role::Write, GrantOpts::default()).unwrap();
    let joiner = w.index(&b).unwrap();
    w.spans_by_db();
    let newest = format!("message number {:0>180}", n + 39).into_bytes();
    let to_page = joiner_reads_newest(&mut w, &b, c, &newest);
    let page_spans = w.take_db_spans(joiner);
    println!("SPANS of the joiner to its newest page: {}", show_spans(page_spans, 1));
    println!("NEWEST PAGE m={m} n={n}: joiner {:.1?} inside its node, {} B down, {} steps", w.busy(&b) - joiner0, w.traffic(&b).down, to_page);
    w.spans_by_db();
    fill_rest(&mut w);
    println!("SPANS of the joiner, the rest of its fill: {}", show_spans(w.take_db_spans(joiner), 1));
    let d = since(&mut w, &before);
    let others: Vec<Duration> = d.iter().enumerate().filter(|(j, _)| *j != 0 && *j != joiner && *j <= env("OSIS_SCALE_ACTIVE", m)).map(|(_, t)| *t).collect();
    println!("JOIN after the {n} messages m={m}: other member median {:.1?}, joiner {:.1?}, joiner down {} B, sim {:.1?}", median(others), d[joiner], w.traffic(&b).down, t.elapsed());
    // and one with its joiner asleep: what the others spend
    let b2 = w.account(51, &[host]);
    w.run();
    let p = meet(&mut w, &a, &b2);
    w.sleep(&b2);
    w.run();
    let before = w.busy_all();
    a.grant(c, p, Role::Write, GrantOpts::default()).unwrap();
    w.spans_by_db();
    w.run();
    println!("SPANS of an add at a member, its joiner asleep: {}", show_spans(w.take_db_spans(1), 1));
    let d = since(&mut w, &before);
    let others: Vec<Duration> = d.iter().enumerate().filter(|(j, _)| *j != 0 && *j != joiner && *j <= env("OSIS_SCALE_ACTIVE", m)).map(|(_, t)| *t).collect();
    println!("ADD with its joiner asleep m={m}: admin {:.1?}, other member median {:.1?}", d[0], median(others));
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
    a.set_role(c, tids[1], None, osis::SetRoleOpts { retain_copy: None }).unwrap();
    w.run();
    post(&a, c, 3);
    w.advance(1);
    let n = counted(&mut w, |w| {
        post(&a, c, 4);
        w.advance(1);
    });
    check(&n, "after a kick");
    let texts = members[0].at(c, osis::DynamicAspectKey::untyped(Ak::new(MSGS).unwrap())).history(osis::HistoryFrom::Oldest, 50).unwrap();
    assert_eq!(texts.entries.len(), 5, "every post arrived");
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
// `OSIS_SCALE_N=1000 cargo test --release -p osis-sim --test it -- --ignored --nocapture scale::many_labels`

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

/// This thread's CPU time: wall time says little on a shared box.
fn cpu() -> Duration {
    let s = std::fs::read_to_string("/proc/thread-self/schedstat").unwrap_or_default();
    Duration::from_nanos(s.split(' ').next().and_then(|x| x.parse().ok()).unwrap_or(0))
}

/// Runs one measured phase: CPU time, round trips, passes, what `dbs` sent and got, frames by kind.
fn phase(w: &mut World, name: &str, n: usize, dbs: &[&Osis], f: impl FnOnce(&mut World)) {
    use osis::internals::Internals;
    w.start_tally();
    let before: Vec<_> = dbs.iter().map(|d| w.traffic(d)).collect();
    let passes = |dbs: &[&Osis]| dbs.iter().map(|d| d.sync_engine(|s| (s.pass_stats().passes, s.pass_stats().examined))).fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
    let spans = std::env::var_os("OSIS_SCALE_SPANS").is_some();
    if spans {
        osis_node::costs::take();
    }
    let (t, hops, p) = (cpu(), w.hops(), passes(dbs));
    f(w);
    let took = cpu() - t;
    if spans {
        println!("  SPANS {}", show_spans(osis_node::costs::take(), 1));
    }
    let (q, e) = passes(dbs);
    let (trips, p, e) = ((w.hops() - hops) / 2, q - p.0, e.saturating_sub(p.1));
    let mut kinds: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let (mut up, mut down) = (0, 0);
    for (d, b) in dbs.iter().zip(&before) {
        let a = w.traffic(d);
        up += a.up - b.up;
        down += a.down - b.down;
        for (k, (c, by)) in w.tally(d) {
            let e = kinds.entry(k).or_default();
            e.0 += c;
            e.1 += by;
        }
    }
    let frames: Vec<String> = kinds.iter().filter(|(k, _)| !k.starts_with("down")).map(|(k, (c, _))| format!("{k} {c}")).collect();
    println!("{name:<12} n={n:<6} {took:>10.1?}  {:>8.1?}/label  {trips} trips, {p} passes, {e} exams, up {up} B, down {down} B; {}", took / n.max(1) as u32, frames.join(", "));
}

// spec/sync.md §6, spec/requirements.md (Scale): costs per label. `OSIS_SCALE_N` (default 10^3).
#[test]
#[ignore = "tier 2, by hand"]
fn many_labels() {
    let n = env("OSIS_SCALE_N", 1000);
    let mut w = World::new();
    let host = w.add_host();
    w.no_storm = true;
    let (a, a_store) = node(&mut w, 1, host);
    let (b, b_store) = node(&mut w, 2, host);
    w.run();
    let card = b.contact_card().unwrap();
    w.run();
    let p = w.until(a.import_contact(&card), 1000, 10).unwrap();
    w.run();
    // each knows the other: a stranger's invites wait for the user, at most `INBOX_WAITING` of them
    let card = a.contact_card().unwrap();
    w.run();
    w.until(b.import_contact(&card), 1000, 10).unwrap();
    w.run();
    let empty = (a_store.rows(), b_store.rows(), w.hosts[host].backend.dump().len());

    let mut things = Vec::with_capacity(n);
    phase(&mut w, "create", n, &[&a, &b], |w| {
        for i in 0..n {
            let mut x = a.write();
            let t = x.create().unwrap();
            x.at(t, osis::DynamicAspectKey::untyped(Ak::new(TEXT).unwrap())).overwrite(&Value::Bytes(format!("text {i}").into_bytes())).unwrap();
            x.commit().unwrap();
            a.sync(t, &[]).unwrap();
            things.push(t);
            if (i + 1) % 100 == 0 {
                w.pump();
            }
        }
        w.run();
    });
    let unread = |b: &Osis| things.iter().filter(|t| read(b, **t).is_none()).count();
    phase(&mut w, "first sync", n, &[&a, &b], |w| {
        for (i, t) in things.iter().enumerate() {
            a.grant(*t, p, Role::Read, GrantOpts::default()).unwrap();
            if (i + 1) % 100 == 0 {
                w.pump();
            }
        }
        w.run();
        // a burst past the inbox's deposit budget goes as its slots free
        let mut waits = 0;
        while unread(&b) > 0 {
            assert!(waits < 100, "b lacks {} of {n}", unread(&b));
            w.advance(61_000);
            waits += 1;
        }
        println!("first sync: {waits} resyncs");
    });
    let (ar, br, hr) = (a_store.rows(), b_store.rows(), w.hosts[host].backend.dump().len());
    println!("rows per label: writer {:.1}, reader {:.1}, host {:.1}", (ar.saturating_sub(empty.0)) as f64 / n as f64, (br.saturating_sub(empty.1)) as f64 / n as f64, (hr.saturating_sub(empty.2)) as f64 / n as f64);

    phase(&mut w, "idle tick", n, &[&a, &b], |w| w.run());
    phase(&mut w, "idle resync", n, &[&a, &b], |w| w.advance(61_000));
    phase(&mut w, "idle again", n, &[&a, &b], |w| w.advance(61_000));
    // what one pass costs at this many labels, now that idle runs none: a refresh judges all
    for name in ["pass each", "pass again"] {
        phase(&mut w, name, n, &[&a, &b], |w| {
            a.nudge_sync().unwrap();
            b.nudge_sync().unwrap();
            w.run();
        });
    }
    phase(&mut w, "one write", n, &[&a, &b], |w| {
        write(&a, things[n / 2], n + 1);
        w.run();
    });
    assert_eq!(read(&b, things[n / 2]), Some(Value::Bytes(format!("text {}", n + 1).into_bytes())));

    w.set_online(&b, false);
    write(&a, things[n / 3], n + 2);
    w.run();
    phase(&mut w, "connect", n, &[&b], |w| {
        w.set_online(&b, true);
        w.advance(61_000);
        w.run();
    });
    assert_eq!(read(&b, things[n / 3]), Some(Value::Bytes(format!("text {}", n + 2).into_bytes())));
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

// spec/sync.md §6: resyncs of settled, subscribed labels run no pass, however many there are;
// what time alone wants still comes, for the labels it is due on: a heartbeat interval later,
// each label passes about once. Counted.
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
    // labels at both nodes, each with its heartbeat due once in the interval
    let day = counted_work(&[&a, &b], || {
        w.advance(osis_base::format::HEARTBEAT_MIN_INTERVAL_MS + 61_000);
        w.advance(61_000);
    });
    assert!(day.passes >= 2 * N as u64, "{} passes a heartbeat interval on", day.passes);
    let idle = counted_work(&[&a, &b], || {
        w.advance(61_000);
        w.advance(61_000);
    });
    assert_eq!(idle.passes, 0, "resyncs after the heartbeats ran passes");
}

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

// spec/sync.md §6: a quiet label's slowest pass stays one heartbeat interval away when the clock
// goes back: its own `pass_at` and resync do not wait for the clock to catch up (counted).
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
    w.clock.set(osis_base::WallMs(w.now() - 10 * osis_base::format::HEARTBEAT_MIN_INTERVAL_MS));
    let back = counted_work(&[&a, &b], || {
        w.advance(61_000);
        w.advance(61_000);
    });
    assert!(back.passes >= 2 * N as u64, "{} passes after the clock went back", back.passes);
    w.advance(61_000);
    let idle = counted_work(&[&a, &b], || w.advance(61_000));
    assert_eq!(idle.passes, 0, "quiet again");
    let day = counted_work(&[&a, &b], || {
        w.advance(osis_base::format::HEARTBEAT_MIN_INTERVAL_MS + 61_000);
        w.advance(61_000);
    });
    assert!(day.passes >= 2 * N as u64, "{} passes a heartbeat interval on", day.passes);
}

// spec/sync.md §6: a heartbeat a pass cannot send is no reason to pass at every resync (a label
// stranded once keeps that time for good; here, with heartbeats off) (counted).
#[test]
fn a_past_heartbeat_leaves_a_label_quiet() {
    use osis::internals::Internals;
    let (mut w, a, _, _, _) = labels_world(3);
    w.advance(310_000);
    w.advance(61_000);
    a.sync_engine(|s| s.config_mut().heartbeats = false);
    for _ in 0..2 {
        w.advance(osis_base::format::HEARTBEAT_MIN_INTERVAL_MS + 61_000);
        w.advance(61_000);
    }
    let idle = counted_work(&[&a], || {
        w.advance(61_000);
        w.advance(61_000);
    });
    assert_eq!(idle.passes, 0, "a past heartbeat passes the label at every resync");
}
