//! One aspect with very many retained writes: chat design E (notes/chat-designs/e.md), every
//! message one register write on an aspect of the chat, kept forever. spec/requirements.md, Scale.
//! Numbers in notes/testing.md, "Scale checks". By hand, release, one size at a time:
//! `OSIS_SCALE_N=100000 OSIS_SCALE_DIR=/some/dir cargo test --release -p osis-node --test it -- --ignored --nocapture --test-threads 1 scale::long_aspect::cost`
//! (`OSIS_SCALE_STEPS`: a comma list of gen, build, open, write, kick, fall, default all;
//! `OSIS_SCALE_FALL_FEW`: only the small falls; `OSIS_SCALE_UNBOUNDED`: no `any_bounded` scan; a
//! built size is reused; each step runs in a process of its own over a copy of the built stores, so its
//! peak resident set is its own). `scale::long_aspect::first_sync` does the sync steps on the sim.

use super::{decode_packages, encode_packages, peak_kib, reset_peak, rss_kib};
use crate::common::{edge, set_edge};
use crate::net;
use osis_base::{Ak, Clock, ManualClock, Role, Tid, Value, WallMs};
use osis_crypto::SeededRng;
use osis_node::flows::{Demotion, PreSync};
use osis_node::local_peer::{LocalPeer, Package, Peer};
use osis_node::{Config, Engine, Ingested, Mutation};
use osis_perm::DemotionScope;
use osis_schema::core_types as ct;
use osis_schema::{Aspect, Codec, StaticSchema};
use osis_store::{Backend, BackendError, FileRoot, KeyValue, RedbBackend, WriteBatch};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

// keep_at_least: FOREVER (osis_commit::header)
static LONG: StaticSchema = StaticSchema::new("long.osis", "version 1; aspect l:msgs.0: string [by: author, keep_at_least: abs 9223372036854775807];\n");
const MSG: Aspect<Value> = Aspect::new("l:msgs.0", &LONG);

const T0: u64 = 1_700_000_000_000;
/// The first message's time, and the gap between messages.
const FIRST: u64 = T0 + 60_000;
const GAP: u64 = 1_000;
const WRITERS: usize = 20;
/// Messages generated past N: what the steps receive.
const SPARE: usize = 200;
const HEAVY: usize = 1;
const AVG: usize = 2;
const AVG_FALL: usize = 3;
const AVG_WINNER: usize = 4;
const M_SEED: u64 = 1001;
const R_SEED: u64 = 1002;

fn ak_msg() -> Ak {
    Ak::new("l:msgs.0").unwrap()
}

fn mix(i: u64) -> u64 {
    let mut x = i.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0x5eed;
    x ^= x >> 29;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^ (x >> 32)
}

/// Who writes message `i`: writer `HEAVY` 30% of them, the others evenly.
fn author(i: usize) -> usize {
    let r = mix(i as u64);
    if r % 100 < 30 {
        return HEAVY;
    }
    let k = ((r >> 8) % (WRITERS as u64 - 1)) as usize;
    if k == HEAVY { WRITERS - 1 } else { k }
}

/// A 200 B message.
fn body(i: usize) -> String {
    let mut s = format!("{i:010} ");
    let mut x = mix(i as u64 + 1);
    while s.len() < 200 {
        x = mix(x);
        s.push(char::from(b'a' + (x % 26) as u8));
    }
    s
}

fn msg_time(i: usize) -> u64 {
    FIRST + GAP * i as u64
}

/// Seconds of CPU this process used so far (user + system, ticks of 10 ms).
fn cpu() -> f64 {
    let s = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let f: Vec<&str> = s.rsplit(')').next().unwrap_or("").split_whitespace().collect();
    let tick = |k: usize| f.get(k).and_then(|x| x.parse::<f64>().ok()).unwrap_or(0.0);
    (tick(11) + tick(12)) / 100.0
}

/// `OSIS_SCALE_UNBOUNDED`: without the scan of issues/long-aspect-cost.md.
fn unscanned(e: &mut Engine) {
    if std::env::var_os("OSIS_SCALE_UNBOUNDED").is_some() {
        e.assume_unbounded(true);
    }
}

fn load() -> String {
    std::fs::read_to_string("/proc/loadavg").unwrap_or_default().split_whitespace().next().unwrap_or("?").to_string()
}

/// Runs `f`, printing wall, CPU, peak and final resident set (MiB) and the load.
fn step<T>(n: usize, what: &str, f: impl FnOnce() -> T) -> T {
    reset_peak();
    let (t0, c0) = (Instant::now(), cpu());
    let r = f();
    println!("LONG n={n} {what}: wall {:.3?}, cpu {:.2} s, peak {} MiB, rss {} MiB, load {}", t0.elapsed(), cpu() - c0, peak_kib() / 1024, rss_kib() / 1024, load());
    r
}

fn dir() -> PathBuf {
    std::env::var_os("OSIS_SCALE_DIR").map_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("long-aspect"), PathBuf::from)
}

fn size_n() -> usize {
    std::env::var("OSIS_SCALE_N").ok().and_then(|s| s.parse().ok()).unwrap_or(10_000)
}

/// A redb store filled with an fsync per `OSIS_SCALE_SYNC_EVERY` commits, default 50 (at 1, 3 h
/// at 10^6 on this disk; redb reuses a freed page only after a durable commit, so with none at
/// all the file grows 200 KB per message: at 10^4, 14 MiB at 1, 514 MiB at 1000, 2 GiB at none),
/// durable once dropped. Also the bytes each commit gave the backend.
struct Unsynced(RedbBackend, u64, u64);

fn sync_every() -> u64 {
    std::env::var("OSIS_SCALE_SYNC_EVERY").ok().and_then(|s| s.parse().ok()).unwrap_or(50)
}

impl Backend for Unsynced {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, BackendError> {
        self.0.get(key)
    }
    fn scan(&self, start: &[u8], end: Option<&[u8]>, limit: usize) -> Result<Vec<KeyValue>, BackendError> {
        self.0.scan(start, end, limit)
    }
    fn commit(&mut self, batch: WriteBatch) -> Result<(), BackendError> {
        self.1 += 1;
        self.2 += batch.bytes() as u64;
        if self.1.is_multiple_of(sync_every()) { self.0.commit(batch) } else { self.0.commit_unsynced(batch) }
    }
    fn get_blob(&self, id: &osis_base::BlobId) -> Result<Option<Vec<u8>>, BackendError> {
        self.0.get_blob(id)
    }
    fn read_blob(&self, id: &osis_base::BlobId, offset: u64, len: usize) -> Result<Option<Vec<u8>>, BackendError> {
        self.0.read_blob(id, offset, len)
    }
    fn blob_len(&self, id: &osis_base::BlobId) -> Result<Option<u64>, BackendError> {
        self.0.blob_len(id)
    }
}

impl Drop for Unsynced {
    fn drop(&mut self) {
        println!("LONG store writes: {} batches, {} B each", self.1, self.2 / self.1.max(1));
        self.0.commit(WriteBatch::default()).unwrap();
    }
}

/// What every step knows: the chat, its writers, the admin M and the receiver R.
struct Meta {
    t: Tid,
    writers: Vec<Tid>,
}

fn write_frame(w: &mut impl Write, p: &Package) {
    let b = encode_packages(std::slice::from_ref(p));
    w.write_all(&(b.len() as u32).to_le_bytes()).unwrap();
    w.write_all(&b).unwrap();
}

/// The packages of a file, one at a time.
struct Frames(BufReader<std::fs::File>);

impl Frames {
    fn open(p: &Path) -> Frames {
        Frames(BufReader::with_capacity(1 << 20, std::fs::File::open(p).unwrap()))
    }
}

impl Iterator for Frames {
    type Item = Package;
    fn next(&mut self) -> Option<Package> {
        let mut len = [0; 4];
        self.0.read_exact(&mut len).ok()?;
        let mut b = vec![0; u32::from_le_bytes(len) as usize];
        self.0.read_exact(&mut b).unwrap();
        decode_packages(&b).pop()
    }
}

fn meta_read(d: &Path) -> Meta {
    let b = std::fs::read(d.join("meta.bin")).unwrap();
    let Value::List(l) = osis_base::decode(&b, &osis_base::Limits { max_depth: 4, max_bytes: b.len() }).unwrap() else { panic!() };
    let tids: Vec<Tid> = l
        .iter()
        .map(|v| match v {
            Value::Tid(x) => *x,
            _ => panic!(),
        })
        .collect();
    Meta { t: tids[0], writers: tids[1..].to_vec() }
}

/// The chat and `count` messages, at `d`: `setup.bin` (roles and actors, in any order: nodes wait
/// for what they lack), `msgs.bin` (by time), `meta.bin`.
fn gen_messages(d: &Path, count: usize) {
    let t = Instant::now();
    let mut peers: Vec<Peer> = (0..WRITERS as u64).map(|i| Peer::new(100 + i, WallMs(T0)).unwrap()).collect();
    peers.push(Peer::new(M_SEED, WallMs(T0)).unwrap());
    peers.push(Peer::new(R_SEED, WallMs(T0)).unwrap());
    let mut lp = LocalPeer::of(peers, 7);
    let tids: Vec<Tid> = lp.peers.iter().map(|p| p.engine.tid()).collect();
    let mut m = Mutation::new();
    let chat = lp.peers[0].engine.new_thing(&mut m, tids[0]);
    lp.peers[0].commit(m).unwrap().unwrap();
    for (i, x) in tids.iter().enumerate().skip(1) {
        let role = if i >= WRITERS { Role::Admin } else { Role::Write };
        set_edge(&mut lp.peers[0].engine, chat, *x, Some(edge(role)), None);
    }
    lp.sync_all().unwrap();
    let mut seen = BTreeSet::new();
    let mut w = BufWriter::new(std::fs::File::create(d.join("setup.bin")).unwrap());
    for i in 0..lp.peers.len() {
        for p in lp.packages(i).unwrap() {
            if seen.insert(p.id) {
                write_frame(&mut w, &p);
            }
        }
    }
    w.flush().unwrap();
    let mut schedule: Vec<Vec<usize>> = vec![Vec::new(); WRITERS];
    for i in 0..count {
        schedule[author(i)].push(i);
    }
    // nothing a writer's commit reads depends on the others' writes: a register's join is by stamp
    let mut peers = lp.peers;
    peers.truncate(WRITERS);
    let mut all: Vec<(usize, Vec<u8>)> = std::thread::scope(|s| {
        let hs: Vec<_> = peers
            .into_iter()
            .zip(schedule)
            .map(|(mut p, sch)| {
                s.spawn(move || {
                    let mut out = Vec::with_capacity(sch.len());
                    unscanned(&mut p.engine);
                    for i in sch {
                        p.clock.set(WallMs(msg_time(i)));
                        let mut m = Mutation::new();
                        m.set(chat, &MSG, &Value::Str(body(i))).unwrap();
                        let id = p.commit(m).unwrap().unwrap();
                        let pk = p.engine.package(&id).unwrap().unwrap();
                        out.push((i, encode_packages(std::slice::from_ref(&pk))));
                    }
                    out
                })
            })
            .collect();
        hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
    });
    all.sort_by_key(|x| x.0);
    let mut w = BufWriter::new(std::fs::File::create(d.join("msgs.bin")).unwrap());
    let mut bytes = 0;
    for (_, b) in &all {
        bytes += b.len();
        w.write_all(&(b.len() as u32).to_le_bytes()).unwrap();
        w.write_all(b).unwrap();
    }
    w.flush().unwrap();
    let meta = osis_base::encode(&Value::List(std::iter::once(chat).chain(tids.iter().copied()).map(Value::Tid).collect()));
    std::fs::write(d.join("meta.bin"), meta).unwrap();
    println!("LONG generated {count} messages by {WRITERS} writers in {:?}, {} B each framed", t.elapsed(), bytes / count.max(1));
}

fn store_paths(d: &Path, who: &str) -> (PathBuf, PathBuf) {
    (d.join(format!("{who}.redb")), d.join(format!("{who}.root")))
}

fn file_mib(p: &Path) -> u64 {
    std::fs::metadata(p).map_or(0, |m| m.len()) / (1 << 20)
}

/// A fresh node takes the setup and the first N messages, in order, into a redb store.
fn build(d: &Path, n: usize, who: &str, seed: u64) {
    let (db, root) = store_paths(d, who);
    let _ = std::fs::remove_file(&db);
    let _ = std::fs::remove_file(&root);
    let clock = Arc::new(ManualClock::new(WallMs(T0)));
    let c: Arc<dyn Clock> = clock.clone();
    let mut e = Engine::create(Box::new(Unsynced(RedbBackend::open(&db).unwrap(), 0, 0)), Box::new(FileRoot::new(root)), Config::default(), c, Box::new(SeededRng::from_u64(seed))).unwrap();
    unscanned(&mut e);
    let up = d.parent().unwrap();
    let meta = meta_read(up);
    assert!(meta.writers.contains(&e.tid()), "the node's tid is not the generated one");
    clock.set(WallMs(FIRST));
    for p in Frames::open(&up.join("setup.bin")) {
        e.ingest(&p.bytes, p.blobs).unwrap();
    }
    let (t0, c0) = (Instant::now(), cpu());
    let mut lap = (Instant::now(), cpu());
    let tenth = (n / 10).max(1);
    let mut inside = 0.0;
    for (i, p) in Frames::open(&up.join("msgs.bin")).take(n).enumerate() {
        clock.set(WallMs(msg_time(i)));
        let t1 = Instant::now();
        let r = e.ingest(&p.bytes, p.blobs).unwrap();
        inside += t1.elapsed().as_secs_f64();
        assert!(matches!(r, Ingested::Applied(_)), "message {i}: {r:?}");
        if (i + 1) % tenth == 0 {
            println!("LONG n={n} {who} at {}: {:.0} us per message wall, {:.0} us cpu, rss {} MiB, store {} MiB", i + 1, lap.0.elapsed().as_secs_f64() * 1e6 / tenth as f64, (cpu() - lap.1) * 1e6 / tenth as f64, rss_kib() / 1024, file_mib(&db));
            lap = (Instant::now(), cpu());
        }
    }
    println!("LONG n={n} {who} ingested in order: wall {:?} ({inside:.1} s in ingest, {:.0} us each), cpu {:.1} s, peak {} MiB", t0.elapsed(), inside * 1e6 / n as f64, cpu() - c0, peak_kib() / 1024);
    e.tick().unwrap();
    assert_eq!(e.held_bodies(&meta.t, &ak_msg()), n, "every body held");
    check_page(&mut e, &meta, n, n);
    drop(e);
    println!("LONG n={n} {who} store {} MiB on disk, {} B per message", file_mib(&db), std::fs::metadata(&db).unwrap().len() / n as u64);
}

/// The oldest and newest bodies are the messages written (`held` of them, the newest message `last - 1`).
fn check_page(e: &mut Engine, meta: &Meta, held: usize, last: usize) {
    let a = ak_msg();
    let page = e.body_page(&meta.t, &a, false, 0, 1).unwrap();
    assert_eq!(page[0].value, Some(Value::Str(body(0))));
    let page = e.body_page(&meta.t, &a, true, 0, 1).unwrap();
    assert_eq!(page[0].value, Some(Value::Str(body(last - 1))));
    assert_eq!(e.held_bodies(&meta.t, &a), held);
}

fn open_at(db: &Path, root: &Path, now: u64, seed: u64) -> (Engine, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(WallMs(now)));
    let c: Arc<dyn Clock> = clock.clone();
    let mut e = Engine::open(Box::new(RedbBackend::open(db).unwrap()), Box::new(FileRoot::new(root.to_path_buf())), Config::default(), c, Box::new(SeededRng::from_u64(seed))).unwrap();
    unscanned(&mut e);
    (e, clock)
}

/// Copies a built store to `work-<who>`, for a step that changes it.
fn work_copy(d: &Path, who: &str) -> (PathBuf, PathBuf) {
    let (db, root) = store_paths(d, who);
    let (wdb, wroot) = store_paths(d, &format!("work-{who}"));
    std::fs::copy(db, &wdb).unwrap();
    std::fs::copy(root, &wroot).unwrap();
    (wdb, wroot)
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

/// Open, reading the state, pages of old bodies.
fn step_open(d: &Path, n: usize) {
    let meta = meta_read(d.parent().unwrap());
    let (db, root) = work_copy(d, "m");
    let now = msg_time(n) + 3_600_000;
    let (e, _) = step(n, "open", || open_at(&db, &root, now, 3));
    println!("LONG n={n} open restored {} walks; after open rss {} MiB", e.walks_restored(), rss_kib() / 1024);
    drop(e);
    let (mut e, _) = step(n, "open again", || open_at(&db, &root, now, 4));
    let a = ak_msg();
    let v = step(n, "read the state first", || e.get(&meta.t, &a).unwrap());
    assert_eq!(v, Some(Value::Str(body(n - 1))));
    step(n, "read the state again", || e.get(&meta.t, &a).unwrap());
    let page = |e: &mut Engine, what: &str, newest: bool, skip: usize, n: usize| {
        let p = step(n, what, || e.body_page(&meta.t, &a, newest, skip, 50).unwrap());
        assert_eq!(p.len(), 50);
        assert!(p.iter().all(|x| x.valid && matches!(&x.value, Some(Value::Str(s)) if s.len() == 200)));
    };
    for k in 0..3 {
        page(&mut e, &format!("page of 50, newest ({k})"), true, 0, n);
    }
    for k in 0..3 {
        page(&mut e, &format!("page of 50, oldest ({k})"), false, 0, n);
    }
    let p = step(n, "page of 50, middle (skip N/2)", || e.body_page(&meta.t, &a, true, n / 2, 50).unwrap());
    assert_eq!(p.len(), 50);
}

/// One local write and one received commit, on a durable store.
fn step_write(d: &Path, n: usize) {
    let up = d.parent().unwrap().to_path_buf();
    let meta = meta_read(&up);
    let (db, root) = work_copy(d, "m");
    let now = msg_time(n + SPARE) + 7_200_000;
    let (mut e, clock) = open_at(&db, &root, now, 5);
    let mut spare = Frames::open(&up.join("msgs.bin")).skip(n).take(30);
    let (mut w, mut r) = (Vec::new(), Vec::new());
    let (mut c_w, mut c_r) = (0.0, 0.0);
    for k in 0..30 {
        clock.advance(1_000);
        let c1 = cpu();
        let t0 = Instant::now();
        let mut m = Mutation::new();
        m.set(meta.t, &MSG, &Value::Str(body(n + 1000 + k))).unwrap();
        e.commit(m).unwrap().unwrap();
        w.push(t0.elapsed().as_secs_f64() * 1e3);
        c_w += cpu() - c1;
        let p = spare.next().unwrap();
        let c1 = cpu();
        let t0 = Instant::now();
        assert!(matches!(e.ingest(&p.bytes, p.blobs).unwrap(), Ingested::Applied(_)));
        r.push(t0.elapsed().as_secs_f64() * 1e3);
        c_r += cpu() - c1;
    }
    println!("LONG n={n} one local write (durable): median {:.2} ms, max {:.2} ms, {:.2} ms cpu; one received commit (durable, older than the state's winner): median {:.2} ms, max {:.2} ms, {:.2} ms cpu; rss {} MiB, load {}", median(w.clone()), w.iter().copied().fold(0.0, f64::max), c_w * 1e3 / 30.0, median(r.clone()), r.iter().copied().fold(0.0, f64::max), c_r * 1e3 / 30.0, rss_kib() / 1024, load());
}

fn pkg_size(p: &Package) -> (usize, usize, usize) {
    (p.bytes.len(), p.blobs.len(), p.blobs.iter().map(|b| b.1.len()).sum())
}

fn in_order(e: &mut Engine, meta: &Meta, n: usize) {
    let inv = e.invalid_writes(&meta.t, &ak_msg()).len();
    println!("LONG n={n} invalid writes now: {inv}");
}

/// Sets `holder`'s edge at `e`, timed, keeping the commit.
fn edge_commit(e: &mut Engine, n: usize, what: &str, (t, holder): (Tid, Tid), role: Option<Role>, f: Option<Value>, out: &mut impl Write) {
    let id = step(n, what, || set_edge(e, t, holder, role.map(edge), f));
    let p = e.package(&id).unwrap().unwrap();
    let (b, k, s) = pkg_size(&p);
    println!("LONG n={n} {what}: commit {b} B + {k} blobs, {s} B");
    write_frame(out, &p);
    out.flush().unwrap();
}

/// Kicks with today's frontier at the admin M; their commits for R.
fn step_kick_m(d: &Path, n: usize) {
    let meta = meta_read(d.parent().unwrap());
    let (db, root) = work_copy(d, "m");
    let (mut e, clock) = open_at(&db, &root, msg_time(n) + 10_800_000, 6);
    let mut out = BufWriter::new(std::fs::File::create(d.join("kick.bin")).unwrap());
    for (name, w) in [("avg", AVG), ("heavy", HEAVY)] {
        let v = meta.writers[w];
        let count = (0..n).filter(|i| author(*i) == w).count();
        clock.advance(60_000);
        let scope = DemotionScope { roles: BTreeMap::from([(v, BTreeSet::from([meta.t]))]), content: BTreeMap::from([(v, BTreeSet::from([meta.t]))]) };
        let now = e.now();
        let f = step(n, &format!("kick {name} ({count} messages): the frontier alone"), || e.frontier(&scope, now).unwrap());
        let enc = osis_base::encode(&f.to_value()).len();
        println!("LONG n={n} kick {name}: the frontier lists {} commits, {enc} B encoded", f.commits.len());
        let d = Demotion { holder: v, new: None, presync: PreSync::Synced };
        let done = step(n, &format!("kick {name}: the whole demote"), || e.demote(&meta.t, &d));
        match done {
            Ok(done) => {
                for id in &done.commits {
                    let p = e.package(id).unwrap().unwrap();
                    let (b, k, s) = pkg_size(&p);
                    println!("LONG n={n} kick {name}: commit {b} B + {k} blobs, {s} B");
                    write_frame(&mut out, &p);
                }
            }
            Err(err) => println!("LONG n={n} kick {name}: FAILED: {err:?}"),
        }
        in_order(&mut e, &meta, n);
        clock.advance(60_000);
        edge_commit(&mut e, n, &format!("kick {name}: re-add"), (meta.t, v), Some(Role::Write), None, &mut out);
    }
    out.flush().unwrap();
}

/// R applies what `step_kick_m` or `step_fall_m` wrote.
fn apply_at_r(d: &Path, n: usize, file: &str, labels: &[&str], now: u64) {
    let meta = meta_read(d.parent().unwrap());
    let (db, root) = work_copy(d, "r");
    let (mut e, _) = open_at(&db, &root, now, 7);
    let a = ak_msg();
    for (p, what) in Frames::open(&d.join(file)).zip(labels.iter().cycle()) {
        match step(n, &format!("R applies: {what}"), || e.ingest(&p.bytes, p.blobs.clone())) {
            Ok(Ingested::Applied(_)) => (),
            r => println!("LONG n={n} R did not apply {what}: {r:?}"),
        }
        let v = step(n, &format!("R reads the state after: {what}"), || e.get(&meta.t, &a).unwrap());
        let s = match &v {
            Some(Value::Str(s)) => s.get(..10).unwrap_or_default().to_string(),
            _ => format!("{v:?}"),
        };
        println!("LONG n={n} R after {what}: state message {s}, {} invalid", e.invalid_writes(&meta.t, &a).len());
    }
}

/// What a fall's frontier leaves out of the member's received commits.
enum Omit {
    /// All of them: an admin that received nothing of the member's.
    Whole,
    Some(usize),
    One(osis_base::CommitId),
}

/// The falls measured: 100 messages of an average member; only the state's winner; then with
/// nothing listed, an average member, its winner and the heavy one. Un-merging is quadratic in
/// the fallen deltas (over 26 min for 3.7*10^4 of them at 10^6), so 10^6 stops at the first two.
fn fall_cases(n: usize, meta: &Meta, winner: osis_base::CommitId) -> Vec<(&'static str, Tid, Omit)> {
    let (avg, win) = (meta.writers[AVG_FALL], meta.writers[AVG_WINNER]);
    let mut v = vec![("few", avg, Omit::Some(100)), ("winner alone", win, Omit::One(winner))];
    if n < 1_000_000 && std::env::var_os("OSIS_SCALE_FALL_FEW").is_none() {
        v.extend([("avg", avg, Omit::Whole), ("winner", win, Omit::Whole), ("heavy", meta.writers[HEAVY], Omit::Whole)]);
    }
    v
}

/// Validity falling and rising at M: an admin kicks with a frontier leaving out some or all of the
/// member's commits, then adds it again (`fall_cases`).
fn step_fall_m(d: &Path, n: usize) {
    let up = d.parent().unwrap().to_path_buf();
    let meta = meta_read(&up);
    let (db, root) = work_copy(d, "m");
    let (mut e, clock) = open_at(&db, &root, msg_time(n + SPARE) + 14_400_000, 8);
    let mut out = BufWriter::new(std::fs::File::create(d.join("fall.bin")).unwrap());
    let a = ak_msg();
    // the winner's author's newest message
    let i = (n..n + SPARE).find(|i| author(*i) == AVG_WINNER).expect("a spare message by the writer");
    let p = Frames::open(&up.join("msgs.bin")).nth(i).unwrap();
    assert!(matches!(e.ingest(&p.bytes, p.blobs.clone()).unwrap(), Ingested::Applied(_)));
    write_frame(&mut out, &p);
    for (name, v, omit) in fall_cases(n, &meta, p.id) {
        clock.advance(60_000);
        // the frontier as today, less what `omit` leaves out: those commits fall, the others stay
        let empty = if let Omit::Whole = omit {
            ct::Frontier::default()
        } else {
            let scope = DemotionScope { roles: BTreeMap::from([(v, BTreeSet::from([meta.t]))]), content: BTreeMap::from([(v, BTreeSet::from([meta.t]))]) };
            let now = e.now();
            let mut f = e.frontier(&scope, now).unwrap();
            match omit {
                Omit::Some(k) => {
                    let gone: Vec<_> = f.commits.iter().take(k).copied().collect();
                    for c in gone {
                        f.commits.remove(&c);
                    }
                }
                Omit::One(c) => {
                    f.commits.remove(&c);
                }
                Omit::Whole => (),
            }
            f
        }
        .to_value();
        edge_commit(&mut e, n, &format!("fall {name}: M's kick"), (meta.t, v), None, Some(empty), &mut out);
        let g = step(n, &format!("fall {name}: M reads the state"), || e.get(&meta.t, &a).unwrap());
        println!("LONG n={n} fall {name}: state {:?}, {} invalid", g.map(|x| format!("{x:?}").chars().take(16).collect::<String>()), e.invalid_writes(&meta.t, &a).len());
        clock.advance(60_000);
        edge_commit(&mut e, n, &format!("rise {name}: M's re-add"), (meta.t, v), Some(Role::Write), None, &mut out);
        let g = step(n, &format!("rise {name}: M reads the state"), || e.get(&meta.t, &a).unwrap());
        println!("LONG n={n} rise {name}: state {:?}, {} invalid", g.map(|x| format!("{x:?}").chars().take(16).collect::<String>()), e.invalid_writes(&meta.t, &a).len());
    }
    out.flush().unwrap();
}

fn run_child(step: &str) -> std::process::Child {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "scale::long_aspect::cost", "--nocapture", "--test-threads", "1"])
        .env("OSIS_SCALE_STEP", step)
        .spawn()
        .unwrap()
}

// spec/commits.md §5 (a kept body stays), spec/permissions.md §5.2; spec/requirements.md, Scale: no operation O(history). The numbers: notes/testing.md, "Scale checks". Fills and measures redb stores; a run of 10^6
// wants about 10 GB of disk and about as much memory for each of two builds.
#[test]
#[ignore]
fn cost() {
    let n = size_n();
    let up = dir();
    let d = up.join(format!("n{n}"));
    if let Ok(s) = std::env::var("OSIS_SCALE_STEP") {
        let later = msg_time(n + SPARE) + 20_000_000;
        match s.as_str() {
            "gen" => gen_messages(&up, n + SPARE),
            "build-m" => build(&d, n, "m", M_SEED),
            "build-r" => build(&d, n, "r", R_SEED),
            "open" => step_open(&d, n),
            "write" => step_write(&d, n),
            "kick-m" => step_kick_m(&d, n),
            "kick-r" => apply_at_r(&d, n, "kick.bin", &["kick", "re-add"], later),
            "fall-m" => step_fall_m(&d, n),
            "fall-r" => apply_at_r(&d, n, "fall.bin", &["the winner's message", "fall few", "rise few", "fall winner alone", "rise winner alone", "fall avg", "rise avg", "fall winner", "rise winner", "fall heavy", "rise heavy"], later),
            _ => panic!("unknown step {s}"),
        }
        return;
    }
    std::fs::create_dir_all(&d).unwrap();
    let steps = std::env::var("OSIS_SCALE_STEPS").unwrap_or_else(|_| "gen,build,open,write,kick,fall".into());
    for s in steps.split(',') {
        let mut kids: Vec<std::process::Child> = match s {
            "build" => vec![run_child("build-m"), run_child("build-r")],
            "kick" | "fall" => {
                let mut k = run_child(&format!("{s}-m"));
                assert!(k.wait().unwrap().success(), "{s}-m");
                vec![run_child(&format!("{s}-r"))]
            }
            _ => vec![run_child(s)],
        };
        for k in &mut kids {
            assert!(k.wait().unwrap().success(), "{s}");
        }
    }
    for who in ["work-m", "work-r"] {
        let (db, root) = store_paths(&d, who);
        let _ = std::fs::remove_file(db);
        let _ = std::fs::remove_file(root);
    }
}

// spec/sync.md §6, §7: the sync steps through one host on the sim (stores in memory): one writer
// (a sync pass's cost does not depend on who wrote; `cost` has 20) writes N kept messages and
// uploads; a fresh member syncs them; a pass with nothing new; one more message. The hub's and
// each node's time apart. `OSIS_SCALE_N` sets N.
#[test]
#[ignore]
fn first_sync() {
    let n = size_n();
    let mut net = net::Net::new();
    let host = net.add_host();
    let a = net.node(1, &[host]);
    let c = net.node(3, &[host]);
    let g = net.group(a, &[(c, Role::Read)], &[host]);
    let t = net.item(a, g, g, "chat");
    net.run();
    unscanned(net.engine(a));
    unscanned(net.engine(c));
    net.set_online(c, false);
    let t0 = Instant::now();
    for i in 0..n {
        let mut m = Mutation::new();
        m.set(t, &MSG, &Value::Str(body(i))).unwrap();
        net.engine(a).commit(m).unwrap().unwrap();
    }
    println!("LONG sync n={n}: writing {:?}, rss {} MiB", t0.elapsed(), rss_kib() / 1024);
    let up = Instant::now();
    net.busy.clear();
    osis_node::costs::take();
    net.run();
    for (k, d, calls) in osis_node::costs::take() {
        println!("LONG   upload {k}: {d:?} ({calls})");
    }
    println!("LONG sync n={n}: upload {:?} (writer {:?}, hub {:?}), rss {} MiB, load {}", up.elapsed(), net.busy.get(&a).copied().unwrap_or_default(), net.hub_busy, rss_kib() / 1024, load());
    let l = net.label(a);
    let held = net.host_ids(host, &l).len();
    assert!(held >= n, "{held} entries at the host");
    let hub0 = net.hub_busy;
    net.busy.clear();
    osis_node::costs::take();
    net.set_online(c, true);
    reset_peak();
    let (t1, c1) = (Instant::now(), cpu());
    net.advance(61_000);
    net.run();
    println!("LONG sync n={n}: the reader holds {} commits", net.engine(c).commit_ids().len());
    let (first, cp) = (t1.elapsed(), cpu() - c1);
    let phases = osis_node::costs::take();
    let k = ak_msg();
    assert_eq!(net.engine(c).held_bodies(&t, &k), n, "every body held");
    let p = net.engine(c).body_page(&t, &k, false, 0, 1).unwrap();
    assert_eq!(p[0].value, Some(Value::Str(body(0))));
    println!(
        "LONG sync n={n}: first sync {first:?}, {:.0} us per message, cpu {cp:.1} s (reader {:?}, writer {:?}, hub {:?}), {held} entries, peak {} MiB, load {}",
        first.as_secs_f64() * 1e6 / n as f64,
        net.busy.get(&c).copied().unwrap_or_default(),
        net.busy.get(&a).copied().unwrap_or_default(),
        net.hub_busy.saturating_sub(hub0),
        peak_kib() / 1024,
        load()
    );
    for (k, d, calls) in &phases {
        println!("LONG   {k}: {d:?} ({calls})");
    }
    assert_eq!(net.read(c, t), Some(net::s("chat")));
    let d = |x: osis_node::sync::PassStats, y: osis_node::sync::PassStats| (y.passes - x.passes, y.full - x.full, y.bodies - x.bodies, y.entries - x.entries);
    net.advance(61_000);
    let s0 = (net.sync(a).pass_stats(), net.sync(c).pass_stats());
    let t2 = Instant::now();
    net.advance(61_000);
    let quiet = t2.elapsed();
    let s1 = (net.sync(a).pass_stats(), net.sync(c).pass_stats());
    println!("LONG sync n={n}: 61 s with nothing new {quiet:?}, (passes, full, bodies, entries) writer {:?} reader {:?}", d(s0.0, s1.0), d(s0.1, s1.1));
    let t3 = Instant::now();
    let mut m = Mutation::new();
    m.set(t, &MSG, &Value::Str(body(n))).unwrap();
    net.engine(a).commit(m).unwrap().unwrap();
    net.run();
    let one = t3.elapsed();
    let s2 = (net.sync(a).pass_stats(), net.sync(c).pass_stats());
    println!("LONG sync n={n}: one more message synced {one:?}, writer {:?} reader {:?}; rss {} MiB", d(s1.0, s2.0), d(s1.1, s2.1), rss_kib() / 1024);
    assert_eq!(net.engine(c).held_bodies(&t, &k), n + 1);
}
