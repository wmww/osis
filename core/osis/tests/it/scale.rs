//! Large values read as streams (spec/requirements.md Scale): work counted at n and 10n MiB
//! (default tests), and a multi-GB value's peak memory while it is read, by hand:
//! `OSIS_LARGE_MIB=1024 cargo test --release -p osis --test it -- --ignored scale::multi_gb_value_streams --nocapture`
//! (a store in a directory under the target dir).

use crate::common::{cfg, clock};
use osis::{DynamicAspectKey, MemStore, Osis, Store, Tid, p};
use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom};

const MIB: usize = 1 << 20;

/// Byte `i` of the test value.
fn byte(i: usize) -> u8 {
    (i % 251) as u8 ^ (i >> 20) as u8
}

fn data(mib: usize) -> Vec<u8> {
    (0..mib * MIB).map(byte).collect()
}

/// Chunks of the blob of `mib` MiB as the format cuts its canonical bytes.
fn chunks(mib: usize) -> u64 {
    let canonical = osis_base::encode(&osis::Value::Bytes(data(mib)));
    osis_base::chunker::chunk_lengths(&canonical, osis_base::ChunkParams::FORMAT).len() as u64
}

/// Writes a blob of `mib` MiB as one value of a new thing.
fn write(db: &Osis, mib: usize) -> Tid {
    let data = data(mib);
    let mut w = db.write();
    let t = w.create().unwrap();
    w.at(t, key()).path(p![]).set_stream(&data[..]).unwrap();
    w.commit().unwrap();
    t
}

fn key() -> DynamicAspectKey {
    DynamicAspectKey::untyped(osis::Ak::new("t:blob.0").unwrap())
}

/// Reads the value whole through `s` in 64 KiB reads, checking every byte.
fn read_all(s: &mut osis::ValueStream, from: usize) {
    let mut buf = vec![0u8; 64 * 1024];
    let mut at = from;
    loop {
        let n = s.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        assert!(buf[..n].iter().enumerate().all(|(k, b)| *b == byte(at + k)), "bytes at {at}");
        at += n;
    }
    assert_eq!(at as u64, s.len());
}

// spec/requirements.md, Scale: large values stream; spec/data-model.md §6, spec/wire.md §6: from
// n to 10n MiB a whole read fetches each chunk once and holds at most one chunk (256 KiB
// at most) and the tree path, whatever the size; a read of the last MiB after a seek fetches only
// that range's chunks (flat). Counted on `ValueStream`.
#[test]
fn large_value_read_work_is_linear() {
    let run = |mib: usize| {
        let c = clock();
        let db = osis::internals::create(cfg(0, MemStore::new(), &c)).unwrap();
        let t = write(&db, mib);
        let mut s = db.at(t, key()).path(p![]).stream().unwrap().unwrap();
        assert_eq!(s.len(), (mib * MIB) as u64);
        read_all(&mut s, 0);
        let (whole, held) = osis::internals::stream_work(&s);
        let mut s = db.at(t, key()).path(p![]).stream().unwrap().unwrap();
        let tail = (mib - 1) * MIB;
        s.seek(SeekFrom::Start(tail as u64)).unwrap();
        let before = osis::internals::stream_work(&s).0;
        read_all(&mut s, tail);
        (whole, held, osis::internals::stream_work(&s).0 - before)
    };
    let (small, big) = (run(1), run(10));
    assert_eq!((small.0, big.0), (chunks(1), chunks(10)), "each chunk fetched once");
    // one chunk at its largest plus room for the tree path
    assert!(small.1.max(big.1) <= osis_base::ChunkParams::FORMAT.max + 64 * 1024, "held {} at 1 MiB, {} at 10", small.1, big.1);
    assert!(big.2 <= 2 * small.2 + 2, "tail MiB fetched {} chunks at 1 MiB, {} at 10", small.2, big.2);
}

/// Peak resident set (VmHWM) in KiB.
fn peak_kib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = s.lines().find(|l| l.starts_with("VmHWM:")).unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

/// Resets VmHWM to the current RSS (Linux: `5` to clear_refs).
fn reset_peak() {
    std::fs::write("/proc/self/clear_refs", "5").unwrap();
}

// spec/requirements.md, Scale: multi-GB single values; no whole value is needed in memory to
// read one. spec/data-model.md §6: a value read back as a `ValueStream` grows peak RSS within a
// fixed bound. The write holds the value whole (`set_stream` reads it in first,
// issues/api-deferred.md), so only the read is measured.
#[test]
#[ignore = "memory: by hand, release"]
fn multi_gb_value_streams() {
    let mib: usize = std::env::var("OSIS_LARGE_MIB").ok().and_then(|s| s.parse().ok()).unwrap_or(1024);
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("large-value");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let c = clock();
    let mut o = osis::internals::Opening::at(Store::Dir(dir.clone()));
    o.app.internals.seed = Some(0);
    o.app.internals.clock = Some(c.clone());
    let db = osis::internals::create(o).unwrap();
    let t = write(&db, mib);
    let mut s = db.at(t, key()).path(p![]).stream().unwrap().unwrap();
    reset_peak();
    let base = peak_kib();
    read_all(&mut s, 0);
    let peak = peak_kib().saturating_sub(base);
    println!("large value {mib} MiB: stream held at most {} B, peak RSS growth {peak} KiB reading", osis::internals::stream_work(&s).1);
    drop((s, db));
    let _ = std::fs::remove_dir_all(&dir);
    // Fixed bound, independent of the value size: one chunk (256 KiB max) plus the tree path.
    assert!(peak < 64 * 1024, "peak RSS growth {peak} KiB");
}

/// The sync judgements (`read: judged`, `read: local judged`) `n` commits by `write` made, and
/// those one more made.
fn judgements(n: usize, setup: impl Fn(&Osis) -> Tid, write: impl Fn(&Osis, Tid, usize)) -> [(&'static str, u64, u64); 2] {
    use osis::internals::costs;
    let db = crate::common::db(0);
    let t = setup(&db);
    db.settle();
    costs::take();
    for i in 0..n {
        write(&db, t, i);
    }
    db.settle();
    let all = costs::take();
    write(&db, t, n);
    db.settle();
    let last = costs::take();
    let count = |cs: &[(&str, std::time::Duration, u64)], name: &str| cs.iter().find(|c| c.0 == name).map_or(0, |c| c.2);
    ["read: judged", "read: local judged"].map(|name| (name, count(&all, name), count(&last, name)))
}

/// `judgements` at n and 10n: linearly many over the commits, as many for the next one at both.
fn judged_per_commit(what: &str, small: [(&str, u64, u64); 2], big: [(&str, u64, u64); 2]) {
    for ((name, n_all, n_last), (_, big_all, big_last)) in small.into_iter().zip(big) {
        assert!(n_all > 0 && big_all <= 12 * n_all, "{what}, {name}: {n_all} judgements over n, {big_all} over 10n");
        assert_eq!(n_last, big_last, "{what}, {name}: the next one after n and after 10n");
    }
}

// spec/sync.md §2 (work in proportion to change): sync read judges again only the
// bodies whose facts a write changes (`Engine::read_facts`, `Engine::held_fate`: kept per body),
// not every body on the written aspect. Writing n and 10n times on one aspect of a thing keeping
// its history for good judges linearly many bodies (a few per write; every body per write would
// be quadratic), and the next write judges as many at both.
#[test]
fn a_write_judges_the_bodies_it_changes() {
    use crate::common::TestWrites as _;
    let setup = |db: &Osis| {
        let x = crate::common::setting(&[("t:msg.0", osis::History::FOREVER)]);
        db.commit_with(|w| {
            let t = w.create()?;
            w.at(t, osis::core::RETENTION).set(&x)?;
            w.group(db.home()).add(osis::Member::Subgroup(t))?;
            Ok(t)
        })
        .unwrap()
    };
    let write = |db: &Osis, t: Tid, i: usize| db.commit_set(t, DynamicAspectKey::untyped(crate::common::ak("t:msg.0")), &osis::Value::Int(i as i64)).unwrap();
    judged_per_commit("writes on one aspect", judgements(10, setup, write), judgements(100, setup, write));
}

/// A new thing listed in the account's home group (a write on its `group.0`).
fn new_thing(db: &Osis) {
    let mut w = db.write();
    let t = w.create().unwrap();
    w.group(db.home()).add(osis::Member::Subgroup(t)).unwrap();
    w.commit().unwrap();
    db.settle();
}

fn cost(cs: &[(&str, std::time::Duration, u64)], name: &str) -> u64 {
    cs.iter().find(|c| c.0 == name).map_or(0, |c| c.2)
}

/// `n` new things, then 8 more: per one of those, the bodies sync read judged (`read: judged`)
/// and whether it wrote a compaction snapshot of the home group's `group.0`.
fn new_things(n: usize) -> Vec<(u64, bool)> {
    use osis::internals::costs;
    let db = crate::common::db(0);
    for _ in 0..n {
        new_thing(&db);
    }
    costs::take();
    (0..8)
        .map(|_| {
            new_thing(&db);
            let cs = costs::take();
            (cost(&cs, "read: judged"), cost(&cs, "compact: snapshots written") > 0)
        })
        .collect()
}

// spec/sync.md §2 (work in proportion to change): a new thing is listed in the account's home
// group (a write on its `group.0`), which moves no earlier body's facts: after n and 10n new
// things, each next one that writes no compaction snapshot judges as many bodies (the account's
// signing chain reads only the account's role commits on home, `Indexes::role_on`: read from all
// its commits there, each listing moves every judgement reading the chain). One writing a
// snapshot judges the bodies since the last (`snapshots_judge_what_they_newly_cover`).
#[test]
fn a_new_thing_judges_the_bodies_it_changes() {
    let plain = |v: Vec<(u64, bool)>| v.into_iter().filter(|x| !x.1).map(|x| x.0).collect::<BTreeSet<u64>>();
    let (small, big) = (plain(new_things(10)), plain(new_things(100)));
    assert!(!small.is_empty() && small == big, "judgements per new thing writing no snapshot, after 10: {small:?}, after 100: {big:?}");
}

/// Over `n` new things: bodies judged, their facts derived (`sync: read facts`), snapshot joins (`covered: join`), forgotten coverers
/// keeping their covers (`forget: covers kept`, rows written), commits' bodies asked by a sync ID
/// pass (`pass: bodies of a commit`: sync status's own commits among them), things' sync rows
/// settled (`sync: set rows`), snapshots written, and folds of the whole sync set (`sync: set
/// folded`).
fn listing_work(n: usize) -> [u64; 8] {
    use osis::internals::costs;
    let db = crate::common::db(0);
    costs::take();
    for _ in 0..n {
        new_thing(&db);
    }
    let cs = costs::take();
    let facts = cs.iter().filter(|c| c.0.starts_with("sync: read facts <- ")).map(|c| c.2).sum();
    let [judged, joins, kept, bodies, rows, snapshots, folded] = ["read: judged", "covered: join", "forget: covers kept", "pass: bodies of a commit", "sync: set rows", "compact: snapshots written", "sync: set folded"].map(|x| cost(&cs, x));
    [judged, facts, joins, kept, bodies, rows, snapshots, folded]
}

// spec/sync.md §2, spec/permissions.md §5.2: covers are transitive along the chain of
// snapshots, so each compaction snapshot of the home group's `group.0` joins and judges only
// the bodies the previous one did not cover: a body dropped as covered stays covered while its
// chain carries it (`Engine::part_covered`), its carriers matter only once its whole body is
// covered (`read_facts`), and a snapshot forgotten under the next keeps its covers in one row
// (`retention::handed`) instead of rewriting every body dropped under it. Sync status's own
// commits under home are rows moved per commit (`sync::own`, spec/sync-status.md §2), and the
// engine's readers of the sync set (passes wanted, the read things, a sync ID read) read rows
// per sync ID and per thing (`sync::rows`), never the whole set folded. n and 10n
// new things do linearly much of each (every body per snapshot is quadratic: 20 to 200 things
// judged 538 to 21,830 bodies, joined 330 to 14,310 pairs and rewrote 63 to 3,399 parts' covers;
// own commits walked whole per pass asked 524 to 25,818 commits' bodies; the whole sync set
// folded per change walked 270 to 20,700 things).
#[test]
fn snapshots_judge_what_they_newly_cover() {
    let (small, big) = (listing_work(20), listing_work(200));
    assert!(small[6] > 1, "snapshots written over 20 things: {small:?}");
    assert_eq!((small[7], big[7]), (0, 0), "the whole sync set folded");
    for (i, what) in ["judgements", "facts", "joins", "kept covers", "bodies asked", "things' sync settled"].iter().enumerate() {
        assert!(small[i] > 0 && big[i] <= 12 * small[i], "{what} over 20 things {}, over 200 {}", small[i], big[i]);
    }
}


