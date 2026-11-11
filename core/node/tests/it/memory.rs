//! Memory checks (by hand, release, each alone: they read this process's resident set):
//! what a holder keeps per byte of ephemeral data, and the peak of applying a huge map.
//! `cargo test --release -p osis-node --test it -- --ignored --nocapture --test-threads 1 memory::<name>`.

use osis_base::{Ak, BlobId, Clock, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::Mutation;

/// A size from `var`, else `release` in a release build and `dev` in a dev one.
fn size(var: &str, release: usize, dev: usize) -> usize {
    std::env::var(var).ok().and_then(|s| s.parse().ok()).unwrap_or(if cfg!(debug_assertions) { dev } else { release })
}

fn ak(s: &str) -> Ak {
    Ak::new(s).unwrap()
}

/// Resident set size of this process (KiB; Linux).
fn rss_kib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    s.split_whitespace().nth(1).and_then(|p| p.parse::<u64>().ok()).unwrap_or(0) * 4
}

/// A net where `x` writes ephemeral data on durable thing `t` that `b` holds: (net, b, x, t).
fn eph_net() -> (crate::net::Net, usize, usize, Tid) {
    let (net, _, [_, b, x], _, [t]) = crate::net::hosted::<3, 1>(&[(1, Role::Write), (2, Role::Write)], ["durable"], true);
    (net, b, x, t)
}

/// Node `x`'s ephemeral commits setting `per` keys of `doc:notes.0` of `t` each, `commits` times
/// (fresh keys every time), as blobs.
fn eph_map_commits(net: &mut crate::net::Net, x: usize, t: Tid, commits: usize, per: usize, value: &Value) -> Vec<osis_commit::CommitBlob> {
    let notes = crate::common::ak("doc:notes+.0");
    let mut blobs = Vec::new();
    for c in 0..commits {
        let mut m = Mutation::new();
        for e in 0..per {
            m.op(t, &notes, PathOp { path: vec![PathSeg::Key(Value::Int((c * per + e) as i64))], op: Op::Set(value.clone()) }).unwrap();
        }
        net.engine(x).write(m).unwrap();
        blobs.extend(take_memory(net, x));
    }
    blobs
}

/// Node `x`'s own memory commits not placed by its sync engine yet, as blobs (each once).
fn take_memory(net: &mut crate::net::Net, x: usize) -> Vec<osis_commit::CommitBlob> {
    thread_local! { static TAKEN: std::cell::RefCell<std::collections::BTreeSet<osis_base::CommitId>> = Default::default(); }
    let ids = net.sync(x).unplaced_memory_commits();
    let e = net.engine(x);
    ids.into_iter().filter(|c| TAKEN.with(|t| t.borrow_mut().insert(*c))).filter_map(|c| e.memory_blob(&c).unwrap()).collect()
}

// issues/eph-node-cost-bounds.md (memory), spec/sync.md §9 (caps): RSS a holder gains per
// encoded byte held, against what the node cap charges (`Engine::memory_charge`), for
// `OSIS_EPH_SHAPE` tiny (many tiny map entries), large (a few 8 KB strings) or aspects (one small
// write on each of many aspects). `OSIS_EPH_PER` entries per commit (tiny), `OSIS_EPH_ROOM`: what
// the holder may hold (`Engine::ingest_memory`, as a node passes its cap's room; unset: no
// bound). Run each shape alone (a fresh process):
// `cargo test --release -p osis-node --test it -- --ignored --nocapture --test-threads 1 memory::eph_decoded_memory`.
#[test]
#[ignore]
fn eph_decoded_memory() {
    let shape = std::env::var("OSIS_EPH_SHAPE").unwrap_or_else(|_| "tiny".into());
    let (mut net, b, x, t) = eph_net();
    let (commits, per, value) = match shape.as_str() {
        "large" => (size("OSIS_EPH_COMMITS", 64, 4), 4, crate::net::s(&"v".repeat(8000))),
        "aspects" => (size("OSIS_EPH_COMMITS", 16, 2), 2000, Value::Int(1)),
        _ => (size("OSIS_EPH_COMMITS", 64, 4), size("OSIS_EPH_PER", 2000, 2000), Value::Int(1)),
    };
    let room: u64 = std::env::var("OSIS_EPH_ROOM").ok().and_then(|s| s.parse().ok()).unwrap_or(u64::MAX);
    let blobs = if shape == "aspects" {
        // one register write on each of `per` aspects, `commits` times (fresh aspects each time)
        let mut blobs = Vec::new();
        for c in 0..commits {
            let mut m = Mutation::new();
            for e in 0..per {
                m.set(t, &crate::common::ak(&format!("x:a{:06}+.0", c * per + e)), &value).unwrap();
            }
            net.engine(x).write(m).unwrap();
            blobs.extend(take_memory(&mut net, x));
        }
        blobs
    } else {
        eph_map_commits(&mut net, x, t, commits, per, &value)
    };
    let blob_bytes: usize = blobs.iter().map(|b| b.parts.iter().map(|p| p.delta.len()).sum::<usize>()).sum();
    let rss0 = rss_kib();
    let mut refused = 0;
    for bl in blobs {
        let ids: Vec<_> = net.engine(b).memory_commits().into_iter().map(|h| h.0).collect();
        let charged: u64 = ids.iter().map(|id| net.engine(b).memory_charge(id).unwrap()).sum();
        let left = room.saturating_sub(charged);
        if matches!(net.engine(b).ingest_memory(&bl.encode(), left).unwrap(), osis_node::Ingested::TooLarge(_)) {
            refused += 1;
        }
    }
    println!("decoded memory ({shape}): {refused} commits refused for the room");
    let rss = rss_kib().saturating_sub(rss0);
    let writes = commits * per;
    let ids: Vec<_> = net.engine(b).memory_commits().into_iter().map(|h| h.0).collect();
    let charge: u64 = ids.iter().map(|id| net.engine(b).memory_charge(id).unwrap()).sum();
    let held = charge as usize;
    println!("decoded memory ({shape}): charged {} KiB", charge / 1024);
    println!("decoded memory ({}): {commits} commits x {per} entries: {} KiB encoded (held {} KiB), RSS +{rss} KiB: {:.1}x, {} B per write", shape, blob_bytes / 1024, held / 1024, rss as f64 * 1024.0 / blob_bytes.max(1) as f64, rss * 1024 / writes as u64);
}

// spec/crdt.md §4.7, spec/commits.md §5 (an expired ephemeral delta is held as its leftover until a
// snapshot covers it): what a holder keeps per expired ephemeral commit, and that a snapshot frees
// it. `x` writes `OSIS_EPH_COMMITS` commits, each one expiring list element (a disappearing
// message: never superseded), `b` holds them. Past their expiry `b` holds their leftovers; `x`
// expires them too, its compaction trigger weighs the leftovers and writes a snapshot, `b` takes
// it and drops every leftover. Prints RSS, held commits and the charge at each stage, and the
// expiry's phases. Run alone:
// `cargo test --release -p osis-node --test it -- --ignored --nocapture --test-threads 1 memory::eph_leftover_memory`.
#[test]
#[ignore]
fn eph_leftover_memory() {
    let (mut net, b, x, t) = eph_net();
    let n = size("OSIS_EPH_COMMITS", 2_000, 200);
    let log = crate::common::LOG;
    let mut m = Mutation::new();
    m.set(t, &log, &Value::List(vec![Value::Str("start".into())])).unwrap();
    net.engine(x).write(m).unwrap();
    let mut blobs = take_memory(&mut net, x);
    for c in 0..n {
        let mut m = Mutation::new();
        m.op(t, &log, PathOp { path: vec![], op: Op::Insert { at: c + 1, items: vec![Value::Str(c.to_string())] } }).unwrap();
        m.expires(t, &log, osis_base::WallMs(net.now() + 60_000)).unwrap();
        net.engine(x).write(m).unwrap();
        blobs.extend(take_memory(&mut net, x));
    }
    let held = |net: &mut crate::net::Net| -> (usize, u64) {
        let ids: Vec<_> = net.engine(b).memory_commits().into_iter().filter(|h| h.1 > 0).map(|h| h.0).collect();
        let charge = ids.iter().map(|id| net.engine(b).memory_charge(id).unwrap()).sum();
        (ids.len(), charge)
    };
    let base = (rss_kib(), held(&mut net));
    for bl in &blobs {
        net.engine(b).ingest_memory(&bl.encode(), u64::MAX).unwrap();
    }
    let ingested = (rss_kib(), held(&mut net));
    net.clock.advance(61_000);
    net.sync(b).expire_due();
    let expired = (rss_kib(), held(&mut net));
    net.sync(x).expire_due();
    let snaps = net.engine(x).memory_compactions(false).unwrap();
    for bl in take_memory(&mut net, x) {
        net.engine(b).ingest_memory(&bl.encode(), u64::MAX).unwrap();
    }
    let covered = (rss_kib(), held(&mut net));
    println!("leftover memory: {n} expiring commits; {} snapshot(s) by x", snaps.len());
    for (stage, (rss, (commits, charge))) in [("baseline", base), ("ingested", ingested), ("expired", expired), ("covered", covered)] {
        println!("leftover memory: {stage}: RSS {rss} KiB, {commits} commits held, charged {charge} B");
    }
    assert!(snaps.len() == 1 && covered.1.0 <= base.1.0 + 1, "the leftovers dropped under x's snapshot");
    let ak = crate::common::ak("t:log+.0");
    assert_eq!(net.engine(b).get(&t, &ak).unwrap(), net.engine(x).get(&t, &ak).unwrap());
}

/// Peak resident set (KiB) since the last `reset_peak` (Linux `VmHWM`).
fn peak_kib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines().find_map(|l| l.strip_prefix("VmHWM:")).and_then(|v| v.split_whitespace().next()?.parse().ok()).unwrap_or(0)
}

/// Resets `peak_kib` to the current resident set (Linux `clear_refs` 5).
fn reset_peak() {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
}

/// Packages as bytes (`big_map_apply_memory` hands them to a child process).
fn encode_packages(pks: &[osis_node::local_peer::Package]) -> Vec<u8> {
    let b = |x: &[u8]| Value::Bytes(x.to_vec());
    osis_base::encode(&Value::List(pks.iter().map(|p| Value::List(vec![b(&p.id.0), b(&p.bytes), Value::List(p.blobs.iter().map(|(i, x)| Value::List(vec![b(&i.0), b(x)])).collect())])).collect()))
}

fn decode_packages(bytes: &[u8]) -> Vec<osis_node::local_peer::Package> {
    let lim = osis_base::Limits { max_depth: 8, max_bytes: bytes.len() };
    let bytes_of = |v: &Value| match v {
        Value::Bytes(x) => x.clone(),
        _ => panic!("package file"),
    };
    let arr = |v: &Value| -> [u8; 32] { bytes_of(v).try_into().unwrap() };
    let Value::List(pks) = osis_base::decode(bytes, &lim).unwrap() else { panic!("package file") };
    pks.iter()
        .map(|p| {
            let Value::List(f) = p else { panic!("package file") };
            let Value::List(blobs) = &f[2] else { panic!("package file") };
            let blobs = blobs
                .iter()
                .map(|x| {
                    let Value::List(x) = x else { panic!("package file") };
                    (BlobId(arr(&x[0])), bytes_of(&x[1]))
                })
                .collect();
            osis_node::local_peer::Package { id: osis_base::CommitId(arr(&f[0])), bytes: bytes_of(&f[1]), blobs, lists: Vec::new() }
        })
        .collect()
}

// spec/requirements.md, Scale (a value needs not be whole in memory), spec/crdt.md §8 (pages),
// issues/durable-decode-bound.md:
// peak memory above the resident set before each step, while one node writes an N-key map in one
// commit and snapshots it, then, each in a fresh process (so no step reuses memory an earlier one
// freed), a node holding the thing applies that commit, one starts from the snapshot alone, and
// one holding both judges the commit covered and the snapshot live and drops the commit.
// The stores are in memory, so what a step stores stays resident too (`kept`).
// `OSIS_SCALE_N` sets N (default 10^6 in release: the writer peaks at about 10 GB, run it alone).
#[test]
#[ignore]
fn big_map_apply_memory() {
    let step = |what: &str, f: &mut dyn FnMut()| {
        let rss0 = rss_kib();
        reset_peak();
        f();
        let (peak, rss1) = (peak_kib(), rss_kib());
        println!("{what}: peak +{} MiB, kept +{} MiB", peak.saturating_sub(rss0) / 1024, rss1.saturating_sub(rss0) / 1024);
    };
    let n = size("OSIS_SCALE_N", 1_000_000, 10_000);
    let a = ak("app:big.0");
    // the child: a fresh node takes the thing's commits, then the one measured
    if let Ok(file) = std::env::var("OSIS_SCALE_APPLY_FILE") {
        let bytes = std::fs::read(&file).unwrap();
        let mut pks = decode_packages(&bytes);
        let (target, t) = (pks.pop().unwrap(), pks.pop().unwrap());
        let Value::List(t) = osis_base::decode(&t.bytes, &osis_base::Limits { max_depth: 4, max_bytes: t.bytes.len() }).unwrap() else { panic!() };
        let (Value::Tid(t), Value::Int(now)) = (&t[0], &t[1]) else { panic!() };
        let mut p = osis_node::local_peer::Peer::new(5, WallMs(*now as u64)).unwrap();
        for pk in &pks {
            p.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
        }
        drop(bytes);
        let what = std::env::var("OSIS_SCALE_APPLY").unwrap_or_default();
        if what == "covered" {
            // holding the commit (`fill`, the thing package's ID) and the snapshot: compaction's
            // reads of both (issues/durable-decode-bound.md step 4)
            let (fill, snap) = (pks.last().unwrap().id, target.id);
            p.engine.ingest(&target.bytes, target.blobs.clone()).unwrap();
            step(&format!("n={n} judge the commit covered"), &mut || assert_eq!(p.engine.covered(&snap, &fill, t, &a).unwrap(), Some(true)));
            step(&format!("n={n} judge the snapshot live"), &mut || assert!(p.engine.body_live(&snap, t, &a).unwrap()));
            step(&format!("n={n} drop the covered commit"), &mut || p.engine.drop_body(&fill, t, &a).unwrap());
            assert_eq!(p.engine.get_at(t, &a, &[PathSeg::Key(Value::Int(7))]).unwrap(), Some(Value::Int(7)));
            return;
        }
        step(&format!("n={n} apply the {what}"), &mut || {
            p.engine.ingest(&target.bytes, target.blobs.clone()).unwrap();
        });
        assert_eq!(p.engine.get_at(t, &a, &[PathSeg::Key(Value::Int(7))]).unwrap(), Some(Value::Int(7)));
        step(&format!("n={n} reopen and read one key"), &mut || {
            p.restart(6).unwrap();
            assert_eq!(p.engine.get_at(t, &a, &[PathSeg::Key(Value::Int(7))]).unwrap(), Some(Value::Int(7)));
        });
        return;
    }
    let mut lp = crate::common::net(1, 0);
    let me = lp.peers[0].engine.me();
    let mut m = Mutation::new();
    let t = lp.peers[0].engine.new_thing(&mut m, me);
    lp.peers[0].commit(m).unwrap().unwrap();
    let setup = lp.packages(0).unwrap();
    let kv: osis_base::ValueMap = (0..n as i64).map(|i| (Value::Int(i), Value::Int(i))).collect();
    let mut fill = None;
    step(&format!("n={n} write the commit"), &mut || {
        let mut m = Mutation::new();
        m.set(t, &a, &Value::Map(kv.clone())).unwrap();
        fill = lp.peers[0].commit(m).unwrap();
    });
    drop(kv);
    let mut snap = None;
    step(&format!("n={n} snapshot"), &mut || snap = lp.peers[0].engine.snapshot(&t, &a).unwrap());
    let (fill, snap) = (fill.unwrap(), snap.unwrap());
    let fill = lp.peers[0].engine.package(&fill).unwrap().unwrap();
    let snap = lp.peers[0].engine.package(&snap).unwrap().unwrap();
    let size_of = |p: &osis_node::local_peer::Package| p.bytes.len() + p.blobs.iter().map(|b| b.1.len()).sum::<usize>();
    println!("n={n}: commit {} KiB, snapshot {} KiB with pages", size_of(&fill) / 1024, size_of(&snap) / 1024);
    // the thing and the clock, as a package for the child
    let now = lp.peers[0].clock.now_wall_ms().0 as i64;
    let meta = osis_node::local_peer::Package { id: fill.id, bytes: osis_base::encode(&Value::List(vec![Value::Tid(t), Value::Int(now)])), blobs: Vec::new(), lists: Vec::new() };
    drop(lp);
    for (what, pk) in [("commit", &fill), ("snapshot", &snap), ("covered", &snap)] {
        let file = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("big-map-apply-{}.bin", std::process::id()));
        let mut pks = setup.clone();
        if what == "covered" {
            pks.push(fill.clone());
        }
        pks.extend([meta.clone(), pk.clone()]);
        std::fs::write(&file, encode_packages(&pks)).unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "memory::big_map_apply_memory", "--nocapture", "--test-threads", "1"])
            .env("OSIS_SCALE_APPLY_FILE", &file)
            .env("OSIS_SCALE_APPLY", what)
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&file);
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{what}: {text}\n{}", String::from_utf8_lossy(&out.stderr));
        for l in text.lines().filter(|l| l.contains("n=")) {
            println!("{}", l.trim_start_matches("test memory::big_map_apply_memory ... "));
        }
    }
}
