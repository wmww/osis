//! What one thing costs (notes/thing-cost.md): a plain thing made under the account root and a
//! thing with its own keys made under the account, for the maker and for the account's second
//! node: commits, store rows by family, bytes a peer downloads, KEM and signature operations.

use crate::common::{REG, s};
use crate::flows::{account_two_nodes, edge_of, people};
use osis_base::Role;
use osis_base::{Tid, costs};
use osis_engine::local_peer::LocalPeer;
use osis_engine::Mutation;
use std::collections::BTreeMap;

type Census = BTreeMap<String, (usize, usize)>;

/// The families that changed from `a` to `b`: (family, rows, bytes) added.
fn grown(a: &Census, b: &Census) -> Vec<(String, i64, i64)> {
    let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter_map(|k| {
            let (x, y) = (a.get(k).copied().unwrap_or_default(), b.get(k).copied().unwrap_or_default());
            (x != y).then(|| (k.clone(), y.0 as i64 - x.0 as i64, y.1 as i64 - x.1 as i64))
        })
        .collect()
}

fn ops() -> BTreeMap<&'static str, u64> {
    costs::take().into_iter().filter(|(k, _, _)| k.starts_with("kem") || k.starts_with("sign") || k.starts_with("verify")).map(|(k, _, n)| (k, n)).collect()
}

#[derive(Debug, Default)]
#[allow(dead_code)] // read by its Debug print
struct Cost {
    commits: usize,
    maker_rows: i64,
    maker_blobs: i64,
    download: usize,
    reader_rows: i64,
    reader_blobs: i64,
    maker_ops: BTreeMap<&'static str, u64>,
    reader_ops: BTreeMap<&'static str, u64>,
}

fn blob_bytes(lp: &LocalPeer, i: usize) -> i64 {
    let p = &lp.peers[i];
    (p.backend.held_split().1 + p.blob_disk.0.held_split().1) as i64
}

/// Peer 0 makes a thing under `admin` (as `flows::thing_of`); peer 1, its account's second node,
/// receives the commits. Prints the breakdown when `show`.
fn make(lp: &mut LocalPeer, admin: Tid, label: &str, show: bool) -> (Cost, Tid) {
    let (c0, r0) = (lp.peers[0].engine.census().unwrap(), lp.peers[1].engine.census().unwrap());
    let (b0, rb0) = (blob_bytes(lp, 0), blob_bytes(lp, 1));
    let before: std::collections::BTreeSet<_> = lp.peers[0].engine.commit_ids().into_iter().collect();
    costs::take();
    let e = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, admin);
    m.set(t, &REG, &s("new")).unwrap();
    e.commit(m).unwrap().unwrap();
    let maker_ops = ops();
    let mut new: Vec<_> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect();
    new.sort_by_key(|c| lp.peers[0].engine.header(c).unwrap().ts);
    let mut cost = Cost { commits: new.len(), maker_ops, ..Cost::default() };
    if show {
        eprintln!("== {label}: {} commits", new.len());
    }
    let mut pks = Vec::new();
    for c in &new {
        let pk = lp.peers[0].engine.package(c).unwrap().unwrap();
        let blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
        let size = pk.bytes.len() + pk.blobs.iter().map(|b| b.1.len()).sum::<usize>() + pk.lists.iter().map(Vec::len).sum::<usize>();
        cost.download += size;
        if show {
            let h = &blob.header;
            eprintln!("  commit {:?} by {}: {} B (header {} B, {} delete keys, {} blobs)", h.kind, if h.author == h.actor { "self" } else { "other" }, size, h.encode().len(), h.keys.len(), pk.blobs.len());
            for p in &blob.parts {
                let a = &h.aspects[p.ai];
                let whose = if a.tid == t { "t" } else if a.tid == admin { "admin" } else { "other" };
                eprintln!("    {whose}.{} {} B", a.ak.as_str(), p.delta.len());
            }
        }
        pks.push(pk);
    }
    costs::take();
    for pk in &pks {
        lp.deliver(1, pk).unwrap();
    }
    lp.peers[1].engine.settle_needs().unwrap();
    cost.reader_ops = ops();
    let (c1, r1) = (lp.peers[0].engine.census().unwrap(), lp.peers[1].engine.census().unwrap());
    let (mg, rg) = (grown(&c0, &c1), grown(&r0, &r1));
    cost.maker_rows = mg.iter().map(|x| x.2).sum();
    cost.reader_rows = rg.iter().map(|x| x.2).sum();
    cost.maker_blobs = blob_bytes(lp, 0) - b0;
    cost.reader_blobs = blob_bytes(lp, 1) - rb0;
    if show {
        eprintln!("  maker rows by family (rows, bytes): {mg:?}");
        eprintln!("  reader rows by family: {rg:?}");
        eprintln!("  {cost:?}");
    }
    (cost, t)
}

// What a plain and a keyed thing cost (notes/thing-cost.md). Each kind is made once first, so
// neither pays a first write's rows; the second is measured. Bounds are the measured figures
// rounded up: a change that grows a thing's cost fails here and says by how much.
#[test]
fn what_a_thing_costs() {
    let (mut lp, _) = account_two_nodes();
    let (p, d) = lp.peers[0].engine.account().unwrap().unwrap();
    make(&mut lp, d, "plain warm-up", false);
    make(&mut lp, p, "keyed warm-up", false);
    let show = std::env::var_os("THING_COST").is_some();
    let (plain, pt) = make(&mut lp, d, "plain (under the account root)", show);
    let (keyed, kt) = make(&mut lp, p, "keyed (under the account)", show);
    eprintln!("plain: {plain:?}\nkeyed: {keyed:?}");
    // spec/permissions.md §3: made under the account root it stays plain; under the account it
    // has secrets of its own and its sync ID from its creating transaction
    let e = &mut lp.peers[0].engine;
    assert!(e.home_sync_id(&pt).unwrap().is_none() && e.home_sync_id(&kt).unwrap().is_some());
    assert_eq!((plain.commits, keyed.commits), (1, 3), "its record, its rotation, then what the plain one writes");
    assert!(plain.maker_rows < 1_900 && plain.reader_rows < 1_800 && plain.download < 800, "{plain:?}");
    assert!(keyed.maker_rows < 29_000 && keyed.reader_rows < 29_000 && keyed.download < 9_800, "{keyed:?}");
    assert_eq!(keyed.maker_ops.get("kem: keygen"), Some(&4), "a KEM key per role");
    assert!(!keyed.reader_ops.keys().any(|k| k.starts_with("kem")), "the account's node opens symmetric boxes");
}

// What a second account reading a keyed thing costs (notes/thing-cost.md): peer 0 grants peer
// 1's account read on it; the grant's commits, what peer 1 stores and downloads, KEM operations.
#[test]
fn what_a_reader_costs() {
    let (mut lp, ps) = people(2);
    let show = std::env::var_os("THING_COST").is_some();
    let mut each = Vec::new();
    for i in 0..2 {
        let e = &mut lp.peers[0].engine;
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, ps[0]);
        m.set(t, &REG, &s("new")).unwrap();
        e.commit(m).unwrap().unwrap();
        crate::flows::spread(&mut lp);
        let (c0, r0) = (lp.peers[0].engine.census().unwrap(), lp.peers[1].engine.census().unwrap());
        costs::take();
        let done = lp.peers[0].engine.grant(&t, &ps[1], &edge_of(Role::Read)).unwrap();
        let maker_ops = ops();
        let mut download = 0;
        for c in &done.commits {
            let pk = lp.peers[0].engine.package(c).unwrap().unwrap();
            let blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
            download += pk.bytes.len();
            if show && i == 1 {
                let h = &blob.header;
                eprintln!("  grant commit {:?}: {} B (header {} B)", h.kind, pk.bytes.len(), h.encode().len());
                for p in &blob.parts {
                    let a = &h.aspects[p.ai];
                    eprintln!("    {}.{} {} B", if a.tid == t { "t" } else { "other" }, a.ak.as_str(), p.delta.len());
                }
            }
        }
        costs::take();
        lp.hold_at(1, t);
        crate::flows::spread(&mut lp);
        let reader_ops = ops();
        let (mg, rg) = (grown(&c0, &lp.peers[0].engine.census().unwrap()), grown(&r0, &lp.peers[1].engine.census().unwrap()));
        assert!(lp.peers[1].engine.epochs(&t).is_some_and(|x| x.read.held().next().is_some()), "the reader holds t's secrets");
        if show && i == 1 {
            eprintln!("  granter rows: {mg:?}\n  reader rows: {rg:?}");
        }
        each.push((done.commits.len(), download, mg.iter().map(|x| x.2).sum::<i64>(), rg.iter().map(|x| x.2).sum::<i64>(), maker_ops, reader_ops));
    }
    eprintln!("grant read to another account: (commits, grant bytes, granter rows, reader rows, granter ops, reader ops) {:?}", each[1]);
    let (commits, bytes, _, reader, _, _) = &each[1];
    assert!(*commits == 1 && *bytes < 4_200 && *reader < 36_500, "{:?}", each[1]);
}
