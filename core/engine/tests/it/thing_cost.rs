//! What one thing costs (notes/thing-cost.md; spec/requirements.md Cost, spec/sync-set.md §2 Cost): a dependent thing minted with the account root as admin and an
//! independent thing minted with the account as admin, for the maker and for the account's second
//! node: commits, store rows by family, bytes a peer downloads, KEM and signature operations.

use crate::common::{REG, s};
use crate::flows::{account_two_nodes, edge_of, people};
use osis_base::Role;
use osis_base::{CommitId, Tid, costs};
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

/// Peer 0 mints a thing with admin `admin` (as `flows::thing_of`); peer 1, its account's second node,
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
        let size = pk.bytes.len() + pk.blobs.iter().map(|b| b.1.len()).sum::<usize>();
        cost.download += size;
        // spec/wire.md §4 field 2: an ordinary commit states the empty path, unmarked: 2 bytes
        assert_eq!(blob.header.path, osis_commit::Paths::One(osis_commit::Path::default()), "{label}");
        assert_eq!(osis_commit::Path::default().encode().len(), 2);
        if show {
            let h = &blob.header;
            eprintln!("  commit {:?} by {}: {} B (header {} B, {} delete keys, {} blobs)", h.kind, if h.purge_author() == h.signer { "self" } else { "other" }, size, h.encode().len(), h.keys.len(), pk.blobs.len());
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

// What a dependent and an independent thing cost (notes/thing-cost.md). Each kind is made once first, so
// neither pays a first write's rows; the second is measured. Bounds are the measured figures
// rounded up: a change that grows a thing's cost fails here and says by how much.
#[test]
#[ignore = "accounts: counting"]
fn what_a_thing_costs() {
    let (mut lp, a) = account_two_nodes();
    let p = lp.peers[0].engine.me();
    make(&mut lp, a, "dependent warm-up", false);
    make(&mut lp, p, "independent warm-up", false);
    let show = std::env::var_os("THING_COST").is_some();
    let (dependent, pt) = make(&mut lp, a, "dependent (minted with the account)", show);
    let (independent, kt) = make(&mut lp, p, "independent (minted with the account)", show);
    eprintln!("dependent: {dependent:?}\nindependent: {independent:?}");
    // spec/permissions.md §3: minted with the account root as admin it stays dependent; with the
    // account it is independent and has its sync ID from its creating transaction
    let e = &mut lp.peers[0].engine;
    assert!(e.sync_id_of(&pt).unwrap().is_none() && e.sync_id_of(&kt).unwrap().is_some());
    assert_eq!((dependent.commits, independent.commits), (1, 2), "its rotation carrying its record, then what the dependent one writes");
    assert!(dependent.maker_rows < 1_700 && dependent.reader_rows < 1_700 && dependent.download < 700, "{dependent:?}");
    assert!(independent.maker_rows < 15_000 && independent.reader_rows < 15_300 && independent.download < 9_400, "{independent:?}");
    assert_eq!(independent.maker_ops.get("kem: keygen"), Some(&4), "a KEM key per role");
    assert!(!independent.reader_ops.keys().any(|k| k.starts_with("kem")), "the account's node opens symmetric boxes");
}

// What a second account reading an independent thing costs (notes/thing-cost.md): peer 0 grants peer
// 1's account read on it; the grant's commits, what peer 1 stores and downloads, KEM operations.
#[test]
fn what_a_reader_costs() {
    let (mut lp, ps) = people(2);
    let show = std::env::var_os("THING_COST").is_some();
    let (mut each, mut rows) = (Vec::new(), String::new());
    for i in 0..2 {
        let e = &mut lp.peers[0].engine;
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, ps[0]);
        m.set(t, &REG, &s("new")).unwrap();
        e.commit(m).unwrap().unwrap();
        // measured from an independent thing: the grant alone
        e.make_independent(&t).unwrap();
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
        let (mg, offered) = (grown(&c0, &lp.peers[0].engine.census().unwrap()), grown(&r0, &lp.peers[1].engine.census().unwrap()));
        assert!(lp.peers[1].engine.epochs(&t).is_some_and(|x| x.read.held().next().is_some()), "the reader holds t's secrets");
        // the grant's offer (its fire, with the copy's evidence and records) is held its keep
        // only: past the inbox lifetime the reader holds what syncing t costs
        lp.advance(osis_base::format::INBOX_LIFETIME_MS + 3_600_000);
        lp.peers[1].tick().unwrap();
        // a fire out of history is forgotten, as sync forgets it once no source holds it
        let e = &mut lp.peers[1].engine;
        let fires: Vec<CommitId> = e.commit_ids().into_iter().filter(|c| e.header(c).is_some_and(|h| h.aspects.iter().any(|a| a.ak.as_str() == "grant@~0"))).collect();
        for f in fires {
            assert!(e.forgettable(&f).unwrap(), "the offer is out of history");
            e.forget_commits(&[f]).unwrap();
        }
        e.settle_needs().unwrap();
        let rg = grown(&r0, &lp.peers[1].engine.census().unwrap());
        assert_eq!(lp.peers[1].engine.role_on(&t), Some(Role::Read), "the reader reads t past its offer");
        rows = format!("  granter rows: {mg:?}\n  reader rows with the offer: {offered:?}\n  reader rows: {rg:?}");
        if show && i == 1 {
            eprintln!("{rows}");
        }
        let sum = |x: &[(String, i64, i64)]| x.iter().map(|x| x.2).sum::<i64>();
        each.push((done.commits.len(), download, sum(&mg), sum(&rg), sum(&offered), maker_ops, reader_ops));
    }
    eprintln!("grant read to another account: (commits, grant bytes, granter rows, reader rows, reader rows with the offer, granter ops, reader ops) {:?}", each[1]);
    let (commits, bytes, _, reader, offered, _, _) = &each[1];
    // the grant replaces writes of the thing's `secrets.0`: its first death, so the reader (and
    // the granter) keeps its held writes from here on, 4,460 B for its 50 writes (89 B a write,
    // notes/thing-cost.md): what dating replaced role bodies costs (spec/commits.md §5 Fixed
    // retention: a replaced one is kept `ROLE_KEEP` after replaced). The reader is measured past
    // the inbox lifetime, the offer's fire forgotten (37,900 B, a history cursor of t the passing
    // time writes among it, `hf/`: its last place out; `keys.0` carries the step's read KEM key), and before (37,860 B: a node thing takes
    // no grant fire, so no offer is held; offers reach a node through its account's inbox)
    assert!(*commits == 1 && *bytes < 4_000 && *reader < 38_400 && *offered < 59_200, "{:?}, rows by table:\n{rows}", each[1]);
}
