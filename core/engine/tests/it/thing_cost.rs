//! What one thing costs (notes/thing-cost.md; spec/requirements.md Cost, spec/sync-set.md §2 Cost): a dependent thing minted with the account as admin and an
//! independent thing minted with the account as admin, for the minting node and for the account's second
//! node: commits, store rows by family, bytes a peer downloads, KEM and signature operations.

use crate::common::{REG, s};
use crate::flows::{account_two_nodes, edge_of, people};
use osis_base::Role;
use osis_base::{CommitId, Tid, costs};
use osis_engine::local_peer::LocalPeer;
use osis_base::Value;
use osis_crdt::{Op, PathOp};
use osis_engine::{Engine, MintAdmin, Mutation};
use osis_schema::core_types as ct;
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
    minting_rows: i64,
    minting_blobs: i64,
    download: usize,
    reader_rows: i64,
    reader_blobs: i64,
    minting_ops: BTreeMap<&'static str, u64>,
    reader_ops: BTreeMap<&'static str, u64>,
}

fn blob_bytes(lp: &LocalPeer, i: usize) -> i64 {
    let p = &lp.peers[i];
    (p.backend.held_split().1 + p.blob_disk.0.held_split().1) as i64
}

/// A dependent thing of `admin` with one small value: its record, the value and the strong in
/// `admin`'s `holds.0`, one commit.
fn a_dependent(e: &mut Engine, admin: Tid) -> Tid {
    let mut m = Mutation::new();
    let t = e.new_thing(&mut m, admin);
    m.set(t, &REG, &s("new")).unwrap();
    e.commit(m).unwrap().unwrap();
    t
}

/// An independent thing minted with admin `admin` (`Engine::mint_independent`, as the account
/// library mints A's inbox and profile): its own-secrets rotation carrying its record, then the
/// value and the strong in `admin`'s `holds.0`.
fn an_independent(e: &mut Engine, admin: Tid) -> Tid {
    e.mint_independent(&[MintAdmin::Thing(admin)], |ts| {
        let mut m = Mutation::new();
        m.op(admin, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Add(Value::Strong(ts[0])) })?;
        m.set(ts[0], &REG, &s("new"))?;
        Ok(vec![m])
    })
    .unwrap()
    .0[0]
}

/// Peer 0 makes a thing with admin `admin` by `build`; peer 1, its account's second node,
/// receives the commits. Prints the breakdown when `show`.
fn make(lp: &mut LocalPeer, admin: Tid, build: fn(&mut Engine, Tid) -> Tid, label: &str, show: bool) -> (Cost, Tid) {
    let (c0, r0) = (lp.peers[0].engine.census().unwrap(), lp.peers[1].engine.census().unwrap());
    let (b0, rb0) = (blob_bytes(lp, 0), blob_bytes(lp, 1));
    let before: std::collections::BTreeSet<_> = lp.peers[0].engine.commit_ids().into_iter().collect();
    costs::take();
    let t = build(&mut lp.peers[0].engine, admin);
    let minting_ops = ops();
    let mut new: Vec<_> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect();
    new.sort_by_key(|c| lp.peers[0].engine.header(c).unwrap().ts);
    let mut cost = Cost { commits: new.len(), minting_ops, ..Cost::default() };
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
    cost.minting_rows = mg.iter().map(|x| x.2).sum();
    cost.reader_rows = rg.iter().map(|x| x.2).sum();
    cost.minting_blobs = blob_bytes(lp, 0) - b0;
    cost.reader_blobs = blob_bytes(lp, 1) - rb0;
    if show {
        eprintln!("  minting node rows by family (rows, bytes): {mg:?}");
        eprintln!("  reader rows by family: {rg:?}");
        eprintln!("  {cost:?}");
    }
    (cost, t)
}

// What a dependent and an independent thing cost (notes/thing-cost.md). Each kind is made once first, so
// neither pays a first write's rows; the second is measured. Bounds are the measured figures
// rounded up: a change that grows a thing's cost fails here and says by how much.
#[test]
fn what_a_thing_costs() {
    let (mut lp, a) = account_two_nodes();
    make(&mut lp, a, a_dependent, "dependent warm-up", false);
    make(&mut lp, a, an_independent, "independent warm-up", false);
    let show = std::env::var_os("THING_COST").is_some();
    let (dependent, pt) = make(&mut lp, a, a_dependent, "dependent (minted with the account)", show);
    let (independent, kt) = make(&mut lp, a, an_independent, "independent (minted with the account)", show);
    eprintln!("dependent: {dependent:?}\nindependent: {independent:?}");
    // spec/permissions.md §3: minted with admin A it stays dependent (A's unit, A's secrets); minted
    // independent it has its sync ID from its creating transaction
    let e = &mut lp.peers[0].engine;
    assert!(e.sync_id_of(&pt).unwrap().is_none() && e.sync_id_of(&kt).unwrap().is_some());
    assert_eq!((dependent.commits, independent.commits), (1, 2), "its rotation carrying its record, then what the dependent one writes");
    assert!(dependent.minting_rows < 1_500 && dependent.reader_rows < 1_500 && dependent.download < 600, "{dependent:?}");
    assert_eq!(dependent.minting_ops.get("sign"), Some(&1), "the commit's signature alone");
    assert!(independent.minting_rows < 10_000 && independent.reader_rows < 10_100 && independent.download < 4_800, "{independent:?}");
    // it holds nothing and takes no signal: no KEM key (spec/crypto.md §3 Published KEM keys)
    assert_eq!(independent.minting_ops.get("kem: keygen"), None, "no KEM key made");
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
        let minting_ops = ops();
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
        each.push((done.commits.len(), download, sum(&mg), sum(&rg), sum(&offered), minting_ops, reader_ops));
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

/// A one-value commit on `t` by peer `i` (signed as `as_` where given, by a key granted on it):
/// (opened bytes, header bytes, path bytes, signer form bytes over the first form, sealed blob
/// bytes).
fn small_commit(lp: &mut LocalPeer, i: usize, t: Tid, as_: Option<Tid>, v: &str) -> [usize; 5] {
    let mut m = Mutation::new();
    if let Some(x) = as_ {
        m.sign_as(x);
    }
    m.set(t, &REG, &s(v)).unwrap();
    let c = lp.peers[i].commit(m).unwrap().unwrap();
    let e = &mut lp.peers[i].engine;
    let pk = e.package(&c).unwrap().unwrap();
    let h = osis_commit::CommitBlob::decode(&pk.bytes).unwrap().header;
    let path = match &h.path {
        osis_commit::Paths::One(p) => p.encode().len(),
        osis_commit::Paths::Split(_) => panic!("one path serves a commit on one thing"),
    };
    let mut rng = osis_crypto::SeededRng::from_u64(7);
    let sealed = e.seal_package(&c, &mut rng).unwrap().unwrap().entries.iter().map(|x| x.blob.len()).sum();
    let mut first = h.clone();
    first.key = None;
    [pk.bytes.len(), h.encode().len(), path, h.encode().len() - first.encode().len(), sealed]
}

// What a small commit costs in the accounts shape (notes/thing-cost.md): no epoch, no inner
// signature; the account's first node writes its dependents along record grants (the empty
// path, `[0]`, 2 B), a paired node states A (`[0, A]`, 2 B + 16 B), and a key granted on a thing
// signs in the signer's second form, `[tid, signing_key]` (40 B more, spec/wire.md §4 field 1).
#[test]
fn what_a_small_commit_costs() {
    let (mut lp, a) = account_two_nodes();
    let t = a_dependent(&mut lp.peers[0].engine, a);
    lp.sync_all().unwrap();
    small_commit(&mut lp, 0, t, None, "x");
    let by_minting = small_commit(&mut lp, 0, t, None, "y");
    let by_paired = small_commit(&mut lp, 1, t, None, "z");
    // a key granted write on a thing signs as it (as key_grants::granted): peer 1's node reads
    // T, its key holds write on T
    let (mut kp, ps) = people(2);
    let k = crate::flows::thing_of(&mut kp, 0, ps[0]);
    kp.peers[0].engine.grant(&k, &ps[1], &edge_of(Role::Read)).unwrap();
    let key = osis_base::SignKey(kp.peers[1].engine.identity().signing().verifying_key().to_bytes());
    kp.peers[0].engine.grant_key(&k, &key, Some(&edge_of(Role::Write))).unwrap();
    kp.advance(1000);
    crate::flows::spread(&mut kp);
    small_commit(&mut kp, 0, k, None, "x");
    let by_admin = small_commit(&mut kp, 0, k, None, "y");
    let by_key = small_commit(&mut kp, 1, k, Some(k), "z");
    eprintln!("small commit (opened, header, path, second signer form, sealed blob): minting node {by_minting:?}, paired node {by_paired:?}, T's admin {by_admin:?}, a key granted on T {by_key:?}");
    assert_eq!((by_minting[2], by_paired[2]), (2, 18), "the empty path; A's tid stated");
    assert_eq!(by_paired[0] - by_minting[0], 16, "only the path differs");
    // the second form's key is a `signing_key` agility value (1617([1, h'..32..']), 39 B) in a
    // two-item list; the key's commit takes the commit form (1 B), not the node's session
    // form (19 B: its nonce), as no session of the key's is open
    assert_eq!(by_key[3], 40, "{by_key:?}");
    assert_eq!(by_key[0] - by_admin[0], 40 - 18, "the signer's second form and the commit form: {by_admin:?} {by_key:?}");
    assert!(by_minting[0] < 420 && by_minting[4] < 520, "{by_minting:?}");
}

/// Per independent thing nobody seals to (`an_independent`: holding no role, no card, no
/// signal): what `n` of them cost the minting node, averaged: (stored bytes, bytes its commits
/// download as, ML-KEM keygens).
fn independent_each(n: usize) -> (i64, usize, u64) {
    let (mut lp, a) = account_two_nodes();
    let make = |lp: &mut LocalPeer| {
        an_independent(&mut lp.peers[0].engine, a);
    };
    // the first thing minted pays once for what every later one shares
    make(&mut lp);
    let census = |lp: &mut LocalPeer| lp.peers[0].engine.census().unwrap().values().map(|x| x.1 as i64).sum::<i64>() + blob_bytes(lp, 0);
    let (c0, before) = (census(&mut lp), lp.peers[0].engine.commit_ids().into_iter().collect::<std::collections::BTreeSet<_>>());
    costs::take();
    for _ in 0..n {
        make(&mut lp);
    }
    let keygens = ops().get("kem: keygen").copied().unwrap_or(0);
    let new: Vec<CommitId> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect();
    let download: usize = new.iter().map(|c| lp.peers[0].engine.package(c).unwrap().map_or(0, |pk| pk.bytes.len() + pk.blobs.iter().map(|b| b.1.len()).sum::<usize>())).sum();
    ((census(&mut lp) - c0) / n as i64, download / n, keygens / n as u64)
}

// notes/thing-cost.md, spec/crypto.md §3 (Published KEM keys): an independent thing nobody seals
// to carries no KEM key: no ML-KEM keygen, and its commits download in well under the 4864 B four
// KEM keys alone took; its cost per thing is the same at n and 10n.
#[test]
fn an_independent_thing_nobody_seals_to_carries_no_kem_key() {
    let (small, big) = (independent_each(2), independent_each(20));
    if std::env::var_os("THING_COST").is_some() {
        eprintln!("per independent thing (stored, download, keygens): n {small:?}, 10n {big:?}");
    }
    assert_eq!((small.2, big.2), (0, 0), "no KEM key made");
    assert!(small.1 < 4_864 && big.1 <= small.1, "{small:?} {big:?}");
    assert!(big.0 <= small.0 + 256, "stored per thing grows with n: {small:?} {big:?}");
}

/// What a commit on a public thing costs per referring unit (spec/sync-set.md §2 T's keys open:
/// a strong to a public thing brings it whole into the referrer's unit): an account's public
/// profile P referenced by strongs from `n` independent things of the account, each a unit of its
/// own as an importer's account is. Then, at the minting node: the bodies (entries, one per sync ID
/// logging it) of a small value write on P and of the account's card on P written again (its
/// keys refreshed after a rotation of A), with each commit's bytes, and the card's own bytes.
#[derive(Debug, PartialEq, Eq)]
struct PublicCost {
    value_entries: usize,
    value_bytes: usize,
    card_entries: usize,
    card_bytes: usize,
    card_value: usize,
}

fn public_referenced(n: usize) -> PublicCost {
    let (mut lp, acc) = LocalPeer::one_account(1, 0, crate::common::T0).unwrap();
    let (a, p) = (acc.thing, acc.profile);
    let e = &mut lp.peers[0].engine;
    assert!(e.public_reads(&p), "the profile is public");
    for _ in 0..n {
        let t = an_independent(e, a);
        let mut m = Mutation::new();
        m.op(t, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Add(Value::Strong(p)) }).unwrap();
        e.commit(m).unwrap();
    }
    let unit_bodies = |e: &mut Engine, c: &CommitId| e.sync_bodies(c).unwrap().keys().filter(|(_, on)| on.is_none()).count();
    let bytes = |e: &mut Engine, c: &CommitId| e.package(c).unwrap().map_or(0, |pk| pk.bytes.len() + pk.blobs.iter().map(|b| b.1.len()).sum::<usize>());
    let mut m = Mutation::new();
    m.set(p, &REG, &s("hello")).unwrap();
    let v = e.commit(m).unwrap().unwrap();
    // A's keys move (a rotation), so the card on P is stale and written again
    e.rotate_leaving_out(&a, &[Role::Read], &[]).unwrap().expect("a rotation");
    let before: std::collections::BTreeSet<CommitId> = e.commit_ids().into_iter().collect();
    assert!(e.refresh_cards().unwrap(), "the card is rewritten");
    let card = e.commit_ids().into_iter().find(|c| !before.contains(c)).expect("the card's commit");
    let card_value = e.state(&p, &ct::card_ak(&a)).unwrap().and_then(|f| f.read()).map(|v| osis_base::encode(&v).len()).unwrap();
    PublicCost { value_entries: unit_bodies(e, &v), value_bytes: bytes(e, &v), card_entries: unit_bodies(e, &card), card_bytes: bytes(e, &card), card_value }
}

// spec/sync-set.md §2 (T's keys open: a strong to a public thing brings it into the referrer's
// unit whole), notes/thing-cost.md: a commit on a public thing is logged once under its own
// sync ID, once under its mint admin account's, and once more under each unit referring to it, the
// accepted cost of the built unit: exactly one entry per referrer at n and 10n, the commit's
// bytes the same whatever the referrers. The account's card on its public profile alike (its
// bytes: A's and the inbox's `keys.0` commits with their evidence).
#[test]
fn a_commit_on_a_public_thing_costs_an_entry_per_referring_unit() {
    let (small, big) = (public_referenced(2), public_referenced(20));
    if std::env::var_os("THING_COST").is_some() {
        eprintln!("a public profile referenced by n units: n {small:?}, 10n {big:?}");
    }
    assert_eq!(small.value_entries, 2 + 2, "its own sync ID, the account's and one per referrer: {small:?}");
    assert_eq!(big.value_entries - small.value_entries, 18, "one entry more per referrer: {small:?} {big:?}");
    assert_eq!(big.card_entries - small.card_entries, 18, "{small:?} {big:?}");
    assert_eq!((small.value_bytes, small.card_value), (big.value_bytes, big.card_value), "a commit's bytes do not grow with referrers");
    assert!(big.card_bytes <= small.card_bytes + 64, "{small:?} {big:?}");
}
