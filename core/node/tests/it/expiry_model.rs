//! Expiry takes a commit's own values and nothing else (spec/crdt.md §4.7, §5.6, §5.7 Live,
//! spec/commits.md §5 Expiry): an entry or element shows while it holds a live value, its
//! creation's or another commit's inside it.

use crate::common;
use common::*;
use osis_base::{Ak, CommitId, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::local_peer::LocalPeer;
use osis_node::Mutation;

const HOUR: u64 = 3_600_000;

/// One container: commit 1 creates its entry holding "ab" (or a record), commit 2 writes inside it.
struct Holder {
    name: &'static str,
    ak: &'static str,
    aspect: &'static osis_schema::Aspect<Value>,
    create: fn() -> PathOp,
    edit: fn() -> PathOp,
    /// The entry's read, given which commits' values live.
    expect: fn(bool, Option<bool>) -> Option<Value>,
    /// The entry as the aspect's read holds it.
    entry: fn(Option<Value>) -> Option<Value>,
}

fn text(c1: bool, c2: Option<bool>) -> Option<Value> {
    let t = format!("{}{}", if c1 { "ab" } else { "" }, if c2 == Some(true) { "cd" } else { "" });
    (!t.is_empty()).then(|| s(&t))
}

fn holders() -> [Holder; 4] {
    [
        // text: commit 2's chars sit between commit 1's, anchored on them
        Holder {
            name: "text",
            ak: "t:text.0",
            aspect: &TEXT,
            create: || PathOp { path: vec![], op: Op::Set(s("ab")) },
            edit: || PathOp { path: vec![], op: Op::Insert { at: 1, items: vec![s("cd")] } },
            expect: |c1, c2| match (c1, c2 == Some(true)) {
                (true, true) => Some(s("acdb")),
                (true, false) => Some(s("ab")),
                (false, true) => Some(s("cd")),
                (false, false) => None,
            },
            entry: |v| v.filter(|v| *v != s("")),
        },
        Holder {
            name: "map entry of text",
            ak: "t:docs.0",
            aspect: &DOCS,
            create: || PathOp { path: vec![PathSeg::Key(s("k"))], op: Op::Set(s("ab")) },
            edit: || PathOp { path: vec![PathSeg::Key(s("k"))], op: Op::Insert { at: 2, items: vec![s("cd")] } },
            expect: text,
            entry: |v| match v {
                Some(Value::Map(m)) => m.get(&s("k")).cloned(),
                _ => None,
            },
        },
        Holder {
            name: "list element of text",
            ak: "t:listtext.0",
            aspect: &LISTTEXT,
            create: || PathOp { path: vec![], op: Op::Insert { at: 0, items: vec![s("ab")] } },
            edit: || PathOp { path: vec![PathSeg::Index(0)], op: Op::Insert { at: 2, items: vec![s("cd")] } },
            expect: text,
            entry: |v| match v {
                Some(Value::List(l)) => l.first().cloned(),
                _ => None,
            },
        },
        // a record: commit 1 creates it with both fields, commit 2 sets field 1; commit 2 expired,
        // its value-less write still beats commit 1's (a value-less winner reads absent)
        Holder {
            name: "record",
            ak: "t:map.0",
            aspect: &MAP,
            create: || PathOp { path: vec![PathSeg::Key(s("k"))], op: Op::Set(item("a", 1)) },
            edit: || PathOp { path: vec![PathSeg::Key(s("k")), PathSeg::Field(1)], op: Op::Set(Value::Int(2)) },
            expect: |c1, c2| {
                let mut m = osis_base::ValueMap::new();
                if c1 {
                    m.insert(Value::Int(0), s("a"));
                }
                match c2 {
                    None if c1 => {
                        m.insert(Value::Int(1), Value::Int(1));
                    }
                    Some(true) => {
                        m.insert(Value::Int(1), Value::Int(2));
                    }
                    _ => {}
                }
                (!m.is_empty()).then_some(Value::Map(m))
            },
            entry: |v| match v {
                Some(Value::Map(m)) => m.get(&s("k")).cloned(),
                _ => None,
            },
        },
    ]
}

/// Six peers; peer 0's new thing `t`, peer 1 granted write on it, all synced: built once.
fn six() -> (LocalPeer, Tid) {
    LocalPeer::cached("expiry_model::six", || {
        let mut lp = net(6, 0);
        let t = new_thing(&mut lp, 0);
        let w = lp.peers[1].engine.me();
        set_edge(&mut lp.peers[0].engine, t, w, Some(edge(osis_base::Role::Write)), None);
        lp.sync_all().unwrap();
        (lp, t)
    })
}

fn drop_covered_by(e: &mut osis_node::Engine, s: &CommitId, t: &Tid, a: &Ak) {
    let held: Vec<CommitId> = e.core.ix.by_aspect.get(&(*t, a.clone())).into_iter().flatten().map(|x| x.1).collect();
    for c in held {
        if c != *s && e.body_not_dropped(&c, t, a) && e.covered(s, &c, t, a).unwrap() == Some(true) {
            e.drop_body(&c, t, a).unwrap();
        }
    }
}

/// Commit 1 by peer 0 (expiring at `e1`) creates the entry; commit 2 by peer 1 (`c2`: none, or
/// expiring at the given time) writes inside it. Holders: 0 and 1 the writers (1 compacting before
/// and after the first expiry), 2 given commit 1 then 2, 3 given 2 then 1, 4 a snapshot written
/// before the first expiry (never commit 1), 5 one written after it. Each reads by the model at every
/// step past the first expiry.
fn run(h: &Holder, e1: Option<u64>, c2: Option<Option<u64>>) {
    let (mut lp, t) = six();
    let k = ak(h.ak);
    let now0 = lp.peers[0].engine.now().0;
    let at = |x: Option<u64>| x.map(|x| now0 + x);
    let mut m = Mutation::new();
    if let Some(x) = at(e1) {
        m.expires(t, &k, WallMs(x)).unwrap();
    }
    m.op(t, h.aspect, (h.create)()).unwrap();
    let c1 = lp.peers[0].commit(m).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    lp.advance(10);
    let mut ids = vec![c1];
    if let Some(e2) = c2 {
        let mut m = Mutation::new();
        if let Some(x) = at(e2) {
            m.expires(t, &k, WallMs(x)).unwrap();
        }
        m.op(t, h.aspect, (h.edit)()).unwrap();
        let c = lp.peers[1].commit(m).unwrap().unwrap();
        assert_eq!(lp.peers[1].engine.header(&c).unwrap().expires, at(e2), "{}: commit 2 keeps its own expiry", h.name);
        ids.push(c);
        sync(&mut lp, 1, 0);
    }
    let pk = |lp: &mut LocalPeer, c: &CommitId| lp.peers[1].engine.package(c).unwrap().unwrap();
    let pks: Vec<_> = ids.iter().map(|c| pk(&mut lp, c)).collect();
    for p in &pks {
        lp.deliver(2, p).unwrap();
    }
    for p in pks.iter().rev() {
        lp.deliver(3, p).unwrap();
    }
    lp.advance(10);
    let snap = lp.peers[1].engine.snapshot(&t, &k).unwrap().unwrap();
    drop_covered_by(&mut lp.peers[1].engine, &snap, &t, &k);
    let p = pk(&mut lp, &snap);
    lp.deliver(4, &p).unwrap();
    // commit 2 when it is not covered (it expires: its values travel in no snapshot)
    let lasting2 = c2.is_some_and(|e| e.is_none());
    if c2.is_some() && !lasting2 {
        lp.deliver(4, &pks[1]).unwrap();
    }
    let live = |x: Option<u64>, now: u64| x.is_none_or(|x| now < now0 + x);
    let read = |lp: &mut LocalPeer, i: usize| (h.entry)(lp.peers[i].engine.get(&t, &k).unwrap());
    // every holder reads the entry by the model, and the whole aspect alike
    let check = |lp: &mut LocalPeer, when: &str| {
        let now = lp.peers[0].engine.now().0;
        let want = (h.expect)(live(e1, now), c2.map(|e| live(e, now)));
        let whole = lp.peers[0].engine.get(&t, &k).unwrap();
        for i in 0..6 {
            // peer 5 has nothing yet; peer 4 lacks expiring commit 1 before its expiry (a
            // partial receipt)
            if (i == 5 && when == "before") || (i == 4 && e1.is_some() && live(e1, now)) {
                continue;
            }
            assert_eq!(read(lp, i), want, "{}, e1 {e1:?}, c2 {c2:?}, {when}: peer {i}", h.name);
            assert_eq!(lp.peers[i].engine.get(&t, &k).unwrap(), whole, "{}, e1 {e1:?}, c2 {c2:?}, {when}: peer {i}", h.name);
        }
    };
    check(&mut lp, "before");
    let mut late = false;
    for (step, when) in [(HOUR + HOUR / 2, "between"), (HOUR, "past both")] {
        lp.advance(step);
        for i in 0..6 {
            lp.peers[i].tick().unwrap();
        }
        if !late {
            late = true;
            let snap = lp.peers[1].engine.snapshot(&t, &k).unwrap().unwrap();
            drop_covered_by(&mut lp.peers[1].engine, &snap, &t, &k);
            let p = pk(&mut lp, &snap);
            lp.deliver(5, &p).unwrap();
            let now = lp.peers[0].engine.now().0;
            // the expiring commits still live, which no snapshot covers
            for (p, e) in pks.iter().zip([Some(e1), c2]) {
                if e.is_some_and(|e| e.is_some() && live(e, now)) {
                    lp.deliver(5, p).unwrap();
                }
            }
        }
        check(&mut lp, when);
    }
}

// spec/crdt.md §4.7, §5.6, §5.7 Live, spec/commits.md §5 Expiry: commit 1 creates an entry (a map
// entry or list element holding text, or a record) and commit 2 writes inside it. At each one's
// expiry only its own values go: the entry stays while either holds a live value. Expiring
// commit 1 with no commit 2: the entry goes; with lasting commit 2: commit 2's content stays;
// with commit 2 expiring later: the entry goes then; lasting commit 1 with expiring commit 2:
// commit 2's content goes alone. Alike in either arrival order, at a node holding a snapshot
// in place of commit 1, and through compaction before and after the expiry.
#[test]
fn expiry_takes_only_its_commits_values_spec_crdt_4_7() {
    for h in &holders() {
        for (e1, c2) in [(Some(HOUR), None), (Some(HOUR), Some(None)), (Some(HOUR), Some(Some(2 * HOUR))), (None, Some(Some(HOUR))), (Some(2 * HOUR), Some(Some(HOUR)))] {
            run(h, e1, c2);
        }
    }
}

/// Alice's write expiring at an hour, `m0399` of a paged map set to "secret", and writer
/// Mallory's snapshot carrying valued copies of it under its stamp, `copy`, inside other entries
/// spread over the pages, on pages the expiring write does not touch (forged: an honest snapshot
/// carries it value-less). Every peer holds it: Alice 0, Mallory 1, reader 2. The copied keys.
fn forged_copies(lp: &mut LocalPeer, t: Tid, copy: &Value) -> Vec<Value> {
    let (m_id, r_id) = (lp.peers[1].engine.me(), lp.peers[2].engine.me());
    set_edge(&mut lp.peers[0].engine, t, m_id, Some(edge(osis_base::Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, t, r_id, Some(edge(osis_base::Role::Read)), None);
    lp.sync_all().unwrap();
    let k = big();
    // Mallory's filler pages the map
    for i in 0..400 {
        let mut m = Mutation::new();
        m.op(t, &k, PathOp { path: vec![PathSeg::Key(s(&format!("m{i:04}")))], op: Op::Set(s(&format!("{i:08}{}", "v".repeat(192)))) }).unwrap();
        lp.peers[1].commit(m).unwrap().unwrap();
    }
    lp.sync_all().unwrap();
    lp.advance(1_000);
    let now0 = lp.peers[0].engine.now().0;
    let mut m = Mutation::new();
    m.expires(t, &k, WallMs(now0 + HOUR)).unwrap();
    m.op(t, &k, PathOp { path: vec![PathSeg::Key(s("m0399"))], op: Op::Set(s("secret")) }).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    let h = lp.peers[0].engine.header(&c).unwrap();
    let x = h.aspects.iter().find(|x| x.tid == t && x.ak == k).unwrap();
    let asrc = h.form.own_source(h.author, CommitId([0; 32]));
    let st = lp.peers[1].engine.state(&t, &k).unwrap().unwrap();
    let mut v = lp.peers[1].engine.get(&t, &k).unwrap().unwrap();
    let Value::Map(vm) = &mut v else { panic!() };
    let keys: Vec<Value> = (0..8).map(|j| s(&format!("m{:04}", j * 50))).collect();
    for key in &keys {
        vm.insert(key.clone(), copy.clone());
    }
    let mut w = osis_crdt::Writer::new(h.ts, asrc, x.lo);
    let f = osis_crdt::diff(&mut w, Some(&st), &osis_crdt::AnyView, &v).unwrap().unwrap();
    lp.advance(1_000);
    let now = osis_base::Ts::make(lp.peers[1].engine.now(), 0).unwrap();
    let forged = forge_snapshot(lp, 1, t, &k, now, f);
    for i in 0..3 {
        assert!(matches!(lp.peers[i].receive(&forged, Vec::new()), Ok(osis_node::Ingested::Applied(_))), "peer {i}: the snapshot applies");
    }
    keys
}

fn big() -> Ak {
    Ak::new(osis_schema::RawKey::ak(&BIG)).unwrap()
}

// spec/crdt.md §4.7 Copies, §8: a forged snapshot's valued copies of an expiring write, on pages
// the write does not touch, go at its expiry at every holder, also after a restart (debug
// builds: the state equals a rebuild).
#[test]
fn forged_copy_of_expiring_write_goes_at_expiry_spec_crdt_4_7() {
    let mut lp = net(3, 0);
    let t = new_thing(&mut lp, 0);
    let copy = s("zzz secret");
    let keys = forged_copies(&mut lp, t, &copy);
    let read = |lp: &mut LocalPeer, i: usize| match lp.peers[i].engine.get(&t, &big()).unwrap() {
        Some(Value::Map(m)) => m,
        other => panic!("{other:?}"),
    };
    let secret = |m: &osis_base::ValueMap| keys.iter().filter(|k| m.get(k) == Some(&copy)).count();
    assert_eq!(secret(&read(&mut lp, 2)), 8, "before T the copies win (spec/crdt.md §4.1 copy order)");
    lp.advance(HOUR);
    for i in 0..3 {
        lp.peers[i].tick().unwrap();
    }
    for i in 0..3 {
        let m = read(&mut lp, i);
        assert_ne!(m.get(&s("m0399")), Some(&s("secret")), "peer {i}: the expired write goes");
        assert_eq!(secret(&m), 0, "peer {i}: the forged copies go");
    }
    for i in 0..3 {
        lp.peers[i].restart(0x7e00 + i as u64).unwrap();
        assert_eq!(secret(&read(&mut lp, i)), 0, "peer {i}: the forged copies go, after a restart");
    }
}

// spec/crdt.md §4.7 Copies, notes/engine-refs.md: a forged snapshot's valued copies of an
// expiring write linking a thing count as references until the write expires; then backlinks no
// longer list the aspect, at every holder, also after a restart.
#[test]
fn forged_copy_linking_a_thing_leaves_backlinks_at_expiry_spec_crdt_4_7() {
    let mut lp = net(3, 0);
    let t = new_thing(&mut lp, 0);
    let target = new_thing(&mut lp, 0);
    forged_copies(&mut lp, t, &Value::Tid(target));
    let lists = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.references_page(&target, None, 10).unwrap().contains(&(t, big()));
    for i in 0..3 {
        assert!(lists(&mut lp, i), "peer {i}: before T the copies link the target");
    }
    lp.advance(HOUR);
    for i in 0..3 {
        lp.peers[i].tick().unwrap();
        assert!(!lists(&mut lp, i), "peer {i}: the expired copies link nothing");
    }
    for i in 0..3 {
        lp.peers[i].restart(0x7e10 + i as u64).unwrap();
        assert!(!lists(&mut lp, i), "peer {i}: the expired copies link nothing, after a restart");
    }
}
