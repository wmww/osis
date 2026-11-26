#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Commit listings' relations and filters, undo, redo, revert (notes/api.md Commits; spec/commits.md
//! §7, spec/crdt.md §4.6).

use osis::internals::CommitRaw as _;
use osis::internals::Internals as _;
use crate::common;
use common::*;
use osis::{CommitQuery, NotUndoableReason, Error, MemStore, Osis, Scope, Value};

// spec/commits.md §7, notes/api.md Commits: undo and redo walk this actor's own commits in
// scope; redo is an undo of the undo; a new undo after a redo undoes the redone change. A
// register edited twice undoes twice (spec/crdt.md §4.6: each undo restores the read before its
// commit), then redoes twice.
#[test]
fn undo_redo_cycle_spec_commits_7() {
    let db = db(0);
    typed_any(&db, &["t:a.0", "t:b.0", "t:other.0", "t:x.0"]);
    let k = ak("t:x.0");
    let mut w = db.write();
    let t = w.create_held().unwrap();
    keep_all(&mut w, t);
    w.commit().unwrap();
    db.commit_set(t, kept(&db, &k.clone()), &Value::Int(1)).unwrap();
    db.commit_set(t, kept(&db, &k.clone()), &Value::Int(2)).unwrap();
    let scope = Scope::Aspects(vec![(t, k.clone())]);
    let get = || db.at(t, kept(&db, &k.clone())).get().unwrap();
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), Some(Value::Int(1)));
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(get(), Some(Value::Int(2)));
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), Some(Value::Int(1)));
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), None);
    assert_eq!(db.undo(&scope).unwrap(), None);
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(get(), Some(Value::Int(1)));
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(get(), Some(Value::Int(2)));
    assert_eq!(db.redo(&scope).unwrap(), None);
    // and back again through the redone changes
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), Some(Value::Int(1)));
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(get(), None);
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(get(), Some(Value::Int(1)));
    // separate aspects undo step by step
    let scope = Scope::Thing(t);
    let (a, b) = (ak("t:a.0"), ak("t:b.0"));
    db.commit_set(t, kept(&db, &a.clone()), &Value::Int(1)).unwrap();
    db.commit_set(t, kept(&db, &b.clone()), &Value::Int(1)).unwrap();
    db.undo(&scope).unwrap().unwrap();
    db.undo(&scope).unwrap().unwrap();
    assert_eq!((db.at(t, kept(&db, &a.clone())).get().unwrap(), db.at(t, kept(&db, &b.clone())).get().unwrap()), (None, None));
    // another scope sees nothing to undo
    let other = Scope::Aspects(vec![(t, ak("t:other.0"))]);
    assert_eq!(db.undo(&other).unwrap(), None);
}

// notes/api.md Commits (decided): a new change clears the redo stack.
#[test]
fn new_commit_clears_redo_spec_commits_7() {
    let db = db(0);
    typed_any(&db, &["t:a.0", "t:b.0"]);
    let (a, b) = (ak("t:a.0"), ak("t:b.0"));
    let mut w = db.write();
    let t = w.create_held().unwrap();
    keep_all(&mut w, t);
    w.commit().unwrap();
    db.commit_set(t, kept(&db, &a.clone()), &Value::Int(1)).unwrap();
    let scope = Scope::Thing(t);
    db.undo(&scope).unwrap().unwrap();
    db.commit_set(t, kept(&db, &b.clone()), &Value::Int(1)).unwrap();
    assert_eq!(db.redo(&scope).unwrap(), None);
    assert_eq!(db.at(t, kept(&db, &a)).get().unwrap(), None);
    // undo then redo still pairs up after the new change
    db.undo(&scope).unwrap().unwrap();
    assert_eq!(db.at(t, kept(&db, &b.clone())).get().unwrap(), None);
    db.redo(&scope).unwrap().unwrap();
    assert_eq!(db.at(t, kept(&db, &b)).get().unwrap(), Some(Value::Int(1)));
}

// spec/commits.md §7: when the newest commit's body was dropped (as covered by a snapshot), undo
// is refused and never undoes an older change instead.
#[test]
fn undo_blocked_by_dropped_body_spec_commits_7() {
    let db = db(0);
    let (a, b) = (ak("t:a.0"), ak("t:b.0"));
    let mut w = db.write();
    let t = w.create_held().unwrap();
    w.commit().unwrap();
    db.commit_set(t, osis::DynamicAspectKey::untyped(a.clone()), &Value::Int(1)).unwrap();
    let newest = commit_with(&db, |w| w.at(t, osis::DynamicAspectKey::untyped(b.clone())).set(&Value::Int(1))).stamp.id.raw();
    db.engine(|e| {
        e.snapshot(&t, &b)?;
        e.drop_body(&newest, &t, &b)
    })
    .unwrap();
    // `newest`, dropped as covered, is forgotten once no entry of it is known (spec/commits.md §5
    // Forgetting): undo is refused for it or for the snapshot standing for it, never undoes `a`
    let r = db.undo(&Scope::Thing(t));
    assert!(matches!(r, Err(Error::NotUndoable { reason: NotUndoableReason::NotKept, .. })), "{r:?}");
    assert_eq!(db.at(t, osis::DynamicAspectKey::untyped(a)).get().unwrap(), Some(Value::Int(1)));
    assert!(db.revert(osis::CommitId::from(newest)).is_err());
}

fn sync2(a: &Osis, b: &Osis) {
    deliver(a, b);
    deliver(b, a);
}

const DOC_SCHEMA: &str = "revision 1;\naspect x:doc.0: struct { name 0: string, tags 1: set<string>, extra 2: enum { none 0, some 1 (struct { notes 0: set<string> }) }, items 3: list<string> };\n";

fn field(id: u64) -> osis::Step {
    osis::Step::Field(id)
}

// spec/crdt.md §4.6 (read as it did just before that commit): undoing the first write into a spot that did not
// exist (a struct field's set, a set in an enum payload, a list) makes it absent again, so the
// read equals the read before; another's write into it already held when undoing stays.
#[test]
fn exact_undo_spec_crdt_4_6() {
    let (a, b, _) = shared();
    for d in [&a, &b] {
        d.register_schema("doc.osis", DOC_SCHEMA).unwrap();
    }
    let doc = ak("x:doc.0");
    // kept history: undo writes back what the undone write replaced, which no compaction may drop
    // first (spec/commits.md §7)
    let t = a
        .commit_with(|w| {
            let t = w.create_held()?;
            w.at(t, osis::core::RETENTION).set(&crate::common::setting(&[("x:doc.0", crate::common::DAY)]))?;
            Ok(t)
        })
        .unwrap();
    a.commit_with(|w| {
        w.at(t, osis::DynamicAspectKey::untyped(doc.clone())).path(osis::Path(vec![field(0)])).set(&"n".to_string())?;
        w.at(t, osis::DynamicAspectKey::untyped(doc.clone())).path(osis::Path(vec![field(2)])).set(&Value::Enum(1, Some(Box::new(Value::Map(Default::default())))))
    })
    .unwrap();
    sync2(&a, &b);
    let before = a.at(t, osis::DynamicAspectKey::untyped(doc.clone())).get().unwrap();
    let scope = Scope::Thing(t);
    let spots: [(&str, osis::Path); 3] = [
        ("struct field set", osis::Path(vec![field(1)])),
        ("enum payload set", osis::Path(vec![field(2), osis::Step::Case(1), field(0)])),
        ("list", osis::Path(vec![field(3)])),
    ];
    let write = |d: &Osis, p: &osis::Path, item: &str| {
        let item = item.to_string();
        let key = d.aspect_key("x:doc.0").unwrap();
        d.commit_with(|w| if p.0.len() == 1 && p.0[0] == field(3) { w.at(t, key.clone()).path(p.clone()).splice(0..0, &[item]) } else { w.at(t, key.clone()).path(p.clone()).add(&item) }).unwrap();
    };
    for (name, p) in &spots {
        write(&a, p, "x");
        assert_ne!(a.at(t, osis::DynamicAspectKey::untyped(doc.clone())).get().unwrap(), before, "{name}");
        a.undo(&scope).unwrap().unwrap();
        assert_eq!(a.at(t, osis::DynamicAspectKey::untyped(doc.clone())).get().unwrap(), before, "{name}");
        // seen: b's write is held when a undoes, so only a's write goes
        sync2(&a, &b);
        write(&b, p, "y");
        sync2(&a, &b);
        let b_only = a.at(t, osis::DynamicAspectKey::untyped(doc.clone())).get().unwrap();
        write(&a, p, "x");

        a.undo(&scope).unwrap().unwrap();
        assert_eq!(a.at(t, osis::DynamicAspectKey::untyped(doc.clone())).get().unwrap(), b_only, "{name}: b's held write stays");
        // back to the start for the next spot: b undoes its write (a's undone write's
        // tombstone carries no value, so it does not block the reset)
        sync2(&a, &b);
        b.undo(&scope).unwrap().unwrap();
        sync2(&a, &b);
        assert_eq!(a.at(t, osis::DynamicAspectKey::untyped(doc.clone())).get().unwrap(), before, "{name}");
    }
}

// spec/crdt.md §2.2 (total order on stamps): commits order by hybrid time, then ID; notes/api.md Commits: commits of one millisecond keep their order: a moment's places hold them all, and paging by a commit's place loses none
#[test]
fn one_moment_many_commits_lose_none_api_commits() {
    let c = clock();
    let db = osis::internals::create(cfg(0, MemStore::new(), &c)).unwrap();
    typed_any(&db, &["t:x.0"]);
    let k = kept(&db, &ak("t:x.0"));
    let t = db.commit_with(|w| { let t = w.create_held()?; keep_all(w, t); Ok(t) }).unwrap();
    let made: Vec<_> = (0..5).map(|i| commit_with(&db, |w| w.at(t, k.clone()).set(&Value::Int(i)))).collect();
    let at = made[0].stamp.written;
    assert!(made.iter().all(|m| m.stamp.written == at), "the clock did not move");
    assert_eq!(made.windows(2).filter(|w| w[0].pos() < w[1].pos()).count(), 4, "in the order written");
    let newest_first: Vec<_> = made.iter().rev().map(|m| m.stamp.id).collect();
    let ids = |from| db.at(t, k.clone()).writes(&page(from, 10)).unwrap().commits.into_iter().map(|e| e.stamp.id).collect::<Vec<_>>();
    assert_eq!(ids(osis::CommitFrom::Newest), newest_first);
    assert_eq!(ids(osis::CommitFrom::Before(osis::CommitPos::time(osis::Time(at.0 + 1)))), newest_first, "the moment holds them all");
    assert_eq!(ids(osis::CommitFrom::Before(osis::CommitPos::time(at))), vec![], "all before none of them");
    // one by one, by a commit's place, both ways
    let (mut seen, mut from) = (Vec::new(), osis::CommitFrom::Newest);
    while let Some(e) = db.at(t, k.clone()).writes(&page(from, 1)).unwrap().commits.pop() {
        seen.push(e.stamp.id);
        from = osis::CommitFrom::Before(e.pos());
    }
    assert_eq!(seen, newest_first);
    let (mut seen, mut from) = (Vec::new(), osis::CommitFrom::After(osis::CommitPos::time(at)));
    while let Some(e) = db.at(t, k.clone()).writes(&page(from, 1)).unwrap().commits.pop() {
        seen.push(e.stamp.id);
        from = osis::CommitFrom::After(e.pos());
    }
    assert_eq!(seen, made.iter().map(|m| m.stamp.id).collect::<Vec<_>>());
}

// spec/commits.md §7 (Listed parts), notes/api.md Commits: a purged part is listed while it would
// be unpurged: on an aspect keeping history for good, a purged expiring write lists as purged until
// its expiry and not after, a purged permanent one for good; undo reads kept history alone, so its
// answer is the same either side of the expiry
#[test]
fn purged_part_lists_until_its_expiry_spec_commits_7() {
    let c = clock();
    let db = osis::internals::create(cfg(0, MemStore::new(), &c)).unwrap();
    typed_any(&db, &["t:x.0"]);
    let k = ak("t:x.0");
    let t = db.commit_with(|w| w.create_held()).unwrap();
    db.commit_with(|w| w.at(t, osis::core::RETENTION).set(&setting(&[("t:x.0", osis::History::FOREVER)]))).unwrap();
    let set = |v: i64, expires: bool| {
        let mut w = db.write();
        if expires {
            w.expires(osis::Expiry::In(std::time::Duration::from_secs(60)));
        }
        w.at(t, kept(&db, &k)).set(&Value::Int(v)).unwrap();
        w.commit().unwrap().unwrap().stamp.id
    };
    let (lasting, brief) = (set(0, false), set(1, true));
    set(2, false);
    for id in [lasting, brief] {
        db.commit_with(|w| w.at(t, kept(&db, &k)).purge(osis::Purge::Commit(id))).unwrap();
    }
    let listed = |db: &Osis| {
        let h = db.writes(&Scope::Aspects(vec![(t, k.clone())]), &CommitQuery::default()).unwrap().commits;
        h.iter().filter(|e| [lasting, brief].contains(&e.stamp.id)).map(|e| (e.stamp.id, matches!(part(e, t, &k).body, osis::Body::Purged { .. }))).collect::<Vec<_>>()
    };
    let scope = Scope::Aspects(vec![(t, k.clone())]);
    let undo = |db: &Osis| format!("{:?}", db.undo_target(&scope).map(|c| c.map(|c| c.stamp.id)));
    assert_eq!(listed(&db), [(brief, true), (lasting, true)]);
    let before = undo(&db);
    c.advance(61_000);
    db.engine(|e| e.tick().unwrap());
    assert_eq!(listed(&db), [(lasting, true)], "the expired one leaves the listing");
    assert_eq!(undo(&db), before, "undo is unaffected");
    c.advance(400 * 86_400_000);
    db.engine(|e| e.tick().unwrap());
    assert_eq!(listed(&db), [(lasting, true)], "a permanent one's for good");
}

// spec/requirements.md (Decentralization: a commit holds at least 2 000 changes, of values of
// any size), notes/principles.md (Check scaling): the worst shape for the floor, one change on
// each of 2 000 different things (each its own secrets and framing), with one large value beside
// them (in blobs of its own, past `MAX_BLOB` itself), is one commit within `MAX_BLOB` that another
// node applies whole; and the work of making the things, writing that commit and applying it is
// linear in the things, every counted kind of it (engine phases and counts, perm's role walks,
// debug checks' walks included), counted at a tenth of the floor and at the floor.
#[test]
fn changes_on_as_many_things_spec_requirements_decentralization() {
    // per kind summed over the three steps: which step does some work depends on size, not on a
    // per-step cost. The things are made in four commits of n / 4 (at the floor 500 each), each
    // listing them in home: which make passes home's compaction trigger (a snapshot of its
    // holds.0, whose apply derives each listed thing's epochs at b) depends on the size, the
    // epochs derived once per thing either way, and a superlinear step still shows in the sum.
    let total = |w: std::collections::BTreeMap<String, u64>| {
        let mut t = std::collections::BTreeMap::<String, u64>::new();
        for (k, n) in w {
            *t.entry(k.split_once(' ').map_or(k.clone(), |(_, kind)| kind.to_string())).or_default() += n;
        }
        t
    };
    let (small, big) = (total(commit_work(200)), total(commit_work(2_000)));
    // `linear` as notes/test-scale.md (Scale checks) has it: at 10n at most 15x + 15 the count at n
    let over: Vec<_> = big.iter().map(|(k, n)| (k, small.get(k).copied().unwrap_or(0), *n)).filter(|(_, s, b)| *b > 15 * s + 15).collect();
    assert!(over.is_empty(), "work at n and 10n (kind, n, 10n): {over:?}");
}

/// Per kind, the work of making `n` things (four commits, delivered), then of writing one
/// commit with a change on each of them beside one value past `MAX_BLOB`, and of applying it on
/// another node, which reads every value written.
fn commit_work(n: usize) -> std::collections::BTreeMap<String, u64> {
    use osis::internals::costs;
    let (a, b, _c) = shared();
    let mut work = std::collections::BTreeMap::new();
    let mut add = |side: &str, cs: Vec<(&'static str, std::time::Duration, u64)>, reached: u64| {
        for (k, _, n) in cs {
            work.insert(format!("{side} {k}"), n);
        }
        work.insert(format!("{side} perm: roles reached"), reached);
    };
    let key = untyped("t:x.0");
    let big: Vec<u8> = (0..osis_base::format::MAX_BLOB + 1).map(|i| (i % 251) as u8).collect();
    // the large value's thing, made before the counts: its making is the same at every n
    let large = a.commit_with(|w| w.create_held_with_admin(crate::common::home(&a))).unwrap();
    costs::take();
    let r0 = osis_perm::roles_reached();
    let mut things = Vec::new();
    while things.len() < n {
        let mut w = a.write();
        let k = (n - things.len()).min(n / 4);
        // plain: minted with the account as admin, whose keys they take
        things.extend((0..k).map(|_| w.create_held_with_admin(crate::common::home(&a)).unwrap()));
        w.commit().unwrap();
    }
    deliver(&a, &b);
    add("create", costs::take(), osis_perm::roles_reached() - r0);
    let before: std::collections::BTreeSet<_> = a.engine(|e| e.commit_ids()).into_iter().collect();
    costs::take();
    let r0 = osis_perm::roles_reached();
    let mut w = a.write();
    w.at(large, key.clone()).path(osis::p![]).set_stream(&big[..]).unwrap();
    for (i, t) in things.iter().enumerate() {
        w.at(*t, key.clone()).set(&Value::Int(i as i64)).unwrap();
    }
    w.commit().unwrap();
    add("write", costs::take(), osis_perm::roles_reached() - r0);
    let new: Vec<_> = a.engine(|e| e.commit_ids()).into_iter().filter(|id| !before.contains(id)).collect();
    assert_eq!(new.len(), 1, "one commit");
    let pk = a.engine(|e| e.package(&new[0]).unwrap().unwrap());
    assert!(pk.bytes.len() <= osis_base::format::MAX_BLOB, "{} bytes", pk.bytes.len());
    costs::take();
    let r0 = osis_perm::roles_reached();
    b.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()).unwrap());
    add("apply", costs::take(), osis_perm::roles_reached() - r0);
    for (i, t) in things.iter().enumerate() {
        assert_eq!(b.at(*t, key.clone()).get().unwrap(), Some(Value::Int(i as i64)), "thing {i}");
    }
    assert_eq!(b.at(large, key).get().unwrap(), Some(Value::Bytes(big)));
    work
}
