//! The reference index (issues/thing-lifetimes.md, Index and backlinks; notes/engine-refs.md),
//! read through `internals`: rows follow the held values, whatever changes them.

use crate::common::*;
use osis::internals::Internals as _;
use osis::internals::node::costs;
use osis::{DynamicAspectKey, MemStore, Osis, Role, SetRoleOpts, Tid, Value, p};
use osis_sim::world::World;
use std::collections::BTreeSet;

fn key(k: &str) -> DynamicAspectKey {
    DynamicAspectKey::untyped(ak(k))
}

type Row = (Tid, String, u64);

/// `source`'s rows: (target, AK, count).
fn rows(db: &Osis, source: Tid) -> BTreeSet<Row> {
    db.engine(|e| e.references_from(&source).unwrap()).into_iter().map(|r| (r.target, r.ak.as_str().to_string(), r.count)).collect()
}

fn things(db: &Osis, n: usize) -> Vec<Tid> {
    db.commit_with(|w| (0..n).map(|_| w.create()).collect()).unwrap()
}

fn row(t: Tid, k: &str, n: u64) -> (Tid, String, u64) {
    (t, k.to_string(), n)
}

// issues/thing-lifetimes.md (What a reference is): a tid at any depth of a held value counts,
// map keys and set elements included, per aspect and class; a string spelling one does not;
// `retainers^.0` is indexed too, as a list; rows follow every write, and leave with the value.
#[test]
fn rows_follow_the_values() {
    let db = db(1);
    let [r, x, y] = things(&db, 3)[..] else { panic!() };
    let m = Value::Map([(Value::Tid(x), Value::List(vec![Value::Tid(y), Value::Tid(y)])), (Value::Str("k".into()), Value::Tid(x))].into_iter().collect());
    db.commit_with(|w| {
        w.at(r, key("t:a.0")).set(&m)?;
        w.at(r, key("t:s.0")).set(&Value::Set([Value::Tid(y)].into_iter().collect()))?;
        w.at(r, key("t:txt.0")).set(&Value::Str(x.to_uri()))?;
        w.at(r, key("retainers^.0")).set(&Value::Set([Value::Tid(y)].into_iter().collect()))
    })
    .unwrap();
    db.commit_with(|w| w.at(r, key("t:e+.0")).set(&Value::Tid(x))).unwrap();
    assert_eq!(rows(&db, r), [row(x, "t:a.0", 2), row(x, "t:e+.0", 1), row(y, "retainers^.0", 1), row(y, "t:a.0", 2), row(y, "t:s.0", 1)].into());
    let to_y = db.engine(|e| e.references_to(&y).unwrap());
    assert!(to_y.iter().all(|x| x.source == r && !x.ephemeral()));
    assert_eq!(to_y.iter().filter(|x| x.lists()).count(), 1, "the list, flagged");
    assert!(db.engine(|e| e.references_to(&x).unwrap()).iter().any(|x| x.ephemeral()), "the ephemeral class");
    // a path write changes the rows of the entry it writes
    db.commit_with(|w| w.at(r, key("t:a.0")).path(p!(Value::Str("k".into()))).set(&Value::Tid(y))).unwrap();
    let got = rows(&db, r);
    assert!(got.contains(&row(x, "t:a.0", 1)) && got.contains(&row(y, "t:a.0", 3)), "{got:?}");
    // a removal, a delete
    db.commit_with(|w| w.at(r, key("t:a.0")).remove()).unwrap();
    assert!(!rows(&db, r).iter().any(|x| x.1 == "t:a.0"));
    db.commit_with(|w| w.delete(r)).unwrap();
    assert_eq!(rows(&db, r), BTreeSet::new(), "the deleter drops its ephemeral state too");
}

// issues/thing-lifetimes.md (Index): another node's rows are the writer's, in any arrival order of
// the commits that wrote them.
#[test]
fn rows_follow_the_value_in_any_arrival_order() {
    let orders = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
    for order in orders {
        let (a, b, _) = paired();
        let [r, x, y] = things(&a, 3)[..] else { panic!() };
        let before: std::collections::BTreeSet<_> = a.engine(|e| e.commit_ids()).into_iter().collect();
        let mine = [
            a.commit_with(|w| w.at(r, key("t:a.0")).set(&Value::Map([(Value::Int(1), Value::Tid(x)), (Value::Int(2), Value::Tid(x))].into_iter().collect()))).unwrap(),
            a.commit_with(|w| w.at(r, key("t:a.0")).path(p!(Value::Int(1))).set(&Value::Tid(y))).unwrap(),
            a.commit_with(|w| w.at(r, key("t:a.0")).path(p!(Value::Int(3))).set(&Value::Set([Value::Tid(x), Value::Tid(y)].into_iter().collect()))).unwrap(),
        ];
        assert_eq!(mine.len(), 3);
        let ids = a.engine(|e| e.commit_ids());
        let (old, new): (Vec<_>, Vec<_>) = ids.into_iter().partition(|c| before.contains(c));
        assert_eq!(new.len(), 3);
        let pk = |c| a.engine(|e| e.package(c).unwrap().unwrap());
        for c in &old {
            let p = pk(c);
            b.engine(|e| e.ingest(&p.bytes, p.blobs.clone()).unwrap());
        }
        // the content commits by stamp, delivered in `order`
        let mut new: Vec<_> = new.into_iter().map(|c| (a.engine(|e| e.header(&c).unwrap().ts), c)).collect();
        new.sort();
        for i in order {
            let p = pk(&new[i].1);
            b.engine(|e| e.ingest(&p.bytes, p.blobs.clone()).unwrap());
        }
        b.engine(|e| e.reexamine().unwrap());
        assert_eq!(rows(&a, r), [row(x, "t:a.0", 2), row(y, "t:a.0", 2)].into());
        assert_eq!(rows(&b, r), rows(&a, r), "order {order:?}");
    }
}

// issues/thing-lifetimes.md (What a reference is: not a value-less write): an expiry and a purge
// remove the rows of the values they take.
#[test]
fn an_expiry_and_a_purge_remove_rows() {
    let c = clock();
    let db = osis::internals::create(cfg(1, MemStore::new(), &c)).unwrap();
    let [r, x, y] = things(&db, 3)[..] else { panic!() };
    let mut w = db.write();
    w.expires(osis::Expiry::In(std::time::Duration::from_secs(60)));
    w.at(r, key("t:a.0")).set(&Value::Tid(x)).unwrap();
    w.commit().unwrap();
    let ret = osis::Retention { by: osis::internals::schema::PurgeBy::Writer };
    db.commit_with(|w| w.at(r, key("t:b.0")).retention(ret).set(&Value::Tid(y))).unwrap();
    assert_eq!(rows(&db, r), [row(x, "t:a.0", 1), row(y, "t:b.0", 1)].into());
    c.advance(61_000);
    db.engine(|e| e.tick()).unwrap();
    assert_eq!(rows(&db, r), [row(y, "t:b.0", 1)].into(), "expired");
    db.commit_with(|w| w.at(r, key("t:b.0")).purge(osis::Purge::All)).unwrap();
    assert_eq!(rows(&db, r), BTreeSet::new(), "purged");
}

// issues/thing-lifetimes.md (Disputes, validity): a reference whose write turns invalid (its
// writer removed with a frontier that omits it) leaves the index.
#[test]
fn a_validity_flip_removes_rows() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let g = alice
        .commit_with(|x| {
            let g = x.create()?;
            x.group(alice.home()).add(osis::Member::Item(g))?;
            Ok(g)
        })
        .unwrap();
    alice.sync(g, &[]).unwrap();
    alice.grant(g, b, Role::Write, Default::default()).unwrap();
    w.run();
    for r in bob.invite_requests().unwrap_or_default() {
        let _ = bob.accept_invite(r);
    }
    w.run();
    w.set_online(&bob, false);
    w.advance(1000);
    alice.set_role(g, b, None, SetRoleOpts { retain_copy: Some(true) }).unwrap();
    w.run();
    bob.commit_with(|x| x.at(g, key("t:a.0")).set(&Value::Tid(alice.home()))).unwrap();
    assert_eq!(rows(&bob, g), [row(alice.home(), "t:a.0", 1)].into(), "valid where written");
    w.set_online(&bob, true);
    w.advance(60_000);
    w.run();
    assert_eq!(rows(&bob, g), BTreeSet::new(), "invalid once the removal arrives");
    assert_eq!(rows(&alice, g), BTreeSet::new());
}

// issues/thing-lifetimes.md (The judgment: an unknown retainer keeps): a node that loses access to
// a thing keeps no row of it.
#[test]
fn lost_access_leaves_no_rows() {
    let mut w = World::new();
    let host = w.add_host();
    let alice = w.account(1, &[host]);
    let bob = w.account(2, &[host]);
    w.run();
    let card = bob.contact_card().unwrap();
    w.run();
    let b = w.until(alice.import_contact(&card), 1000, 10).unwrap();
    let mut wr = alice.write();
    let g = wr.create_in(alice.me(), &[alice.home()]).unwrap();
    wr.commit().unwrap();
    alice.sync(g, &[]).unwrap();
    let mut wr = alice.write();
    let t = wr.create_in(g, &[g]).unwrap();
    wr.at(t, key("t:a.0")).set(&Value::Tid(g)).unwrap();
    wr.commit().unwrap();
    alice.grant(g, b, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(rows(&bob, t), [row(g, "t:a.0", 1)].into(), "held");
    alice.set_role(g, b, None, SetRoleOpts { retain_copy: Some(false) }).unwrap();
    w.run();
    assert_eq!(bob.at(t, key("t:a.0")).get().unwrap(), None, "forgotten");
    assert_eq!(rows(&bob, t), BTreeSet::new());
    assert!(bob.engine(|e| e.references_to(&g).unwrap()).is_empty());
}

// issues/thing-lifetimes.md (Cost): a path write into a map of n and 10n entries reads the values
// it writes and those it replaces, and changes their rows: no other entry.
#[test]
fn a_path_write_costs_what_it_writes() {
    fn count(n: i64) -> Vec<(&'static str, u64)> {
        let db = db(1);
        let [r, x, y] = things(&db, 3)[..] else { panic!() };
        let m = Value::Map((0..n).map(|i| (Value::Int(i), Value::Tid(x))).collect());
        db.commit_with(|w| w.at(r, key("t:a.0")).set(&m)).unwrap();
        assert_eq!(rows(&db, r), [row(x, "t:a.0", n as u64)].into());
        costs::take();
        // one entry replaced: the old value read and replaced, the new written
        db.commit_with(|w| w.at(r, key("t:a.0")).path(p!(Value::Int(0))).set(&Value::Tid(y))).unwrap();
        let cs = costs::take();
        assert_eq!(rows(&db, r), [row(x, "t:a.0", n as u64 - 1), row(y, "t:a.0", 1)].into());
        let out = ["refs: value read", "refs: row written"].iter().map(|k| (*k, cs.iter().find(|x| x.0 == *k).map_or(0, |x| x.2))).collect();
        // a whole replace (a paged map's reset joins by pages) counts what it removes and adds
        let m = Value::Map((0..n / 2).map(|i| (Value::Tid(r), Value::Int(i))).chain((0..n / 2).map(|i| (Value::Int(i), Value::Tid(y)))).collect());
        db.commit_with(|w| w.at(r, key("t:a.0")).overwrite(&m)).unwrap();
        assert_eq!(rows(&db, r), [row(r, "t:a.0", 1), row(y, "t:a.0", n as u64 / 2)].into());
        out
    }
    let small = count(200);
    assert_eq!(small, vec![("refs: value read", 4), ("refs: row written", 2)], "the key and value of the old entry and of the new");
    assert_eq!(count(2000), small);
}
