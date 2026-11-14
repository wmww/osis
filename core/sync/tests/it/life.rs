//! Lifecycle duties the engine judges and sync drives (notes/sync-driver.md, Duties).

use crate::harness::history::file;
use crate::harness::lies::Lie;
use crate::harness::{World, fixture_with, siblings};
use osis_base::{Ak, Tid, Value};
use osis_engine::Mutation;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

fn v() -> Ak {
    Ak::new("u:v.0").unwrap()
}

/// `siblings` with node 1 having filed in D a root R whose value references X, and X retained
/// by R (`retainers^.0` {R}), both read at node 2: (world, R, X). Built once.
fn retained() -> (World, Tid, Tid) {
    let (w, (r, x)) = fixture_with("life retained", || {
        let mut w = siblings();
        let a1 = w.node(1).account.unwrap();
        let (r, x) = w.write(1, |e| {
            let mut m = Mutation::new();
            let r = e.new_thing(&mut m, a1);
            let x = e.new_thing(&mut m, a1);
            m.set(r, &v(), &Value::Tid(x)).unwrap();
            m.set(x, &v(), &Value::Str("x".into())).unwrap();
            m.set(x, &ct::RETAINERS, &BTreeSet::from([r])).unwrap();
            e.commit(m).unwrap();
            (r, x)
        });
        file(&mut w, 1, vec![r, x], Vec::new());
        w.run();
        assert_eq!(w.engine(2).get(&x, &v()).unwrap(), Some(Value::Str("x".into())), "node 2 reads X");
        (w, (r, x))
    });
    (w, r, x)
}

/// Node 1 drops R's reference to X.
fn unreference(w: &mut World, r: Tid) {
    w.write(1, |e| {
        let mut m = Mutation::new();
        m.set(r, &v(), &Value::Str("none".into())).unwrap();
        e.commit(m).unwrap();
    });
}

// spec/commits.md §5 (Lifetimes: a node judges once, for each sync ID carrying X, a source of it
// is connected and the node holds everything it holds there; while a peer sharing it is away it
// releases nothing): X,
// under D's sync ID, is unreachable once R stops referencing it; cut off from its sibling node 1
// keeps it, and releases it once D is heard out again, which node 2 then holds. Node 2 shows none
// of its own new entries meanwhile (`Lie::Withhold`), so the release is node 1's judgment of the
// thing it held, not node 2's of the write reaching it.
#[test]
fn an_unreachable_thing_is_released_once_heard_out_spec_commits_5() {
    let (mut w, r, x) = retained();
    w.partition(1, 2);
    w.partition(0, 1);
    unreference(&mut w, r);
    w.flush();
    assert_eq!(w.engine(1).get(&x, &v()).unwrap(), Some(Value::Str("x".into())), "released offline");
    w.lie(2, Some(Lie::Withhold));
    w.heal();
    w.run();
    assert_eq!(w.engine(1).get(&x, &v()).unwrap(), None, "not released once heard out");
    assert_eq!(w.engine(2).get(&x, &v()).unwrap(), None, "the release did not reach node 2");
}

// spec/commits.md §5 (Lifetimes: a sync ID no peer shares with it needs no source): a single-device
// account, no peer sharing D's sync ID, releases X as soon as R stops referencing it. (A peer
// that shares it but is away is waited on: `an_unreachable_thing_is_released_once_heard_out`.)
#[test]
fn a_node_alone_releases_at_once_spec_commits_5() {
    let mut w = World::new(0);
    w.add_node();
    w.run();
    let a = w.node(0).account.unwrap();
    let (r, x) = w.write(0, |e| {
        let mut m = Mutation::new();
        let r = e.new_thing(&mut m, a);
        let x = e.new_thing(&mut m, a);
        m.set(r, &v(), &Value::Tid(x)).unwrap();
        m.set(x, &v(), &Value::Str("x".into())).unwrap();
        m.set(x, &ct::RETAINERS, &BTreeSet::from([r])).unwrap();
        e.commit(m).unwrap();
        (r, x)
    });
    file(&mut w, 0, vec![r, x], Vec::new());
    w.run();
    assert_eq!(w.engine(0).get(&x, &v()).unwrap(), Some(Value::Str("x".into())), "kept while referenced");
    w.write(0, |e| {
        let mut m = Mutation::new();
        m.set(r, &v(), &Value::Str("none".into())).unwrap();
        e.commit(m).unwrap();
    });
    w.run();
    assert_eq!(w.engine(0).get(&x, &v()).unwrap(), None, "a node alone releases");
}
