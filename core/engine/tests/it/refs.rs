//! Known references (spec/data-model.md §8): the index holds every reference in held readable
//! values and held valid fires, each with its kind; a fire's leave with it.

use crate::common::*;
use osis_base::{PurgeBy, RefKind, Tid, Value};
use osis_engine::Mutation;
use osis_engine::local_peer::LocalPeer;
use osis_schema::core_types as ct;
use osis_schema::{History, Retention};

fn rows(lp: &mut LocalPeer, i: usize, target: &Tid) -> Vec<(Tid, String, RefKind, u64)> {
    lp.peers[i].engine.references_to(target).unwrap().into_iter().map(|r| (r.source, r.ak.as_str().to_string(), r.kind, r.count)).collect()
}

// spec/data-model.md §8 What counts: a strong and a weak to one target in one value are two rows,
// each with its kind; a core aspect's names are weaks
#[test]
fn rows_carry_the_kind_spec_data_model_8() {
    let mut lp = net(1, 0);
    let me = lp.peers[0].engine.me();
    let mut m = Mutation::new();
    let (t, x) = (lp.peers[0].engine.new_thing(&mut m, me), lp.peers[0].engine.new_thing(&mut m, me));
    m.set(t, &REFS, &Value::Set([Value::Strong(x), Value::Weak(x)].into_iter().collect())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let got = rows(&mut lp, 0, &x);
    assert_eq!(got, vec![(t, "t:refs.0".into(), RefKind::Strong, 1), (t, "t:refs.0".into(), RefKind::Weak, 1)]);
    // the account is named by each creation record's `admin`, a weak
    assert!(rows(&mut lp, 0, &me).iter().any(|r| r.0 == t && r.1 == "created.0" && r.2 == RefKind::Weak));
}

// spec/data-model.md §8 Known references: a held valid fire's references count at every holder
// and go with the fire
#[test]
fn a_fires_references_go_with_it_spec_data_model_8() {
    let mut lp = net(2, 0);
    let ids: Vec<Tid> = (0..2).map(|i| lp.peers[i].engine.me()).collect();
    let log = ak("t:log~0");
    let mut m = Mutation::new();
    let d = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    let x = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    m.set(d, &ct::RETENTION, &setting(&[(log.as_str(), History::FOREVER)])).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    set_edge(&mut lp.peers[0].engine, d, ids[1], Some(edge(osis_base::Role::Write)), None);
    lp.sync_all().unwrap();
    let mut m = Mutation::new();
    m.retention(d, &log, Retention { by: PurgeBy::AuthorOrAdmin }).unwrap();
    m.set(d, &log, &Value::List(vec![Value::Weak(x), Value::Weak(x)])).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    for i in 0..2 {
        assert_eq!(rows(&mut lp, i, &x), vec![(d, "t:log~0".into(), RefKind::Weak, 2)], "peer {i}");
    }
    let item = lp.peers[0].engine.purge_item(&c, d, log.clone()).unwrap();
    let mut m = Mutation::new();
    m.set(d, &ct::PURGE, &lp.peers[0].engine.now()).unwrap();
    m.purge(item);
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    for i in 0..2 {
        assert_eq!(rows(&mut lp, i, &x), vec![], "peer {i}: purged");
    }
}
