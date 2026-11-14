//! Two-node flows end to end through the product's sync, nothing carried by hand.

use crate::harness::World;
use crate::harness::history::introduce;
use osis_base::{Ak, Role, Tid, Value};
use osis_engine::Mutation;
use osis_schema::core_types as ct;

fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, tied: None }
}

/// Node `i` files `t` in its account's D (in every synced group's closure of the account), as
/// an item, or as a subgroup (an accept, spec/sync-set.md §4).
pub fn file(w: &mut World, i: usize, t: Tid, sub: bool) {
    w.write(i, |e| {
        let (_, d) = e.account().unwrap().unwrap();
        let mut g = e.get_typed(&d, &ct::GROUP).unwrap().unwrap_or_default();
        if sub { g.subgroups.insert(t); } else { g.items.insert(t); }
        let mut m = Mutation::new();
        m.set(d, &ct::GROUP, &g).unwrap();
        e.commit(m).unwrap().unwrap();
    });
}

#[test]
fn probe_two_accounts_share() {
    let mut w = World::new(0);
    w.add_node();
    w.add_node();
    // contacts by hand: each account reads the other's profile, filed in its synced group
    let (p0, p1) = (w.node(0).profile.unwrap(), w.node(1).profile.unwrap());
    let (x0, x1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    introduce(&mut w);
    w.write(0, |e| e.grant(&p0, &x1, &edge(Role::Read))).unwrap();
    w.write(1, |e| e.grant(&p1, &x0, &edge(Role::Read))).unwrap();
    crate::harness::history::hand_all(&mut w);
    file(&mut w, 0, p1, true);
    file(&mut w, 1, p0, true);
    file(&mut w, 0, p0, false);
    file(&mut w, 1, p1, false);
    crate::harness::history::hand_all(&mut w);
    eprintln!("known a0 at 1: {} a1 at 0: {}", w.engine(1).known_actor(&x0), w.engine(0).known_actor(&x1));
    w.discover(0, 1);
    w.discover(1, 0);
    w.run();
    let (a0, a1) = (w.node(0).account.unwrap(), w.node(1).account.unwrap());
    let ak = Ak::new("u:v.0").unwrap();
    let t = w.write(0, |e| {
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a0);
        m.set(t, &ak, &Value::Str("x".into())).unwrap();
        e.commit(m).unwrap();
        t
    });
    file(&mut w, 0, t, false);
    w.write(0, |e| e.grant(&t, &a1, &edge(Role::Read))).unwrap();
    w.trace = true;
    w.run();
    let inbox = w.engine(0).inbox_of(&a1).unwrap();
    eprintln!("node 0 entries under 1's inbox: {:?}", w.store(0).entries(&inbox).unwrap());
    eprintln!("node 1 entries under 1's inbox: {:?}", w.store(1).entries(&inbox).unwrap().len());
    eprintln!("links 0: {:?}; ups {:?}", w.links_of(0), w.net.ups);
    eprintln!("seen: {:?}", w.seen.iter().filter(|s| !matches!(s, crate::harness::Seen::Taken{..})).collect::<Vec<_>>());
    eprintln!("invitations at 1: {:?}", w.engine(1).invitations().unwrap());
    eprintln!("set 0: {:?}", w.engine(0).sync_set().unwrap().ids);
    file(&mut w, 1, t, true);
    w.run();
    eprintln!("set 1: {:?}", w.engine(1).sync_set().unwrap().ids);
    eprintln!("status 1: {:?}", w.status(1));
    assert_eq!(w.engine(1).get(&t, &ak).unwrap(), Some(Value::Str("x".into())));
}
