//! A node that hosts (notes/api.md Hosting, notes/sync.md Hosting), in process: its `host.0^`
//! runs a hub the world steps; the node's own dials of its host address reach it like anyone's.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;
use common::*;
use crate::common::CreateIn;
use osis::internals::Internals as _;
use osis::{Admit, HostAddr, Hosting, LabelId, Osis, Role, Tid, Value};
use osis_host::Admission;
use osis_sim::world::World;
use std::collections::BTreeSet;

fn item(db: &Osis, g: Tid, v: &str) -> Tid {
    let mut w = db.write();
    let t = w.create_in(db.me(), &[g]).unwrap();
    w.at(t, ak("t:x.0")).set(&Value::Str(v.into())).unwrap();
    w.commit().unwrap();
    t
}

fn home_label(db: &Osis) -> LabelId {
    let home = db.home();
    db.sync_engine(|s| s.labels().into_iter().find(|(g, _)| *g == home).map(|(_, l)| l.id)).unwrap()
}

fn hosted(w: &World, s: usize) -> Vec<LabelId> {
    w.hosts[s].hub.store().labels_after(None, 1000).unwrap()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|x| x == needle)
}

// spec/sync.md §5 (an unadmitted genesis step gets code 12), notes/sync.md Hosting, spec/requirements.md
// Untrusted nodes: Alice hosts with `own` admission: her home label, once its hosts name her
// host address, is admitted and served from her host store (her own copy placed there like
// anyone's); Bob's is refused until she opens admission, then hosted blind (she holds none of
// its keys) and served to Bob's restored device. Her host store holds no tid or AK of either
// label in any row it ever wrote.
#[test]
fn hosting_own_then_open_spec_sync_5() {
    let mut w = World::new();
    let base = w.add_host();
    let (alice, _) = w.person(1, &[base]);
    let (bob, bob_card) = w.person(2, &[base]);
    w.run();
    assert_eq!(alice.host_address().unwrap(), None);
    alice.set_hosting(Some(Hosting { listen: vec!["quic://alice:1".into()], admit: Admit::Own, ..Default::default() })).unwrap();
    w.run();
    let ha = alice.host_address().unwrap().expect("listening");
    assert_eq!(alice.hosting().unwrap().admit, Admit::Own);
    let ai = w.index(&alice).unwrap();
    let s = w.host_of(ai).unwrap();

    // own: Alice's home label names her host, Bob's too: only hers is admitted
    alice.add_host(&ha).unwrap();
    bob.add_host(&ha).unwrap();
    let ta = item(&alice, alice.home(), "alice's");
    let tb = item(&bob, bob.home(), "bob's");
    w.run();
    w.advance(120_000);
    let (la, lb) = (home_label(&alice), home_label(&bob));
    assert!(hosted(&w, s).contains(&la), "own: admitted");
    assert!(!hosted(&w, s).contains(&lb), "own: another person's label refused");

    // open: Bob's label is taken at his next registration
    alice.set_hosting(Some(Hosting { admit: Admit::Open, ..alice.hosting().unwrap() })).unwrap();
    w.run();
    for _ in 0..5 {
        w.advance(120_000);
    }
    assert!(hosted(&w, s).contains(&lb), "open: admitted");
    assert_eq!(alice.host_address().unwrap(), Some(ha.clone()), "the host kept its key and address");

    // Bob's new device reaches only Alice's host: his label is served from her store, blind
    let mut cfg = w.cfg(3, &[]);
    cfg.hosts = vec![ha];
    let restored = w.until(Osis::restore(cfg, &bob_card), 1000, 30).unwrap();
    w.run();
    assert_eq!(restored.get(tb, ak("t:x.0")).unwrap(), Some(Value::Str("bob's".into())));

    // hygiene: no tid or AK of the label Alice reads or the one she does not
    let history = w.hosts[s].hub.store().backend().history();
    assert!(!history.is_empty());
    for needle in [ta.as_bytes().as_slice(), tb.as_bytes(), alice.me().as_bytes(), bob.me().as_bytes(), alice.node().as_bytes(), bob.node().as_bytes(), b"t:x.0"] {
        for (k, v) in &history {
            assert!(!contains(k, needle) && !contains(v, needle));
        }
    }

    // stopping shreds the host secret: the next start has a new key
    alice.set_hosting(None).unwrap();
    w.run();
    assert_eq!(alice.host_address().unwrap(), None);
    assert!(alice.sync_engine(|e| e.host_key()).is_none());
}

/// A group owned by `owner` (held by `db`), placed in `within`, synced on `hosts`.
fn group_of(db: &Osis, owner: Tid, within: Tid, hosts: &[HostAddr]) -> Tid {
    let mut w = db.write();
    let g = w.create_in(owner, &[within]).unwrap();
    w.make_group(g).unwrap();
    w.commit().unwrap();
    db.sync(g, hosts).unwrap();
    g
}

fn label_of(db: &Osis, g: Tid) -> LabelId {
    db.sync_engine(|s| s.labels().into_iter().find(|(x, _)| *x == g).map(|(_, l)| l.id)).expect("Alice reads it")
}

fn admitted(db: &Osis) -> BTreeSet<LabelId> {
    match db.sync_engine(|s| s.host_config()).expect("hosting").admission {
        Admission::Only(ids) => ids,
        Admission::Open => panic!("own expected"),
    }
}

// spec/data-model.md §9 (`host.0^` `own`), spec/requirements.md Untrusted nodes: `own` admits
// the groups Alice's person owns (the owner chain reaches her person, or an actor her person
// admins), not every group she reads. Bob, a contact, grants her read, then admin, on a group he
// owns that names her host: not admitted. A group owned by an actor her person admins is.
#[test]
fn own_admits_only_owned_groups_spec_data_model_9() {
    let mut w = World::new();
    let base = w.add_host();
    let (alice, _) = w.person(1, &[base]);
    let (bob, _) = w.person(2, &[base]);
    w.run();
    alice.set_hosting(Some(Hosting { listen: vec!["quic://alice:1".into()], admit: Admit::Own, ..Default::default() })).unwrap();
    w.run();
    let ha = alice.host_address().unwrap().expect("listening");
    let hosts = [w.addr(base).unwrap(), ha.clone()];
    let card = alice.contact_card().unwrap();
    w.run();
    let a = w.until(bob.import_contact(&card), 1000, 10).unwrap();

    // Bob's group naming Alice's host, Alice a reader: not hers
    let x = group_of(&bob, bob.me(), bob.home(), &hosts);
    bob.grant(x, a, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(alice.role_on(x), Some(Role::Read));
    let lx = label_of(&alice, x);
    assert!(!admitted(&alice).contains(&lx), "own: a group Alice only reads");

    // nor when she co-administers it: Bob still owns it
    bob.grant(x, a, Role::Admin, Default::default()).unwrap();
    w.run();
    assert_eq!(alice.role_on(x), Some(Role::Admin));
    assert!(!admitted(&alice).contains(&lx), "own: a group Bob owns that Alice co-administers");
    for _ in 0..3 {
        w.advance(120_000);
    }
    let ai = w.index(&alice).unwrap();
    let s = w.host_of(ai).unwrap();
    assert!(!hosted(&w, s).contains(&lx), "own: refused at registration");

    // a group owned by an actor Alice's person admins (a family actor Bob made): hers
    let fam = group_of(&bob, bob.me(), bob.home(), &[]);
    bob.grant(fam, a, Role::Admin, Default::default()).unwrap();
    let shared = group_of(&bob, fam, fam, &hosts);
    w.run();
    let ls = label_of(&alice, shared);
    assert!(admitted(&alice).contains(&ls), "own: owned by an actor Alice's person admins");

    // her own group naming her host
    let mine = group_of(&alice, alice.me(), alice.home(), &hosts);
    w.run();
    assert!(admitted(&alice).contains(&label_of(&alice, mine)), "own: Alice's own group");
}
