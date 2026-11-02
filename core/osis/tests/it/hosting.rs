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
// Untrusted nodes: Alice hosts with `own` admission (its key known before it listens): her home label, once its hosts name her
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
    assert_eq!(alice.host_key(), None);
    alice.set_hosting(Some(Hosting { listen: vec!["quic://alice:1".into()], admit: Admit::Own, ..Default::default() })).unwrap();
    let key = alice.host_key().expect("known before it listens");
    w.run();
    let ha = alice.host_address().unwrap().expect("listening");
    assert_eq!(HostAddr::new("quic://alice:1", key), ha, "the key it listens with");
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
    let mut history = w.hosts[s].backend.history();
    assert!(!history.is_empty());
    let keys = w.hosts[s].hub.store_mut().store_mut().unwrap().forensic_keys().unwrap();
    let plain = osis_store::forensic_plaintexts(keys, &history);
    history.extend(plain.into_iter().map(|p| (Vec::new(), p)));
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
    assert_eq!(alice.host_key(), None);
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

/// Alice (hosting under `own` on a test host) and Bob, contacts both ways: (world, alice, bob,
/// base host, Alice's host address, Alice's person as Bob knows it, Bob's as Alice knows it).
fn own_pair(seed: u64) -> (World, Osis, Osis, usize, HostAddr, Tid, Tid) {
    let mut w = World::new();
    let base = w.add_host();
    let (alice, _) = w.person(seed * 2 + 1, &[base]);
    let (bob, _) = w.person(seed * 2 + 2, &[base]);
    w.run();
    alice.set_hosting(Some(Hosting { listen: vec!["quic://alice:1".into()], admit: Admit::Own, ..Default::default() })).unwrap();
    w.run();
    let ha = alice.host_address().unwrap().expect("listening");
    let (ca, cb) = (alice.contact_card().unwrap(), bob.contact_card().unwrap());
    w.run();
    let a = w.until(bob.import_contact(&ca), 1000, 10).unwrap();
    let b = w.until(alice.import_contact(&cb), 1000, 10).unwrap();
    (w, alice, bob, base, ha, a, b)
}

// spec/data-model.md §9 (`host.0^` `own`), spec/requirements.md Untrusted nodes: `own` admits
// the groups whose owner chain reaches Alice's person, not every group she reads. Bob, a contact,
// grants her person read, then admin, and her node admin, on a group he owns that names her
// host: not admitted; nor a group under an actor of Bob's that Bob made her person admin of
// (grants need no consent). A group under an actor her person owns is.
#[test]
fn own_admits_only_owned_groups_spec_data_model_9() {
    let (mut w, alice, bob, base, ha, a, _) = own_pair(0);
    let hosts = [w.addr(base).unwrap(), ha.clone()];

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
    // nor when Bob grants her node admin directly
    bob.grant(x, alice.node(), Role::Admin, Default::default()).unwrap();
    w.run();
    assert!(!admitted(&alice).contains(&lx), "own: a group Bob owns, Alice's node its admin");
    for _ in 0..3 {
        w.advance(120_000);
    }
    let ai = w.index(&alice).unwrap();
    let s = w.host_of(ai).unwrap();
    assert!(!hosted(&w, s).contains(&lx), "own: refused at registration");

    // an actor Bob made and made Alice's person admin of: still Bob's
    let fam = group_of(&bob, bob.me(), bob.home(), &[]);
    bob.grant(fam, a, Role::Admin, Default::default()).unwrap();
    let shared = group_of(&bob, fam, fam, &hosts);
    w.run();
    let ls = label_of(&alice, shared);
    assert!(!admitted(&alice).contains(&ls), "own: owned by an actor Bob made Alice's person admin of");

    // her own group naming her host, and one under an actor she owns
    let mine = group_of(&alice, alice.me(), alice.home(), &hosts);
    let y = group_of(&alice, alice.me(), alice.home(), &[]);
    let under = group_of(&alice, y, y, &hosts);
    w.run();
    let got = admitted(&alice);
    assert!(got.contains(&label_of(&alice, mine)), "own: Alice's own group");
    assert!(got.contains(&label_of(&alice, under)), "own: under an actor Alice's person owns");
    // a driver's start (`host_restart`; the World's runtime never restarts one) keeps the person
    alice.sync_engine(|s| s.host_restart());
    assert!(admitted(&alice).contains(&label_of(&alice, mine)), "own: the person kept across a driver restart");
}

// spec/data-model.md §9 (`host.0^` `own`): the invariant (`SyncEngine::owns`) over random ownership and grant graphs: Alice
// admits exactly the groups she reads that name her host and whose owner chain (as created)
// reaches her person, whatever read or admin edges Bob gives her person or node, or she gives
// Bob (who then creates under her actors). Seeds picked so each fails with the rule that also
// counted admin edges (on the group, or on an owner above it).
#[test]
fn own_admits_owner_chain_random_0_spec_data_model_9() {
    own_random(2);
}

// spec/data-model.md §9: as above, another seed.
#[test]
fn own_admits_owner_chain_random_1_spec_data_model_9() {
    own_random(3);
}

// spec/data-model.md §9: as above, another seed.
#[test]
fn own_admits_owner_chain_random_2_spec_data_model_9() {
    own_random(7);
}

fn own_random(seed: u64) {
    {
        let (mut w, alice, bob, base, ha, a, b) = own_pair(10 + seed);
        let (plain, named) = (vec![w.addr(base).unwrap()], vec![w.addr(base).unwrap(), ha.clone()]);
        let mut rng = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut next = move |n: usize| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            (rng % n as u64) as usize
        };
        // created groups: owner, whether they name Alice's host
        let mut owner: std::collections::BTreeMap<Tid, Tid> = Default::default();
        let mut names: BTreeSet<Tid> = BTreeSet::new();
        // direct admin edges given to Bob's person (by Alice)
        let mut bob_admin: BTreeSet<Tid> = BTreeSet::new();
        let mut granted: BTreeSet<(Tid, Tid)> = BTreeSet::new();
        let chain = |owner: &std::collections::BTreeMap<Tid, Tid>, g: Tid| std::iter::successors(Some(g), |t| owner.get(t).copied()).collect::<Vec<_>>();
        let mut ops = Vec::new();
        for _ in 0..10 {
            let groups: Vec<Tid> = owner.keys().copied().collect();
            let op = [0, 0, 1, 1, 2, 2, 2, 4][next(8)];
            let hosts = if next(2) == 0 { &plain } else { &named };
            match op {
                // Alice creates under her person or one of her own groups
                0 => {
                    let mine: Vec<Tid> = std::iter::once(alice.me()).chain(groups.iter().copied().filter(|g| chain(&owner, *g).contains(&alice.me()))).collect();
                    let o = mine[next(mine.len())];
                    let g = group_of(&alice, o, if o == alice.me() { alice.home() } else { o }, hosts);
                    owner.insert(g, o);
                    if hosts.len() > 1 {
                        names.insert(g);
                    }
                    ops.push(format!("alice creates {g:?} under {o:?} named {}", hosts.len() > 1));
                }
                // Bob creates under his person or a group he admins
                1 => {
                    let his: Vec<Tid> = std::iter::once(bob.me()).chain(groups.iter().copied().filter(|g| chain(&owner, *g).iter().any(|x| *x == bob.me() || bob_admin.contains(x)))).collect();
                    let o = his[next(his.len())];
                    if bob.role_on(o) != Some(Role::Admin) {
                        continue;
                    }
                    let g = group_of(&bob, o, if o == bob.me() { bob.home() } else { o }, hosts);
                    owner.insert(g, o);
                    if hosts.len() > 1 {
                        names.insert(g);
                    }
                    ops.push(format!("bob creates {g:?} under {o:?} named {}", hosts.len() > 1));
                }
                // Bob grants Alice's person read or admin, or her node admin, on a group he admins
                2 => {
                    let his: Vec<Tid> = groups.iter().copied().filter(|g| bob.role_on(*g) == Some(Role::Admin)).collect();
                    if his.is_empty() {
                        continue;
                    }
                    let g = his[next(his.len())];
                    let (who, role) = match next(3) {
                        0 => (a, Role::Read),
                        1 => (a, Role::Admin),
                        _ => (alice.node(), Role::Admin),
                    };
                    // one edge per holder: a change down would be a demotion
                    if !granted.insert((g, who)) {
                        continue;
                    }
                    bob.grant(g, who, role, Default::default()).unwrap();
                    ops.push(format!("bob grants {who:?} {role:?} on {g:?}"));
                }
                // Alice grants Bob's person admin on one of her groups
                _ => {
                    let mine: Vec<Tid> = groups.iter().copied().filter(|g| chain(&owner, *g).contains(&alice.me())).collect();
                    if mine.is_empty() {
                        continue;
                    }
                    let g = mine[next(mine.len())];
                    if !bob_admin.insert(g) {
                        continue;
                    }
                    alice.grant(g, b, Role::Admin, Default::default()).unwrap();
                    ops.push(format!("alice grants bob admin on {g:?}"));
                }
            }
            w.run();
        }
        let got = admitted(&alice);
        let reads: Vec<(Tid, LabelId)> = alice.sync_engine(|s| s.labels().into_iter().map(|(g, l)| (g, l.id)).collect());
        let want: BTreeSet<LabelId> = reads.iter().filter(|(g, _)| names.contains(g) && chain(&owner, *g).contains(&alice.me())).map(|(_, l)| *l).collect();
        assert_eq!(got, want, "seed {seed}: ops {ops:#?}");
    }
}

/// Waits (up to 30 s) for `f` to hold.
fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !f() {
        assert!(std::time::Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// The labels in the host store at `dir` (the database closed).
fn host_store_labels(dir: &std::path::Path) -> Vec<LabelId> {
    let b = osis_store::RedbBackend::open(&dir.join("host.redb")).unwrap();
    let r = osis_store::FileRoot::new(dir.join("host.root"));
    let s = osis_store::Store::open(Box::new(b), Box::new(r), osis_store::StoreConfig::default()).unwrap();
    let clock: std::sync::Arc<dyn osis::Clock> = std::sync::Arc::new(osis_base::SystemClock);
    let h = osis_host::HostStore::open(s, clock, osis_host::HostPolicy::default(), Box::new(osis_crypto::OsRng)).unwrap();
    h.labels_after(None, 1000).unwrap()
}

// spec/data-model.md §9 (`host.0^` absent: it does not host; stopping erases the host store),
// spec/requirements.md Deletion: stopping hosting erases the host store (`host.redb`,
// `host.root`) once the host closes it, on a running driver or at the next driver start when
// it stopped while none ran; a start under a new host key after a stop no driver carried out
// serves nothing of the old store.
#[test]
fn stop_hosting_erases_host_store_spec_data_model_9() {
    let dir = std::env::temp_dir().join(format!("osis-host-erase-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let net = osis_transport::Net::new(41);
    // the app's runtime: `close` returns once the driver, and with it the host, ended
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let at = |i: u64, run: bool| {
        let mut c = osis::Config::at(osis::StoreAt::Dir(dir.clone()));
        c.seed = Some(i);
        c.peers = false;
        if run {
            c.runtime = osis::Runtime::Tokio(rt.handle().clone());
            c.transport = Some(osis::Transport::InProcess(net.endpoint(&format!("e{i}"))));
        }
        c
    };
    let files = || dir.join("host.redb").exists() || dir.join("host.root").exists();
    let hosting = || Some(Hosting { listen: vec!["mem://e".into()], admit: Admit::Open, ..Default::default() });
    let listening = |db: &Osis| wait_for("listening", || db.host_address().unwrap().is_some());

    // hosting, with the home label registered there
    let db = Osis::create(at(1, true)).unwrap().0;
    db.set_hosting(hosting()).unwrap();
    listening(&db);
    db.add_host(&db.host_address().unwrap().unwrap()).unwrap();
    common::block_on(db.wait_synced(osis::SyncScope::All, std::time::Duration::from_secs(30))).unwrap();
    let home = home_label(&db);
    db.close().unwrap();
    assert_eq!(host_store_labels(&dir), vec![home]);

    // stopped and started again with no driver running: the new key's host starts empty
    let db = Osis::open(at(2, false)).unwrap();
    let old = db.host_key();
    db.set_hosting(None).unwrap();
    db.set_hosting(hosting()).unwrap();
    assert_ne!(db.host_key(), old);
    db.close().unwrap();
    let db = Osis::open(at(3, true)).unwrap();
    listening(&db);
    db.close().unwrap();
    assert_eq!(host_store_labels(&dir), Vec::new());

    // stopped on a running driver: the files go
    let db = Osis::open(at(4, true)).unwrap();
    listening(&db);
    assert!(files());
    db.set_hosting(None).unwrap();
    wait_for("the host store erased", || !files());
    db.close().unwrap();

    // stopped with no driver running: the next driver start erases
    let db = Osis::open(at(5, true)).unwrap();
    db.set_hosting(hosting()).unwrap();
    listening(&db);
    db.close().unwrap();
    assert!(files());
    let db = Osis::open(at(6, false)).unwrap();
    db.set_hosting(None).unwrap();
    db.close().unwrap();
    assert!(files());
    let db = Osis::open(at(7, true)).unwrap();
    wait_for("the host store erased", || !files());
    db.close().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
