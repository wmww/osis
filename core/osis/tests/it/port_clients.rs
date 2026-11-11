//! Thin clients on the client port (notes/client-port.md §3): a node serves a bearer secret its
//! `clients^.0` lists over a keyed listener (here the in-process transport), acting as the client's
//! actor for every row. The rights of that actor are the whole authorization.

use osis::internals::CommitRaw as _;
use crate::common::watched;
use crate::common::MembersOf as _;
use crate::common::TestWrites as _;
use crate::common::{T0, ak, block_on, kept, page, typed_any};
use crate::port::{Raw, set_write};
use osis::internals::Internals as _;
use osis::{SetRoleOpts, ClientSecret, CommitQuery, Error, Address, LinkOpts, MemStore, Osis, Role, Runtime, Scope, Store, Tid, Value, Time};
use osis::internals::{ManualClock};
use osis_proto::{Command, Outcome};
use osis_schema::core_types as ct;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::channel;
use std::time::Duration;

const WRITE: u64 = 10;
const GET: u64 = 1;
const SETTLE: u64 = 19;

static NAMES: AtomicUsize = AtomicUsize::new(0);

/// A node with a runtime on the in-process transport, on a manual clock; things it serves.
struct Node {
    n: Osis,
    net: osis_transport::Net,
    clock: Arc<ManualClock>,
    store: MemStore,
    /// A group under the account, a thing under the group, a thing under the account as a member
    /// of it, one only under the account, another group with a thing of its own.
    g: Tid,
    t: Tid,
    member: Tid,
    out: Tid,
    h: Tid,
    u: Tid,
}

fn open(store: &MemStore, net: &osis_transport::Net, clock: &Arc<ManualClock>, create: bool) -> Osis {
    let mut c = osis::internals::Opening::at(Store::Memory(store.clone()));
    c.runtime = Runtime::Own;
    c.app.internals.transport = Some(net.endpoint("n"));
    c.app.internals.clock = Some(clock.clone());
    let n = if create { osis::internals::create(c).unwrap() } else { osis::internals::open(c).unwrap() };
    // the keyed listener is up once reach.0 is published
    for _ in 0..2000 {
        if n.sync_engine(|s| s.own_reach()).is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    n
}

/// `db`, an admin of `t`, writes `t`'s setting keeping `k`'s replaced writes for good.
fn keep_forever(db: &Osis, t: Tid, k: &osis_base::Ak) {
    keep_all_forever(db, t, &[k]);
}

/// `t`'s setting keeping each of `ks` for good.
fn keep_all_forever(db: &Osis, t: Tid, ks: &[&osis_base::Ak]) {
    let keep = osis::core::RetentionEntry { history: Some(osis::History::FOREVER), ..Default::default() };
    db.commit_with(|w| w.at(t, osis::core::RETENTION).set(&osis::core::RetentionSetting { rules: ks.iter().map(|k| ((*k).clone(), keep)).collect(), ..Default::default() })).unwrap();
}

fn node() -> Node {
    let (net, clock, store) = (osis_transport::Net::new(1), Arc::new(ManualClock::new(Time(T0))), MemStore::new());
    let n = open(&store, &net, &clock, true);
    let (g, t, member, out, h, u) = n
        .commit_with(|w| {
            let g = w.create()?;
            let t = w.create_with_admin(g)?;
            w.group(g).add(osis::Member::Item(t))?;
            let member = w.create()?;
            w.group(g).add(osis::Member::Item(member))?;
            let out = w.create()?;
            let h = w.create()?;
            let u = w.create_with_admin(h)?;
            for x in [g, t, member, out, h, u] {
                crate::common::keep_all(w, x);
            }
            Ok((g, t, member, out, h, u))
        })
        .unwrap();
    for x in [t, member, out, u] {
        n.commit_set(x, osis::DynamicAspectKey::untyped(ak("t:name.0")), &Value::Str("x".into())).unwrap();
    }
    Node { n, net, clock, store, g, t, member, out, h, u }
}

impl Node {
    fn addr(&self) -> Address {
        Address::new(&"mem://n-peer".parse().unwrap(), self.key())
    }

    fn key(&self) -> [u8; 32] {
        let secret = self.n.sync_engine(|s| s.dialable_secret());
        osis_transport::InProcess::public_key(&osis_transport::StaticSecret::from_bytes(*secret.expose()))
    }

    fn connect(&self, secret: &ClientSecret) -> osis::Result<Osis> {
        let mut c = osis::internals::Opening::memory();
        c.app.internals.transport = Some(self.net.endpoint(&format!("c{}", NAMES.fetch_add(1, Ordering::Relaxed))));
        // a reopened node: its reach is stored, its listener comes up a moment later
        for _ in 0..2000 {
            match crate::common::block_on(osis::internals::connect(&self.addr(), secret, c.clone())) {
                Err(Error::Network(m)) if m.contains("unreachable") => std::thread::sleep(Duration::from_millis(10)),
                r => return r,
            }
        }
        panic!("the node's listener did not come up");
    }

    /// A client with `role` on the group.
    fn client(&self, role: Role) -> (Tid, ClientSecret, Osis) {
        let (a, s) = self.n.add_client(None).unwrap();
        self.n.grant(self.g, a, role, Default::default()).unwrap();
        let c = self.connect(&s).unwrap();
        (a, s, c)
    }

    fn raw(&self, secret: &ClientSecret) -> Raw {
        let ep = self.net.endpoint(&format!("r{}", NAMES.fetch_add(1, Ordering::Relaxed)));
        let mut r = Raw::over(&ep, osis_transport::Address { url: "mem://n-peer".into(), key: self.key() });
        let a = r.ask(Command::Auth { token: 0, session: [1; 16], secret: Some(osis_crypto::Secret32::from_bytes(*secret.expose())) }, 0);
        assert!(matches!(a, Ok(Outcome::Ok { .. })), "{a:?}");
        r
    }

    /// Served sessions now.
    fn served(&self) -> usize {
        self.n.sync_engine(|s| s.served_opened().len())
    }

    /// Waits until `f` holds (the port worker and the driver run off this thread).
    fn until(&self, f: impl Fn(&Node) -> bool) {
        for _ in 0..2000 {
            if f(self) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("condition not reached");
    }
}

/// Everything a client can ask about a tid, errors with the tid taken out: a thing its actor may
/// not read must answer this exactly as a tid nobody knows.
pub(crate) fn answers(c: &Osis, t: Tid) -> String {
    let k = ak("t:name.0");
    let e = |r: osis::Result<String>| r.unwrap_or_else(|e| format!("{e:?}").replace(&format!("{t:?}"), "T"));
    let mut out = vec![
        e(c.at(t, osis::DynamicAspectKey::untyped(k.clone())).get().map(|v| format!("{v:?}"))),
        e(c.aspects(t).map(|v| format!("{v:?}"))),
        format!("{:?}", c.has_content(t).unwrap()),
        format!("{:?}", c.groups_of(t).unwrap()),
        format!("{:?}", c.grants(t).unwrap()),
        format!("{:?}", c.role_on(t).unwrap()),
        format!("{:?}", c.created(t).unwrap()),
        format!("{:?}", c.changed(t).unwrap()),
        e(c.writes(&Scope::Thing(t), &CommitQuery::default()).map(|v| format!("{v:?}"))),
        e(c.at(t, osis::DynamicAspectKey::untyped(k.clone())).writes(&CommitQuery::default()).map(|v| format!("{v:?}"))),
        e(c.at(t, osis::DynamicAspectKey::untyped(k.clone())).path(osis::p![]).stream().map(|s| format!("{:?}", s.map(|x| x.len())))),
        e(c.commit_set(t, osis::DynamicAspectKey::untyped(k.clone()), &Value::Int(1)).map(|_| "written".to_string())),
        e(c.commit_with(|w| w.delete(t)).map(|_| "written".to_string())),
        e(c.undo(&Scope::Thing(t)).map(|v| format!("{v:?}"))),
        e(c.undo_target(&Scope::Thing(t)).map(|v| format!("{v:?}"))),
        e(c.holders(t).map(|v| format!("{v:?}"))),
        e(c.leave(c.me(), t).map(|()| "left".to_string())),
        e(c.leave(t, t).map(|()| "left".to_string())),
    ];
    let w = watched(c, t, osis::DynamicAspectKey::untyped(k)).unwrap();
    out.push(format!("{:?}", w.current()));
    out.join("\n")
}

// spec/wire.md §11.2, notes/client-port.md §3: a client granted Read on a group reads what is under the group; the account, its node, a link's K and seed, another group and its thing, a member of the group made under another account all answer every read and write exactly as a tid nobody knows; no row runs as the node's account
#[test]
fn reads_are_exactly_the_actors() {
    let x = node();
    let (a, _, c) = x.client(Role::Read);
    assert_eq!(c.me(), a);
    assert_eq!(c.at(x.t, osis::DynamicAspectKey::untyped(ak("t:name.0"))).get().unwrap(), Some(Value::Str("x".into())));
    assert_eq!(c.role_on(x.t).unwrap(), Some(Role::Read));
    assert_eq!(c.role_on(x.g).unwrap(), Some(Role::Read));
    assert!(c.has_content(x.t).unwrap());
    assert_eq!(c.groups_of(x.t).unwrap(), x.n.groups_of(x.t).unwrap());
    assert_eq!(c.grants(x.t).unwrap().get(&x.g).map(|e| e.role), Some(Role::Admin), "its first admin");
    assert_eq!(c.writes(&Scope::Thing(x.t), &CommitQuery::default()).unwrap(), x.n.acting_as(a).writes(&Scope::Thing(x.t), &CommitQuery::default()).unwrap(), "as the node reads for its actor");
    // a group listing it shows only groups it reads
    let mut w = x.n.write();
    w.group(x.h).add(osis::Member::Item(x.t)).unwrap();
    w.commit().unwrap();
    assert!(c.groups_of(x.t).unwrap().item_of.contains(&x.g) && !c.groups_of(x.t).unwrap().item_of.contains(&x.h));
    assert!(x.n.groups_of(x.t).unwrap().item_of.contains(&x.h));
    // what it may not read: the account, its node, a link, another group
    let link_target = x.u;
    let _link = x.n.make_link(link_target, Role::Read, LinkOpts { until: None, single_use: false, direct: true }).unwrap();
    let k = x.n.links_of(link_target).unwrap()[0].id.actor();
    let home = x.n.at(x.n.home(), ct::GROUP).get().unwrap().unwrap();
    let seed = home.items.iter().copied().find(|i| x.n.aspects(*i).unwrap().iter().any(|a| a.as_str() == "link:seed.0")).unwrap();
    let ghost = Tid::from_bytes([9; 15]);
    let g_answers = answers(&c, ghost);
    let d = |t: Tid| answers(&c, t).replace(&format!("{t:?}"), "T");
    let gd = g_answers.replace(&format!("{ghost:?}"), "T");
    assert!(gd.contains("UnknownThing"), "{gd}");
    for (name, t) in [("account", x.n.me()), ("node", x.n.node()), ("k", k), ("seed", seed), ("other group", x.h), ("its thing", x.u), ("member only", x.member), ("made elsewhere", x.out)] {
        assert_eq!(d(t), gd, "{name}");
    }
    // nothing of it changed through those attempts
    assert_eq!(x.n.at(x.out, osis::DynamicAspectKey::untyped(ak("t:name.0"))).get().unwrap(), Some(Value::Str("x".into())));
    assert!(x.n.has_content(x.out).unwrap());
    // status lists no group it may not read
    x.n.sync(x.h, &[]).unwrap();
    assert!(x.n.status().unwrap().groups.contains_key(&x.h));
    assert!(!c.status().unwrap().groups.contains_key(&x.h));
}

// spec/wire.md §11.2, notes/client-port.md §3 (Acting as the actor): a write needs the actor's rights, however wide the node's: Permission on what it only reads, its commits carry its actor and this node as author; created things need a writable first admin, its own actor refused; a commit naming another actor is refused; adding what it may not read to a group fails as unknown; a purge needs admin
#[test]
fn writes_are_the_actors() {
    let x = node();
    let name = ak("t:name.0");
    let (a, s, c) = x.client(Role::Read);
    assert!(matches!(c.commit_set(x.t, osis::DynamicAspectKey::untyped(name.clone()), &Value::Int(1)), Err(Error::Permission { tid, .. }) if tid == x.t));
    assert!(matches!(c.commit_with(|w| w.create_with_admin(x.g)), Err(Error::Permission { .. })), "read on the first admin is no write");
    x.n.grant(x.g, a, Role::Write, Default::default()).unwrap();
    // one it may purge (below)
    c.commit_with(|w| w.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).retention(osis::Retention { by: osis::PurgeBy::AuthorOrAdmin }).set(&Value::Int(2))).unwrap();
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).get().unwrap(), Some(Value::Int(2)));
    let last = &crate::common::listed(&x.n, Scope::Thing(x.t))[0];
    assert_eq!(last.stamp.actor, a);
    // created things
    let made = c.commit_with(|w| {
        let m = w.create_with_admin(x.g)?;
        w.at(m, osis::DynamicAspectKey::untyped(name.clone())).set(&Value::Int(3))?;
        Ok(m)
    });
    let made = made.unwrap();
    assert_eq!(x.n.grants(made).unwrap().get(&x.g).map(|e| e.role), Some(Role::Admin), "its first admin");
    assert_eq!(c.at(made, osis::DynamicAspectKey::untyped(name.clone())).get().unwrap(), Some(Value::Int(3)));
    assert!(matches!(c.commit_with(|w| w.create_with_admin(a)), Err(Error::Invalid(_))), "its own actor as first admin");
    assert!(matches!(c.commit_with(|w| w.create_with_admin(x.n.me())), Err(Error::Permission { .. })), "the account as first admin");
    assert!(matches!(c.commit_with(|w| w.create()), Err(Error::Invalid(_))), "the acting actor: its own");
    // a commit naming another actor: a raw session (the API records its own)
    let mut r = x.raw(&s);
    let forged = r.call_at(1, WRITE, set_write(1, x.n.me(), x.t, &name, Value::Int(4)));
    assert!(matches!(forged, Outcome::Err { .. }), "{forged:?}");
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).get().unwrap(), Some(Value::Int(2)));
   // adding what it may not read
    assert!(matches!(c.commit_with(|w| w.group(x.g).add(osis::Member::Item(x.out))), Err(Error::UnknownThing { .. })));
    assert!(matches!(c.commit_with(|w| w.group(x.h).add(osis::Member::Item(x.t))), Err(Error::UnknownThing { .. })), "a group it does not read");
    // a purge needs write, whatever the node may do: read was refused above; with write it names
    // what the actor has no right to: its reset stands, the body stays (see the test below)
    c.commit_with(|w| w.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).purge(osis::Purge::All)).unwrap();
    x.n.grant(x.g, a, Role::Admin, Default::default()).unwrap();
    // an aspect of the node needs the actor's rights too
    let node_thing = x.n.node();
    assert!(matches!(c.commit_with(|w| w.at(node_thing, ct::CLIENTS).remove()), Err(Error::UnknownThing { .. })));
}

// spec/commits.md §5, §6, notes/client-port.md §2: a client's write that cannot be one commit is
// refused at the node before anything applies, the node's message naming what clashed, by the API
// and by a raw commit alike; its expiry is the commit's; written apart each comes back with its id.
#[test]
fn a_clashing_write_is_refused_through_the_port_spec_commits_6() {
    let x = node();
    let (name, brief, hot) = (ak("t:name.0"), ak("t:brief.0"), ak("t:hot+.0"));
    let (a, _s, c) = x.client(Role::Read);
    x.n.grant(x.g, a, Role::Write, Default::default()).unwrap();
    let n = x.n.engine(|e| e.commit_ids().len());
    let hour = osis::Expiry::In(Duration::from_secs(3600));
    // a key's default beside a plain write
    x.n.register_schema("t.osis", "revision 1;\nexpires(1h) aspect t:soon.0: int;").unwrap();
    let mut w = c.write();
    w.at(x.t, osis::DynamicAspectKey::untyped(ak("t:soon.0"))).set(&Value::Int(2)).unwrap();
    w.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).set(&Value::Int(1)).unwrap();
    let r = w.commit();
    assert!(matches!(&r, Err(Error::Invalid(m)) if m.contains("t:soon.0") && m.contains("t:name.0")), "{r:?}");
    // durable and ephemeral
    let mut w = c.write();
    w.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).set(&Value::Int(1)).unwrap();
    w.at(x.t, osis::DynamicAspectKey::untyped(hot.clone())).set(&Value::Int(1)).unwrap();
    let r = w.commit();
    assert!(matches!(&r, Err(Error::Invalid(m)) if m.contains("t:hot+.0") && m.contains("t:name.0")), "{r:?}");
    assert_eq!(x.n.engine(|e| e.commit_ids().len()), n, "nothing applied");
    // a removal in a commit that expires
    let mut w = c.write();
    w.expires(hour);
    w.group(x.g).remove(osis::Member::Item(x.t)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Invalid(_))));
    // apart: one commit each, the expiry the commit's
    let mut w = c.write();
    w.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).set(&Value::Int(1)).unwrap();
    let first = w.commit().unwrap().unwrap().stamp.id.raw();
    let mut w = c.write();
    w.expires(hour);
    w.at(x.t, osis::DynamicAspectKey::untyped(brief.clone())).set(&Value::Int(2)).unwrap();
    let other = w.commit().unwrap().unwrap().stamp.id.raw();
    let h = |id| x.n.engine(|e| e.header(&id)).unwrap();
    assert_eq!(h(first).expires, None);
    assert_eq!(h(other).expires, Some(h(other).ts.wall_ms().0 + 3_600_000));
    assert_eq!(h(other).aspects.iter().map(|a| a.ak.as_str().to_string()).collect::<Vec<_>>(), vec!["t:brief.0"]);
    assert_eq!((c.at(x.t, osis::DynamicAspectKey::untyped(name)).get().unwrap(), c.at(x.t, osis::DynamicAspectKey::untyped(brief)).get().unwrap()), (Some(Value::Int(1)), Some(Value::Int(2))));
}

// spec/permissions.md §6, notes/client-port.md §3 (Acting as the actor): a purge acting for a
// client drops what its node and the client both have the right to: a write client drops no
// `admin` delta (the default) of its account, though the node alone may, and drops its own
// `author_or_admin` one; an admin client drops any
#[test]
fn client_purge_is_judged_by_the_actor_spec_perm_6() {
    let x = node();
    let name = ak("t:name.0");
    let (a, _, c) = x.client(Role::Admin);
    let (_, _, w2) = x.client(Role::Write);
    let mut w = x.n.write();
    w.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).set(&Value::Int(1)).unwrap();
    let first = w.commit().unwrap().unwrap().stamp.id.raw();
    let held = |k: &osis_base::Ak| x.n.engine(|e| e.body_not_dropped(&first, &x.t, k));
    // the writer holds no right over any held delta of the aspect (the node's, kept by the
    // thing's setting): refused, nothing dropped
    let mut w = w2.write();
    w.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).purge(osis::Purge::All).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })));
    assert!(held(&name), "the account's admin-only delta");
    // a writer's own
    let own = ak("t:own.0");
    let mut w = w2.write();
    w.at(x.t, osis::DynamicAspectKey::untyped(own.clone())).retention(osis::Retention { by: osis::PurgeBy::AuthorOrAdmin }).set(&Value::Int(2)).unwrap();
    w.commit().unwrap();
    let mut w = w2.write();
    w.at(x.t, osis::DynamicAspectKey::untyped(own.clone())).purge(osis::Purge::All).unwrap();
    w.commit().unwrap();
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(own.clone())).get().unwrap(), None);
    // an admin, any class
    let other = ak("t:other.0");
    x.n.commit_set(x.t, osis::DynamicAspectKey::untyped(other.clone()), &Value::Int(3)).unwrap();
    let mut w = c.write();
    w.at(x.t, osis::DynamicAspectKey::untyped(other.clone())).purge(osis::Purge::All).unwrap();
    w.commit().unwrap();
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(other.clone())).get().unwrap(), None);
    let mut w = c.write();
    w.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).purge(osis::Purge::All).unwrap();
    w.commit().unwrap();
    assert!(!held(&name));
    assert_eq!(c.me(), a);
}

// spec: none (API surface); notes/api.md Sync status: `connected` counts sync connections: a client's session is none.
#[test]
fn a_client_session_is_no_sync_connection() {
    let x = node();
    let before = x.n.status().unwrap().connected;
    let (_, _, c) = x.client(Role::Read);
    assert_eq!(c.at(x.t, osis::DynamicAspectKey::untyped(ak("t:none.0"))).get().unwrap(), None, "the session is up");
    x.n.settle();
    assert_eq!(x.n.status().unwrap().connected, before);
}

// spec/commits.md §5, notes/api.md Commits: a purged delta reads as a tombstone in a listing:
// author, time, the purge that dropped it. A thin client reads it as it reads other history: of what
// it may read only, and nothing of what it may not.
#[test]
fn tombstone_reads_through_the_client_port_spec_commits_5() {
    let x = node();
    let (k, both) = (ak("t:msg.0"), ak("t:both.0"));
    for t in [x.t, x.u] {
        keep_all_forever(&x.n, t, &[&k, &both]);
    }
    let (ca, _, c) = x.client(Role::Read);
    let q = |db: &Osis, t: Tid| db.writes(&Scope::Thing(t), &CommitQuery::default()).unwrap().commits;
    let mut by = None;
    for t in [x.t, x.u] {
        let mut w = x.n.write();
        w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Str("secret".into())).unwrap();
        w.commit().unwrap();
        let mut w = x.n.write();
        w.at(t, osis::DynamicAspectKey::untyped(k.clone())).purge(osis::Purge::All).unwrap();
        let rq = w.commit().unwrap().unwrap().stamp.id;
        by = by.or(Some(rq));
    }
    let purged = |c: &osis::Commit| c.parts().filter(|(_, _, p)| matches!(p.body, osis::Body::Purged { .. })).map(|(t, k, _)| (t, k.clone())).collect::<Vec<_>>();
    let entries = q(&x.n, x.t);
    let e = entries.iter().find(|e| !purged(e).is_empty()).expect("a tombstone");
    let by = by.unwrap();
    assert_eq!(purged(e), vec![(x.t, k.clone())]);
    assert_eq!(e.at(x.t, osis::DynamicAspectKey::untyped(k.clone())).unwrap().body, osis::Body::Purged { by, actor: Some(x.n.me()) });
    assert_eq!(e.stamp.actor, x.n.me());
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap(), None);
    // the same through the port, and only what the client reads
    assert_eq!(q(&c, x.t), q(&x.n.acting_as(ca), x.t));
    assert_eq!(q(&c, x.t).iter().map(|e| e.stamp.id).collect::<Vec<_>>(), entries.iter().map(|e| e.stamp.id).collect::<Vec<_>>());
    assert!(q(&x.n, x.u).iter().any(|e| !purged(e).is_empty()));
    assert!(q(&c, x.u).is_empty());
    // one commit on both things, both purged: the client reads the half it may read
    let id = x.n.commit_with(|w| {
        w.at(x.t, osis::DynamicAspectKey::untyped(both.clone())).set(&Value::Int(1))?;
        w.at(x.u, osis::DynamicAspectKey::untyped(both.clone())).set(&Value::Int(2))
    });
    id.unwrap();
    let mut w = x.n.write();
    w.at(x.t, osis::DynamicAspectKey::untyped(both.clone())).purge(osis::Purge::All).unwrap();
    w.at(x.u, osis::DynamicAspectKey::untyped(both.clone())).purge(osis::Purge::All).unwrap();
    w.commit().unwrap();
    let sc = Scope::Aspects(vec![(x.t, both.clone()), (x.u, both.clone())]);
    assert!(crate::common::listed(&x.n, sc.clone()).iter().any(|e| purged(e).len() == 2), "the node reads both");
    let seen = crate::common::listed(&c, sc);
    assert!(seen.iter().any(|e| !purged(e).is_empty()));
    assert!(seen.iter().all(|e| e.parts().all(|(t, _, _)| t == x.t)), "a thin client sees only the parts it may read: {seen:?}");
    // at the thing it reads too
    let at_t = q(&c, x.t);
    assert!(at_t.iter().any(|e| purged(e).iter().any(|p| p.1 == both)));
    assert!(at_t.iter().all(|e| e.parts().all(|(t, _, _)| t != x.u)), "{at_t:?}");
}

// spec/commits.md §7, notes/client-port.md §3 (Undo/redo/revert): undo picks the actor's own commits; a revert of someone else's needs the actor's write on all it touches; a revert of what it may not read is unknown
#[test]
fn undo_and_revert_are_the_actors() {
    let x = node();
    let (a, b) = (ak("t:a.0"), ak("t:b.0"));
    let (ca, _, c) = x.client(Role::Write);
    typed_any(&x.n, &["t:a.0", "t:b.0"]);
    x.n.commit_set(x.t, kept(&x.n, &a.clone()), &Value::Int(1)).unwrap();
    c.commit_set(x.t, kept(&x.n, &b.clone()), &Value::Int(2)).unwrap();
    x.n.commit_set(x.t, kept(&x.n, &a.clone()), &Value::Int(3)).unwrap();
    // only its own: the node's newer write stays
    assert!(c.undo(&Scope::Thing(x.t)).unwrap().is_some());
    assert_eq!(x.n.at(x.t, kept(&x.n, &a.clone())).get().unwrap(), Some(Value::Int(3)));
    assert_eq!(x.n.at(x.t, kept(&x.n, &b.clone())).get().unwrap(), None);
    c.redo(&Scope::Thing(x.t)).unwrap().unwrap();
    assert_eq!(x.n.at(x.t, kept(&x.n, &b.clone())).get().unwrap(), Some(Value::Int(2)));
    assert!(c.undo(&Scope::Thing(x.t)).unwrap().is_some());
    assert!(c.undo(&Scope::Thing(x.t)).unwrap().is_none(), "nothing of its own is left");
    let q = |t: Tid| crate::common::listed(&x.n, Scope::Thing(t));
    // someone else's on what it writes
    let id = q(x.t).iter().find(|e| e.stamp.actor != ca && e.parts().any(|(_, k, _)| *k == a)).unwrap().stamp.id;
    c.revert(id).unwrap();
    // what it may not read
    let hidden = q(x.u)[0].stamp.id;
    assert!(matches!(c.revert(hidden), Err(Error::Invalid(m)) if m.contains("unknown commit")));
    // Read only: a revert it may not write
    x.n.commit_set(x.t, kept(&x.n, &a.clone()), &Value::Int(5)).unwrap();
    let mine = q(x.t)[0].stamp.id;
    x.n.set_role(x.g, ca, Some(Role::Read), SetRoleOpts { retain_copy: None }).unwrap();
    assert!(matches!(c.revert(mine), Err(Error::Permission { .. })));
    assert_eq!(x.n.at(x.t, kept(&x.n, &a)).get().unwrap(), Some(Value::Int(5)));
}

// spec/sync.md §10, notes/client-port.md §3 (until, Checked at execution): an expired client: a request after the clock passed its until is refused at execution before any tick closed it; the driver then closes the connection with no other change; a later Auth is refused; `until` at or before now is refused; a restart keeps the entry and the rule
#[test]
fn until_ends_the_client() {
    let x = node();
    let name = ak("t:name.0");
    assert!(matches!(x.n.add_client(Some(Time(T0))), Err(Error::Invalid(_))));
    assert!(matches!(x.n.add_client(Some(Time(T0 - 1))), Err(Error::Invalid(_))));
    let (a, s) = x.n.add_client(Some(Time(T0 + 60_000))).unwrap();
    x.n.grant(x.g, a, Role::Write, Default::default()).unwrap();
    assert_eq!(x.n.clients().unwrap(), vec![osis::Client { actor: a, until: Some(Time(T0 + 60_000)) }]);
    let mut r = x.raw(&s);
    assert!(matches!(r.call_at(1, GET, vec![Value::Tid(x.t), Value::Str("t:name.0".into()), Value::List(vec![])]), Outcome::Ok { .. }));
    let c = x.connect(&s).unwrap();
    c.commit_set(x.t, osis::DynamicAspectKey::untyped(name.clone()), &Value::Int(1)).unwrap();
    x.clock.advance(60_000);
    // whatever the driver did by now, the row does not run
    assert!(c.commit_set(x.t, osis::DynamicAspectKey::untyped(name.clone()), &Value::Int(2)).is_err());
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).get().unwrap(), Some(Value::Int(1)));
    // the driver's wake for its until (asked for: osis-node `bound_sessions_end_with_their_entry`)
    x.n.feed(osis_node::sync::Event::Tick);
    x.until(|x| x.served() == 0);
    assert!(matches!(x.connect(&s), Err(Error::Refused(_))));
    // the entry stays until removed, its actor with its grants
    assert!(x.n.clients().unwrap().iter().any(|e| e.actor == a));
    assert!(x.n.grants(x.g).unwrap().contains_key(&a));
    drop((c, r));
}

// spec/data-model.md §9, notes/client-port.md §3 (until), restart with a timer pending: sessions do not survive a restart and no timer is stored: a reopened node takes a client's Auth before its until and ends it at its until from the entry alone
#[test]
fn restart_with_a_client_until_pending() {
    let (net, clock, store) = (osis_transport::Net::new(1), Arc::new(ManualClock::new(Time(T0))), MemStore::new());
    let n = open(&store, &net, &clock, true);
    let (a, s) = n.add_client(Some(Time(T0 + 60_000))).unwrap();
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
    let n = open(&store, &net, &clock, false);
    let x = Node { n, net, clock, store, g: a, t: a, member: a, out: a, h: a, u: a };
    let c = x.connect(&s).unwrap();
    assert_eq!(c.me(), a);
    assert_eq!(x.served(), 1);
    x.clock.advance(60_000);
    x.n.feed(osis_node::sync::Event::Tick);
    x.until(|x| x.served() == 0);
    assert!(matches!(x.connect(&s), Err(Error::Refused(_))));
    // a restart past it: refused from the entry alone
    let Node { n, net, clock, store, .. } = x;
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
    let n = open(&store, &net, &clock, false);
    let x = Node { n, net, clock, store, g: a, t: a, member: a, out: a, h: a, u: a };
    assert!(matches!(x.connect(&s), Err(Error::Refused(_))));
}

// spec/permissions.md §3, notes/client-port.md §3 (remove_client): removal closes its connections, removes its actor's roles everywhere with the normal rotation, and removes the entry; the next Auth fails; a second call says none; a stale session never comes back; a role removal made elsewhere (the node's own API) leaves an entry whose actor reads nothing
#[test]
fn remove_client_revokes() {
    let x = node();
    let (a, s, c) = x.client(Role::Write);
    x.n.grant(x.h, a, Role::Read, Default::default()).unwrap();
    assert!(c.has_content(x.u).unwrap());
    let keys_before = x.n.engine(|e| e.epochs(&x.g).map(|ep| format!("{:?}", ep.role(Role::Read).newest_held().map(|h| h.0))));
    assert_eq!(x.served(), 1);
    assert!(x.n.remove_client(a).unwrap());
    x.until(|x| x.served() == 0);
    assert!(!x.n.grants(x.g).unwrap().contains_key(&a) && !x.n.grants(x.h).unwrap().contains_key(&a));
    assert_ne!(x.n.engine(|e| e.epochs(&x.g).map(|ep| format!("{:?}", ep.role(Role::Read).newest_held().map(|h| h.0)))), keys_before, "the removal rotated");
    assert!(x.n.clients().unwrap().is_empty());
    assert!(matches!(x.connect(&s), Err(Error::Refused(_))));
    assert!(c.at(x.t, osis::DynamicAspectKey::untyped(ak("t:name.0"))).get().is_err());
    // the session is over for good, and a listener on it would never hear anything: it says so
    x.until(|_| matches!(c.at(x.t, osis::DynamicAspectKey::untyped(ak("t:name.0"))).get(), Err(Error::Refused(_))));
    assert!(matches!(c.on_diagnostic(|_, _| {}), Err(Error::Refused(_))));
    // the entry's removal writes back what `clients^.0` keeps no history of: not undone; a half
    // removal revives under no clock (half_removed_client_stays_ended)
    let node_thing = x.n.node();
    let last = crate::common::listed(&x.n, Scope::Aspects(vec![(node_thing, ak("clients^.0"))]))[0].stamp.id;
    assert_eq!(x.n.revert(last), Err(Error::NotUndoable { commit: last, reason: osis::NotUndoableReason::ContentGone }));
    assert!(matches!(x.connect(&s), Err(Error::Refused(_))));
    assert!(!x.n.remove_client(a).unwrap());
    assert!(!x.n.remove_client(x.n.me()).unwrap(), "only a registered client: never a role removal of something else");
    assert!(x.n.grants(x.n.home()).unwrap().contains_key(&x.n.node()));
    // its until passed already (a removal cut short ends there): the removal still removes its roles
    let (late, s2) = x.n.add_client(Some(Time(T0 + 1))).unwrap();
    x.n.grant(x.g, late, Role::Read, Default::default()).unwrap();
    x.clock.advance(1);
    assert!(matches!(x.connect(&s2), Err(Error::Refused(_))));
    assert!(x.n.remove_client(late).unwrap());
    assert!(!x.n.grants(x.g).unwrap().contains_key(&late));
    // its roles removed elsewhere: the entry stays, its actor reads nothing
    let (b, _, d) = x.client(Role::Read);
    assert!(d.has_content(x.t).unwrap());
    x.n.set_role(x.g, b, None, SetRoleOpts { retain_copy: None }).unwrap();
    assert!(!d.has_content(x.t).unwrap());
    assert!(x.n.clients().unwrap().iter().any(|e| e.actor == b));
}

// spec/wire.md §11.2 (checked at the time it runs), notes/client-port.md §3: a write already queued when the client's entry goes does not run: the worker asks at execution, not at enqueue (the worker is held on a settle behind a callback of the node's while the entry goes; the grant is still there, so only that check stops it)
#[test]
fn queued_request_rechecked_at_execution() {
    let x = node();
    let name = ak("t:name.0");
    let (a, s, _c) = x.client(Role::Write);
    let mut r = x.raw(&s);
    // the node's dispatcher blocks on this callback, the worker on its settle behind it
    let (hold_tx, hold_rx) = channel::<()>();
    let (in_tx, in_rx) = channel::<()>();
    let _w = x.n.at(x.t, osis::DynamicAspectKey::untyped(ak("t:hold.0"))).on_change(move |_, _: osis::Change<Value>| {
        let _ = in_tx.send(());
        let _ = hold_rx.recv();
    });
    in_rx.recv_timeout(Duration::from_secs(20)).unwrap();
    r.send(Command::Call { token: 1, max_reply: osis_proto::client::SMALL_REPLY as u64, method: SETTLE, args: vec![] });
    r.pump(100);
    // queued behind the settle
    r.send(Command::Call { token: 2, max_reply: osis_proto::client::SMALL_REPLY as u64, method: WRITE, args: set_write(1, a, x.t, &name, Value::Int(7)) });
    // both requests are at the worker (the sync engine answered nothing yet); revoke the entry alone
    r.pump(200);
    let node = x.n.node();
    let mut w = x.n.write();
    w.at(node, ct::CLIENTS).path(osis::p![a]).remove().unwrap();
    w.commit().unwrap();
    hold_tx.send(()).unwrap();
    x.until(|x| x.served() == 0);
    // the worker's queue drained: a settle of a live session of another client goes behind it
    let (_, _, d) = x.client(Role::Read);
    d.settle();
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(name)).get().unwrap(), Some(Value::Str("x".into())), "the queued write did not run");
    assert_eq!(x.n.grants(x.g).unwrap().get(&a).map(|e| e.role), Some(Role::Write), "the grant alone would have let it");
}

// spec/data-model.md §9 (`secret_hash`), notes/client-port.md §3: the secret's hash is what is kept, the secret never is; rotation invalidates the old secret and its live connections, keeps the actor and its grants; an unknown secret is refused
#[test]
fn secret_hash_and_rotation() {
    let x = node();
    let (a, s, c) = x.client(Role::Read);
    let e = x.n.at(x.n.node(), ct::CLIENTS).get().unwrap().unwrap().remove(&a).unwrap();
    assert_eq!(e.secret_hash, osis_base::hash::hash(s.expose()));
    assert_ne!(&e.secret_hash, s.expose());
    assert_eq!(format!("{s:?}").matches("Secret32(..)").count(), 1, "redacted");
    let auth = osis_proto::Message::Auth { id: 1, secret: Some(osis_crypto::Secret32::from_bytes(*s.expose())), session: [0; 16] };
    assert!(!format!("{auth:?}").contains(&format!("{:?}", s.expose()[0..4].to_vec())));
    assert!(matches!(x.connect(&ClientSecret::from_bytes([1; 32])), Err(Error::Refused(_))));
    assert!(matches!(x.n.rotate_client_secret(x.n.me()), Err(Error::Invalid(_))));
    let s2 = x.n.rotate_client_secret(a).unwrap();
    assert_ne!(s2.expose(), s.expose());
    x.until(|x| x.served() == 0);
    assert!(c.at(x.t, osis::DynamicAspectKey::untyped(ak("t:name.0"))).get().is_err());
    assert!(matches!(x.connect(&s), Err(Error::Refused(_))));
    let c2 = x.connect(&s2).unwrap();
    assert_eq!(c2.me(), a);
    assert!(c2.has_content(x.t).unwrap(), "actor and grants kept");
}

// spec/wire.md §11.2, notes/client-port.md §2 (Writes): a client's nonce outcomes are its own: another client's same session id and nonce is a new write, a repeat of its own is answered once
#[test]
fn nonces_per_client() {
    let x = node();
    let name = ak("t:name.0");
    let (a, s, _c) = x.client(Role::Write);
    let (b, s2, _d) = x.client(Role::Write);
    let mut ra = x.raw(&s);
    let mut rb = x.raw(&s2);
    assert!(matches!(ra.call_at(1, WRITE, set_write(1, a, x.t, &name, Value::Int(1))), Outcome::Ok { .. }));
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).get().unwrap(), Some(Value::Int(1)));
    assert!(matches!(rb.call_at(1, WRITE, set_write(1, b, x.t, &name, Value::Int(2))), Outcome::Ok { .. }));
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).get().unwrap(), Some(Value::Int(2)), "the same session id and nonce of another client");
    assert!(matches!(ra.call_at(2, WRITE, set_write(1, a, x.t, &name, Value::Int(3))), Outcome::Ok { .. }));
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(name)).get().unwrap(), Some(Value::Int(2)), "its own repeat ran once");
}

// spec/wire.md §11.2, notes/client-port.md §2, §3: a watch sees what its actor may read, lapses when it stops being readable; a watch of what it never could read stays as silent as one of an unknown tid; process-wide rows are Unsupported
#[test]
fn watches_and_rows() {
    let x = node();
    let name = ak("t:name.0");
    let (a, _, c) = x.client(Role::Read);
    let w = watched(&c, x.t, osis::DynamicAspectKey::untyped(name.clone())).unwrap();
    let hidden = watched(&c, x.out, osis::DynamicAspectKey::untyped(name.clone())).unwrap();
    assert_eq!(hidden.current().unwrap(), None);
    x.n.commit_set(x.t, osis::DynamicAspectKey::untyped(name.clone()), &Value::Int(1)).unwrap();
    x.n.commit_set(x.out, osis::DynamicAspectKey::untyped(name.clone()), &Value::Int(1)).unwrap();
    c.settle();
    assert_eq!(w.current().unwrap(), Some(Value::Int(1)));
    assert_eq!(hidden.current().unwrap(), None, "nothing of what it cannot read");
    // a fired ephemeral signal on what it may not read: not queued for it, not sent
    let (stx, srx) = channel();
    let sig = ak("t:sig+~0");
    let _s = c.at(x.out, osis::DynamicAspectKey::untyped(sig.clone())).on_fire(move |_, e| stx.send(e).unwrap()).unwrap();
    x.n.commit_fire(x.out, osis::DynamicAspectKey::untyped(sig.clone()), &Value::Int(9)).unwrap();
    c.settle();
    assert!(srx.try_recv().is_err(), "a signal of what it cannot read");
    // one of what it reads: heard once, as fired
    let (ltx, lrx) = channel();
    let vis = ak("t:sigv+~0");
    let _v = c.at(x.t, osis::DynamicAspectKey::untyped(vis.clone())).on_fire(move |_, e| ltx.send(e).unwrap()).unwrap();
    let mut wr = x.n.write();
    wr.at(x.t, osis::DynamicAspectKey::untyped(vis.clone())).fire(&Value::Int(3)).unwrap();
    let id = wr.commit().unwrap().unwrap().stamp.id;
    c.settle();
    match lrx.recv_timeout(Duration::from_secs(20)).unwrap() {
        osis::CommitEvent::Commit { id: i, commit: Some(e) } => assert_eq!((i, e.at(x.t, osis::DynamicAspectKey::untyped(vis.clone())).unwrap().body), (id, osis::Body::Held(Some(Value::Int(3))))),
        e => panic!("{e:?}"),
    }
    assert!(lrx.try_recv().is_err(), "once");
    // one past the connection's push budget: a signal of what it reads lapses its watch, one of what it cannot read takes no budget (a lapse would tell)
    let huge = Value::Str("s".repeat(osis::internals::PUSH_BYTES + 1));
    let live = x.n.watches();
    x.n.commit_fire(x.out, osis::DynamicAspectKey::untyped(sig.clone()), &huge).unwrap();
    c.settle();
    assert_eq!(x.n.watches(), live, "a hidden signal past the budget lapses nothing");
    assert!(srx.try_recv().is_err());
    x.n.commit_fire(x.t, osis::DynamicAspectKey::untyped(vis.clone()), &huge).unwrap();
    c.settle();
    x.until(|x| x.n.watches() == live - 1);
    c.settle();
    assert!(matches!(lrx.recv_timeout(Duration::from_secs(20)).unwrap(), osis::CommitEvent::Ended(_)), "past the budget the client hears its watch end");
    // diagnostics: those naming only what it reads
    let (dtx, drx) = channel();
    let _d = c.on_diagnostic(move |_, d| if let osis::Diagnostic::Storage { detail } = d { dtx.send(detail).unwrap() }).unwrap();
    let diag = |tids: Vec<Tid>, detail: &str| osis_node::Diagnostic { kind: osis_node::DiagnosticKind::Storage, tids, commit: None, peer: None, detail: detail.into() };
    x.n.engine(|e| {
        e.report(diag(vec![x.out], "hidden"));
        e.report(diag(vec![], "general"));
        e.report(diag(vec![x.t, x.out], "partly"));
        e.report(diag(vec![x.t], "shown"));
    });
    assert_eq!(drx.recv_timeout(Duration::from_secs(20)).unwrap(), "shown");
    assert!(drx.try_recv().is_err());
    let subs = x.n.watches();
    x.n.set_role(x.g, a, None, SetRoleOpts { retain_copy: None }).unwrap();
    x.n.commit_set(x.t, osis::DynamicAspectKey::untyped(name.clone()), &Value::Int(2)).unwrap();
    c.settle();
    assert!(!matches!(w.current(), Ok(Some(Value::Int(2)))), "{:?}", w.current());
    // the one it could read lapsed; the one it never could stays, as for an unknown tid
    assert_eq!(x.n.watches(), subs - 1, "exactly the watch of what it stopped reading");
    drop(hidden);
    // rows
    assert!(matches!(c.sync(x.g, &[]), Err(Error::Unsupported(_))));
    assert!(matches!(c.grant(x.t, a, Role::Admin, Default::default()), Err(Error::Unsupported(_))));
    assert!(matches!(c.add_client(None), Err(Error::Unsupported(_))));
    assert!(matches!(c.clients(), Err(Error::Unsupported(_))));
    assert!(matches!(c.remove_client(a), Err(Error::Unsupported(_))));
    assert!(matches!(c.rotate_client_secret(a), Err(Error::Unsupported(_))));
    assert!(matches!(c.register_schema("x.osis", "revision 1;\naspect x:y.0: int;\n"), Err(Error::Unsupported(_))));
    // the rows of the node's own (the socket's main actor only), those that wait too
    let plain = SetRoleOpts { retain_copy: None };
    let link = x.n.make_link(x.g, Role::Read, LinkOpts { direct: true, ..Default::default() }).unwrap();
    assert!(matches!(c.set_role(x.t, a, None, plain), Err(Error::Unsupported(_))));
    assert!(matches!(c.leave(x.n.me(), x.t), Err(Error::Permission { .. })), "only its own actor's role");
    assert!(matches!(c.add_with_grant(osis::Member::Item(x.t), x.g, Role::Read), Err(Error::Unsupported(_))));
    assert!(matches!(c.revoke_link(x.t.to_uri().parse().unwrap()), Err(Error::Unsupported(_))));
    // refused here: the link's secret never goes to a node that would only refuse it
    let r = block_on(c.redeem(&link));
    assert!(matches!(&r, Err(Error::Unsupported(m)) if m.starts_with("a client with")), "{r:?}");
    assert!(matches!(c.nodes(), Err(Error::Unsupported(_))));
    assert!(matches!(c.add_peer(&osis::Address::new(&"quic://x:1".parse().unwrap(), [1; 32])), Err(Error::Unsupported(_))));
    assert!(matches!(c.contact_card(), Err(Error::Unsupported(_))));
    assert!(matches!(c.pair_offer(), Err(Error::Unsupported(_))));
    assert!(matches!(c.invite_requests(), Err(Error::Unsupported(_))));
    assert!(matches!(c.rotate_peer_address(), Err(Error::Unsupported(_))));
    assert!(matches!(c.export_bundle(&[x.g], Vec::new()), Err(Error::Unsupported(_))));
    assert!(matches!(c.import_bundle(&b"x"[..]), Err(Error::Unsupported(_))));
    // never "it does not serve" from one who may not read the node's thing
    assert!(matches!(c.serving(), Err(Error::Unsupported(_))));
    assert!(matches!(c.listen(&[]), Err(Error::Unsupported(_))), "the node's own: not for a client");
    assert!(matches!(c.saved_peers(), Err(Error::Unsupported(_))));
    assert!(c.set_serving(Some(Default::default())).is_err());
    assert_eq!(x.n.serving().unwrap(), None);
}

// notes/client-port.md §2 (Backlinks), notes/api.md Backlinks: a client's backlinks are what its
// actor may read, whoever may read the target; paged through the port; its listener hears the
// page at once, then a change of it, and nothing of what it may not read.
#[test]
fn backlinks_are_the_actors() {
    let x = node();
    let link = osis::DynamicAspectKey::untyped(ak("t:link.0"));
    let (_, _, c) = x.client(Role::Read);
    for s in [x.t, x.u] {
        x.n.commit_set(s, link.clone(), &Value::Tid(x.out)).unwrap();
    }
    let bl = |t: Tid| osis::Backlink { tid: t, ak: ak("t:link.0") };
    let q = osis::BacklinkQuery::default();
    assert_eq!(c.backlinks(x.out, &q).unwrap().backlinks, vec![bl(x.t)], "not the thing under another group");
    assert_eq!(x.n.backlinks(x.out, &q).unwrap().backlinks.len(), 2);
    let (tx, rx) = channel();
    let _s = c.on_backlinks_change(x.out, &q, move |_, p| tx.send(p.unwrap().backlinks).unwrap()).unwrap();
    assert_eq!(rx.recv_timeout(Duration::from_secs(20)).unwrap(), vec![bl(x.t)], "initial");
    x.n.commit_set(x.u, link.clone(), &Value::Int(0)).unwrap();
    c.settle();
    assert!(rx.try_recv().is_err(), "a change of what it may not read is none");
    x.n.commit_set(x.member, link.clone(), &Value::Tid(x.out)).unwrap();
    c.settle();
    assert!(rx.try_recv().is_err(), "a member it may not read is none either");
    x.n.commit_set(x.t, osis::DynamicAspectKey::untyped(ak("t:also.0")), &Value::Tid(x.out)).unwrap();
    c.settle();
    let want = vec![osis::Backlink { tid: x.t, ak: ak("t:also.0") }, bl(x.t)];
    assert_eq!(rx.recv_timeout(Duration::from_secs(20)).unwrap(), want);
    // paged
    let p = c.backlinks(x.out, &osis::BacklinkQuery { after: None, limit: Some(1) }).unwrap();
    assert_eq!((p.backlinks.clone(), p.more), (vec![want[0].clone()], true));
    let p = c.backlinks(x.out, &osis::BacklinkQuery { after: p.backlinks.last().cloned(), limit: Some(1) }).unwrap();
    assert_eq!((p.backlinks, p.more), (vec![want[1].clone()], false));
}

// spec/wire.md §11.2 (Error 4), notes/client-port.md §3: the API's view of the connection cap: the ninth connection fails Network, one going frees a slot
#[test]
fn connections_past_the_cap() {
    let x = node();
    let (_, s) = x.n.add_client(None).unwrap();
    let mut all: Vec<Osis> = (0..osis::internals::MAX_CONNS_PER_CLIENT).map(|_| x.connect(&s).unwrap()).collect();
    assert!(matches!(x.connect(&s), Err(Error::Network(_))));
    drop(all.pop());
    x.until(|x| x.served() < osis::internals::MAX_CONNS_PER_CLIENT + 1);
    for _ in 0..2000 {
        if x.connect(&s).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("a slot was not freed");
}

// spec/sync.md §10 (never on another transport), notes/client-port.md §3 (main-actor rows): the registry calls run through a daemon's main actor session; a client secret never goes to a unix socket
#[test]
fn registry_through_the_main_session() {
    let (net, clock, store) = (osis_transport::Net::new(1), Arc::new(ManualClock::new(Time(T0))), MemStore::new());
    let n = open(&store, &net, &clock, true);
    let dir = std::env::temp_dir().join(format!("osis-port-clients-{}-{}", std::process::id(), NAMES.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("n.sock");
    n.listen_socket_at(&sock).unwrap();
    let o = crate::common::block_on(osis::internals::connect_socket(&sock, osis::internals::Opening::memory())).unwrap();
    let (a, s) = o.add_client(Some(Time(T0 + 1000))).unwrap();
    assert_eq!(n.clients().unwrap(), o.clients().unwrap());
    assert_eq!(n.at(n.node(), ct::CLIENTS).get().unwrap().unwrap().remove(&a).unwrap().secret_hash, osis_base::hash::hash(s.expose()));
    let s2 = o.rotate_client_secret(a).unwrap();
    assert_eq!(n.at(n.node(), ct::CLIENTS).get().unwrap().unwrap().remove(&a).unwrap().secret_hash, osis_base::hash::hash(s2.expose()));
    assert!(o.remove_client(a).unwrap());
    assert!(!o.remove_client(a).unwrap());
    let unix = Address::new(&format!("unix://{}", sock.display()).parse().unwrap(), [0; 32]);
    assert!(matches!(crate::common::block_on(osis::internals::connect(&unix, &s2, osis::internals::Opening::memory())), Err(Error::Invalid(_))));
    drop((o, n));
    let _ = std::fs::remove_dir_all(&dir);
}

// spec/wire.md §11.2, notes/client-port.md §3: `group.0` is not written as an aspect, on the client or in a commit sent by hand; the group calls add nothing the actor may not read
#[test]
fn group_aspect_ops_add_only_what_it_reads() {
    let x = node();
    let (a, sec, c) = x.client(Role::Write);
    let hidden = |r: osis::Result<()>| assert!(matches!(r, Err(Error::UnknownThing { .. })), "{r:?}");
    hidden(c.commit_with(|w| w.group(x.g).add(osis::Member::Item(x.out))));
    hidden(c.commit_with(|w| w.group(x.g).add(osis::Member::Item(Tid::from_bytes([9; 15])))));
    let with_out = ct::Group { items: [x.t, x.out].into_iter().collect(), subgroups: Default::default() };
    assert!(matches!(c.commit_set(x.g, ct::GROUP, &with_out), Err(Error::Invalid(_))));
    assert!(matches!(c.commit_with(|w| w.at(x.g, ct::GROUP).overwrite(&with_out)), Err(Error::Invalid(_))));
    let mut raw = x.raw(&sec);
    assert!(matches!(raw.call_at(1, WRITE, set_write(1, a, x.g, &ak("group.0"), osis::Codec::to_value(&with_out))), Outcome::Err { .. }));
    assert!(!x.n.groups_of(x.out).unwrap().item_of.contains(&x.g));
    // what it reads, and what the commit creates
    let mut w = c.write();
    let m = w.create_with_admin(x.g).unwrap();
    w.group(x.g).add(osis::Member::Item(m)).unwrap();
    let g2 = m;
    w.commit().unwrap();
    assert!(x.n.groups_of(g2).unwrap().item_of.contains(&x.g));
    // a listed name it may not read may go: it holds write on the list
    let mut w = x.n.write();
    w.group(x.g).add(osis::Member::Item(x.out)).unwrap();
    w.commit().unwrap();
    let mut w = c.write();
    w.group(x.g).remove(osis::Member::Item(x.out)).unwrap();
    w.commit().unwrap();
    assert!(!x.n.groups_of(x.out).unwrap().item_of.contains(&x.g));
}

// spec/wire.md §11.2, notes/api.md Writes, notes/client-port.md §3: a commit sent by hand names `group.0` for nothing, even with only what the actor reads in it; a membership that expires still goes
#[test]
fn a_commit_by_hand_writes_group_0_by_no_op() {
    let x = node();
    let (a, sec, c) = x.client(Role::Write);
    let mut raw = x.raw(&sec);
    let invalid = |o: Outcome, what: &str| assert!(matches!(&o, Outcome::Err { detail, .. } if format!("{detail:?}").contains("Write::group")), "{what}: {o:?}");
    let readable = ct::Group { items: [x.t].into_iter().collect(), subgroups: Default::default() };
    invalid(raw.call_at(1, WRITE, set_write(1, a, x.g, &ak("group.0"), osis::Codec::to_value(&readable))), "set");
    let batch = |nonce: u64, op: Vec<Value>| vec![Value::uint(nonce), Value::Tid(a), Value::List(vec![Value::Str("group.0".into())]), Value::List(vec![Value::List(op)]), Value::opt(None)];
    let (key, g) = (Value::Int(0), Value::Tid(x.g));
    invalid(raw.call_at(2, WRITE, batch(2, vec![Value::Int(6), g.clone(), key.clone()])), "purge");
    invalid(raw.call_at(3, WRITE, batch(3, vec![Value::Int(9), g.clone(), key.clone(), Value::Tid(a)])), "purge an author");
    invalid(raw.call_at(4, WRITE, batch(4, vec![Value::Int(8), g.clone(), key.clone(), Value::bytes(&[0; 32])])), "purge a commit");
    let none = Value::List(vec![Value::opt(None), Value::opt(None)]);
    invalid(raw.call_at(5, WRITE, batch(5, vec![Value::Int(5), g, key, Value::List(vec![Value::Int(0), none.clone(), none])])), "retention");
    assert_eq!(x.n.items(x.g).unwrap().len(), 2, "nothing written");
    // an expiry names no key: the commit's, a member's leaving with it
    let mut w = c.write();
    let m = w.create_with_admin(x.g).unwrap();
    w.at(m, osis::DynamicAspectKey::untyped(ak("t:name.0"))).set(&Value::Int(1)).unwrap();
    w.commit().unwrap();
    let mut w = c.write();
    w.expires(osis::Expiry::In(Duration::from_secs(60)));
    w.group(x.g).add(osis::Member::Item(m)).unwrap();
    w.commit().unwrap();
    assert!(x.n.items(x.g).unwrap().contains(&m));
}

// spec/wire.md §11.2 (a thing the actor may not read answers as unknown), spec/commits.md §7: a group it may not read scopes nothing, even an item it reads: no membership oracle, and no undo through it
#[test]
fn hidden_group_scopes_nothing() {
    let x = node();
    let name = ak("t:name.0");
    let (_, _, c) = x.client(Role::Write);
    typed_any(&x.n, &["t:name.0"]);
    let mut w = x.n.write();
    w.group(x.h).add(osis::Member::Item(x.t)).unwrap();
    w.commit().unwrap();
    // replacing the setup's untyped name would leave nothing kept to write back
    x.n.commit_set(x.t, kept(&x.n, &name.clone()), &Value::Int(0)).unwrap();
    c.commit_set(x.t, kept(&x.n, &name.clone()), &Value::Int(1)).unwrap();
    let ghost = Tid::from_bytes([9; 15]);
    let scoped = |g: Tid| crate::common::listed(&c, Scope::Group(g));
    assert!(scoped(ghost).is_empty());
    assert!(scoped(x.h).is_empty(), "an item's commits through a group it may not read");
    assert_eq!(c.undo(&Scope::Group(x.h)).unwrap(), None);
    assert_eq!(x.n.at(x.t, kept(&x.n, &name.clone())).get().unwrap(), Some(Value::Int(1)));
    assert!(!scoped(x.g).is_empty());
    assert!(c.undo(&Scope::Group(x.g)).unwrap().is_some());
    // the synthetic list of its groups shows what `groups_of` shows
    assert_eq!(c.at(x.t, kept(&x.n, &ak("groups.0"))).get().unwrap(), Some(Value::Set([Value::Tid(x.g)].into_iter().collect())));
    assert!(matches!(x.n.at(x.t, kept(&x.n, &ak("groups.0"))).get().unwrap(), Some(Value::Set(s)) if s.len() == 2));
}

// spec/wire.md §11.2, notes/client-port.md §3 (Undo/redo/revert): a revert that would write what the actor may not read is refused naming only what it reads; an ephemeral change of a thing it may not read answers as an unknown commit
#[test]
fn revert_names_only_what_it_reads() {
    let x = node();
    let name = ak("t:name.0");
    let (_, _, c) = x.client(Role::Write);
    let id = {
        let mut w = x.n.write();
        w.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).set(&Value::Int(7)).unwrap();
        w.at(x.out, osis::DynamicAspectKey::untyped(name.clone())).set(&Value::Int(7)).unwrap();
        w.commit().unwrap().unwrap().stamp.id
    };
    let r = c.revert(id);
    assert!(matches!(r, Err(Error::Permission { tid, .. }) if tid == x.t), "{r:?}");
    assert_eq!(x.n.at(x.out, osis::DynamicAspectKey::untyped(name.clone())).get().unwrap(), Some(Value::Int(7)));
    let eph = {
        let mut w = x.n.write();
        w.at(x.out, osis::DynamicAspectKey::untyped(ak("t:e+.0"))).set(&Value::Int(7)).unwrap();
        w.commit().unwrap().unwrap().stamp.id
    };
    let r = c.revert(eph);
    assert!(matches!(r, Err(Error::Invalid(_))), "{r:?}");
    assert_eq!(x.n.at(x.out, osis::DynamicAspectKey::untyped(ak("t:e+.0"))).get().unwrap(), Some(Value::Int(7)));
}

// spec/crdt.md §4.6, spec/wire.md §11.2, notes/client-port.md §3: reverting a creation deletes the thing as `delete` does: every held aspect, each membership in a group the actor may write. A writer removes no admin-only aspect that way; a membership in a group it may not write stays, and the answer does not tell of it
#[test]
fn revert_of_a_creation_needs_what_the_delete_writes() {
    let x = node();
    let (name, adm) = (ak("t:name.0"), ak("t:adm^.0"));
    let (_, _, c) = x.client(Role::Write);
    let made = |x: &Node| {
        let mut w = x.n.write();
        let m = w.create_with_admin(x.g).unwrap();
        w.at(m, osis::DynamicAspectKey::untyped(name.clone())).set(&Value::Int(1)).unwrap();
        w.group(x.g).add(osis::Member::Item(m)).unwrap();
        (m, w.commit().unwrap().unwrap().stamp.id)
    };
    let (m, id) = made(&x);
    x.n.commit_set(m, osis::DynamicAspectKey::untyped(adm.clone()), &Value::Int(2)).unwrap();
    assert!(matches!(c.revert(id), Err(Error::Permission { .. })));
    assert_eq!(x.n.at(m, osis::DynamicAspectKey::untyped(adm)).get().unwrap(), Some(Value::Int(2)));
    let (m, id) = made(&x);
    let mut w = x.n.write();
    w.group(x.h).add(osis::Member::Item(m)).unwrap();
    w.commit().unwrap();
    c.revert(id).unwrap();
    assert!(!x.n.has_content(m).unwrap());
    assert!(x.n.at(x.h, ct::GROUP).get().unwrap().unwrap().items.contains(&m), "a membership in a group it may not write");
    assert!(!x.n.at(x.g, ct::GROUP).get().unwrap().unwrap().items.contains(&m));
    // nothing beyond its rights: the revert runs
    let (m, id) = made(&x);
    c.revert(id).unwrap();
    assert!(!x.n.has_content(m).unwrap());
}

// spec/wire.md §11.2: however a raw session spells an addition to `group.0` (set add, whole value, insert, edit, a key step), nothing it may not read gets listed
#[test]
fn raw_group_ops_list_nothing_hidden() {
    let x = node();
    let (a, s, _c) = x.client(Role::Write);
    let mut r = x.raw(&s);
    let n = Value::Int;
    let out = Value::Tid(x.out);
    let set = Value::Set([out.clone()].into_iter().collect());
    let list = Value::List(vec![out.clone()]);
    let whole = Value::Map([(n(0), set.clone()), (n(1), Value::Set(Default::default()))].into_iter().collect());
    let cases: Vec<(Vec<Value>, Vec<Value>)> = vec![
        (vec![field(0)], vec![n(4), out.clone()]),
        (vec![field(1)], vec![n(4), out.clone()]),
        (vec![field(0)], vec![n(4), set.clone()]),
        (vec![field(0)], vec![n(0), set.clone()]),
        (vec![field(0)], vec![n(0), list.clone()]),
        (vec![field(0)], vec![n(1), set.clone()]),
        (vec![field(0)], vec![n(2), set.clone()]),
        (vec![field(0)], vec![n(2), out.clone()]),
        (vec![field(0)], vec![n(7), n(0), list.clone()]),
        (vec![field(0)], vec![n(10), Value::Set(Default::default()), set.clone()]),
        (vec![field(0)], vec![n(10), Value::List(vec![]), list.clone()]),
        (vec![field(0), key(out.clone())], vec![n(0), Value::Bool(true)]),
        (vec![field(0), key(out.clone())], vec![n(2), Value::Bool(true)]),
        (vec![key(out.clone())], vec![n(0), Value::Bool(true)]),
        (vec![], vec![n(0), whole.clone()]),
        (vec![], vec![n(1), whole.clone()]),
        (vec![], vec![n(2), whole.clone()]),
        (vec![], vec![n(10), Value::Map(Default::default()), whole.clone()]),
    ];
    for (i, (path, op)) in cases.into_iter().enumerate() {
        let o = path_op(&mut r, i as u64 + 1, a, "group.0", x.g, path, op);
        assert!(matches!(o, Outcome::Err { .. }), "{i}: {o:?}");
        let g = x.n.at(x.g, ct::GROUP).get().unwrap().unwrap();
        assert!(!g.items.contains(&x.out) && !g.subgroups.contains(&x.out), "{i}");
    }
    // a neighbouring key adds nothing
    path_op(&mut r, 101, a, "group.1", x.g, vec![field(0)], vec![n(4), out.clone()]);
    assert!(!x.n.groups_of(x.out).unwrap().item_of.contains(&x.g));
}

/// One raw path op on `t`'s aspect `k`, as a `write` call.
fn path_op(r: &mut Raw, nonce: u64, actor: Tid, k: &str, t: Tid, path: Vec<Value>, op: Vec<Value>) -> Outcome {
    let pop = Value::List(vec![Value::List(path), Value::List(op)]);
    let args = vec![Value::uint(nonce), Value::Tid(actor), Value::List(vec![Value::Str(k.into())]), Value::List(vec![Value::List(vec![Value::Int(3), Value::Tid(t), Value::Int(0), pop])])];
    r.call_at(nonce, WRITE, args)
}

fn field(i: i64) -> Value {
    Value::List(vec![Value::Int(0), Value::Int(i)])
}

fn key(v: Value) -> Value {
    Value::List(vec![Value::Int(2), v])
}

// spec/wire.md §11.2: a client writes no link, anywhere in a write: one of a hidden value (its blob would go under the labels of what it writes), one naming no blob (an element of a set breaks the whole aspect for every reader); nothing is written
#[test]
fn a_client_writes_no_link() {
    let x = node();
    let name = ak("t:name.0");
    let (a, s, c) = x.client(Role::Write);
    let mut r = x.raw(&s);
    x.n.commit_set(x.out, osis::DynamicAspectKey::untyped(name.clone()), &Value::Str("q".repeat(1 << 20))).unwrap();
    let hidden = x.n.engine(|e| e.get(&x.out, &name)).unwrap().unwrap();
    assert!(matches!(hidden, Value::Link(_)));
    let bogus = Value::link(osis_base::Link { hash: [3; 32], blob: osis_base::BlobId([4; 32]), suite: 1, key: [5; 32] });
    let n = Value::Int;
    let in_list = Value::List(vec![bogus.clone()]);
    let in_map = Value::Map([(bogus.clone(), n(1))].into_iter().collect());
    let cases: Vec<(&str, Tid, Vec<Value>, Vec<Value>)> = vec![
        ("t:name.0", x.t, vec![], vec![n(0), hidden.clone()]),
        ("t:b.0", x.t, vec![], vec![n(0), bogus.clone()]),
        ("t:b.0", x.t, vec![], vec![n(1), in_list.clone()]),
        ("t:b.0", x.t, vec![], vec![n(2), in_map]),
        ("t:b.0", x.t, vec![], vec![n(0), Value::Map([(n(0), bogus.clone())].into_iter().collect())]),
        ("t:b.0", x.t, vec![], vec![n(0), Value::Enum(1, Some(Box::new(bogus.clone())))]),
        ("t:b.0", x.t, vec![], vec![n(0), Value::List(vec![Value::Map([(n(0), Value::Set([bogus.clone()].into_iter().collect()))].into_iter().collect())])]),
        ("t:b.0", x.t, vec![], vec![n(4), bogus.clone()]),
        ("t:b.0", x.t, vec![], vec![n(6), bogus.clone()]),
        ("t:b.0", x.t, vec![], vec![n(10), n(0), in_list.clone()]),
        ("t:b.0", x.t, vec![], vec![n(7), n(0), in_list]),
        ("t:b.0", x.t, vec![key(bogus.clone())], vec![n(0), n(1)]),
        ("group.0", x.g, vec![field(0)], vec![n(4), bogus.clone()]),
        ("group.0", x.g, vec![field(0)], vec![n(5), bogus.clone()]),
    ];
    let before = x.n.engine(|e| e.commit_ids().len());
    for (i, (k, t, path, op)) in cases.into_iter().enumerate() {
        let o = path_op(&mut r, i as u64 + 1, a, k, t, path, op);
        assert!(matches!(o, Outcome::Err { code: 8, .. }), "{i}: {o:?}");
    }
    assert_eq!(x.n.engine(|e| e.commit_ids().len()), before);
    assert_eq!(c.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).get().unwrap(), Some(Value::Str("x".into())));
    assert!(x.n.at(x.g, ct::GROUP).get().unwrap().is_some());
    // a large value the ordinary way: the node chunks it
    c.commit_set(x.t, osis::DynamicAspectKey::untyped(name.clone()), &Value::Str("r".repeat(1 << 20))).unwrap();
    assert_eq!(c.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).get().unwrap(), Some(Value::Str("r".repeat(1 << 20))));
    assert!(matches!(x.n.engine(|e| e.get(&x.t, &name)).unwrap().unwrap(), Value::Link(_)), "stored chunked");
    // nested too, and a read's value written back
    let big = |c: char| Value::Str(c.to_string().repeat(1 << 20));
    let k = ak("t:big.0");
    let nested = Value::Map([(n(0), Value::List(vec![big('a'), big('b')])), (n(1), Value::Enum(2, Some(Box::new(big('c')))))].into_iter().collect());
    c.commit_set(x.t, osis::DynamicAspectKey::untyped(k.clone()), &nested).unwrap();
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap(), Some(nested.clone()));
    let read: Value = c.at(x.t, osis::DynamicAspectKey::untyped(k.clone())).get().unwrap().unwrap();
    assert_eq!(read, nested);
    c.commit_set(x.t, osis::DynamicAspectKey::untyped(ak("t:big2.0")), &read).unwrap();
    assert_eq!(x.n.at(x.t, osis::DynamicAspectKey::untyped(ak("t:big2.0"))).get().unwrap(), Some(nested));
}

// spec/wire.md §11.2: a revert's answer does not depend on a body dropped of what the actor may not read: refused the same with or without
#[test]
fn revert_tells_no_hidden_body_dropped() {
    let x = node();
    let name = ak("t:name.0");
    let (_, _, c) = x.client(Role::Write);
    let id = {
        let mut w = x.n.write();
        w.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).set(&Value::Int(7)).unwrap();
        w.at(x.out, osis::DynamicAspectKey::untyped(name.clone())).set(&Value::Int(7)).unwrap();
        w.commit().unwrap().unwrap().stamp.id
    };
    x.n.commit_set(x.out, osis::DynamicAspectKey::untyped(name.clone()), &Value::Int(8)).unwrap();
    let mut w = x.n.write();
    w.at(x.out, osis::DynamicAspectKey::untyped(name.clone())).purge(osis::Purge::All).unwrap();
    w.commit().unwrap();
    assert!(!x.n.engine(|e| e.body_not_dropped(&id.raw(), &x.out, &name)), "the body went");
    assert!(matches!(x.n.revert(id), Err(Error::NotUndoable { .. })), "the node sees it");
    let r = c.revert(id);
    assert!(matches!(r, Err(Error::Permission { tid, .. }) if tid == x.t), "{r:?}");
}

// spec/wire.md §11.2, notes/client-port.md §3: an undo refused for what it may not read blocks that scope's undo (nothing older is undone instead, as for a compacted change) and nothing else: a narrower scope and a revert by id reach older changes; once it may read the name, the undo runs
#[test]
fn refused_undo_blocks_only_its_scope() {
    let x = node();
    let name = ak("t:name.0");
    let (a, _, c) = x.client(Role::Write);
    typed_any(&x.n, &["t:name.0"]);
    let set = |v: i64| {
        let mut w = c.write();
        w.at(x.t, kept(&x.n, &name.clone())).set(&Value::Int(v)).unwrap();
        w.commit().unwrap().unwrap().stamp.id
    };
    set(1);
    let older = set(2);
    let unplaced = {
        let mut w = c.write();
        w.group(x.g).remove(osis::Member::Item(x.member)).unwrap();
        w.commit().unwrap().unwrap().stamp.id
    };
    for _ in 0..2 {
        assert!(matches!(c.undo(&Scope::Group(x.g)), Err(Error::Permission { .. })));
        assert_eq!(c.at(x.t, kept(&x.n, &name.clone())).get().unwrap(), Some(Value::Int(2)), "nothing older instead");
    }
    c.undo(&Scope::Thing(x.t)).unwrap().unwrap();
    assert_eq!(c.at(x.t, kept(&x.n, &name.clone())).get().unwrap(), Some(Value::Int(1)));
    c.redo(&Scope::Thing(x.t)).unwrap().unwrap();
    c.revert(older).unwrap();
    assert_eq!(c.at(x.t, kept(&x.n, &name.clone())).get().unwrap(), Some(Value::Int(1)));
    x.n.grant(x.member, a, Role::Read, Default::default()).unwrap();
    c.revert(unplaced).unwrap();
    assert!(x.n.groups_of(x.member).unwrap().item_of.contains(&x.g));
}

// spec/wire.md §11.2 (a thing the actor may not read answers every method as a thing the node does not know): the side-by-side beyond `answers`: group scopes, every way a write names it, with what is written; durable, a group, made elsewhere
#[test]
fn hidden_answers_writes_as_unknown() {
    let x = node();
    let (_, _, c) = x.client(Role::Write);
    let me = x.n.me();
    let ghost = Tid::from_bytes([9; 15]);
    let g = write_answers(&c, &x, ghost);
    assert!(g.contains("UnknownThing"), "{g}");
    for (name, t) in [("thing", x.out), ("group", x.h), ("its thing", x.u), ("account", me), ("node", x.n.node())] {
        assert_eq!(write_answers(&c, &x, t), g, "{name}");
        assert_eq!(answers(&c, t).replace(&format!("{t:?}"), "T"), answers(&c, ghost).replace(&format!("{ghost:?}"), "T"), "{name}");
    }
}

fn write_answers(c: &Osis, x: &Node, t: Tid) -> String {
    let k = ak("t:name.0");
    let read = |r: osis::Result<String>| r.unwrap_or_else(|e| format!("{e:?}"));
    let write = |f: &dyn Fn(&mut osis::Write<'_>) -> osis::Result<()>| {
        let mut w = c.write();
        match f(&mut w).and_then(|()| w.commit()) {
            Ok(Some(z)) => format!("written {:?}", z.stamp.id),
            Ok(None) => "nothing".into(),
            // a refused creation names the new tid, random each time
            Err(Error::Permission { needs, .. }) => format!("Permission {needs:?}"),
            Err(e) => format!("{e:?}"),
        }
    };
    let out = [
        read(c.writes(&Scope::Group(t), &CommitQuery::default()).map(|v| format!("{v:?}"))),
        read(c.writes(&Scope::Aspects(vec![(t, k.clone())]), &CommitQuery::default()).map(|v| format!("{v:?}"))),
        read(c.undo(&Scope::Group(t)).map(|v| format!("{v:?}"))),
        read(c.redo(&Scope::Group(t)).map(|v| format!("{v:?}"))),
        read(c.redo(&Scope::Thing(t)).map(|v| format!("{v:?}"))),
        write(&|w| w.group(x.g).add(osis::Member::Item(t))),
        write(&|w| w.group(x.g).remove(osis::Member::Item(t))),
        write(&|w| w.group(x.g).add(osis::Member::Subgroup(t))),
        write(&|w| w.group(x.g).remove(osis::Member::Subgroup(t))),
        write(&|w| w.group(t).add(osis::Member::Item(x.t))),
        write(&|w| w.group(t).remove(osis::Member::Item(x.t))),
        write(&|w| w.create_with_admin(t).map(|_| ())),
        write(&|w| {
            let m = w.create_with_admin(x.g)?;
            w.group(t).add(osis::Member::Item(m))
        }),
        write(&|w| w.at(t, osis::DynamicAspectKey::untyped(ak("t:sig+~0"))).fire(&Value::Int(1))),
        write(&|w| w.at(t, osis::DynamicAspectKey::untyped(ak("t:e+.0"))).set(&Value::Int(1))),
        read(c.at(t, osis::DynamicAspectKey::untyped(ak("groups.0"))).get().map(|v| format!("{v:?}"))),
        read(c.at(t, ct::GROUP).get().map(|v| format!("{v:?}"))),
        read(c.items(t).map(|v| format!("{v:?}"))),
        read(c.subgroups(t).map(|v| format!("{v:?}"))),
    ];
    out.join("\n").replace(&format!("{t:?}"), "T")
}

// spec/wire.md §11.2, notes/client-port.md §3: a revert is held to the actor as a write is: reverting a removal or subgroup removal, the actor's own too, puts back nothing it may not read, refused naming what it reads; what it reads goes back; the node's own revert is unchanged
#[test]
fn revert_lists_nothing_hidden() {
    let x = node();
    let (_, _, c) = x.client(Role::Write);
    typed_any(&x.n, &["t:name.0"]);
    let refused = |r: osis::Result<osis::Commit>, g: Tid| assert!(matches!(r, Err(Error::Permission { tid, .. }) if tid == g), "{r:?}");
    let unplaced = |m: Tid| {
        let mut w = x.n.write();
        w.group(x.g).remove(osis::Member::Item(m)).unwrap();
        w.commit().unwrap().unwrap().stamp.id
    };
    let listed = |m: Tid| x.n.groups_of(m).unwrap().item_of.contains(&x.g);
    // durable
    let mut w = x.n.write();
    w.group(x.g).add(osis::Member::Item(x.out)).unwrap();
    w.commit().unwrap();
    let id = unplaced(x.out);
    refused(c.revert(id), x.g);
    assert!(!listed(x.out));
    // a subgroup
    let mut w = x.n.write();
    w.group(x.g).add(osis::Member::Subgroup(x.h)).unwrap();
    w.commit().unwrap();
    let rm = {
        let mut w = x.n.write();
        w.group(x.g).remove(osis::Member::Subgroup(x.h)).unwrap();
        w.commit().unwrap().unwrap().stamp.id
    };
    refused(c.revert(rm), x.g);
    assert!(!x.n.groups_of(x.h).unwrap().subgroup_of.contains(&x.g));
    // its own remove of a listed name it may not read: gone stays gone
    let mut w = x.n.write();
    w.group(x.g).add(osis::Member::Item(x.member)).unwrap();
    w.commit().unwrap();
    let mut w = c.write();
    w.group(x.g).remove(osis::Member::Item(x.member)).unwrap();
    w.commit().unwrap();
    assert!(matches!(c.undo(&Scope::Group(x.g)), Err(Error::Permission { .. })));
    assert!(!listed(x.member));
    // what it reads goes back
    let mut w = c.write();
    let m = w.create_with_admin(x.g).unwrap();
    w.at(m, kept(&x.n, &ak("t:name.0"))).set(&Value::Int(1)).unwrap();
    w.group(x.g).add(osis::Member::Item(m)).unwrap();
    let mine = m;
    w.commit().unwrap();
    let id = unplaced(mine);
    c.revert(id).unwrap();
    assert!(listed(mine));
    // the node may, what the actor may not
    let mut w = x.n.write();
    w.group(x.g).add(osis::Member::Item(x.out)).unwrap();
    w.commit().unwrap();
    let id = unplaced(x.out);
    x.n.revert(id).unwrap();
    assert!(listed(x.out));
    // a client's thing, its write undone and redone: its own, added by it
    let name = ak("t:name.0");
    let d = c
        .commit_with(|w| {
            let m = w.create_with_admin(x.g)?;
            w.group(x.g).add(osis::Member::Item(m))?;
            Ok(m)
        })
        .unwrap();
    // a writer may not write its setting: the node, an admin of it, keeps its history
    x.n.commit_with(|w| { crate::common::keep_all(w, d); Ok(()) }).unwrap();
    c.commit_set(d, kept(&x.n, &name.clone()), &Value::Int(2)).unwrap();
    assert!(x.n.at(x.g, ct::GROUP).get().unwrap().unwrap().items.contains(&d));
    c.undo(&Scope::Thing(d)).unwrap().unwrap();
    assert_eq!(x.n.at(d, kept(&x.n, &name.clone())).get().unwrap(), None);
    c.redo(&Scope::Thing(d)).unwrap().unwrap();
    assert_eq!(x.n.at(d, kept(&x.n, &name.clone())).get().unwrap(), Some(Value::Int(2)));
    assert!(x.n.at(x.g, ct::GROUP).get().unwrap().unwrap().items.contains(&d));
}

// spec/wire.md §11.2 (a session ends when its until passes), notes/client-port.md §3 (remove_client): a removal cut short leaves the entry ended under any clock: no session, nothing revived by the clock or a secret rotation; retrying finishes it
#[test]
fn half_removed_client_stays_ended() {
    let x = node();
    let (a, s) = x.n.add_client(None).unwrap();
    x.n.grant(x.g, a, Role::Read, Default::default()).unwrap();
    let node_thing = x.n.node();
    let e = x.n.at(node_thing, ct::CLIENTS).get().unwrap().unwrap().remove(&a).unwrap();
    let mut w = x.n.write();
    w.at(node_thing, ct::CLIENTS).path(osis::p![a]).set(&ct::Client { until: Some(Time(0)), ..e }).unwrap();
    w.commit().unwrap();
    assert!(matches!(x.connect(&s), Err(Error::Refused(_))));
    let s2 = x.n.rotate_client_secret(a).unwrap();
    assert!(matches!(x.connect(&s2), Err(Error::Refused(_))), "a rotation revives nothing");
    assert!(x.n.grants(x.g).unwrap().contains_key(&a));
    assert!(x.n.remove_client(a).unwrap());
    assert!(!x.n.grants(x.g).unwrap().contains_key(&a));
    assert!(x.n.clients().unwrap().is_empty());
    assert!(!x.n.remove_client(a).unwrap());
}

/// A small xorshift (the walk's choices; failure messages name the seed).
struct Rng(u64);
impl Rng {
    fn next(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

// spec/sync.md §10, spec/wire.md §11.2, notes/client-port.md §3 (Invariant: every client-session row runs as the client's actor; authority ends at revocation), spec/permissions.md §1: a random walk of grants, lowered roles, secret rotations, expiries and removals against a model of plain grants: at every step every read answers what the model says the actor may read, as an unknown tid otherwise, and every write succeeds exactly when the model says it may write
#[test]
fn client_session_differential_against_grants() {
    for seed in [0x51u64, 0x7a3, 0x10f07] {
        walk(seed);
    }
}

fn walk(seed: u64) {
    let mut rng = Rng(seed);
    let x = node();
    let name = ak("t:name.0");
    // the model: per group the role granted; a direct grant on a thing; the thing's first admin
    let things = [(x.t, Some(x.g)), (x.u, Some(x.h)), (x.member, None), (x.out, None)];
    let mut on_group: [Option<Role>; 2] = [None, None];
    let mut on_thing: Option<Role> = None; // on `x.out`, directly
    let (g, h) = (x.g, x.h);
    // an item of a group it may not read tells nothing of that group
    let mut w = x.n.write();
    w.group(h).add(osis::Member::Item(x.t)).unwrap();
    w.commit().unwrap();
    let (mut a, mut s) = x.n.add_client(None).unwrap();
    let mut c = x.connect(&s).unwrap();
    let skip = SetRoleOpts { retain_copy: None };
    let mut value = 100i64;
    let mut last: [Value; 4] = std::array::from_fn(|_| Value::Str("x".into()));
    for step in 0..40 {
        let why = format!("seed {seed:#x} step {step}");
        match rng.next(10) {
            0 | 1 => {
                let i = rng.next(2) as usize;
                let r = [Role::Read, Role::Write][rng.next(2) as usize];
                let target = [g, h][i];
                match on_group[i] {
                    Some(old) if r < old => x.n.set_role(target, a, Some(r), skip).unwrap(),
                    _ => x.n.grant(target, a, r, Default::default()).unwrap(),
                }
                on_group[i] = Some(r);
            }
            2 => {
                let i = rng.next(2) as usize;
                if on_group[i].take().is_some() {
                    x.n.set_role([g, h][i], a, None, skip).unwrap();
                }
            }
            3 => {
                let r = [Role::Read, Role::Write][rng.next(2) as usize];
                match on_thing {
                    Some(old) if r < old => x.n.set_role(x.out, a, Some(r), skip).unwrap(),
                    _ => x.n.grant(x.out, a, r, Default::default()).unwrap(),
                }
                on_thing = Some(r);
            }
            4 => {
                s = x.n.rotate_client_secret(a).unwrap();
                assert!(c.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).get().is_err() || x.served() >= 1, "{why}");
                x.until(|x| x.served() == 0);
                assert!(c.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).get().is_err(), "{why}: a session of the old secret");
                c = x.connect(&s).unwrap();
            }
            5 => {
                // removal: nothing of the old actor works; a new client starts with no grants
                assert!(x.n.remove_client(a).unwrap(), "{why}");
                x.until(|x| x.served() == 0);
                assert!(c.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).get().is_err(), "{why}");
                assert!(matches!(x.connect(&s), Err(Error::Refused(_))), "{why}");
                (a, s) = x.n.add_client(None).unwrap();
                c = x.connect(&s).unwrap();
                on_group = [None, None];
                on_thing = None;
            }
            6 => {
                // an until set directly and passed: revoked with the grants still there
                let at = Time(x.n.now().unwrap().0 + 1000);
                let e = x.n.at(x.n.node(), ct::CLIENTS).get().unwrap().unwrap().remove(&a).unwrap();
                let node = x.n.node();
                let mut w = x.n.write();
                w.at(node, ct::CLIENTS).path(osis::p![a]).set(&ct::Client { until: Some(at), ..e }).unwrap();
                w.commit().unwrap();
                if rng.next(2) == 0 {
                    x.clock.advance(1000);
                    assert!(c.at(x.t, osis::DynamicAspectKey::untyped(name.clone())).get().is_err(), "{why}: past its until");
                    assert!(c.commit_set(x.t, osis::DynamicAspectKey::untyped(name.clone()), &Value::Int(0)).is_err(), "{why}");
                    x.until(|x| x.served() == 0);
                    assert!(matches!(x.connect(&s), Err(Error::Refused(_))), "{why}");
                    // back in by a new until (an admin's edit), with a new secret
                    let node = x.n.node();
                    s = x.n.rotate_client_secret(a).unwrap();
                    let e = x.n.at(node, ct::CLIENTS).get().unwrap().unwrap().remove(&a).unwrap();
                    let mut w = x.n.write();
                    w.at(node, ct::CLIENTS).path(osis::p![a]).set(&ct::Client { until: None, ..e }).unwrap();
                    w.commit().unwrap();
                    c = x.connect(&s).unwrap();
                } else {
                    let e = x.n.at(node, ct::CLIENTS).get().unwrap().unwrap().remove(&a).unwrap();
                    let mut w = x.n.write();
                    w.at(node, ct::CLIENTS).path(osis::p![a]).set(&ct::Client { until: None, ..e }).unwrap();
                    w.commit().unwrap();
                }
            }
            7 => {
                // an add: it needs write on the group and to read the thing; a successful
                // one leaves it a member only for this step
                let i = rng.next(2) as usize;
                let target = [g, h][i];
                let may = on_group[i] >= Some(Role::Write) && on_thing.is_some();
                let r = c.commit_with(|w| w.group(target).add(osis::Member::Item(x.out)));
                assert_eq!(r.is_ok(), may, "{why}: adding out to group {i} with {:?} on it and {on_thing:?} on out: {r:?}", on_group[i]);
                assert_eq!(x.n.groups_of(x.out).unwrap().item_of.contains(&target), may, "{why}");
                if may {
                    let mut w = x.n.write();
                    w.group(target).remove(osis::Member::Item(x.out)).unwrap();
                    w.commit().unwrap();
                }
            }
            _ => {
                // a write through the client on a random thing
                let (t, _) = things[rng.next(4) as usize];
                let i = things.iter().position(|(x, _)| *x == t).unwrap();
                let may = role_of(&x, t, on_group, on_thing) >= Some(Role::Write);
                value += 1;
                let r = c.commit_set(t, osis::DynamicAspectKey::untyped(name.clone()), &Value::Int(value));
                match (&r, may) {
                    (Ok(_), true) => last[i] = Value::Int(value),
                    (Err(Error::Permission { .. }), false) if role_of(&x, t, on_group, on_thing).is_some() => {}
                    (Err(Error::UnknownThing { .. }), false) if role_of(&x, t, on_group, on_thing).is_none() => {}
                    _ => panic!("{why}: write of {t} with role {:?}: {r:?}", role_of(&x, t, on_group, on_thing)),
                }
                assert_eq!(x.n.at(t, osis::DynamicAspectKey::untyped(name.clone())).get().unwrap(), Some(last[i].clone()), "{why}");
            }
        }
        // every read, every step
        for (i, (t, _)) in things.iter().enumerate() {
            let role = role_of(&x, *t, on_group, on_thing);
            let got = c.at(*t, osis::DynamicAspectKey::untyped(name.clone())).get().unwrap();
            let want = role.map(|_| last[i].clone());
            assert_eq!(got, want, "{why}: read of {t} with role {role:?}");
            assert_eq!(c.has_content(*t).unwrap(), role.is_some(), "{why}: knows {t}");
            assert_eq!(c.role_on(*t).unwrap(), role, "{why}: role_on {t}");
            assert_eq!(crate::common::listed(&c, Scope::Thing(*t)).is_empty(), role.is_none(), "{why}: commits {t}");
        }
        for (i, group) in [g, h].into_iter().enumerate() {
            assert_eq!(crate::common::listed(&c, Scope::Group(group)).is_empty(), on_group[i].is_none(), "{why}: scope of group {i}");
        }
        if on_group[0].is_some() {
            let shown = c.at(x.t, osis::DynamicAspectKey::untyped(ak("groups.0"))).get().unwrap();
            assert!(matches!(&shown, Some(Value::Set(s)) if s.contains(&Value::Tid(h)) == on_group[1].is_some()), "{why}: groups.0 {shown:?}");
        }
        // what it may not ever read, whatever it holds
        assert!(!c.has_content(x.n.me()).unwrap() && !c.has_content(x.n.node()).unwrap(), "{why}");
    }
}

/// The model: a direct grant on `out`, a grant on the group that is first admin of `t` or `u`. `member` and `out`
/// are the account's: membership gives nothing.
fn role_of(x: &Node, t: Tid, g: [Option<Role>; 2], thing: Option<Role>) -> Option<Role> {
    if t == x.t {
        g[0]
    } else if t == x.u {
        g[1]
    } else if t == x.out {
        thing
    } else {
        None
    }
}

// spec/wire.md §11.2, notes/client-port.md §2, notes/api.md Commits: a thin client reads a page as the node would for its
// actor, and a thing it may not read has none, as an unknown tid (`answers`); its listener hears each
// commit, nothing of what it may not read; a purge through the port is judged by its actor.
#[test]
fn listings_as_the_actor() {
    use osis::{Body, CommitEvent};
    let x = node();
    let k = ak("t:msg.0");
    let key = || osis::DynamicAspectKey::untyped(k.clone());
    for t in [x.t, x.u] {
        keep_forever(&x.n, t, &k);
    }
    let (a, _, c) = x.client(Role::Write);
    let (tx, rx) = channel();
    let _s = c.at(x.t, key()).on_write(move |_, e| tx.send(e).unwrap()).unwrap();
    let (htx, hrx) = channel();
    let _h = c.at(x.u, key()).on_write(move |_, e| htx.send(e).unwrap()).unwrap();
    let say = |t: Tid, v: &str| {
        let mut w = x.n.write();
        w.at(t, key()).set(&Value::Str(v.into())).unwrap();
        w.commit().unwrap().unwrap().stamp.id
    };
    let one = say(x.t, "one");
    say(x.u, "hidden");
    c.settle();
    let got: Vec<_> = rx.try_iter().collect();
    assert!(matches!(got.as_slice(), [CommitEvent::Commit { id, commit: Some(e) }] if *id == one && e.at(x.t, key()).unwrap().body == Body::Held(Some(Value::Str("one".into())))), "{got:?}");
    assert!(hrx.try_recv().is_err(), "nothing of what it may not read");
    let five = page(osis::CommitFrom::Newest, 5);
    assert_eq!(c.at(x.t, key()).writes(&five).unwrap(), x.n.at(x.t, key()).writes(&five).unwrap());
    assert!(c.at(x.u, key()).writes(&five).unwrap().commits.is_empty());
    // a client's own write, by its actor; its purge by the port
    c.commit_with(|w| w.at(x.t, key()).retention(osis::Retention { by: osis::PurgeBy::AuthorOrAdmin }).set(&Value::Str("mine".into())).map(|_| ())).unwrap();
    let e = &c.at(x.t, key()).writes(&page(osis::CommitFrom::Newest, 1)).unwrap().commits[0];
    assert_eq!(e.stamp.actor, a);
    let id = e.stamp.id;
    let mut w = c.write();
    w.at(x.t, key()).purge(osis::Purge::Commit(id)).unwrap();
    let rq = w.commit().unwrap().unwrap().stamp.id;
    let two = page(osis::CommitFrom::Newest, 2);
    let e = x.n.at(x.t, key()).writes(&two).unwrap().commits;
    assert!(e.iter().any(|e| e.stamp.id == id && e.at(x.t, key()).unwrap().body == Body::Purged { by: rq, actor: Some(a) }), "{e:?}");
    assert_eq!(c.at(x.t, key()).writes(&two).unwrap().commits, e, "over the port too");
    // what it may not write: refused for that
    let mut w = c.write();
    w.at(x.u, key()).purge(osis::Purge::Author(a)).unwrap();
    assert!(w.commit().is_err());
    let (_, _, ro) = x.client(Role::Read);
    let mut w = ro.write();
    w.at(x.t, key()).purge(osis::Purge::Commit(one)).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })), "a reader's request");
    // the second layer: a handle acting for it hears nothing either
    let acting = x.n.acting_as(a);
    let (etx, erx) = channel();
    let _e = acting.at(x.u, key()).on_write(move |_, e| etx.send(e).unwrap()).unwrap();
    say(x.u, "hidden too");
    x.n.settle();
    let heard: Vec<_> = erx.try_iter().collect();
    assert!(heard.is_empty(), "{heard:?}");
    // by author over the port: the node's writes are not the client's to purge (author or
    // admin), so the request is refused
    let mut w = c.write();
    w.at(x.t, key()).purge(osis::Purge::Author(x.n.me())).unwrap();
    assert!(matches!(w.commit(), Err(Error::Permission { .. })), "no right over another's writes");
    let e = x.n.at(x.t, key()).writes(&page(osis::CommitFrom::Oldest, 1)).unwrap().commits;
    assert_eq!(e[0].stamp.id, one);
    assert_eq!(e[0].at(x.t, key()).unwrap().body, Body::Held(Some(Value::Str("one".into()))));
}

// spec/wire.md §11.2, notes/client-port.md Reconnect, notes/api.md Commits: a dropped connection and its return are
// told as `Reread`: what changed meanwhile was not told one by one.
#[test]
fn commit_listener_across_a_restart_says_reread() {
    use osis::CommitEvent;
    let x = node();
    let k = ak("t:msg.0");
    let (_, _, c) = x.client(Role::Read);
    let (tx, rx) = channel();
    let _s = c.at(x.t, osis::DynamicAspectKey::untyped(k.clone())).on_write(move |_, e| tx.send(e).unwrap()).unwrap();
    let t = x.t;
    let Node { n, net, clock, store, g, member, out, h, u, .. } = x;
    assert_eq!(n.close().unwrap(), osis::Close::Closed);
    let wait = |what: &str| {
        let e = rx.recv_timeout(Duration::from_secs(60));
        assert!(matches!(e, Ok(CommitEvent::Reread)), "{what}: {e:?}");
    };
    wait("the connection dropped");
    let n = open(&store, &net, &clock, false);
    let x = Node { n, net, clock, store, g, t, member, out, h, u };
    wait("it came back");
    let mut w = x.n.write();
    w.at(t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(1)).unwrap();
    let id = w.commit().unwrap().unwrap().stamp.id;
    let e = rx.recv_timeout(Duration::from_secs(60)).unwrap();
    assert!(matches!(e, CommitEvent::Commit { id: i, .. } if i == id), "{e:?}");
}

// spec/wire.md §11.2, notes/client-port.md §2 (`COMMIT_SEND`): more commits waiting than one send reads all go out,
// and a `settle` waits for them.
#[test]
fn commit_listener_sends_everything_waiting() {
    use osis::CommitEvent;
    let x = node();
    let k = ak("t:msg.0");
    let (_, _, c) = x.client(Role::Read);
    let (tx, rx) = channel();
    let _s = c.at(x.t, osis::DynamicAspectKey::untyped(k.clone())).on_write(move |_, e| tx.send(e).unwrap()).unwrap();
    let n = osis::internals::COMMIT_SEND * 3;
    let changes: Vec<osis_node::CommitChange> = (0..n as u32).map(|i| osis_node::CommitChange::held(x.t, k.clone(), osis::internals::RawCommitId([&i.to_be_bytes()[..], &[0; 28]].concat().try_into().unwrap()))).collect();
    x.n.engine(|e| {
        e.core.events.queue(osis_node::Event::Commits(Arc::new(changes)));
        e.core.events.flush();
    });
    x.n.settle();
    c.settle();
    let got: Vec<_> = rx.try_iter().collect();
    assert_eq!(got.len(), n, "{got:?}");
    assert!(got.iter().all(|e| matches!(e, CommitEvent::Commit { commit: None, .. })), "no such commits");
}

// spec/wire.md §11.2, notes/client-port.md §2 (memory per connection): commits waiting in a commit
// subscription count against the connection's budget: with the worker busy, past it the subscription
// lapses and the client hears it; the budget comes back, so a new one works.
#[test]
fn commit_listener_past_its_budget_lapses() {
    use osis::CommitEvent;
    let x = node();
    let k = ak("t:msg.0");
    let (_, _, c) = x.client(Role::Write);
    let (tx, rx) = channel();
    let _s = c.at(x.t, osis::DynamicAspectKey::untyped(k.clone())).on_write(move |_, e| tx.send(e).unwrap()).unwrap();
    // a client's write holds the worker in the hook
    let (busy_tx, busy) = channel();
    let (go, wait) = channel::<()>();
    let (busy_tx, wait) = (Mutex::new(busy_tx), Mutex::new(wait));
    x.n.set_source(x.h, None); // the hook runs only with routing on; no route is set
    x.n.after_source(Box::new(move || {
        busy_tx.lock().unwrap().send(()).unwrap();
        let _ = wait.lock().unwrap().recv_timeout(Duration::from_secs(60));
    }));
    let c2 = c.clone();
    let (t, k2) = (x.t, ak("t:name.0"));
    let writer = std::thread::spawn(move || c2.commit_set(t, osis::DynamicAspectKey::untyped(k2), &Value::Int(7)).map(|_| ()));
    busy.recv_timeout(Duration::from_secs(60)).unwrap();
    let n = osis::internals::PUSH_BYTES / osis::internals::COMMIT_DIRTY_BYTES + 1;
    let changes: Vec<osis_node::CommitChange> = (0..n as u32).map(|i| osis_node::CommitChange::held(x.t, k.clone(), osis::internals::RawCommitId([&i.to_be_bytes()[..], &[0; 28]].concat().try_into().unwrap()))).collect();
    x.n.engine(|e| {
        e.core.events.queue(osis_node::Event::Commits(Arc::new(changes)));
        e.core.events.flush();
    });
    x.n.settle();
    drop(go); // the hook waits no more, however often it runs
    writer.join().unwrap().unwrap();
    x.n.after_source(Box::new(|| {}));
    let mut ended = false;
    while let Ok(e) = rx.recv_timeout(Duration::from_secs(20)) {
        if matches!(e, CommitEvent::Ended(_)) {
            ended = true;
            break;
        }
    }
    assert!(ended, "past the budget");
    // its bytes are back: a new subscription hears
    let (tx, rx) = channel();
    let _again = c.at(x.t, osis::DynamicAspectKey::untyped(k.clone())).on_write(move |_, e| tx.send(e).unwrap()).unwrap();
    let mut w = x.n.write();
    w.at(x.t, osis::DynamicAspectKey::untyped(k.clone())).set(&Value::Int(1)).unwrap();
    let id = w.commit().unwrap().unwrap().stamp.id;
    let e = rx.recv_timeout(Duration::from_secs(20)).unwrap();
    assert!(matches!(e, CommitEvent::Commit { id: i, .. } if i == id), "{e:?}");
}

// spec/wire.md §11.2, notes/client-port.md §3 (nothing of what its actor may not read), §2 (budget): commits on a hidden
// thing take none of the connection's budget: a watch it may read does not lapse for them, which
// would tell of activity there.
#[test]
fn commit_listener_of_a_hidden_thing_takes_no_budget() {
    use osis::CommitEvent;
    let x = node();
    let k = ak("t:msg.0");
    let (_, _, c) = x.client(Role::Write);
    let (tx, rx) = channel();
    let _s = c.at(x.t, osis::DynamicAspectKey::untyped(k.clone())).on_write(move |_, e| tx.send(e).unwrap()).unwrap();
    let (htx, _hrx) = channel();
    let _h = c.at(x.u, osis::DynamicAspectKey::untyped(k.clone())).on_write(move |_, e| htx.send(e).unwrap()).unwrap();
    // a client's write holds the worker in the hook
    let (busy_tx, busy) = channel();
    let (go, wait) = channel::<()>();
    let (busy_tx, wait) = (Mutex::new(busy_tx), Mutex::new(wait));
    x.n.set_source(x.h, None);
    x.n.after_source(Box::new(move || {
        busy_tx.lock().unwrap().send(()).unwrap();
        let _ = wait.lock().unwrap().recv_timeout(Duration::from_secs(60));
    }));
    let c2 = c.clone();
    let (t, k2) = (x.t, ak("t:name.0"));
    let writer = std::thread::spawn(move || c2.commit_set(t, osis::DynamicAspectKey::untyped(k2), &Value::Int(7)).map(|_| ()));
    busy.recv_timeout(Duration::from_secs(60)).unwrap();
    let ids = |n: usize, on: Tid| -> Vec<osis_node::CommitChange> { (0..n as u32).map(|i| osis_node::CommitChange::held(on, k.clone(), osis::internals::RawCommitId([&i.to_be_bytes()[..], &[0; 28]].concat().try_into().unwrap()))).collect() };
    let flood = osis::internals::PUSH_BYTES / osis::internals::COMMIT_DIRTY_BYTES;
    x.n.engine(|e| {
        e.core.events.queue(osis_node::Event::Commits(Arc::new(ids(flood, x.u))));
        e.core.events.queue(osis_node::Event::Commits(Arc::new(ids(1, x.t))));
        e.core.events.flush();
    });
    x.n.settle();
    drop(go);
    writer.join().unwrap().unwrap();
    x.n.after_source(Box::new(|| {}));
    let e = rx.recv_timeout(Duration::from_secs(20)).unwrap();
    assert!(matches!(e, CommitEvent::Commit { .. }), "{e:?}");
}

// spec/wire.md §11.2, notes/api.md Commits: a client pages past large bodies: what a page takes fits
// one reply, and a body past that reads as too large; else every read from there would fail.
#[test]
fn pages_past_large_bodies() {
    use osis::{Body, CommitFrom};
    let x = node();
    let k = ak("t:big.0");
    let (_, _, c) = x.client(Role::Read);
    let half = osis_proto::api::REPLY_BUDGET / 2;
    let fits = half - osis::internals::COMMIT_PAGE * 512 / 2 - 60;
    keep_forever(&x.n, x.t, &k);
    let key = || osis::DynamicAspectKey::untyped(k.clone());
    for (b, n) in [(0u8, half - 60), (1, half - 60), (2, fits), (3, fits), (4, fits)] {
        x.n.commit_with(|w| w.at(x.t, key()).set(&Value::Bytes(vec![b; n]))).unwrap();
    }
    let p = c.at(x.t, key()).writes(&page(CommitFrom::Newest, 10)).unwrap();
    assert_eq!((p.commits.len(), p.more), (2, true));
    assert_eq!(p.commits[0].at(x.t, key()).unwrap().body, Body::Held(Some(Value::Bytes(vec![4; fits]))));
    let mut from = p.commits[1].pos();
    let mut rest = Vec::new();
    loop {
        let p = c.at(x.t, key()).writes(&page(CommitFrom::Before(from), 10)).unwrap();
        rest.extend(p.commits.iter().map(|e| matches!(e.at(x.t, key()).unwrap().body, Body::TooLarge { .. })));
        if !p.more {
            break;
        }
        from = p.commits.last().unwrap().pos();
    }
    assert_eq!(rest, [false, true, true]);
}

// spec/wire.md §11.2, notes/client-port.md §3: a thin client's list of links is refused like any row not for it
#[test]
fn a_client_lists_no_links() {
    let x = node();
    let (_a, _s, c) = x.client(Role::Read);
    x.n.make_link(x.u, Role::Read, LinkOpts { until: None, single_use: false, direct: true }).unwrap();
    assert_eq!(x.n.links().unwrap().len(), 1);
    assert!(matches!(c.links(), Err(Error::Unsupported(_))));
}

// spec/wire.md §11.2 (a thin client's rights: what its actor may not read answers as unknown), notes/client-port.md §3: `holders` on a client shows a thing it reads and who holds it, and nothing of a thing it may not read, nor who holds through an actor it may not read; `undo_target` likewise
#[test]
fn holders_and_targets_show_only_what_the_actor_reads() {
    let x = node();
    let (a, _s, c) = x.client(Role::Read);
    // a team on the group, whose member the client may not know of
    let (behind, _) = x.n.add_client(None).unwrap();
    x.n.grant(x.h, behind, Role::Read, Default::default()).unwrap();
    x.n.grant(x.g, x.h, Role::Read, Default::default()).unwrap();
    x.n.grant(x.out, behind, Role::Read, Default::default()).unwrap();
    assert!(x.n.holders(x.g).unwrap().iter().any(|w| w.actor == behind && w.through == vec![x.h]), "the node sees through it");
    let seen = c.holders(x.g).unwrap();
    assert!(seen.iter().any(|w| w.actor == a && w.through.is_empty()), "{seen:?}");
    assert!(seen.iter().any(|w| w.actor == x.h && w.through.is_empty()), "the team is on the thing it reads: {seen:?}");
    // (its account administers the client's own actor by that actor's record edge: shown through it)
    assert!(seen.iter().all(|w| w.actor != behind && (w.through.is_empty() || w.through == vec![a])), "nothing behind an actor it may not read: {seen:?}");
    for hidden in [x.out, x.h] {
        assert!(!x.n.holders(hidden).unwrap().is_empty(), "the node knows who holds it");
        assert_eq!(c.holders(hidden).unwrap(), vec![], "as a thing the node does not know");
    }
    let hidden = Scope::Thing(x.out);
    assert_eq!(c.undo_target(&hidden).unwrap(), None);
    assert_eq!(c.redo_target(&hidden).unwrap(), None);
    let (_, _, w) = x.client(Role::Write);
    typed_any(&x.n, &["t:name.0"]);
    // replacing the setup's untyped name would leave nothing kept to write back
    x.n.commit_set(x.t, kept(&x.n, &ak("t:name.0")), &Value::Str("kept".into())).unwrap();
    w.commit_set(x.t, kept(&x.n, &ak("t:name.0")), &Value::Str("mine".into())).unwrap();
    let mine = w.undo_target(&Scope::Thing(x.t)).unwrap().unwrap().stamp.id;
    assert_eq!(w.undo(&Scope::Thing(x.t)).unwrap().unwrap().stamp.id, w.redo_target(&Scope::Thing(x.t)).unwrap().unwrap().stamp.id);
    assert_eq!(x.n.writes(&Scope::Thing(x.t), &CommitQuery { reverts: Some(mine), ..Default::default() }).unwrap().commits.len(), 1);
}

// notes/listener-design.md (undo leak), spec/crdt.md §4.6: `undo_target` fails as `undo` would,
// so a UI disables Undo by it: a target whose every write another actor overwrote since would
// write nothing, `NotUndoable{Superseded}` from both, on a node and on a client (confined to its
// actor), nothing written.
#[test]
fn undo_target_superseded_as_undo() {
    let x = node();
    let (_, _, w) = x.client(Role::Write);
    typed_any(&x.n, &["t:name.0"]);
    let k = kept(&x.n, &ak("t:name.0"));
    let scope = Scope::Thing(x.t);
    let superseded = |c| Err(Error::NotUndoable { commit: c, reason: osis::NotUndoableReason::Superseded });
    let set = |db: &Osis, v: &str| crate::common::commit_with(db, |w| w.at(x.t, k.clone()).set(&Value::Str(v.into()))).stamp.id;
    // replacing the setup's untyped name would leave nothing kept to write back
    set(&x.n, "kept");
    let by_node = set(&x.n, "node");
    set(&w, "client");
    let by_client = set(&w, "client 2");
    assert_eq!(x.n.undo_target(&scope).map(|c| c.map(|c| c.stamp.id)), superseded(by_node));
    assert_eq!(x.n.undo(&scope).map(|c| c.map(|c| c.stamp.id)), superseded(by_node));
    set(&x.n, "node 2");
    let marks = x.n.engine(|e| e.commit_ids().len());
    assert_eq!(w.undo_target(&scope).map(|c| c.map(|c| c.stamp.id)), superseded(by_client));
    assert_eq!(w.undo(&scope).map(|c| c.map(|c| c.stamp.id)), superseded(by_client));
    assert_eq!((x.n.engine(|e| e.commit_ids().len()), x.n.at(x.t, k).get().unwrap()), (marks, Some(Value::Str("node 2".into()))), "nothing written");
}

// spec/wire.md §11.2 (a thin client's rights), notes/client-port.md §3: a client ends its own actor's role and no other's: nobody else's grant moves, what it left reads as unknown
#[test]
fn a_client_leaves_alone() {
    let x = node();
    let (a, _s, c) = x.client(Role::Write);
    let (other, _) = x.n.add_client(None).unwrap();
    x.n.grant(x.g, other, Role::Read, Default::default()).unwrap();
    assert!(matches!(c.leave(other, x.g), Err(Error::Permission { .. })));
    assert!(matches!(c.leave(x.n.me(), x.g), Err(Error::Permission { .. })));
    assert!(x.n.grants(x.g).unwrap().contains_key(&other));
    // through a team it reads: says so, names the team, ends nothing
    let (b, _s, cb) = x.client(Role::Read);
    x.n.grant(x.h, b, Role::Read, Default::default()).unwrap();
    x.n.grant(x.out, x.h, Role::Read, Default::default()).unwrap();
    let r = cb.leave(b, x.out);
    assert!(matches!(&r, Err(Error::Invalid(m)) if m.contains(&x.h.to_string())), "{r:?}");
    assert_eq!(x.n.grants(x.h).unwrap().get(&b).map(|g| g.role), Some(Role::Read));
    assert!(x.n.grants(x.out).unwrap().contains_key(&x.h));
    // what it may not read: as a thing nobody knows, and nobody's grant moves
    let (ghost, before) = (Tid::from_bytes([9; 15]), x.n.grants(x.out).unwrap());
    assert_eq!(c.leave(a, ghost), Ok(()));
    assert_eq!(c.leave(a, x.out), Ok(()));
    assert_eq!(x.n.grants(x.out).unwrap(), before);
    assert!(matches!(c.leave(ghost, x.g), Err(Error::Permission { .. })), "another tid, known or not, reads the same");
    c.leave(a, x.g).unwrap();
    assert!(!x.n.grants(x.g).unwrap().contains_key(&a));
    assert!(x.n.grants(x.g).unwrap().contains_key(&other));
    assert!(!c.has_content(x.g).unwrap());
}
