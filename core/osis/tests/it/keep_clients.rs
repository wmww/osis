//! A thin client and its node's kept copy (spec/permissions.md §3, Keep; notes/client-port.md §3): a
//! chat of Alice's, Bob's node serving Bob's app as a thin client over the client port, Bob kicked.

use crate::common::watched;
use crate::common::TestWrites as _;
use crate::common::{ak, block_on};
use osis::{SetRoleOpts, SyncFirst, ClientSecret, CommitQuery, Config, GrantOpts, Error, HostAddr, MemStore, Osis, Role, Runtime, Scope, StoreAt, SyncScope, Tid, Transport, Value};
use std::time::{Duration, Instant};

const W: Duration = Duration::from_secs(20);

fn until(what: &str, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + W;
    while !f() {
        assert!(Instant::now() < end, "not reached: {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn text() -> osis::Ak {
    ak("msg:text.0")
}

fn file() -> osis::Ak {
    ak("msg:file.0")
}

fn big() -> Vec<u8> {
    (0..3_000_000u32).map(|i| (i % 251) as u8).collect()
}

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

fn on(net: &osis_transport::Net, ep: &str, store: &MemStore, hosts: Vec<HostAddr>) -> Config {
    let mut c = Config::at(StoreAt::Memory(store.clone()));
    c.runtime = Runtime::Own;
    c.transport = Some(Transport::InProcess(net.endpoint(ep)));
    c.hosts = hosts;
    c.wait_timeout = W;
    c.peers = false;
    c
}

/// Alice's chat `g` holding message `m`; Bob's node `b`, on the chat with `edge`, has `m`.
struct Chat {
    net: osis_transport::Net,
    _host: Osis,
    addr: HostAddr,
    a: Osis,
    b: Osis,
    b_store: MemStore,
    nc: HostAddr,
    urls: Vec<String>,
    bob: Tid,
    g: Tid,
    m: Tid,
}

fn chat(edge: GrantOpts, role: Role) -> Chat {
    let net = osis_transport::Net::new(5);
    let host = Osis::create(on(&net, "s", &MemStore::new(), vec![])).unwrap().0;
    host.set_hosting(Some(osis::Hosting { listen: vec!["mem://s".into()], admit: osis::Admit::Open, ..Default::default() })).unwrap();
    until("host address", || host.host_address().unwrap().is_some());
    let addr = host.host_address().unwrap().unwrap();
    let a = Osis::create(on(&net, "a", &MemStore::new(), vec![addr.clone()])).unwrap().0;
    let b_store = MemStore::new();
    let b = Osis::create(on(&net, "b", &b_store, vec![addr.clone()])).unwrap().0;
    let card = b.contact_card().unwrap();
    block_on(b.wait_synced(SyncScope::All, W)).unwrap();
    let bob = block_on(a.import_contact(&card)).unwrap();
    let mut w = a.write();
    let g = w.create().unwrap();
    w.group(a.me()).add(osis::Member::Item(g)).unwrap();
    w.commit().unwrap();
    a.sync(g, &[]).unwrap();
    block_on(a.wait_synced(SyncScope::All, W)).unwrap();
    block_on(b.wait_synced(SyncScope::All, W)).unwrap();
    let mut w = a.write();
    let m = w.create_owned_by(g).unwrap();
    w.group(g).add(osis::Member::Item(m)).unwrap();
    w.at(m, text()).set(&s("hello")).unwrap();
    w.at(m, file()).set(&Value::Bytes(big())).unwrap();
    w.commit().unwrap();
    a.grant(g, bob, role, edge).unwrap();
    let nudge = Nudge::default();
    until("Bob has the message", || {
        nudge.at(&b);
        for r in b.invite_requests().unwrap_or_default() {
            let _ = b.accept_invite(r);
        }
        b.at(m, text()).get().ok().flatten() == Some(s("hello"))
    });
    let urls = vec!["mem://b-clients".to_string()];
    let nc = b.client_listen(&urls).unwrap().remove(0);
    Chat { net, _host: host, addr, a, b, b_store, nc, urls, bob, g, m }
}

/// A push that raced a subscription waits for the next pass: asks for one now and then, not at
/// every look, as each restarts the pass.
#[derive(Default)]
struct Nudge(std::cell::Cell<u32>);

impl Nudge {
    fn at(&self, db: &Osis) {
        self.0.set(self.0.get() + 1);
        if self.0.get().is_multiple_of(400) {
            let _ = db.sync_now();
        }
    }
}

static NAMES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn attach(net: &osis_transport::Net, nc: &HostAddr, secret: &ClientSecret) -> Osis {
    let mut c = Config::memory();
    let n = NAMES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    c.transport = Some(Transport::InProcess(net.endpoint(&format!("c{n}"))));
    c.wait_timeout = W;
    Osis::attach_client(nc, secret, c).unwrap()
}

impl Chat {
    fn attach(&self, secret: &ClientSecret) -> Osis {
        attach(&self.net, &self.nc, secret)
    }

    /// A client of Bob's node with `role` on Bob's person: Bob's app.
    fn app(&self, role: Role) -> (Tid, ClientSecret, Osis) {
        let (actor, secret) = self.b.add_client(None).unwrap();
        self.b.grant(self.bob, actor, role, Default::default()).unwrap();
        let c = self.attach(&secret);
        (actor, secret, c)
    }

    /// Another client of Bob's node: it holds a role on nothing here.
    fn stranger(&self) -> (Tid, Osis) {
        let (actor, secret) = self.b.add_client(None).unwrap();
        let c = self.attach(&secret);
        (actor, c)
    }

    /// Alice kicks `who`, the removal saying `keep` if it says, and Bob's node hears.
    fn kick(&self, who: Tid, keep: Option<bool>) {
        let d = SetRoleOpts { sync: SyncFirst::Skip, keep };
        block_on(self.a.set_role(self.g, who, None, d)).unwrap();
        let nudge = Nudge::default();
        until("Bob's node hears", || {
            nudge.at(&self.b);
            self.b.role_on(self.g).unwrap().is_none() && self.b.engine_settled(self.g)
        });
    }

    /// Alice writes on: an edit of `m` and a new message.
    fn write_on(&self) -> Tid {
        let n = self
            .a
            .batch(|w| {
                w.at(self.m, text()).set(&s("edited"))?;
                let n = w.create_owned_by(self.g)?;
                w.group(self.g).add(osis::Member::Item(n))?;
                w.at(n, text()).set(&s("after the kick"))?;
                Ok(n)
            })
            .unwrap();
        block_on(self.a.wait_synced(SyncScope::Group(self.g), W)).unwrap();
        n
    }
}

trait Settled {
    /// No drop left to run for `g`: kept, or no longer read.
    fn engine_settled(&self, g: Tid) -> bool;
}

impl Settled for Osis {
    fn engine_settled(&self, g: Tid) -> bool {
        self.kept_copies().unwrap().contains(&g) || self.at(g, ak("group.0")).get().ok().flatten().is_none()
    }
}

fn read_big(c: &Osis, t: Tid) -> bool {
    use std::io::Read as _;
    let mut got = Vec::new();
    let Ok(Some(mut r)) = c.at(t, file()).stream() else { return false };
    r.read_to_end(&mut got).unwrap();
    got == big()
}

fn hidden(c: &Osis, t: Tid) -> bool {
    !c.knows(t).unwrap() && matches!(c.at(t, text()).get(), Err(Error::UnknownThing { .. }) | Ok(None))
}

fn refused(c: &Osis, t: Tid) -> bool {
    let r = c.commit_set(t, text(), &s("no"));
    matches!(r, Err(Error::Permission { .. }) | Err(Error::UnknownThing { .. }))
}

// spec/permissions.md §3 (Keep), notes/client-port.md §3: the chat: Bob's app reads messages, Bob is kicked with keep, the app still reads and watches them frozen, after a restart of the node too, cannot write or undo, sees no new message; another client of the node reads nothing of it; with erase nothing stays
#[test]
fn chat_kick_as_seen_by_the_app_spec_permissions_3() {
    for keep in [true, false] {
        let x = chat(GrantOpts::default(), Role::Write);
        let (_, secret, app) = x.app(Role::Write);
        let (_, other) = x.stranger();
        assert_eq!(app.at(x.m, text()).get().unwrap(), Some(s("hello")));
        // its own message, before the kick: what the copy holds, and what undo would touch
        app.commit_set(x.m, ak("msg:seen.0"), &s("by the app")).unwrap();
        let watch = watched(&app, x.m, text()).unwrap();
        assert_eq!(watch.current().unwrap(), Some(s("hello")));
        assert!(hidden(&other, x.m) && hidden(&other, x.g));
        block_on(x.b.wait_synced(SyncScope::Group(x.g), W)).unwrap();

        x.kick(x.bob, Some(keep));
        let new = x.write_on();
        let _ = x.b.sync_now();
        std::thread::sleep(Duration::from_millis(200));
        app.settle();

        assert_eq!(x.b.kept_copies().unwrap().contains(&x.g), keep);
        if keep {
            assert_eq!(app.at(x.m, text()).get().unwrap(), Some(s("hello")), "frozen");
            assert_eq!(app.at(x.m, ak("msg:seen.0")).get().unwrap(), Some(s("by the app")));
            assert!(app.groups_of(x.m).unwrap().item_of.contains(&x.g));
            assert!(read_big(&app, x.m), "a large value, by pages");
            assert!(!app.commits(&CommitQuery::new().scope(Scope::Thing(x.m))).unwrap().is_empty());
            // notes/api.md History: its history reads as well, read-only
            let page = app.at(x.m, text()).history(osis::HistoryFrom::Newest, 5).unwrap();
            assert_eq!(page.entries.len(), 1);
            assert_eq!(page.entries[0].body, osis::HistoryBody::Held(Some(s("hello"))));
            assert!(page.complete, "a copy waits for nothing");
            assert_eq!(page, x.b.at(x.m, text()).history(osis::HistoryFrom::Newest, 5).unwrap());
            // a large value's link never shows: its bytes, or too large for a reply
            let big_page = app.at(x.m, file()).history(osis::HistoryFrom::Newest, 5).unwrap();
            assert_eq!(big_page.entries[0].body, osis::HistoryBody::Held(Some(Value::Bytes(big()))));
            let mut w = app.write();
            w.at(x.m, text()).purge(osis::Purge::Change(page.entries[0].commit.id)).unwrap();
            assert!(w.commit().is_err(), "a copy takes no purge");
            assert!(!app.status().unwrap().groups.contains_key(&x.g), "nothing syncs it");
            assert_eq!(watch.current().unwrap(), Some(s("hello")), "the watch goes on");
            assert_eq!(app.kept_copies().unwrap(), vec![x.g]);
            assert_eq!(app.role_on(x.m).unwrap(), None, "no role: this is how an app tells");
            assert!(refused(&app, x.m), "read-only");
            assert!(app.batch(|w| { let n = w.create_owned_by(x.g)?; w.group(x.g).add(osis::Member::Item(n)) }).is_err(), "no new message");
            assert!(matches!(app.undo(&Scope::Thing(x.m)), Err(Error::Permission { .. })), "undo writes nothing");
            assert_eq!(app.at(x.m, ak("msg:seen.0")).get().unwrap(), Some(s("by the app")));
            assert!(hidden(&app, new), "not seen");
            assert!(matches!(app.drop_kept(x.g), Err(Error::Unsupported(_))), "the owner's call");
        } else {
            assert!(hidden(&app, x.m) && hidden(&app, x.g));
            assert_eq!(watch.current().ok().flatten(), None);
            assert!(app.kept_copies().unwrap().is_empty());
        }
        assert!(hidden(&other, x.m) && hidden(&other, x.g), "another client of the node");
        // exactly as a tid nobody knows, on every row (no existence oracle)
        let ghost = Tid::from_bytes([9; 15]);
        let unknown = crate::port_clients::answers(&other, ghost).replace(&format!("{ghost:?}"), "T");
        for t in [x.m, x.g, new] {
            assert_eq!(crate::port_clients::answers(&other, t).replace(&format!("{t:?}"), "T"), unknown);
        }
        assert!(other.kept_copies().unwrap().is_empty());
        let Chat { b, b_store, net, addr, urls, m, g, nc, .. } = x;
        assert_eq!(b.close().unwrap(), osis::Close::Closed);
        until("down", || !app.status().unwrap().remotes[0].connected);
        let b2 = Osis::open(on(&net, "b", &b_store, vec![addr.clone()])).unwrap();
        assert_eq!(b2.client_listen(&urls).unwrap().remove(0), nc);
        until("reconnected", || app.status().unwrap().remotes[0].connected);
        if keep {
            assert_eq!(app.at(m, text()).get().unwrap(), Some(s("hello")), "after a restart");
            assert!(read_big(&app, m));
            until("the watch came back", || watch.current().ok().flatten() == Some(s("hello")));
            assert!(refused(&app, m));
            assert!(hidden(&app, new));
            // a new connection of the same client, after the restart
            let again = attach(&net, &nc, &secret);
            assert_eq!(again.at(m, text()).get().unwrap(), Some(s("hello")));
            // the owner drops it: gone for the app too
            b2.drop_kept(g).unwrap();
            assert!(hidden(&app, m));
            assert!(app.kept_copies().unwrap().is_empty());
        } else {
            assert!(hidden(&app, m));
        }
        assert_eq!(b2.close().unwrap(), osis::Close::Closed);
    }
}

// ---- the rule's two directions, on the simulated world: a handle acting as the client's actor is
// what the port worker runs each row on

use osis::internals::Internals as _;
use osis_sim::world::World;

fn sim(w: &mut World, keep: Option<bool>) -> (Osis, Osis, Tid, Tid, Tid) {
    let host = w.add_host();
    let (a, _) = w.person(1, &[host]);
    let (b, _) = w.person(2, &[host]);
    w.run();
    let card = b.contact_card().unwrap();
    w.run();
    let bob = w.until(a.import_contact(&card), 1000, 10).unwrap();
    let g = sim_group(&a);
    let mut x = a.write();
    let m = x.create_owned_by(g).unwrap();
    x.group(g).add(osis::Member::Item(m)).unwrap();
    x.at(m, text()).set(&s("hello")).unwrap();
    x.commit().unwrap();
    if let Some(k) = keep {
        a.set_keep_default(g, k).unwrap();
    }
    a.grant(g, bob, Role::Write, GrantOpts { invite: Some(Role::Read), ..Default::default() }).unwrap();
    w.run();
    assert_eq!(b.at(m, text()).get().unwrap(), Some(s("hello")));
    (a, b, bob, g, m)
}

fn sim_group(a: &Osis) -> Tid {
    let mut x = a.write();
    let g = x.create().unwrap();
    x.group(a.me()).add(osis::Member::Item(g)).unwrap();
    x.commit().unwrap();
    a.sync(g, &[]).unwrap();
    g
}

fn sim_kick(w: &mut World, a: &Osis, g: Tid, who: Tid, keep: Option<bool>) {
    let d = SetRoleOpts { sync: SyncFirst::Skip, keep };
    w.until(a.set_role(g, who, None, d), 1000, 10).unwrap();
    w.run();
}

/// Alice's group with an item, Bob granted write on it until an hour from now (`keep`: the
/// group's default for endings); a host for both.
fn timed(keep: Option<bool>) -> (World, Osis, Osis, Tid, Tid, Tid, u64, u64) {
    let mut w = World::new();
    let host = w.add_host();
    let (a, _) = w.person(1, &[host]);
    let (b, _) = w.person(2, &[host]);
    w.run();
    let card = b.contact_card().unwrap();
    w.run();
    let bob = w.until(a.import_contact(&card), 1000, 10).unwrap();
    let g = sim_group(&a);
    let mut x = a.write();
    let m = x.create_owned_by(g).unwrap();
    x.group(g).add(osis::Member::Item(m)).unwrap();
    x.at(m, text()).set(&s("hello")).unwrap();
    x.commit().unwrap();
    if let Some(k) = keep {
        a.set_keep_default(g, k).unwrap();
    }
    let (hour, t0) = (3_600_000, w.now());
    a.grant(g, bob, Role::Write, GrantOpts { until: Some(osis::WallMs(t0 + hour)), ..Default::default() }).unwrap();
    w.run();
    assert_eq!(b.at(m, text()).get().unwrap(), Some(s("hello")));
    (w, a, b, bob, g, m, t0, hour)
}

/// Bob's node dropped the group as the default says: erased, or a copy kept.
fn assert_ended(b: &Osis, g: Tid, m: Tid, keep: Option<bool>) {
    assert_eq!(b.kept_copies().unwrap().contains(&g), keep == Some(true), "{keep:?}");
    assert_eq!(b.at(m, text()).get().unwrap().is_some(), keep == Some(true), "{keep:?}");
    assert!(b.role_on(g).unwrap().is_none());
}

// spec/permissions.md §2 (an `until` passing), §3 Keep: a holder online past its `until`, nobody writing a role commit: its labels are heard out at once, and it drops by itself, erasing or keeping as the default says
#[test]
fn an_until_ending_drops_by_itself_spec_permissions_2() {
    for keep in [None, Some(true)] {
        let (mut w, _a, b, _, g, m, _, hour) = timed(keep);
        w.advance(2 * hour);
        w.run();
        assert_ended(&b, g, m, keep);
    }
}

// spec/permissions.md §2 (an `until` passing): a holder offline past its `until`, with a renewal made meanwhile and a write unsent: nothing goes on the time alone, erase or keep; back online the renewal arrives, the write goes up, and it reads and writes on
#[test]
fn an_until_passing_offline_loses_nothing_spec_permissions_2() {
    for keep in [None, Some(true)] {
        let (mut w, a, b, bob, g, m, t0, hour) = timed(keep);
        w.set_online(&b, false);
        let mut x = b.write();
        let n = x.create_owned_by(g).unwrap();
        x.group(g).add(osis::Member::Item(n)).unwrap();
        x.at(n, text()).set(&s("unsent")).unwrap();
        let own = n;
        x.commit().unwrap();
        w.advance(1000);
        a.grant(g, bob, Role::Write, GrantOpts { until: Some(osis::WallMs(t0 + 1000 * hour)), ..Default::default() }).unwrap();
        w.run();
        w.advance(2 * hour);
        w.run();
        assert_eq!(b.at(m, text()).get().unwrap(), Some(s("hello")), "{keep:?}");
        assert_eq!(b.at(own, text()).get().unwrap(), Some(s("unsent")), "{keep:?}");
        assert!(b.kept_copies().unwrap().is_empty(), "{keep:?}");
        w.set_online(&b, true);
        w.advance(60_000);
        w.run();
        assert_eq!(b.role_on(g).unwrap(), Some(Role::Write), "{keep:?}");
        assert_eq!(a.at(own, text()).get().unwrap(), Some(s("unsent")), "{keep:?}");
        b.commit_set(m, text(), &s("after")).unwrap();
        w.run();
        assert_eq!(a.at(m, text()).get().unwrap(), Some(s("after")), "{keep:?}");
    }
}

// spec/permissions.md §2 (an `until` passing), §3 Keep: no renewal: offline nothing goes; back online its labels are heard out, its unsent write from before the `until` going up first (nobody rotated meanwhile: Alice is away too), and then the default holds: erased or kept; Alice back reads the write
#[test]
fn an_until_ended_offline_goes_when_heard_out_spec_permissions_2() {
    for keep in [None, Some(true)] {
        let (mut w, a, b, _, g, m, _, hour) = timed(keep);
        w.set_online(&b, false);
        w.set_online(&a, false);
        let mut x = b.write();
        let n = x.create_owned_by(g).unwrap();
        x.group(g).add(osis::Member::Item(n)).unwrap();
        x.at(n, text()).set(&s("unsent")).unwrap();
        let own = n;
        x.commit().unwrap();
        w.advance(2 * hour);
        w.run();
        assert_eq!(b.at(m, text()).get().unwrap(), Some(s("hello")), "{keep:?}");
        assert!(b.kept_copies().unwrap().is_empty(), "{keep:?}");
        w.set_online(&b, true);
        w.advance(60_000);
        w.run();
        assert_ended(&b, g, m, keep);
        w.set_online(&a, true);
        w.advance(60_000);
        w.run();
        assert_eq!(a.at(own, text()).get().unwrap(), Some(s("unsent")), "{keep:?}: a valid write made before the `until`");
    }
}

// spec/permissions.md §2 (an `until` passing): a host out of reach for good does not hold an `until` off forever: `LOST_HEARD_WAIT_MS` (`ROLE_KEEP`) after the node first found its role gone (here at the `until`, its clock running), it goes by the time alone
#[test]
fn an_until_ended_out_of_reach_goes_past_role_keep_spec_permissions_2() {
    for keep in [None, Some(true)] {
        let (mut w, _a, b, _, g, m, _, hour) = timed(keep);
        w.set_online(&b, false);
        w.advance(2 * hour);
        w.run();
        let wait = osis_node::rotation::LOST_HEARD_WAIT_MS;
        w.advance(wait - hour);
        w.run();
        assert_eq!(b.at(m, text()).get().unwrap(), Some(s("hello")), "{keep:?}");
        assert!(b.kept_copies().unwrap().is_empty(), "{keep:?}");
        w.advance(2 * hour);
        w.run();
        assert_ended(&b, g, m, keep);
    }
}

// spec/permissions.md §2 (an `until` passing), §3 (re-seal): a holder online past its `until`, the renewal made only later: it erased, and is re-sealed through the stranded heartbeat: it returns, not at once
#[test]
fn a_late_renewal_comes_back_by_a_re_seal_spec_permissions_2() {
    let (mut w, a, b, bob, g, m, t0, hour) = timed(None);
    w.advance(2 * hour);
    w.run();
    assert_eq!(b.at(m, text()).get().unwrap(), None, "erased: the default says so, and it heard no more");
    // at its old role: below it `grant` is refused (it would undo what Bob wrote)
    a.grant(g, bob, Role::Write, GrantOpts { until: Some(osis::WallMs(t0 + 1000 * hour)), ..Default::default() }).unwrap();
    a.commit_set(m, text(), &s("during")).unwrap();
    w.run();
    let mut hours = 2;
    while b.at(m, text()).get().unwrap().is_none() {
        hours += 1;
        assert!(hours < 200, "never came back");
        w.advance(hour);
        w.run();
    }
    assert_eq!(b.at(m, text()).get().unwrap(), Some(s("during")));
}

// spec/permissions.md §3 (Keep), notes/client-port.md §3: a client reads the copy while it holds a role on what the copy hangs on: its role ended before the kick or after it, it reads nothing; granted one after the kick (the person's new app), it reads; a client with a role on another thing of the person reads nothing
#[test]
fn a_clients_read_follows_its_role_on_the_holder_spec_permissions_3() {
    let mut w = World::new();
    let (a, b, bob, g, m) = sim(&mut w, Some(true));
    let mk = |role: Option<Role>| {
        let (actor, _) = b.add_client(None).unwrap();
        if let Some(r) = role {
            b.grant(bob, actor, r, Default::default()).unwrap();
        }
        actor
    };
    let (reader, leaves_after, left_before, none) = (mk(Some(Role::Read)), mk(Some(Role::Write)), mk(Some(Role::Read)), mk(None));
    let elsewhere = mk(None);
    let mut x = b.write();
    let t = x.create_owned_by(bob).unwrap();
    x.at(t, text()).set(&s("side")).unwrap();
    let side = t;
    x.commit().unwrap();
    b.grant(side, elsewhere, Role::Admin, Default::default()).unwrap();
    let skip = || SetRoleOpts { sync: SyncFirst::Skip, keep: None };
    w.run();
    for c in [reader, leaves_after, left_before] {
        assert_eq!(b.acting_as(c).at(m, text()).get().unwrap(), Some(s("hello")));
    }
    w.until(b.set_role(bob, left_before, None, skip()), 1000, 10).unwrap();
    w.run();
    sim_kick(&mut w, &a, g, bob, None);
    assert_eq!(b.kept_copies().unwrap(), vec![g]);
    let reads = |c: Tid| b.acting_as(c).at(m, text()).get().ok().flatten() == Some(s("hello"));
    assert!(reads(reader) && reads(leaves_after));
    assert!(!reads(left_before) && !reads(none) && !reads(elsewhere));
    for c in [left_before, none, elsewhere] {
        assert!(!b.acting_as(c).knows(m).unwrap() && !b.acting_as(c).knows(g).unwrap(), "exactly as an unknown thing");
        assert!(b.acting_as(c).kept_copies().unwrap().is_empty());
    }
    assert_eq!(b.acting_as(reader).kept_copies().unwrap(), vec![g]);
    // a reader of the holder writes nothing, whatever its role on the holder
    assert!(refused(&b.acting_as(leaves_after), m));
    w.until(b.set_role(bob, leaves_after, None, skip()), 1000, 10).unwrap();
    w.run();
    assert!(!reads(leaves_after));
    let new = mk(Some(Role::Read));
    w.run();
    assert!(reads(new), "the person's new app");
}

// spec/permissions.md §3 (Keep), notes/client-port.md §3: a client on the chat by an edge of its own keeps through that edge: its copy hangs on the client's actor, so it reads, and the person's other clients that hold no role on it do not; its own edge erasing while its person's keeps, it does not read: the edge it lost said so, though the node keeps for the person
#[test]
fn a_client_with_its_own_edge_spec_permissions_3() {
    for (own, person, reads) in [(Some(true), Some(false), true), (Some(false), Some(true), false), (Some(true), Some(true), true)] {
        let mut w = World::new();
        // each one's word is said at its kick
        let (a, b, bob, g, m) = sim(&mut w, Some(true));
        let (c, _) = b.add_client(None).unwrap();
        let (other, _) = b.add_client(None).unwrap();
        b.grant(g, c, Role::Read, GrantOpts::default()).unwrap();
        w.run();
        assert_eq!(b.acting_as(c).at(m, text()).get().unwrap(), Some(s("hello")));
        assert!(!b.acting_as(other).knows(m).unwrap());
        sim_kick(&mut w, &a, g, c, own);
        sim_kick(&mut w, &a, g, bob, person);
        assert_eq!(b.acting_as(c).at(m, text()).get().ok().flatten() == Some(s("hello")), reads, "own {own:?} person {person:?}");
        assert_eq!(b.at(m, text()).get().unwrap(), Some(s("hello")), "the node keeps by either");
        assert!(!b.acting_as(other).knows(m).unwrap());
        assert!(refused(&b.acting_as(c), m));
    }
}

// spec/permissions.md §3 (Keep), notes/client-port.md §3: a chat read through a realm Bob stays in, the realm kicked from it: the copy is the person's, so his app reads it; a client that is only a member of the realm, from before the kick or after it, reads the realm and nothing of the chat
#[test]
fn a_member_of_the_holder_reads_no_copy_spec_permissions_3() {
    let mut w = World::new();
    let (a, b, bob, f, in_f) = sim(&mut w, Some(true));
    let chat = sim_group(&a);
    let mut x = a.write();
    let m = x.create_owned_by(chat).unwrap();
    x.group(chat).add(osis::Member::Item(m)).unwrap();
    x.at(m, text()).set(&s("in the chat")).unwrap();
    x.commit().unwrap();
    a.set_keep_default(chat, true).unwrap();
    a.grant(chat, f, Role::Read, GrantOpts::default()).unwrap();
    let (app, _) = b.add_client(None).unwrap();
    let (before, _) = b.add_client(None).unwrap();
    b.grant(bob, app, Role::Read, Default::default()).unwrap();
    b.grant(f, before, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(b.acting_as(before).at(m, text()).get().unwrap(), Some(s("in the chat")), "live, through the realm");
    sim_kick(&mut w, &a, chat, f, None);
    assert_eq!(b.kept_copies().unwrap(), vec![chat]);
    assert!(b.role_on(f).unwrap().is_some());
    let (after, _) = b.add_client(None).unwrap();
    b.grant(f, after, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(b.acting_as(app).at(m, text()).get().unwrap(), Some(s("in the chat")));
    assert_eq!(b.acting_as(app).kept_copies().unwrap(), vec![chat]);
    for c in [before, after] {
        let c = b.acting_as(c);
        assert_eq!(c.at(in_f, text()).get().unwrap(), Some(s("hello")), "the realm itself");
        assert!(!c.knows(m).unwrap() && !c.knows(chat).unwrap());
        assert!(c.kept_copies().unwrap().is_empty());
    }
}

// spec/wire.md §11.2, notes/client-port.md §3: an app watching a copy, its role on the person ended: it reads nothing from then on, and its watch gets nothing more and lapses at the next change
#[test]
fn a_watch_on_a_copy_ends_with_the_role_spec_permissions_3() {
    let x = chat(GrantOpts::default(), Role::Write);
    x.a.set_keep_default(x.g, true).unwrap();
    let (actor, _, app) = x.app(Role::Read);
    let watch = watched(&app, x.m, text()).unwrap();
    assert_eq!(watch.current().unwrap(), Some(s("hello")));
    x.kick(x.bob, None);
    assert_eq!(watch.current().unwrap(), Some(s("hello")));
    let d = SetRoleOpts { sync: SyncFirst::Skip, keep: None };
    block_on(x.b.set_role(x.bob, actor, None, d)).unwrap();
    until("hidden", || hidden(&app, x.m));
    assert!(app.kept_copies().unwrap().is_empty());
    assert_eq!(watch.current().unwrap(), Some(s("hello")), "what it had read: nothing more comes");
    x.b.drop_kept(x.g).unwrap();
    app.settle();
    assert!(watch.current().is_err(), "it lapses at the next change, not telling what changed");
}

// spec/permissions.md §3 (Keep), notes/client-port.md §3: through a holder that is itself kept: a chat read through a realm group, Bob kicked from the group: the app reads both, the chain ending at the person; a client on neither reads neither
#[test]
fn a_client_reads_through_a_kept_holder_spec_permissions_3() {
    let mut w = World::new();
    let (a, b, bob, f, _) = sim(&mut w, Some(true));
    let chat = sim_group(&a);
    let mut x = a.write();
    let m = x.create_owned_by(chat).unwrap();
    x.group(chat).add(osis::Member::Item(m)).unwrap();
    x.at(m, text()).set(&s("in the chat")).unwrap();
    x.commit().unwrap();
    a.grant(chat, f, Role::Read, Default::default()).unwrap();
    let (app, _) = b.add_client(None).unwrap();
    let (other, _) = b.add_client(None).unwrap();
    b.grant(bob, app, Role::Read, Default::default()).unwrap();
    w.run();
    assert_eq!(b.acting_as(app).at(m, text()).get().unwrap(), Some(s("in the chat")));
    sim_kick(&mut w, &a, f, bob, None);
    let kept = b.kept_copies().unwrap();
    assert!(kept.contains(&f) && kept.contains(&chat), "{kept:?}");
    assert_eq!(b.acting_as(app).at(m, text()).get().unwrap(), Some(s("in the chat")));
    assert!(!b.acting_as(other).knows(m).unwrap() && !b.acting_as(other).knows(f).unwrap());
    b.drop_kept(f).unwrap();
    assert!(!b.acting_as(app).knows(m).unwrap(), "what hung on it goes");
}

// spec/permissions.md §1 (ownerless things), §3 (Keep): a chat with no owner keeps alike: Bob kicked, the copy stands, his app reads it, another client does not
#[test]
fn an_ownerless_chat_keeps_spec_permissions_3() {
    let mut w = World::new();
    let host = w.add_host();
    let (a, _) = w.person(1, &[host]);
    let (b, _) = w.person(2, &[host]);
    w.run();
    let card = b.contact_card().unwrap();
    w.run();
    let bob = w.until(a.import_contact(&card), 1000, 10).unwrap();
    let g = a.create_ownerless(a.me()).unwrap();
    let mut x = a.write();
    x.group(a.me()).add(osis::Member::Item(g)).unwrap();
    x.commit().unwrap();
    a.sync(g, &[]).unwrap();
    let mut x = a.write();
    let m = x.create_owned_by(g).unwrap();
    x.group(g).add(osis::Member::Item(m)).unwrap();
    x.at(m, text()).set(&s("hello")).unwrap();
    x.commit().unwrap();
    a.set_keep_default(g, true).unwrap();
    a.grant(g, bob, Role::Write, GrantOpts::default()).unwrap();
    w.run();
    assert_eq!(b.at(m, text()).get().unwrap(), Some(s("hello")));
    let (app, _) = b.add_client(None).unwrap();
    let (other, _) = b.add_client(None).unwrap();
    b.grant(bob, app, Role::Read, Default::default()).unwrap();
    w.run();
    sim_kick(&mut w, &a, g, bob, None);
    assert_eq!(b.kept_copies().unwrap(), vec![g]);
    assert_eq!(b.at(m, text()).get().unwrap(), Some(s("hello")));
    assert_eq!(b.acting_as(app).at(m, text()).get().unwrap(), Some(s("hello")));
    assert!(!b.acting_as(other).knows(m).unwrap() && !b.acting_as(other).knows(g).unwrap());
    assert!(refused(&b, m));
}

// spec/permissions.md §3 (Keep): a commit the node takes for what else it carries: content on a copy stays out, its purge of a copy's aspect applies (nothing promises it does not), and the thing beside it moves on
#[test]
fn a_commit_beside_a_copy_spec_permissions_3() {
    let mut w = World::new();
    let (a, b, bob, g, m) = sim(&mut w, Some(true));
    let live = sim_group(&a);
    let mut x = a.write();
    let u = x.create_owned_by(live).unwrap();
    x.group(live).add(osis::Member::Item(u)).unwrap();
    x.at(u, text()).set(&s("live")).unwrap();
    x.commit().unwrap();
    a.grant(live, bob, Role::Read, Default::default()).unwrap();
    let second = ak("t:second.0");
    a.commit_set(m, second.clone(), &s("second")).unwrap();
    w.run();
    assert_eq!(b.at(u, text()).get().unwrap(), Some(s("live")));
    sim_kick(&mut w, &a, g, bob, None);
    assert_eq!(b.kept_copies().unwrap(), vec![g]);
    let mut x = a.write();
    x.at(u, text()).set(&s("live 2")).unwrap();
    x.at(m, text()).set(&s("edited")).unwrap();
    x.at(m, second.clone()).purge(osis::Purge::All).unwrap();
    x.commit().unwrap();
    w.run();
    assert_eq!(b.at(u, text()).get().unwrap(), Some(s("live 2")));
    assert_eq!(b.at(m, text()).get().unwrap(), Some(s("hello")), "frozen");
    assert_eq!(b.at(m, second).get().unwrap(), None);
    assert_eq!(b.kept_copies().unwrap(), vec![g]);
}

// spec/permissions.md §3 (Keep; uploads and serves nothing of it): what Bob's node holds of a copy goes nowhere: placed in a group of his, shared, it does not reach that group's reader; his own write on it, unsent at the kick, stays out at Alice's
#[test]
fn a_copy_goes_nowhere_spec_permissions_3() {
    let mut w = World::new();
    let (a, b, bob, g, m) = sim(&mut w, Some(true));
    let (c, _) = w.person(3, &[0]);
    w.run();
    let card = c.contact_card().unwrap();
    w.run();
    let carol = w.until(b.import_contact(&card), 1000, 10).unwrap();
    let own = sim_group(&b);
    b.grant(own, carol, Role::Read, Default::default()).unwrap();
    let live = sim_group(&a);
    let mut x = a.write();
    let u = x.create_owned_by(live).unwrap();
    x.group(live).add(osis::Member::Item(u)).unwrap();
    x.at(u, text()).set(&s("live")).unwrap();
    x.commit().unwrap();
    a.grant(live, bob, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(b.at(u, text()).get().unwrap(), Some(s("live")));
    w.set_online(&b, false);
    let mut x = b.write();
    x.at(u, text()).set(&s("by bob")).unwrap();
    x.at(m, text()).set(&s("by bob, unsent")).unwrap();
    x.commit().unwrap();
    let d = SetRoleOpts { sync: SyncFirst::Skip, keep: None };
    w.until(a.set_role(g, bob, None, d), 1000, 10).unwrap();
    w.run();
    w.set_online(&b, true);
    w.run();
    w.advance(3_600_000);
    w.run();
    assert_eq!(b.kept_copies().unwrap(), vec![g]);
    assert_eq!(a.at(m, text()).get().unwrap(), Some(s("hello")));
    assert_eq!(b.at(m, text()).get().unwrap(), Some(s("hello")), "past the kick's frontier: validity follows what the node holds");
    let mut x = b.write();
    x.group(own).add(osis::Member::Item(m)).unwrap();
    x.commit().unwrap();
    let mut x = b.write();
    let i = x.create_owned_by(own).unwrap();
    x.group(own).add(osis::Member::Item(i)).unwrap();
    x.at(i, text()).set(&s("in own")).unwrap();
    let item = i;
    x.commit().unwrap();
    w.run();
    assert_eq!(c.at(item, text()).get().unwrap(), Some(s("in own")));
    assert!(c.at(m, text()).get().ok().flatten().is_none(), "its name at most");
}

// spec/permissions.md §3 (Keep; it writes nothing there), notes/client-port.md §3: a client that reads a copy cannot place it in a group it writes
#[test]
fn a_client_places_no_copy_spec_permissions_3() {
    let c = chat(GrantOpts::default(), Role::Write);
    let (actor, _, app) = c.app(Role::Admin);
    let own = c.b.batch(|w| { let o = w.create()?; w.group(c.b.me()).add(osis::Member::Item(o))?; Ok(o) }).unwrap();
    c.b.grant(own, actor, Role::Write, Default::default()).unwrap();
    c.kick(c.bob, Some(true));
    until("the app reads the copy", || app.at(c.m, text()).get().ok().flatten().is_some());
    until("the app writes its group", || app.batch(|w| { let n = w.create_owned_by(own)?; w.group(own).add(osis::Member::Item(n)) }).is_ok());
    assert!(matches!(app.batch(|w| w.group(own).add(osis::Member::Item(c.m))), Err(Error::Permission { .. })));
}

// spec/permissions.md §3 (Keep; ephemeral aspects are not part of a copy, and hold until restart as on any lost thing: issues/ephemeral-data.md): an ephemeral write reaches no copy, and neither the node nor its client writes one; a client reads no ephemeral thing of the chat
#[test]
fn ephemeral_data_and_a_copy_spec_permissions_3() {
    let mut w = World::new();
    let (a, b, bob, g, m) = sim(&mut w, Some(true));
    let (app, _) = b.add_client(None).unwrap();
    b.grant(bob, app, Role::Read, Default::default()).unwrap();
    let e = ak("t:e.0~");
    a.commit_set(m, e.clone(), &s("before")).unwrap();
    let mut x = a.write();
    let t = x.create_owned_by(g).unwrap();
    x.group(g).add(osis::Member::Item(t)).unwrap();
    x.at(t, e.clone()).set(&s("before")).unwrap();
    let thing = t;
    x.commit().unwrap();
    w.run();
    assert_eq!(b.at(thing, e.clone()).get().unwrap(), Some(s("before")));
    sim_kick(&mut w, &a, g, bob, None);
    a.commit_set(m, e.clone(), &s("after")).unwrap();
    a.commit_set(thing, e.clone(), &s("after")).unwrap();
    w.run();
    let c = b.acting_as(app);
    assert_eq!(b.at(m, e.clone()).get().unwrap(), Some(s("before")));
    assert_eq!(b.at(thing, e.clone()).get().unwrap(), Some(s("before")));
    assert!(!c.knows(thing).unwrap());
    for db in [&b, &c] {
        assert!(matches!(db.commit_set(m, e.clone(), &s("no")), Err(Error::Permission { .. })));
        assert!(db.commit_set(thing, e.clone(), &s("no")).is_err());
    }
    w.run();
    assert_eq!(a.at(m, e.clone()).get().unwrap(), Some(s("after")));
    assert_eq!(a.at(thing, e).get().unwrap(), Some(s("after")));
}

// spec/permissions.md §3 (Keep): a chat read through a realm Bob stays in: the kick of the realm from the chat leaves a copy beside a label that goes on syncing, through restarts; the label settles, the realm's new items arrive
#[test]
fn a_copy_beside_a_live_holder_spec_permissions_3() {
    let x0 = chat(GrantOpts::default(), Role::Write);
    let (h, a, b) = (x0.g, &x0.a, &x0.b);
    let mut w = a.write();
    let g = w.create().unwrap();
    w.group(a.me()).add(osis::Member::Item(g)).unwrap();
    let xg = g;
    w.commit().unwrap();
    a.sync(xg, &[]).unwrap();
    a.set_keep_default(xg, true).unwrap();
    a.grant(xg, h, Role::Read, GrantOpts::default()).unwrap();
    let mut w = a.write();
    let t = w.create_owned_by(xg).unwrap();
    w.group(h).add(osis::Member::Item(t)).unwrap();
    w.at(t, text()).set(&s("before")).unwrap();
    w.commit().unwrap();
    let nudge = Nudge::default();
    until("Bob has t", || { nudge.at(b); b.at(t, text()).get().ok().flatten() == Some(s("before")) });
    let d = SetRoleOpts { sync: SyncFirst::Skip, keep: None };
    block_on(a.set_role(xg, h, None, d)).unwrap();
    let nudge = Nudge::default();
    until("kept", || { nudge.at(b); b.kept_copies().unwrap().contains(&xg) });
    assert!(b.role_on(h).unwrap().is_some() && b.role_on(xg).unwrap().is_none());
    a.commit_set(t, text(), &s("after")).unwrap();
    let mut w = a.write();
    let u = w.create_owned_by(h).unwrap();
    w.group(h).add(osis::Member::Item(u)).unwrap();
    w.at(u, text()).set(&s("live")).unwrap();
    w.commit().unwrap();
    let nudge = Nudge::default();
    until("live", || { nudge.at(b); b.at(u, text()).get().ok().flatten() == Some(s("live")) });
    assert_eq!(b.at(t, text()).get().unwrap(), Some(s("before")));
    block_on(b.wait_synced(SyncScope::Group(h), W)).unwrap();
    let Chat { b, b_store, net, addr, .. } = x0;
    assert_eq!(b.close().unwrap(), osis::Close::Closed);
    let b2 = Osis::open(on(&net, "b", &b_store, vec![addr.clone()])).unwrap();
    block_on(b2.wait_synced(SyncScope::Group(h), W)).unwrap();
    assert_eq!(b2.at(t, text()).get().unwrap(), Some(s("before")));
    assert_eq!(b2.at(u, text()).get().unwrap(), Some(s("live")));
    assert!(b2.kept_copies().unwrap().contains(&xg));
    assert_eq!(b2.close().unwrap(), osis::Close::Closed);
}

// spec/sync.md §2 (Route), notes/client-port.md Routes for client actors: a thing granted to Bob that nothing carries shows without a route at Bob's node and to Bob's app (a thin client acting as his actor), and the app reads it once the granter syncs it
#[test]
fn a_thin_client_sees_the_missing_route_and_the_thing_once_synced() {
    let x = chat(GrantOpts::default(), Role::Read);
    let (_, _, app) = x.app(Role::Read);
    let t = x
        .a
        .batch(|w| {
            let t = w.create()?;
            w.at(t, text()).set(&s("plain"))?;
            Ok(t)
        })
        .unwrap();
    x.a.grant(t, x.bob, Role::Read, Default::default()).unwrap();
    let no_route = |db: &Osis| db.status().unwrap().groups.get(&t).is_some_and(|g| g.state == osis::SyncState::NoRoute && g.unrouted == vec![x.bob]);
    assert!(no_route(&x.a), "the granter");
    let nudge = Nudge::default();
    until("Bob's node and his app show the missing route", || {
        nudge.at(&x.b);
        no_route(&x.b) && no_route(&app)
    });
    assert_ne!(app.at(t, text()).get().ok().flatten(), Some(s("plain")));
    // sharing is not for a thin client (`method::for_client`)
    assert!(matches!(app.grant(t, x.bob, Role::Read, Default::default()), Err(osis::Error::Unsupported(_))));
    x.a.sync(t, &[]).unwrap();
    until("the app reads it", || {
        nudge.at(&x.b);
        app.at(t, text()).get().ok().flatten() == Some(s("plain"))
    });
    assert!(!no_route(&x.a) && !no_route(&x.b) && !no_route(&app));
    until("Bob's node syncs it", || x.b.status().unwrap().groups.get(&t).is_some_and(|g| g.state == osis::SyncState::Synced));
}
