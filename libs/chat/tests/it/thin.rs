//! A real thin client over the client port (no sim: it needs a running node). spec: none (notes/client-port.md).
use osis_chat::*;
use super::{leave, participants};
use osis::{Address, Body, CommitEvent, CommitPos, MemStore, Osis, Role, Runtime, Store, SyncScope};
use std::future::Future;
use std::sync::mpsc::channel;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

const W: Duration = Duration::from_secs(20);

fn on(net: &osis_transport::Net, ep: &str, hosts: Vec<Address>) -> osis::internals::Opening {
    let mut c = osis::internals::Opening::at(Store::Memory(MemStore::new()));
    c.runtime = Runtime::Own;
    c.app.internals.transport = Some(net.endpoint(ep));
    c.hosts = hosts;
    c.app.internals.connection_wait = Some(W);
    c.direct_sync = false;
    c
}

fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    let end = Instant::now() + W;
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        assert!(Instant::now() < end, "timed out");
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn newest_text(db: &Osis, c: osis::Tid) -> Option<String> {
    match Timeline::new(db, c).unwrap().older(db, 1).unwrap().messages.pop()?.body {
        Body::Held(Some(m)) => Some(m.text),
        b => Some(format!("{b:?}")),
    }
}

fn post(db: &Osis, c: osis::Tid, text: &str) -> osis::Result<CommitPos> {
    let mut w = db.write();
    w.at(c, schema::MSG).fire(&schema::Message { text: text.into(), name: None, reply_to: None, edit: None })?;
    Ok(w.commit()?.unwrap().pos())
}

// notes/client-port.md §3: an app on a participant's node as a thin client: reads pages and a watch through the port; with write of its own it posts under its own actor; a reader may not; its own edit works
#[test]
fn thin_client_reads_watches_posts_spec_client_port() {
    let net = osis_transport::Net::new(5);
    let peer = osis::internals::create(on(&net, "s", vec![])).unwrap();
    peer.set_serving(Some(osis::Serving { listen: vec!["mem://s".parse().unwrap()], admit: osis::Admit::Open, ..Default::default() })).unwrap();
    let end = Instant::now() + W;
    while peer.serving_address().unwrap().is_none() {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
    let addr = peer.serving_address().unwrap().unwrap();
    let n = osis::internals::create(on(&net, "n", vec![addr])).unwrap();
    let c = create(&n, &Options::default()).unwrap();
    block_on(n.wait_synced(SyncScope::All)).unwrap();
    post(&n, c, "first").unwrap();
    let nc = n.client_listen(&["mem://clients".parse().unwrap()]).unwrap().remove(0);
    let (actor, secret) = n.add_client(None).unwrap();
    n.grant(c, actor, Role::Read, Default::default()).unwrap();
    let mut cfg = osis::internals::Opening::memory();
    cfg.app.internals.transport = Some(net.endpoint("app"));
    cfg.app.internals.connection_wait = Some(W);
    let app = block_on(osis::internals::connect(&nc, &secret, cfg)).unwrap();
    assert_eq!(app.me(), actor);
    assert_eq!(newest_text(&app, c).as_deref(), Some("first"));
    let (tx, rx) = channel();
    let _w = app.at(c, schema::MSG).on_fire(move |_, e| drop(tx.send(e))).unwrap();
    let second = post(&n, c, "second").unwrap();
    let got = rx.recv_timeout(W).unwrap();
    assert!(matches!(&got, CommitEvent::Commit { commit: Some(k), .. } if k.pos() == second), "{got:?}");
    assert!(post(&app, c, "a reader").is_err());
    n.grant(c, actor, Role::Write, Default::default()).unwrap();
    let end = Instant::now() + W;
    let mine = loop {
        match post(&app, c, "from the app") {
            Ok(i) => break i,
            Err(e) => assert!(Instant::now() < end, "{e:?}"),
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let m = find(&n, c, &mine).unwrap().unwrap();
    assert_eq!(m.sender, actor, "a client is its own sender");
    edit(&app, c, &find(&app, c, &mine).unwrap().unwrap(), "fixed").unwrap();
    assert_eq!(newest_text(&n, c).as_deref(), Some("fixed"));
    // the node gone: a participant list says so, and `leave` acts on no empty answer
    net.partition("app", "n");
    net.disconnect("app", "n");
    let end = Instant::now() + W;
    while app.has_content(c).is_ok() {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(matches!(participants(&app, c), Err(osis::Error::Network(_))));
    assert!(matches!(leave(&app, c), Err(osis::Error::Network(_))));
    assert!(n.grants(c).unwrap().contains_key(&actor));
    // back: a client leaves as anyone does, and what it left reads as unknown
    net.heal("app", "n");
    let end = Instant::now() + W;
    while app.has_content(c).is_err() {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(participants(&app, c).unwrap().contains_key(&actor));
    leave(&app, c).unwrap();
    assert!(!n.grants(c).unwrap().contains_key(&actor));
    assert!(!app.has_content(c).unwrap());
}

/// Chat `c`'s sync state at `db` once a status event shows `done` of it (`HANG` only stops a hung
/// run: what is checked is the event).
fn wait_state(db: &Osis, c: osis::Tid, done: impl Fn(&osis::GroupSync) -> bool) -> osis::GroupSync {
    const HANG: Duration = Duration::from_secs(300);
    let (tx, rx) = channel();
    let _s = db.on_status_change(move |_, s| drop(tx.send(s.ok().and_then(|s| s.groups.get(&c).cloned())))).unwrap();
    let end = Instant::now() + HANG;
    let mut last = None;
    loop {
        match rx.recv_timeout(end.saturating_duration_since(Instant::now())) {
            Ok(Some(s)) if done(&s) => return s,
            Ok(s) => last = s.or(last),
            Err(_) => panic!("hung: {last:?}"),
        }
    }
}

// notes/chat.md Create, spec/data-model.md §9 (`host^.0` `own`): a chat's first admin is its maker's account, so the maker's serving node takes it under `admit own`; another account's chat it refuses
#[test]
fn own_serving_node_takes_a_chat_spec_data_model_9() {
    use osis::internals::Internals;
    let net = osis_transport::Net::new(7);
    let cfg = |ep: &str, hosts: Vec<Address>| {
        let mut c = on(&net, ep, hosts);
        c.direct_sync = true;
        c
    };
    let a = osis::internals::create(cfg("a", vec![])).unwrap();
    let j = osis::internals::pair(cfg("h", vec![]), &a.pair_offer().unwrap()).unwrap();
    let (_, reply) = a.pair_accept(j.request()).unwrap();
    let dev = j.finish(&reply).unwrap();
    let url: osis::Url = "mem://h".parse().unwrap();
    dev.set_serving(Some(osis::Serving { listen: vec![url.clone()], admit: osis::Admit::Own, ..Default::default() })).unwrap();
    // a fixed listen URL: the address is known before it listens
    let addr = Address::new(&url, dev.serving_key().unwrap().unwrap());
    a.add_peer(&addr).unwrap();
    let b = osis::internals::create(cfg("b", vec![addr.clone()])).unwrap();
    // the refused-for-now back-off (5 s) shortened: a new label is refused until the host has its record
    for x in [&a, &b] {
        x.sync_engine(|s| s.config_mut().retry_ms = 100);
    }
    let theirs = create(&b, &Options::default()).unwrap();
    let mine = create(&a, &Options::default()).unwrap();
    wait_state(&a, mine, |s| s.state == osis::SyncState::Synced && s.refused_by.is_empty());
    let s = wait_state(&b, theirs, |s| !s.refused_by.is_empty());
    assert_eq!((s.state, s.refused_by), (osis::SyncState::Refused, vec![addr]), "another account's chat");
}
