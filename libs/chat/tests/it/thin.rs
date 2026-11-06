//! A real thin client over the client port (no sim: it needs a running node). spec: none (notes/client-port.md).
use osis_chat::*;
use osis::{Address, MemStore, Osis, Role, Runtime, Store, SyncScope};
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

fn newest_text(db: &Osis, c: osis::Tid) -> Option<Body> {
    Timeline::new(db, c).unwrap().older(db, 1).unwrap().messages.pop().map(|m| m.body)
}

// notes/client-port.md §3: an app on a participant's node as a thin client: reads pages and a watch through the port; with write of its own it posts under its own actor; a reader may not; its own edit works
#[test]
fn thin_client_reads_watches_posts_spec_client_port() {
    let net = osis_transport::Net::new(5);
    let peer = osis::internals::create(on(&net, "s", vec![])).unwrap().0;
    peer.set_serving(Some(osis::Serving { listen: vec!["mem://s".parse().unwrap()], admit: osis::Admit::Open, ..Default::default() })).unwrap();
    let end = Instant::now() + W;
    while peer.serving_address().unwrap().is_none() {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
    let addr = peer.serving_address().unwrap().unwrap();
    let n = osis::internals::create(on(&net, "n", vec![addr])).unwrap().0;
    let c = create(&n, &Options::default()).unwrap();
    block_on(n.wait_synced(SyncScope::AllWithSavedPeers)).unwrap();
    post(&n, c, "first").unwrap();
    let nc = n.client_listen(&["mem://clients".parse().unwrap()]).unwrap().remove(0);
    let (actor, secret) = n.add_client(None).unwrap();
    n.grant(c, actor, Role::Read, Default::default()).unwrap();
    let mut cfg = osis::internals::Opening::memory();
    cfg.app.internals.transport = Some(net.endpoint("app"));
    cfg.app.internals.connection_wait = Some(W);
    let app = block_on(osis::internals::connect(&nc, &secret, cfg)).unwrap();
    assert_eq!(app.me(), actor);
    assert_eq!(newest_text(&app, c), Some(Body::Text("first".into())));
    let (tx, rx) = channel();
    let _w = on_event(&app, c, move |_, e| drop(tx.send(e))).unwrap();
    let second = post(&n, c, "second").unwrap();
    let got = rx.recv_timeout(W).unwrap();
    assert!(matches!(&got, Event::Entry(e) if e.id == second), "{got:?}");
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
    assert_eq!(newest_text(&n, c), Some(Body::Text("fixed".into())));
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
