//! Chats across two people (commits delivered by hand, as in `share`): list, open, send, receive,
//! replies and the sender's name. Joining by link needs a host: checked by hand (notes/app.md Chat).
use osis::internals::Internals as _;
use osis::{Config, ManualClock, MemStore, Osis, Role, StoreAt, WallMs};
use osis_app::chat;
use std::sync::Arc;

fn cfg(seed: u64, clock: &Arc<ManualClock>) -> Config {
    let mut c = Config::at(StoreAt::Memory(MemStore::new()));
    c.seed = Some(seed);
    c.clock = Some(clock.clone());
    // a host that never runs: a profile (where the sender's name lives) needs one named
    c.hosts = vec![osis::HostAddr::new("quic://127.0.0.1:9", [7; 32])];
    c
}

fn deliver(from: &Osis, to: &Osis) {
    let pks = from.engine(|e| e.commit_ids().iter().filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        let _ = to.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()));
    }
}

fn sync(a: &Osis, b: &Osis) {
    for _ in 0..2 {
        deliver(a, b);
        deliver(b, a);
    }
}

#[test]
fn two_people_chat() {
    let clock = Arc::new(ManualClock::new(WallMs(1_760_000_000_000)));
    let a = Osis::create(cfg(1, &clock)).unwrap().0;
    let b = Osis::create(cfg(2, &clock)).unwrap().0;
    sync(&a, &b);
    let c = osis_chat::create(&a, &osis_chat::Options { name: "channel".into(), ..Default::default() }).unwrap();
    osis_chat::add(&a, c, b.me(), Role::Write).unwrap();
    assert_eq!(chat::chats(&a).unwrap(), vec![chat::ChatTile { tid: c, name: "channel".into() }]);

    chat::set_name(&a, "Alice").unwrap();
    assert_eq!(chat::my_name(&a).unwrap().as_deref(), Some("Alice"));
    let first = chat::send(&a, c, "Hello", "first post", None).unwrap();
    clock.advance(1000);
    sync(&a, &b);

    // Bob holds it now: listed, readable
    assert_eq!(chat::chats(&b).unwrap().iter().map(|t| t.tid).collect::<Vec<_>>(), vec![c]);
    let got = chat::recent(&b, c, 20).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].who.as_str(), got[0].text.as_str(), got[0].mine), ("Alice", "Hello\n\nfirst post", false));

    // Bob answers without a subject; the reply names Alice's message
    chat::set_name(&b, "Bob").unwrap();
    chat::send(&b, c, "", "hi back", Some(first)).unwrap();
    assert!(chat::send(&b, c, " ", "  ", None).is_err());
    clock.advance(1000);
    sync(&a, &b);
    let got = chat::recent(&a, c, 20).unwrap();
    assert_eq!(got.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(), vec!["Hello\n\nfirst post", "hi back"]);
    assert_eq!(got[1].who, "Bob");
    assert_eq!(got[1].reply_to, Some((first, "Alice: Hello".to_string())));
    assert!(got[0].mine && !got[1].mine);
    // the newest n only, still oldest first
    assert_eq!(chat::recent(&a, c, 1).unwrap().iter().map(|l| l.text.as_str()).collect::<Vec<_>>(), vec!["hi back"]);
}
