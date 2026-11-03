//! Chats across two people (commits delivered by hand, as in `share`): list, open, send, receive,
//! replies and the sender's name. Joining a new chat by link needs a host: checked by hand (notes/app.md
//! Chat); a link to a chat already here does not.
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

/// What the CLI can do to a timeline the window shows: an edit (the newest text, marked, its
/// replies quoting it), a delete, a sender with no name or a blank one.
#[test]
fn edited_deleted_and_nameless() {
    let clock = Arc::new(ManualClock::new(WallMs(1_760_000_000_000)));
    let a = Osis::create(cfg(1, &clock)).unwrap().0;
    let b = Osis::create(cfg(2, &clock)).unwrap().0;
    sync(&a, &b);
    let c = osis_chat::create(&a, &osis_chat::Options::default()).unwrap();
    osis_chat::add(&a, c, b.me(), Role::Write).unwrap();
    assert_eq!(chat::chats(&a).unwrap()[0].name, "Chat");
    chat::set_name(&a, "Alice").unwrap();
    let first = chat::send(&a, c, "", "typo", None).unwrap();
    let doomed = chat::send(&a, c, "", "oops", None).unwrap();
    clock.advance(1000);
    sync(&a, &b);
    osis_chat::send(&b, c, &osis_chat::Draft::text("anon")).unwrap();
    osis_chat::send(&b, c, &osis_chat::Draft { text: "blank".into(), name: Some("  ".into()), reply_to: Some(first) }).unwrap();
    clock.advance(1000);
    let m = osis_chat::find(&a, c, &first).unwrap().unwrap();
    osis_chat::edit(&a, c, &m, "fixed").unwrap();
    osis_chat::delete(&a, c, &osis_chat::find(&a, c, &doomed).unwrap().unwrap()).unwrap();
    clock.advance(1000);
    sync(&a, &b);

    let got = chat::recent(&b, c, 20).unwrap();
    let shown: Vec<(&str, &str, bool)> = got.iter().map(|l| (l.who.as_str(), l.text.as_str(), l.edited)).collect();
    let short = |o: &Osis| -> String { o.me().to_string().chars().take(8).collect() };
    let (alice, bob) = (short(&a), short(&b));
    // a deleted body takes its name along
    assert_eq!(shown, vec![("Alice", "fixed", true), (alice.as_str(), "<deleted>", false), (bob.as_str(), "anon", false), (bob.as_str(), "blank", false)]);
    assert_eq!(got[0].id, first);
    assert_eq!(got[3].reply_to, Some((first, "Alice: fixed".to_string())));
}

/// A store without hosts has no profile: reading the name writes nothing and sending works,
/// nameless.
#[test]
fn hostless_store_sends_without_a_name() {
    let clock = Arc::new(ManualClock::new(WallMs(1_760_000_000_000)));
    let mut cfg = cfg(1, &clock);
    cfg.hosts.clear();
    let a = Osis::create(cfg).unwrap().0;
    let c = osis_chat::create(&a, &osis_chat::Options::default()).unwrap();
    let before = a.engine(|e| e.commit_ids().len());
    chat::my_name(&a).unwrap();
    assert_eq!(a.engine(|e| e.commit_ids().len()), before);
    assert!(chat::set_name(&a, "Alice").is_err());
    chat::send(&a, c, "", "hi", None).unwrap();
    assert_eq!(chat::recent(&a, c, 20).unwrap()[0].text, "hi");
}

/// A link to a chat already here (pasted by its maker or a member) opens it without the link's
/// host; text that is no link still fails.
#[test]
fn join_held_chat_opens_it() {
    let clock = Arc::new(ManualClock::new(WallMs(1_760_000_000_000)));
    let a = Osis::create(cfg(1, &clock)).unwrap().0;
    let b = Osis::create(cfg(2, &clock)).unwrap().0;
    sync(&a, &b);
    let c = osis_chat::create(&a, &osis_chat::Options::default()).unwrap();
    osis_chat::add(&a, c, b.me(), Role::Write).unwrap();
    let link = osis_chat::link(&a, c, Role::Write, false).unwrap().to_string();
    sync(&a, &b);
    for db in [a, b] {
        // the host never answers: before, this waited on it
        let (tx, rx) = std::sync::mpsc::channel();
        let l = link.clone();
        std::thread::spawn(move || tx.send(chat::join(&db, &format!(" {l}\n")).map_err(|e| e.to_string())));
        assert_eq!(rx.recv_timeout(std::time::Duration::from_secs(20)).expect("join returns at once"), Ok(c));
    }
    let a = Osis::create(cfg(3, &clock)).unwrap().0;
    assert!(chat::join(&a, "osis://nonsense").unwrap_err().to_string().contains("not a chat link"));
}
