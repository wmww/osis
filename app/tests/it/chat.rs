//! Chats across two accounts (commits delivered by hand, as in `share`): list, open, send, receive,
//! replies and the sender's name. Redeeming a new chat's link needs a peer: checked by hand; a link
//! to something already held does not.
use osis::internals::Internals as _;
use osis::{GrantOpts, LinkOpts, MemStore, Osis, Role, Store, Time};
use osis::internals::{ManualClock};
use osis_app::facets::log as chat;
use std::sync::Arc;

fn cfg(seed: u64, clock: &Arc<ManualClock>) -> osis::internals::Opening {
    let mut c = osis::internals::Opening::at(Store::Memory(MemStore::new()));
    c.app.internals.seed = Some(seed);
    c.app.internals.clock = Some(clock.clone());
    // a peer that never runs: a profile (where the sender's name lives) needs one named
    c.hosts = vec![osis::Address::new(&"quic://127.0.0.1:9".parse().unwrap(), [7; 32])];
    c.runtime = osis::Runtime::Manual(osis::internals::ManualNet::new());
    c
}

fn deliver(from: &Osis, to: &Osis) {
    let pks = from.engine(|e| e.commit_ids().iter().filter_map(|id| e.package(id).unwrap()).collect::<Vec<_>>());
    for pk in pks {
        let _ = to.engine(|e| e.ingest(&pk.bytes, pk.blobs.clone()));
    }
}

/// Sets the profile's name (a store with peers has one).
fn set_name(db: &Osis, name: &str) -> osis::Result<()> {
    let p = db.profile()?;
    let mut w = db.write();
    w.at(p, osis::core::NAME).set(&name.to_string())?;
    w.commit()?;
    Ok(())
}

fn fire(db: &Osis, c: osis::Tid, m: osis_chat::schema::Message) {
    let mut w = db.write();
    w.at(c, osis_chat::schema::MSG).fire(&m).unwrap();
    w.commit().unwrap();
}

fn sync(a: &Osis, b: &Osis) {
    for _ in 0..2 {
        deliver(a, b);
        deliver(b, a);
    }
}

#[test]
fn two_people_chat() {
    let clock = Arc::new(ManualClock::new(Time(1_760_000_000_000)));
    let a = osis::internals::create(cfg(1, &clock)).unwrap();
    let b = osis::internals::create(cfg(2, &clock)).unwrap();
    sync(&a, &b);
    let c = osis_chat::create(&a, &osis_chat::Options { name: "channel".into(), ..Default::default() }).unwrap();
    a.grant(c, b.me(), Role::Write, GrantOpts::default()).unwrap();
    set_name(&a, "Alice").unwrap();
    assert_eq!(chat::my_name(&a).unwrap().as_deref(), Some("Alice"));
    let first = chat::send(&a, c, "Hello", "first post", None).unwrap();
    clock.advance(1000);
    sync(&a, &b);

    // Bob holds it now: listed, readable
    assert_eq!(chat::name(&b, c).unwrap(), "channel");
    let got = chat::recent(&b, c, 20).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].who.as_str(), got[0].text.as_str(), got[0].mine), ("Alice", "Hello\n\nfirst post", false));

    // Bob answers without a subject; the reply names Alice's message
    set_name(&b, "Bob").unwrap();
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
    let clock = Arc::new(ManualClock::new(Time(1_760_000_000_000)));
    let a = osis::internals::create(cfg(1, &clock)).unwrap();
    let b = osis::internals::create(cfg(2, &clock)).unwrap();
    sync(&a, &b);
    let c = osis_chat::create(&a, &osis_chat::Options::default()).unwrap();
    a.grant(c, b.me(), Role::Write, GrantOpts::default()).unwrap();
    assert_eq!(chat::name(&a, c).unwrap(), "Chat");
    set_name(&a, "Alice").unwrap();
    let first = chat::send(&a, c, "", "typo", None).unwrap();
    let doomed = chat::send(&a, c, "", "oops", None).unwrap();
    clock.advance(1000);
    sync(&a, &b);
    fire(&b, c, osis_chat::schema::Message { text: "anon".into(), name: None, reply_to: None });
    fire(&b, c, osis_chat::schema::Message { text: "blank".into(), name: Some("  ".into()), reply_to: Some(first.to_string()) });
    clock.advance(1000);
    osis_chat::edit(&a, c, first, "fixed").unwrap();
    let mut w = a.write();
    w.at(c, osis_chat::schema::MSG).purge(osis::Purge::Commit(doomed)).unwrap();
    w.commit().unwrap();
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

/// A store without peers has no profile: reading the name writes nothing and sending works,
/// nameless.
#[test]
fn store_without_peers_sends_without_a_name() {
    let clock = Arc::new(ManualClock::new(Time(1_760_000_000_000)));
    let mut cfg = cfg(0, &clock);
    cfg.hosts.clear();
    let a = osis::internals::create(cfg).unwrap();
    let c = osis_chat::create(&a, &osis_chat::Options::default()).unwrap();
    let before = a.engine(|e| e.commit_ids().len());
    chat::my_name(&a).unwrap();
    assert_eq!(a.engine(|e| e.commit_ids().len()), before);
    assert!(set_name(&a, "Alice").is_err());
    chat::send(&a, c, "", "hi", None).unwrap();
    assert_eq!(chat::recent(&a, c, 20).unwrap()[0].text, "hi");
}

/// A link to a chat already here (pasted by its maker or a member) opens it without the link's
/// peer; text that is no link still fails.
#[test]
fn join_held_chat_opens_it() {
    let clock = Arc::new(ManualClock::new(Time(1_760_000_000_000)));
    let a = osis::internals::create(cfg(1, &clock)).unwrap();
    let b = osis::internals::create(cfg(2, &clock)).unwrap();
    sync(&a, &b);
    let c = osis_chat::create(&a, &osis_chat::Options::default()).unwrap();
    a.grant(c, b.me(), Role::Write, GrantOpts::default()).unwrap();
    let link = a.make_link(c, Role::Write, LinkOpts { until: None, single_use: false, direct: false }).unwrap().to_string();
    sync(&a, &b);
    for db in [a, b] {
        // the peer never answers: a held thing opens at once
        let (tx, rx) = std::sync::mpsc::channel();
        let l = link.clone();
        std::thread::spawn(move || {
            let d = osis_app::store::data(db);
            tx.send(d.redeem(&format!(" {l}\n")).map_err(|e| e.to_string()))
        });
        assert_eq!(rx.recv_timeout(std::time::Duration::from_secs(20)).expect("redeem returns at once"), Ok(c));
    }
    let a = osis::internals::create(cfg(3, &clock)).unwrap();
    assert!(osis_app::store::data(a).redeem("osis://nonsense").unwrap_err().to_string().contains("not a link"));
}

/// A quote costs one commit read, however far back the quoted message is and however often it
/// was edited: showing the newest messages, each answering the first, reads the same at N and 10N
/// messages. The quotes show the newest text.
#[test]
fn quotes_read_flat_in_history() {
    use osis::internals::node::costs;
    const QUOTES: usize = 20;
    let reads = |n: usize| -> (Vec<(&'static str, u64)>, Vec<chat::Line>) {
        let clock = Arc::new(ManualClock::new(Time(1_760_000_000_000)));
        let a = osis::internals::create(cfg(0, &clock)).unwrap();
        let c = osis_chat::create(&a, &osis_chat::Options::default()).unwrap();
        let first = chat::send(&a, c, "", "typo", None).unwrap();
        for i in 0..n {
            clock.advance(1);
            if i % 10 == 0 {
                osis_chat::edit(&a, c, first, &format!("fixed {i}")).unwrap();
            }
            chat::send(&a, c, "", &format!("m{i}"), Some(first)).unwrap();
        }
        osis_chat::edit(&a, c, first, "fixed").unwrap();
        costs::take();
        let lines = chat::recent(&a, c, QUOTES).unwrap();
        let read = ["listing: place walked", "listing: commit read", "listing: body read"];
        let n: Vec<_> = costs::take().into_iter().filter(|(k, _, _)| read.contains(k)).map(|x| (x.0, x.2)).collect();
        (n, lines)
    };
    let (small, lines) = reads(30);
    let (big, _) = reads(300);
    assert!(lines.iter().all(|l| l.reply_to.as_ref().is_some_and(|(_, q)| q.ends_with(": fixed"))), "{lines:?}");
    assert_eq!(small, big, "listing work for {QUOTES} quotes of the first message, 30 against 300 messages back");
}
