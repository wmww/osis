//! The chat pattern end to end (notes/chat.md), tier 1: databases and a blind server in process
//! (osis-sim's `World`: manual clock, in-memory hubs, no sleeps, no network). Tier 2: costs.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use chat::*;
use osis::{Error, Osis, Tid};
use osis_sim::world::World;
use std::sync::mpsc;
use std::time::Duration;

fn person(w: &mut World, seed: u64, sv: usize) -> Osis {
    let db = w.person(seed, &[sv]).unwrap().0;
    w.run();
    db
}

/// Alice's chat, joined by `n` others through one multi-use link: (alice, others, chat,
/// personas with alice's first).
fn chat_of(w: &mut World, n: usize) -> (Osis, Vec<Osis>, Tid, Vec<Tid>) {
    let sv = w.add_server().unwrap();
    let alice = person(w, 1, sv);
    let others: Vec<Osis> = (0..n).map(|i| person(w, 2 + i as u64, sv)).collect();
    let (c, pa) = new_chat(&alice, "Lunch", "alice").unwrap();
    let link = invite(&alice, c, false).unwrap();
    w.run();
    let mut ps = vec![pa];
    for (i, o) in others.iter().enumerate() {
        let (c2, p) = w.until(join(o, &link, &format!("p{i}")), 1000, 10).expect("joined").unwrap();
        assert_eq!(c2, c);
        ps.push(p);
        w.run();
    }
    (alice, others, c, ps)
}

// notes/chat.md Structure (personas, join by link, reactions, read marker), spec/permissions.md
// §9 (links): two people join by one link; everyone reads one timeline with nicks; reactions
// and read markers live on each reader's persona.
#[test]
fn join_by_link_and_talk() {
    let mut w = World::new();
    let (alice, others, c, ps) = chat_of(&mut w, 2);
    let (bob, carol) = (&others[0], &others[1]);
    let t = w.now() as i64;
    let m1 = send(&alice, ps[0], "hi all", t, None).unwrap();
    send(bob, ps[1], "hi alice", t + 1, None).unwrap();
    send(carol, ps[2], "hello", t + 2, None).unwrap();
    w.run();
    for db in [&alice, bob, carol] {
        assert_eq!(texts(db, c).unwrap(), ["hi all", "hi alice", "hello"]);
        assert_eq!(timeline(db, c).unwrap()[1].nick, "p0");
    }
    react(bob, ps[1], m1, "👋").unwrap();
    react(carol, ps[2], m1, "👋").unwrap();
    mark_read(carol, ps[2], m1).unwrap();
    w.run();
    let mut r = reactions(&alice, c, m1).unwrap();
    r.sort();
    assert_eq!(r, [("p0".to_string(), "👋".to_string()), ("p1".to_string(), "👋".to_string())]);
    assert_eq!(read_marker(&alice, ps[2]).unwrap(), Some(m1));
}

// notes/chat.md Structure (typing as signals on the persona), spec/sync.md §9, spec/
// requirements.md (Ephemeral data): typing reaches the other participants and is never stored.
#[test]
fn typing_signals() {
    let mut w = World::new();
    let (alice, others, c, ps) = chat_of(&mut w, 1);
    let bob = &others[0];
    let (tx, rx) = mpsc::channel();
    let _subs = on_typing(&alice, c, move |p, on| {
        let _ = tx.send((p, on));
    })
    .unwrap();
    typing(bob, ps[1], true).unwrap();
    w.run();
    assert_eq!(rx.recv_timeout(Duration::from_secs(20)).unwrap(), (ps[1], true));
    assert!(bob.aspects(ps[1]).unwrap().iter().all(|a| a.as_str() != "/chat/typing"), "not stored");
}

// spec/permissions.md §9 (single-use links), notes/chat.md (join by link): the first redeemer
// joins; a second one is refused.
#[test]
fn single_use_link() {
    let mut w = World::new();
    let sv = w.add_server().unwrap();
    let alice = person(&mut w, 1, sv);
    let bob = person(&mut w, 2, sv);
    let mut cfg = w.cfg(3, &[sv]);
    cfg.wait_timeout = Duration::from_secs(5);
    let carol = Osis::create(cfg).unwrap().0;
    w.run();
    let (c, _) = new_chat(&alice, "Private", "alice").unwrap();
    let link = invite(&alice, c, true).unwrap();
    w.run();
    let (_, pb) = w.until(join(&bob, &link, "bob"), 1000, 10).unwrap().unwrap();
    w.run();
    assert!(personas(&alice, c).unwrap().contains(&pb));
    assert!(matches!(w.until(join(&carol, &link, "carol"), 1000, 10).unwrap(), Err(Error::Network(_))));
    assert_eq!(carol.role_on(c), None);
}

// notes/chat.md Structure (removal with rotation), spec/permissions.md §3, §5.3: the moderator
// removes Bob; Carol keeps reading new messages, Bob reads none, and what Bob posts afterwards
// reaches nobody.
#[test]
fn removal_rotates() {
    let mut w = World::new();
    let (alice, others, c, ps) = chat_of(&mut w, 2);
    let (bob, carol) = (&others[0], &others[1]);
    let t = w.now() as i64;
    send(bob, ps[1], "before", t, None).unwrap();
    w.run();
    w.until(remove(&alice, c, ps[1]), 1000, 20).expect("pre-sync").unwrap();
    assert!(!alice.roster(c).contains_key(&bob.me()));
    assert!(!personas(&alice, c).unwrap().contains(&ps[1]));
    send(&alice, ps[0], "after", t + 10, None).unwrap();
    send(bob, ps[1], "still here?", t + 11, None).unwrap();
    w.run();
    assert_eq!(texts(carol, c).unwrap(), ["after"], "the removed persona is out of the timeline");
    assert!(!texts(bob, c).unwrap().contains(&"after".to_string()), "nothing new for bob");
    assert!(!texts(&alice, c).unwrap().contains(&"still here?".to_string()));
    assert!(matches!(chat::invite(bob, c, false), Err(Error::Permission { .. })));
}

// spec/commits.md §6 (expiry), notes/chat.md (disappearing messages: expiry on the message's
// deltas, placement included), spec/requirements.md (Deletion: every node drops it with nobody
// online): a disappearing message is gone everywhere, from the timeline and the group.
#[test]
fn disappearing_messages() {
    let mut w = World::new();
    let (alice, others, c, ps) = chat_of(&mut w, 1);
    let bob = &others[0];
    let t = w.now() as i64;
    send(&alice, ps[0], "stays", t, None).unwrap();
    let gone = send(&alice, ps[0], "self-destructs", t + 1, Some(Duration::from_secs(10))).unwrap();
    w.run();
    assert_eq!(texts(bob, c).unwrap(), ["stays", "self-destructs"]);
    w.set_online(bob, false);
    w.advance(11_000);
    for db in [&alice, bob] {
        assert_eq!(texts(db, c).unwrap(), ["stays"]);
        assert_eq!(db.get(gone, TEXT).unwrap(), None);
        assert!(!db.get(ps[0], osis::core::GROUP).unwrap().unwrap().items.contains(&gone), "placement expired too");
    }
}

// notes/chat.md Structure (hide set: an admin-written set on C; nobody edits another's message):
// a moderator hides a message for everyone; a participant may not.
#[test]
fn moderator_hides() {
    let mut w = World::new();
    let (alice, others, c, ps) = chat_of(&mut w, 1);
    let bob = &others[0];
    let t = w.now() as i64;
    let spam = send(bob, ps[1], "spam", t, None).unwrap();
    w.run();
    hide(&alice, c, spam).unwrap();
    w.run();
    assert!(texts(bob, c).unwrap().is_empty());
    assert!(bob.write_with(|wr| wr.at(spam, TEXT).set(&"x".to_string())).is_ok(), "his own message stays his");
}

// notes/chat.md Costs, tier 2 (budgets): bytes a join, a message and a removal send to the
// server in a chat of N (`OSIS_CHAT_N`, default 6). Join: persona plus two membership commits
// and one content commit; removal: about 2 sealed boxes of ~1.2 KB per remaining member
// (2 × 199 ≈ 480 KB at 200). Run: `cargo test -p chat --release -- --ignored --nocapture`.
#[test]
#[ignore]
fn costs_join_message_removal() {
    let n: usize = std::env::var("OSIS_CHAT_N").ok().and_then(|s| s.parse().ok()).unwrap_or(6);
    let mut w = World::new();
    let (alice, others, c, ps) = chat_of(&mut w, n - 1);
    let late = person(&mut w, 99, 0);
    let link = invite(&alice, c, false).unwrap();
    w.run();
    w.start_tally();
    let before = w.traffic(&late);
    w.until(join(&late, &link, "late"), 1000, 10).unwrap().unwrap();
    w.run();
    let join_up = w.traffic(&late).up - before.up;
    eprintln!("join sent {:?}", w.tally(&late));
    let a0 = w.traffic(&alice);
    send(&alice, ps[0], "hello", w.now() as i64, None).unwrap();
    w.run();
    let msg_up = w.traffic(&alice).up - a0.up;
    let a1 = w.traffic(&alice);
    w.start_tally();
    w.until(remove(&alice, c, ps[1]), 1000, 20).unwrap().unwrap();
    w.run();
    let rm_up = w.traffic(&alice).up - a1.up;
    eprintln!("removal sent {:?}", w.tally(&alice));
    let others_up: u64 = others.iter().skip(1).map(|o| w.tally(o).values().map(|v| v.1).sum::<u64>()).sum();
    eprintln!("chat of {n} (+1 late): join up {join_up} B, message up {msg_up} B, removal up {rm_up} B (others then {others_up} B)");
    assert!(msg_up < 3_000, "a message: about 350 B plus content, plus protocol framing: {msg_up}");
    assert!(join_up < 40_000, "join: {join_up}");
    let boxes = 2 * n as u64 * 1_300;
    assert!(rm_up < boxes + 30_000, "removal: {rm_up} against {boxes} B of boxes");
}

