//! The chat pattern end to end (notes/chat.md), tier 1: databases and a blind server in process
//! (osis-sim's `World`: manual clock, in-memory hubs, no sleeps, no network). Tier 2: costs and the removal cases
//! (about 10 s each in a debug build).
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
    let (alice, others, c, ps, _) = chat_link(w, n);
    (alice, others, c, ps)
}

/// `chat_of` with the link.
fn chat_link(w: &mut World, n: usize) -> (Osis, Vec<Osis>, Tid, Vec<Tid>, osis::ShareLink) {
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
    (alice, others, c, ps, link)
}

// notes/chat.md Structure (personas, join by link, reactions, read marker), spec/permissions.md
// §9 (links): two people join by one link; everyone reads one timeline with nicks; reactions
// and read markers live on each reader's persona.
#[test]
fn join_by_link_and_talk() {
    let mut w = World::new();
    let (alice, others, c, ps) = chat_of(&mut w, 2);
    let (bob, carol) = (&others[0], &others[1]);
    let m1 = send(&alice, ps[0], "hi all", None).unwrap();
    w.advance(1);
    send(bob, ps[1], "hi alice", None).unwrap();
    w.advance(1);
    send(carol, ps[2], "hello", None).unwrap();
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
// requirements.md (Ephemeral data), notes/api.md Signals (`on_signal_in`): typing reaches the
// other participants, a participant who joined after the listener included, and is never stored.
#[test]
fn typing_signals() {
    let mut w = World::new();
    let (alice, others, c, ps, link) = chat_link(&mut w, 1);
    let bob = &others[0];
    let (tx, rx) = mpsc::channel();
    let _sub = on_typing(&alice, c, move |p, on| {
        let _ = tx.send((p, on));
    });
    typing(bob, ps[1], true).unwrap();
    w.run();
    assert_eq!(rx.recv_timeout(Duration::from_secs(20)).unwrap(), (ps[1], true));
    assert!(bob.aspects(ps[1]).unwrap().iter().all(|a| a.as_str() != "/chat/typing"), "not stored");
    let carol = person(&mut w, 9, 0);
    let (_, pc) = w.until(join(&carol, &link, "carol"), 1000, 10).expect("joined").unwrap();
    w.run();
    typing(&carol, pc, true).unwrap();
    w.run();
    assert_eq!(rx.recv_timeout(Duration::from_secs(20)).unwrap(), (pc, true));
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
#[ignore = "tier 2"]
fn removal_rotates() {
    let mut w = World::new();
    let (alice, others, c, ps) = chat_of(&mut w, 2);
    let (bob, carol) = (&others[0], &others[1]);
    send(bob, ps[1], "before", None).unwrap();
    w.run();
    w.until(remove(&alice, c, ps[1]), 1000, 20).expect("pre-sync").unwrap();
    assert!(!alice.roster(c).contains_key(&bob.me()));
    assert!(!personas(&alice, c).unwrap().contains(&ps[1]));
    send(&alice, ps[0], "after", None).unwrap();
    send(bob, ps[1], "still here?", None).unwrap();
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
    send(&alice, ps[0], "stays", None).unwrap();
    let gone = send(&alice, ps[0], "self-destructs", Some(Duration::from_secs(10))).unwrap();
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
    let spam = send(bob, ps[1], "spam", None).unwrap();
    w.run();
    hide(&alice, c, spam).unwrap();
    w.run();
    assert!(texts(bob, c).unwrap().is_empty());
    assert!(bob.write_with(|wr| wr.at(spam, TEXT).set(&"x".to_string())).is_ok(), "his own message stays his");
}

// notes/chat.md Costs (budgets): bytes a join, a message and a removal send to the server in a
// chat of N (`OSIS_CHAT_N`, default 4), against the measured costs with a margin: join ≈ 41 KB
// (the joiner's chain certificates under two labels, grant, persona, inbox blobs), message
// ≈ 2.5 KB (3 projections), removal ≈ 26 KB at 4 and ≈ 3 KB more per member (one K and one C
// rotation, 2.7 KB of boxes per remaining member), others only heartbeats (≈ 0.5 KB each).
// Tier 2 (about 18 s in a debug build, 5 s in release): run
// `cargo test --release -p chat -- --ignored --nocapture`.
#[test]
#[ignore = "tier 2"]
fn costs_join_message_removal() {
    let n: usize = std::env::var("OSIS_CHAT_N").ok().and_then(|s| s.parse().ok()).unwrap_or(4);
    let mut w = World::new();
    let (alice, others, c, ps, link) = chat_link(&mut w, n - 2);
    let late = person(&mut w, 99, 0);
    // names for the upload trace (`OSIS_TRACE_UPLOADS=1`: one line per entry sent)
    let t4 = |t: Tid| t.to_string().chars().take(4).collect::<String>();
    let mut legend = vec![("chat".to_string(), c), ("link".to_string(), alice.links(c)[0].id)];
    for (i, db) in [&alice].into_iter().chain(&others).chain([&late]).enumerate() {
        legend.push((format!("person{i}"), db.me()));
        legend.push((format!("node{i}"), db.node()));
    }
    legend.extend(ps.iter().enumerate().map(|(i, p)| (format!("persona{i}"), *p)));
    eprintln!("legend {}", legend.iter().map(|(n, t)| format!("{n}={}", t4(*t))).collect::<Vec<_>>().join(" "));
    w.start_tally();
    eprintln!("TRACE step join");
    w.until(join(&late, &link, "late"), 1000, 10).unwrap().unwrap();
    w.run();
    let join = w.tally(&late);
    w.start_tally();
    eprintln!("TRACE step message");
    send(&alice, ps[0], "hello", None).unwrap();
    w.run();
    let msg = w.tally(&alice);
    w.start_tally();
    eprintln!("TRACE step removal");
    w.until(remove(&alice, c, ps[1]), 1000, 20).unwrap().unwrap();
    w.run();
    let rm = w.tally(&alice);
    let others_rm: u64 = others.iter().skip(1).chain([&late]).map(|o| w.tally(o).values().map(|v| v.1).sum::<u64>()).sum();
    let sum = |t: &std::collections::BTreeMap<String, (u64, u64)>| t.values().map(|v| v.1).sum::<u64>();
    eprintln!("chat of {n}\n join {} B {join:?}\n message {} B {msg:?}\n removal {} B {rm:?}\n others during removal {others_rm} B", sum(&join), sum(&msg), sum(&rm));
    assert!(sum(&msg) < 3_000, "a message: 3 projections, about 2.5 KB");
    assert!(sum(&join) < 50_000, "join: about 41 KB");
    assert!(sum(&rm) < 4_000 * n as u64 + 24_000, "removal: about 26 KB at 4 members, 3 KB per member");
    assert!(others_rm < 1_500 * (n as u64 - 1), "others during a removal: heartbeats");
}


// spec/crypto.md §4 (covers rule; a node holding no secret of M judges by M's newest `/keys`
// keyset), spec/permissions.md §3 (no rotation that cannot cover): a late joiner by a second
// link, a writer of C that never read the first link's K1, settles after a joiner of K1 is
// removed instead of rotating C without end.
#[test]
#[ignore = "tier 2"]
fn second_link_then_removal() {
    let mut w = World::new();
    let (alice, _others, c, ps, _) = chat_link(&mut w, 1);
    let late = person(&mut w, 99, 0);
    let k2 = invite(&alice, c, false).unwrap();
    w.run();
    w.until(join(&late, &k2, "late"), 1000, 10).expect("joined").unwrap();
    w.run();
    w.until(remove(&alice, c, ps[1]), 1000, 20).expect("removed").unwrap();
    w.run();
    send(&alice, ps[0], "after", None).unwrap();
    w.run();
    assert_eq!(texts(&late, c).unwrap(), ["after"]);
}
