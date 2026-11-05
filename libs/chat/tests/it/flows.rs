//! Chat end to end on the sim. spec: none (a client surface specified in notes/chat.md).

use osis_chat::*;
use osis::{SyncFirst, ChangeId, HistoryFrom, Osis, Role, Tid, Value};
use osis_sim::world::World;
use std::collections::BTreeSet;
use std::time::Duration;

/// A world with one host, Alice and Bob who know each other, and Alice's chat with Bob in it.
struct Room {
    w: World,
    a: Osis,
    b: Osis,
    c: Tid,
    bob: Tid,
}

fn meet(w: &mut World, a: &Osis, b: &Osis) -> Tid {
    let card = b.contact_card().unwrap();
    w.run();
    w.until(a.import_contact(&card, osis::internals::WAIT), 1000, 10).unwrap()
}

fn room(o: Options) -> Room {
    let mut w = World::new();
    let host = w.add_host();
    let (a, _) = w.person(1, &[host]);
    let (b, _) = w.person(2, &[host]);
    w.run();
    let bob = meet(&mut w, &a, &b);
    let c = create(&a, &o).unwrap();
    add(&a, c, bob, Role::Write).unwrap();
    w.run();
    Room { w, a, b, c, bob }
}

fn texts(db: &Osis, c: Tid) -> Vec<String> {
    let mut t = Timeline::new(db, c).unwrap();
    let mut out: Vec<String> = t
        .older(db, 1000)
        .unwrap()
        .messages
        .iter()
        .map(|m| match &m.body {
            Body::Text(x) => x.clone(),
            Body::Deleted { .. } => "<deleted>".into(),
            b => format!("<{b:?}>"),
        })
        .collect();
    out.reverse();
    out
}

fn newest(db: &Osis, c: Tid) -> Message {
    Timeline::new(db, c).unwrap().older(db, 1).unwrap().messages.remove(0)
}

// spec/permissions.md §1, §5.2 and spec/commits.md §5: a chat in one flow: ownerless, synced, required retention; a post reaches a participant with its verified sender; identical posts are two messages; paging both ways
#[test]
fn create_post_read_spec_commits_5() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    assert_eq!(a.owner_of(c).unwrap(), None);
    assert_eq!(participants(&a, c).unwrap().get(&bob), Some(&Role::Write));
    post(&a, c, "hi").unwrap();
    post(&a, c, "hi").unwrap();
    w.run();
    post(&b, c, "yo").unwrap();
    w.run();
    for db in [&a, &b] {
        assert_eq!(texts(db, c), ["hi", "hi", "yo"]);
        let m = newest(db, c);
        assert_eq!(m.sender, bob);
    }
    let rest = entries(&a, c, HistoryFrom::Oldest, 2).unwrap();
    assert!(rest.more && rest.complete);
    let next = entries(&a, c, HistoryFrom::After(rest.entries[1].id.pos), 2).unwrap();
    assert_eq!(next.entries.len(), 1);
    assert!(!next.more);
}

// notes/chat-designs/e.md Edit, spec/permissions.md §5.2: edits: newest wins in any arrival order; the old text purged by default with no stray tombstone; a repeat edit still answers for the old one; another's edit is its own message, not an edit; off mode ignores replaces; keep mode shows versions
#[test]
fn edit_modes_spec_perm_5() {
    let Room { mut w, a, b, c, .. } = room(Options::default());
    let o = post(&a, c, "orginal").unwrap();
    w.run();
    let m = newest(&a, c);
    assert_eq!(m.id, o);
    edit(&a, c, &m, "origina").unwrap();
    w.run();
    edit(&a, c, &newest(&a, c), "original").unwrap();
    w.run();
    for db in [&a, &b] {
        assert_eq!(texts(db, c), ["original"], "one message, no stray tombstones");
        let m = newest(db, c);
        assert_eq!(m.id, o);
        assert!(m.edited.is_some());
        assert!(m.earlier.is_empty(), "the old text is gone: {m:?}");
        assert!(matches!(entry_at(db, c, &o).unwrap().unwrap().body, Body::Deleted { .. }));
    }
    // Bob's forged edit of Alice's message: a message of his own
    let forged = write_raw_edit(&b, c, "forged", o);
    w.run();
    assert_eq!(texts(&a, c), ["original", "forged"]);
    assert_eq!(newest(&a, c).id, forged);
    // and the library refuses it plainly
    assert!(edit(&b, c, &find(&b, c, &o).unwrap().unwrap(), "x").is_err());
    let Room { mut w, a, b, c, .. } = room(Options { edit: EditMode::Keep, ..Options::default() });
    post(&a, c, "one").unwrap();
    edit(&a, c, &newest(&a, c), "two").unwrap();
    edit(&a, c, &newest(&a, c), "three").unwrap();
    w.run();
    let m = newest(&b, c);
    assert_eq!(m.body, Body::Text("three".into()));
    let e: Vec<_> = m.earlier.iter().map(|e| e.body.clone()).collect();
    assert_eq!(e, [Body::Text("two".into()), Body::Text("one".into())]);
    // an edit deleted takes every version
    delete(&a, c, &m).unwrap();
    w.run();
    assert!(texts(&b, c).iter().all(|t| t == "<deleted>"), "{:?}", texts(&b, c));
    let Room { w: _, a, c, .. } = room(Options { edit: EditMode::Off, ..Options::default() });
    post(&a, c, "fixed").unwrap();
    assert!(edit(&a, c, &newest(&a, c), "x").is_err());
    let o = newest(&a, c).id;
    write_raw_edit(&a, c, "a plain message", o);
    assert_eq!(texts(&a, c), ["fixed", "a plain message"]);
}

// notes/chat-designs/e.md Edit: two devices' edits arrive in either order; the same newest wins
#[test]
fn concurrent_edits_agree_spec_crdt_1() {
    let mut w = World::new();
    let host = w.add_host();
    let (a, _) = w.person(1, &[host]);
    w.run();
    let offer = a.pair_offer().unwrap();
    let join = osis::internals::pair(w.cfg(2, &[]), &offer).unwrap();
    let req: osis::PairRequest = join.request().to_string().parse().unwrap();
    let (_, reply) = a.pair_accept(&req).unwrap();
    let a2 = join.finish(&reply).unwrap();
    w.run();
    let c = create(&a, &Options { edit: EditMode::Keep, ..Options::default() }).unwrap();
    post(&a, c, "base").unwrap();
    w.run();
    assert_eq!(texts(&a2, c), ["base"], "a new device of a participant");
    w.set_online(&a2, false);
    let m = newest(&a, c);
    edit(&a, c, &m, "from one").unwrap();
    w.advance(1000);
    edit(&a2, c, &m, "from two").unwrap();
    w.set_online(&a2, true);
    w.advance(60_000);
    w.run();
    assert_eq!(texts(&a, c), texts(&a2, c));
    assert_eq!(texts(&a, c), ["from two"]);
}

// spec/commits.md §5, spec/sync.md §6: delete for everyone by author and moderator; a participant cannot delete another's; a tombstone reaches a new device with its sender
#[test]
fn delete_for_everyone_spec_commits_5() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    let mine = post(&a, c, "mine").unwrap();
    w.advance(10);
    let his = post(&b, c, "his").unwrap();
    w.advance(10);
    post(&b, c, "kept").unwrap();
    w.run();
    let at = |db: &Osis, id: &Id| find(db, c, id).unwrap().unwrap();
    assert!(matches!(delete(&b, c, &at(&b, &mine)), Err(osis::Error::Permission { .. })));
    // past the library: the request drops nothing
    let mut x = b.write();
    x.at(c, osis::Key::untyped(osis::Ak::new(format!("{MSGS}y{}.0", mine.year)).unwrap())).purge(osis::Purge::Change(mine.pos.id)).unwrap();
    x.commit().unwrap();
    w.run();
    assert!(matches!(at(&a, &mine).body, Body::Text(_)));
    delete(&b, c, &at(&b, &his)).unwrap();
    w.run();
    assert_eq!(texts(&a, c), ["mine", "<deleted>", "kept"]);
    delete(&a, c, &at(&a, &mine)).unwrap();
    w.run();
    assert_eq!(texts(&b, c), ["<deleted>", "<deleted>", "kept"]);
    // a moderator's delete of Bob's
    delete(&a, c, &newest(&a, c)).unwrap();
    w.run();
    assert_eq!(texts(&b, c), ["<deleted>"; 3]);
    let by = |db: &Osis, id: &Id| match at(db, id).body {
        Body::Deleted { who, .. } => who,
        x => panic!("{x:?}"),
    };
    assert_eq!((by(&b, &his), by(&a, &mine)), (Some(bob), Some(a.me())), "who deleted, by its signed header");
    let offer = b.pair_offer().unwrap();
    let join = osis::internals::pair(w.cfg(5, &[]), &offer).unwrap();
    let req: osis::PairRequest = join.request().to_string().parse().unwrap();
    let (_, reply) = b.pair_accept(&req).unwrap();
    let b2 = join.finish(&reply).unwrap();
    w.run();
    assert_eq!(texts(&b2, c), ["<deleted>"; 3], "tombstones on a new device");
    assert_eq!(newest(&b2, c).sender, bob);
    assert_eq!(by(&b2, &his), Some(bob), "on a new device too");
}

// spec/permissions.md §7: purge sets: author only keeps a moderator out; nobody is a permanent chat; admin only keeps an author out
#[test]
fn purge_sets_spec_perm_7() {
    for (by, author, admin) in [(PurgeBy::Author, true, false), (PurgeBy::Admin, false, true), (PurgeBy::Nobody, false, false)] {
        let Room { mut w, a, b, c, .. } = room(Options { purge: by, ..Options::default() });
        post(&b, c, "x").unwrap();
        w.run();
        assert_eq!(delete(&b, c, &newest(&b, c)).is_ok(), author, "{by:?}");
        w.run();
        assert_eq!(texts(&a, c) == ["<deleted>"], author);
        if !author {
            assert_eq!(delete(&a, c, &newest(&a, c)).is_ok(), admin, "{by:?}");
            w.run();
            assert_eq!(texts(&b, c) == ["<deleted>"], admin);
        }
    }
}

// spec/permissions.md §3 (Keep), §5.1: a kicked participant keeps a read-only copy, sees nothing new and writes nothing others accept; the override erases; purge by author erases its messages for those left
#[test]
fn kick_keep_erase_purge_spec_perm_3() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    post(&b, c, "before").unwrap();
    post(&a, c, "hello").unwrap();
    w.run();
    w.until(kick(&a, c, bob, None, SyncFirst::Skip, osis::internals::PRESYNC), 1000, 10).unwrap();
    w.run();
    assert_eq!(b.kept_copies().unwrap(), vec![c]);
    assert_eq!(texts(&b, c).len(), 2, "kept");
    assert!(post(&b, c, "after").is_err(), "the copy is read-only");
    post(&a, c, "new").unwrap();
    w.run();
    assert_eq!(texts(&b, c).len(), 2, "nothing new");
    assert_eq!(texts(&a, c).len(), 3);
    purge_participant(&a, c, bob).unwrap();
    w.run();
    assert!(texts(&a, c).contains(&"<deleted>".to_string()) && !texts(&a, c).contains(&"before".to_string()));

    let Room { mut w, a, b, c, bob } = room(Options::default());
    post(&a, c, "hello").unwrap();
    w.run();
    w.until(kick(&a, c, bob, Some(false), SyncFirst::Skip, osis::internals::PRESYNC), 1000, 10).unwrap();
    w.run();
    assert!(b.kept_copies().unwrap().is_empty());
    assert!(texts(&b, c).is_empty(), "erased");
    assert!(!b.knows(c).unwrap());
}

// spec/commits.md §5: required retention refuses a participant's other retention: refused at its writer, and if forged past it, invalid and unshown; every other aspect too; a stale writer is told
#[test]
fn required_and_stale_writer_spec_commits_5() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    let year = post(&a, c, "x").unwrap().year;
    w.run();
    let k = osis::Ak::new(format!("{MSGS}y{year}.0")).unwrap();
    let mut x = b.write();
    let bad = osis::Retention { by: PurgeBy::Nobody, ..Default::default() };
    assert!(x.at(c, osis::Key::untyped(k.clone())).retention(bad).overwrite(&Value::Str("x".into())).is_err() || x.commit().is_err(), "refused at its writer");
    let (tx, rx) = std::sync::mpsc::channel();
    let _s = on_rejected(&b, c, move |id| tx.send(id).unwrap()).unwrap();
    // Bob offline: the timer changes, he posts under the old rule
    w.set_online(&b, false);
    w.advance(1000);
    set_disappearing(&a, c, Some(Duration::from_secs(60))).unwrap();
    w.run();
    w.advance(1000);
    let stale = post(&b, c, "stale").unwrap();
    let stale2 = post(&b, c, "stale too").unwrap();
    w.set_online(&b, true);
    w.advance(60_000);
    w.run();
    b.settle();
    let told: Vec<_> = rx.try_iter().collect();
    let ids: Vec<ChangeId> = told.clone();
    assert!(ids.contains(&stale.pos.id) && ids.contains(&stale2.pos.id), "told of both: {told:?}");
    assert!(!texts(&a, c).iter().any(|t| t.starts_with("stale")), "others do not show it");
    let mine = find(&b, c, &stale).unwrap().unwrap();
    assert!(!mine.valid, "its sender sees it did not go");
    assert_eq!(mine.body, Body::Text("stale".into()), "and can send it again");
    assert_eq!(participants(&a, c).unwrap().get(&bob), Some(&Role::Write));
    assert!(resend(&a, c, &mine).is_err(), "not another's");
    let again = resend(&b, c, &mine).unwrap();
    w.run();
    assert_eq!(texts(&a, c).last().unwrap(), "stale", "it went this time");
    assert!(resend(&b, c, &find(&b, c, &again).unwrap().unwrap()).is_err(), "delivered: nothing to send again");
    w.advance(1000);
    // he can post again under the new rule
    post(&b, c, "fresh").unwrap();
    w.run();
    assert_eq!(texts(&a, c).last().unwrap(), "fresh");
}

// spec/commits.md §6: disappearing: gone everywhere at its time, offline nodes too, a later timer leaves earlier messages' alone; a watch hears it; no tombstone stays in the timeline
#[test]
fn disappearing_spec_commits_6() {
    let Room { mut w, a, b, c, .. } = room(Options { disappear: Some(Duration::from_secs(60)), ..Options::default() });
    post(&a, c, "short").unwrap();
    w.run();
    assert_eq!(texts(&b, c), ["short"]);
    set_disappearing(&a, c, Some(Duration::from_secs(3600))).unwrap();
    w.run();
    post(&b, c, "long").unwrap();
    w.run();
    w.set_online(&b, false);
    w.advance(61_000);
    w.run();
    assert_eq!(texts(&a, c), ["long"]);
    assert_eq!(texts(&b, c), ["long"], "offline too");
    w.set_online(&b, true);
    w.advance(3_600_000);
    w.run();
    assert!(texts(&a, c).is_empty() && texts(&b, c).is_empty());
    // delete and edit in a disappearing chat (no expiry on a request's commit)
    set_disappearing(&a, c, Some(Duration::from_secs(60))).unwrap();
    w.run();
    post(&a, c, "orginal").unwrap();
    edit(&a, c, &newest(&a, c), "original").unwrap();
    w.run();
    assert_eq!(texts(&b, c), ["original"]);
    delete(&a, c, &newest(&a, c)).unwrap();
    w.run();
    // a deleted edit has lost what linked its versions: a tombstone each (notes/chat.md)
    assert_eq!(texts(&b, c), ["<deleted>"; 2]);
}

// notes/api.md History: a watch hears a post, its edit checked, a deletion
#[test]
fn watch_spec_none() {
    let Room { mut w, a, b, c, .. } = room(Options::default());
    let (tx, rx) = std::sync::mpsc::channel();
    let _s = watch(&b, c, move |_, e| tx.send(e).unwrap()).unwrap();
    let o = post(&a, c, "one").unwrap();
    w.run();
    b.settle();
    let got: Vec<_> = rx.try_iter().collect();
    assert!(got.iter().any(|e| matches!(e, Event::Entry(e) if e.id == o && e.body == Body::Text("one".into()))), "{got:?}");
    let e = edit(&a, c, &newest(&a, c), "two").unwrap();
    w.run();
    b.settle();
    let got: Vec<_> = rx.try_iter().collect();
    assert!(got.iter().any(|x| matches!(x, Event::Entry(x) if x.id == e && x.replaces.as_ref().is_some_and(|r| r.original == o))), "{got:?}");
    assert!(got.iter().any(|x| matches!(x, Event::Entry(x) if x.id == o && matches!(x.body, Body::Deleted { .. }))), "{got:?}");
}

/// Every link in `v`.
fn links(v: &Value, out: &mut Vec<osis::schema::osis_base::Link>) {
    match v {
        Value::Link(l) => out.push(**l),
        Value::Enum(_, Some(p)) => links(p, out),
        Value::Map(m) => m.iter().for_each(|(k, v)| {
            links(k, out);
            links(v, out);
        }),
        Value::List(l) => l.iter().for_each(|v| links(v, out)),
        Value::Set(s) => s.iter().for_each(|v| links(v, out)),
        _ => {}
    }
}

// spec/data-model.md §6 (unreadable link): a message over CHUNK_THRESHOLD whose chunk is not here reads not fetched; when the chunk arrives the watch hears the entry again, with its text. Two such messages: the first chunk's arrival re-delivers both, and the second, still missing, is noted again for its own chunk's arrival
#[test]
fn watch_hears_a_chunk_arrive_spec_dm_6() {
    use osis::internals::Internals;
    let Room { mut w, a, b, c, .. } = room(Options::default());
    let bigs = ["x", "y"].map(|s| s.repeat(200 << 10));
    let ids = bigs.clone().map(|t| post(&a, c, &t).unwrap());
    w.run();
    // Bob loses each body's root blob
    let lost = ids.map(|id| {
        let ak = osis::Ak::new(format!("{MSGS}y{}.0", id.year)).unwrap();
        let row = b.engine(|e| e.history_entry(&c, &ak, &id.pos.id, usize::MAX)).unwrap().unwrap();
        let osis::internals::node::engine::history::RowBody::Held(Some(v)) = &row.body else { panic!("{:?}", row.body) };
        let mut ls = Vec::new();
        links(v, &mut ls);
        let blob = ls[0].blob;
        let bytes = b.engine(|e| e.blob(&blob)).unwrap().unwrap();
        b.engine(|e| {
            e.run(|tx| {
                tx.txn.delete_blob(&blob);
                Ok(())
            })
        })
        .unwrap();
        (blob, bytes)
    });
    let (tx, rx) = std::sync::mpsc::channel();
    let _s = watch(&b, c, move |_, e| tx.send(e).unwrap()).unwrap();
    for id in &ids {
        assert_eq!(entry_at(&b, c, id).unwrap().unwrap().body, Body::NotFetched);
    }
    for (i, (blob, bytes)) in lost.into_iter().enumerate() {
        b.engine(|e| e.put_blobs(vec![(blob, bytes)])).unwrap();
        b.settle();
        let got: Vec<_> = rx.try_iter().collect();
        let shown = || got.iter().map(|e| match e { Event::Entry(e) => format!("{:?}", e.body).chars().take(40).collect(), e => format!("{e:?}") }).collect::<Vec<String>>();
        assert!(got.iter().any(|e| matches!(e, Event::Entry(e) if e.id == ids[i] && e.body == Body::Text(bigs[i].clone()))), "{i}: {:?}", shown());
    }
}

// spec/requirements.md, notes/client-port.md §3: a restart reads the same; a thin client of a participant reads and is its own sender
#[test]
fn restart_and_thin_client_spec_client_port() {
    use osis::internals::Internals as _;
    let mut w = World::new();
    let host = w.add_host();
    let store = osis::MemStore::new();
    let mut cfg = w.cfg(3, &[host]);
    cfg.store = osis::Store::Memory(store.clone());
    let (a, _) = osis::internals::create(cfg.clone()).unwrap();
    let c = create(&a, &Options::default()).unwrap();
    post(&a, c, "before").unwrap();
    w.run();
    let (app, _) = a.add_client(None).unwrap();
    a.grant(a.me(), app, Role::Read, Default::default()).unwrap();
    w.run();
    let thin = a.acting_as(app);
    assert_eq!(texts(&thin, c), ["before"]);
    assert!(post(&thin, c, "no").is_err(), "a reader");
    drop(thin);
    assert_eq!(a.close().unwrap(), osis::Close::Closed);
    w.run();
    let a = osis::internals::open(cfg).unwrap();
    assert_eq!(texts(&a, c), ["before"]);
    post(&a, c, "after").unwrap();
    assert_eq!(texts(&a, c), ["before", "after"]);
}

// spec/permissions.md §5.2: a participant cannot speak as another: refused at its writer; a participant's write as an actor it may not act for is unknown to the API
#[test]
fn no_forged_sender_spec_perm_5() {
    let Room { w: _, a, b, c, .. } = room(Options::default());
    let k = osis::Ak::new(format!("{MSGS}y2023.0")).unwrap();
    let mut x = b.write();
    x.act_as(a.me());
    x.at(c, osis::Key::untyped(k)).overwrite(&Value::Str("as alice".into())).unwrap();
    assert!(matches!(x.commit(), Err(osis::Error::Permission { .. })));
}

// spec/permissions.md §5.1, spec/commits.md §4: a participant offline at the kick: what it wrote after the stamp turns invalid everywhere it is held, its own node says so; others never show it; what it wrote before the pre-sync reached the kicker drops too (design E: accepted without Required)
#[test]
fn kicked_while_offline_spec_perm_5() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    post(&b, c, "seen").unwrap();
    w.run();
    let (tx, rx) = std::sync::mpsc::channel();
    let _s = on_rejected(&b, c, move |id| tx.send(id).unwrap()).unwrap();
    w.set_online(&b, false);
    w.advance(1000);
    w.until(kick(&a, c, bob, None, SyncFirst::Skip, osis::internals::PRESYNC), 1000, 10).unwrap();
    w.run();
    let late = post(&b, c, "late").unwrap();
    w.set_online(&b, true);
    w.advance(60_000);
    w.run();
    b.settle();
    assert_eq!(texts(&a, c), ["seen"]);
    assert!(rx.try_iter().any(|x| x == late.pos.id), "told");
    assert!(!find(&b, c, &late).unwrap().unwrap().valid);
    assert!(post(&b, c, "more").is_err(), "the kick arrived");
    // a re-grant: the copy ends, it follows again; the late post stays what design E says: revived
    add(&a, c, bob, Role::Write).unwrap();
    w.run();
    assert!(b.kept_copies().unwrap().is_empty());
    post(&b, c, "back").unwrap();
    w.run();
    assert_eq!(texts(&a, c).last().unwrap(), "back");
    assert!(texts(&a, c).contains(&"late".to_string()), "a known forced yes: re-adding revives it (notes/chat-cases.md)");
}

// spec/permissions.md §3 (Keep): a kept copy's device of the kicked participant; a new device sees nothing of it (the design's forced "no")
#[test]
fn new_device_of_a_participant_sees_history_spec_sync_6() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    for i in 0..200 {
        post(&a, c, &format!("m{i}")).unwrap();
        w.advance(1);
    }
    w.run();
    let new_device = |w: &mut World, seed: u64| {
        let offer = b.pair_offer().unwrap();
        let join = osis::internals::pair(w.cfg(seed, &[]), &offer).unwrap();
        let req: osis::PairRequest = join.request().to_string().parse().unwrap();
        let (_, reply) = b.pair_accept(&req).unwrap();
        let d = join.finish(&reply).unwrap();
        w.run();
        d
    };
    let d = new_device(&mut w, 7);
    assert_eq!(texts(&d, c).len(), 200);
    assert!(Timeline::new(&d, c).unwrap().older(&d, 1).unwrap().complete);
    // paging back by small pages reaches the same
    let mut t = Timeline::new(&d, c).unwrap();
    let (mut n, mut more) = (0, true);
    while more {
        let p = t.older(&d, 7).unwrap();
        n += p.messages.len();
        more = p.more;
    }
    assert_eq!(n, 200);
    post(&d, c, "from the new device").unwrap();
    w.run();
    assert_eq!(newest(&a, c).sender, bob, "one sender across devices");
    assert_eq!(newest(&a, c).body, Body::Text("from the new device".into()));
    // a device removed erases, a kicked person's new device gets nothing
    w.until(kick(&a, c, bob, None, SyncFirst::Skip, osis::internals::PRESYNC), 1000, 10).unwrap();
    w.run();
    let late = new_device(&mut w, 8);
    assert!(texts(&late, c).is_empty(), "known forced no: notes/chat-cases.md");
}

// spec/commits.md §6, spec/permissions.md §3 (Keep): a disappearing message leaves a kept copy at its time too
#[test]
fn kept_copy_still_disappears_spec_commits_6() {
    let Room { mut w, a, b, c, bob } = room(Options { disappear: Some(Duration::from_secs(60)), ..Options::default() });
    post(&a, c, "short").unwrap();
    w.run();
    w.until(kick(&a, c, bob, None, SyncFirst::Skip, osis::internals::PRESYNC), 1000, 10).unwrap();
    w.run();
    assert_eq!(b.kept_copies().unwrap(), vec![c]);
    assert_eq!(texts(&b, c), ["short"]);
    w.advance(120_000);
    w.run();
    assert!(texts(&a, c).is_empty());
    assert!(texts(&b, c).is_empty(), "gone from the copy: {:?}", texts(&b, c));
}

// spec/permissions.md §1 (admins all equal): a later admin may kick the creator; with no admin left participants still post; two admins kicking each other end the same everywhere
#[test]
fn admins_are_equal_spec_perm_1() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    add(&a, c, bob, Role::Admin).unwrap();
    w.run();
    w.until(kick(&b, c, a.me(), None, SyncFirst::Skip, osis::internals::PRESYNC), 1000, 10).unwrap();
    w.run();
    assert!(post(&a, c, "no").is_err());
    post(&b, c, "mine now").unwrap();
    assert_eq!(participants(&b, c).unwrap().len(), 1);

    let Room { mut w, a, b, c, bob } = room(Options::default());
    add(&a, c, bob, Role::Admin).unwrap();
    w.run();
    w.set_online(&b, false);
    w.until(kick(&a, c, bob, None, SyncFirst::Skip, osis::internals::PRESYNC), 1000, 10).unwrap();
    w.until(kick(&b, c, a.me(), None, SyncFirst::Skip, osis::internals::PRESYNC), 1000, 10).unwrap();
    w.set_online(&b, true);
    w.advance(60_000);
    w.run();
    assert_eq!(participants(&a, c).unwrap(), participants(&b, c).unwrap());
}

// spec/permissions.md §3 (Keep): an erased participant added again gets the chat back
#[test]
fn erased_then_added_again_spec_perm_3() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    post(&a, c, "one").unwrap();
    w.run();
    w.until(kick(&a, c, bob, Some(false), SyncFirst::Skip, osis::internals::PRESYNC), 1000, 10).unwrap();
    w.run();
    assert!(texts(&b, c).is_empty());
    post(&a, c, "two").unwrap();
    w.run();
    add(&a, c, bob, Role::Write).unwrap();
    w.run();
    assert_eq!(texts(&b, c), ["one", "two"]);
    post(&b, c, "back").unwrap();
    w.run();
    assert_eq!(texts(&a, c), ["one", "two", "back"]);
}

// spec/sync.md §2-3: the creator's device paired or restored after the chat exists finds it, unplaced as it is
#[test]
fn creator_on_a_new_device_spec_sync_3() {
    let mut w = World::new();
    let host = w.add_host();
    let (a, card) = w.person(1, &[host]);
    w.run();
    let c = create(&a, &Options::default()).unwrap();
    post(&a, c, "hello").unwrap();
    w.run();
    w.until(a.wait_synced(osis::SyncScope::All, Duration::from_secs(60)), 1000, 60).unwrap();
    let offer = a.pair_offer().unwrap();
    let join = osis::internals::pair(w.cfg(2, &[]), &offer).unwrap();
    let req: osis::PairRequest = join.request().to_string().parse().unwrap();
    let (_, reply) = a.pair_accept(&req).unwrap();
    let d = join.finish(&reply).unwrap();
    w.run();
    assert_eq!(texts(&d, c), ["hello"], "paired");
    post(&d, c, "from two").unwrap();
    w.run();
    assert_eq!(texts(&a, c), ["hello", "from two"]);
    let r = w.until(osis::internals::restore(w.cfg(3, &[host]), &card), 1000, 60).unwrap();
    w.run();
    assert_eq!(texts(&r, c), ["hello", "from two"], "restored");
}

// spec/permissions.md §5.1, §5.2: a participant's write stamped after its kick reaches another participant before the kick does: once the kick is there it is hidden from others, an edit of the participant's older message by it answers for nothing; its own node shows it, marked; a watch says it turned invalid
#[test]
fn turned_invalid_at_a_reader_spec_perm_5() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    let (d, _) = w.person(3, &[0]);
    w.run();
    let dee = meet(&mut w, &a, &d);
    add(&a, c, dee, Role::Write).unwrap();
    w.run();
    let old = post(&b, c, "old").unwrap();
    w.run();
    w.advance(1000);
    w.set_online(&a, false);
    w.until(kick(&a, c, bob, None, SyncFirst::Skip, osis::internals::PRESYNC), 1000, 10).unwrap();
    w.advance(1000);
    let m = find(&b, c, &old).unwrap().unwrap();
    let edit_id = edit(&b, c, &m, "rewritten").unwrap();
    let late = post(&b, c, "late").unwrap();
    w.run();
    assert_eq!(texts(&d, c).last().unwrap(), "late", "there before the kick");
    assert_eq!(find(&d, c, &edit_id).unwrap().unwrap().body, Body::Text("rewritten".into()));
    let (tx, rx) = std::sync::mpsc::channel();
    let _s = watch(&d, c, move |_, e| tx.send(e).unwrap()).unwrap();
    w.set_online(&a, true);
    w.advance(60_000);
    w.run();
    d.settle();
    let t = texts(&d, c);
    assert!(!t.contains(&"late".to_string()) && !t.contains(&"rewritten".to_string()), "{t:?}");
    assert!(rx.try_iter().any(|e| matches!(e, Event::Entry(e) if e.id == late && !e.valid)));
    b.settle();
    assert!(!find(&b, c, &late).unwrap().unwrap().valid, "its own, marked");
    assert_eq!(find(&b, c, &edit_id).unwrap().unwrap().id, edit_id, "an invalid edit replaces nothing");
}

// spec/permissions.md §5.2: an edit's list of what it answers for hides only its sender's own tombstones: a participant naming another's deleted message hides nothing
#[test]
fn forged_prior_hides_no_tombstone_spec_perm_5() {
    let Room { mut w, a, b, c, .. } = room(Options::default());
    let hers = post(&a, c, "hers").unwrap();
    w.run();
    w.advance(10);
    let his = post(&b, c, "his").unwrap();
    w.run();
    delete(&a, c, &find(&a, c, &hers).unwrap().unwrap()).unwrap();
    w.run();
    write_raw_replaces(&b, c, "his, edited", &Replaces { original: his, prior: vec![hers, his] });
    w.run();
    assert_eq!(texts(&a, c), ["<deleted>", "his, edited"]);
}

// spec: none (notes/chat.md Read): a cursor goes by arrival: a participant's post made offline, stamped before what the reader has seen, comes after the cursor; any entry's id is a cursor; nothing new reads as nothing
#[test]
fn late_post_comes_after_a_cursor_spec_none() {
    let Room { mut w, a, b, c, .. } = room(Options::default());
    let first = post(&a, c, "first").unwrap();
    w.run();
    w.set_online(&b, false);
    w.advance(1000);
    let late = post(&b, c, "from the train").unwrap();
    w.advance(1000);
    let seen = post(&a, c, "seen").unwrap();
    w.run();
    let got = since(&a, c, Some(&first), 10).unwrap();
    assert_eq!(got.messages.iter().map(|m| m.id).collect::<Vec<_>>(), [seen]);
    let at = got.cursor.unwrap();
    assert_eq!(cursor(&a, c).unwrap(), Some(at));
    w.set_online(&b, true);
    w.advance(60_000);
    w.run();
    assert!(late.pos < seen.pos);
    let got = since(&a, c, Some(&at), 10).unwrap();
    assert_eq!(got.messages.iter().map(|m| m.id).collect::<Vec<_>>(), [late]);
    assert_eq!(got.cursor, Some(late), "it arrived last");
    assert_eq!(cursor(&a, c).unwrap(), Some(late));
    assert!(since(&a, c, Some(&late), 10).unwrap().messages.is_empty());
    // by the page: one at a time, none lost
    let page = since(&a, c, None, 2).unwrap();
    assert!(page.more);
    assert_eq!(page.messages.len(), 2);
    let rest = since(&a, c, page.cursor.as_ref(), 2).unwrap();
    assert_eq!(rest.messages.iter().map(|m| m.id).collect::<Vec<_>>(), [late]);
}

// spec/permissions.md §8, §3: a link joiner leaves: its edge is on the link's key, so `leave` goes there; it writes no more, keeps its copy, the link's other joiner stays
#[test]
fn link_joiner_leaves_spec_perm_8() {
    let mut w = World::new();
    let host = w.add_host();
    let (a, _) = w.person(1, &[host]);
    let (b, _) = w.person(2, &[host]);
    let (d, _) = w.person(3, &[host]);
    w.run();
    let c = create(&a, &Options::default()).unwrap();
    let l = link(&a, c, Role::Write, false).unwrap();
    post(&a, c, "hi").unwrap();
    w.run();
    w.until(join(&b, &l, osis::internals::WAIT), 1000, 30).unwrap();
    w.until(join(&d, &l, osis::internals::WAIT), 1000, 30).unwrap();
    w.run();
    leave(&b, c).unwrap();
    w.run();
    assert!(post(&b, c, "gone").is_err());
    assert!(!b.holders(c).unwrap().iter().any(|h| h.actor == b.me()));
    assert_eq!(texts(&b, c), ["hi"], "the leaver's copy");
    post(&d, c, "still here").unwrap();
    w.run();
    assert_eq!(texts(&a, c), ["hi", "still here"]);
    assert!(!texts(&b, c).contains(&"still here".to_string()));
}

// spec/permissions.md §8, spec/sync.md §2: a link shared in advance keeps working: someone joins by it and leaves, the next person joins by it, reads, posts; a leaver comes back by it; a kick ends it, says so, and a new link works
#[test]
fn link_after_leave_and_kick_spec_perm_8() {
    let mut w = World::new();
    let host = w.add_host();
    let (a, _) = w.person(1, &[host]);
    let (b, _) = w.person(2, &[host]);
    let (d, _) = w.person(3, &[host]);
    let (e, _) = w.person(4, &[host]);
    w.run();
    let c = create(&a, &Options::default()).unwrap();
    let l = link(&a, c, Role::Write, false).unwrap();
    post(&a, c, "hi").unwrap();
    w.run();
    w.until(join(&b, &l, osis::internals::WAIT), 1000, 30).unwrap();
    w.run();
    leave(&b, c).unwrap();
    w.run();
    w.advance(70_000);
    w.run();
    assert_eq!(osis_chat::links(&a, c).unwrap().len(), 1, "a leave ends no link");
    w.until(join(&d, &l, osis::internals::WAIT), 1000, 30).unwrap();
    w.run();
    assert_eq!(texts(&d, c), ["hi"]);
    post(&d, c, "joined after the leave").unwrap();
    w.run();
    assert_eq!(texts(&a, c), ["hi", "joined after the leave"]);
    assert!(!texts(&b, c).contains(&"joined after the leave".to_string()), "what the leave protects");
    w.until(join(&b, &l, osis::internals::WAIT), 1000, 30).unwrap();
    w.run();
    assert!(texts(&b, c).contains(&"joined after the leave".to_string()), "the link text brings a leaver back");
    w.until(kick(&a, c, d.me(), None, SyncFirst::Skip, osis::internals::PRESYNC), 1000, 10).unwrap();
    w.run();
    w.advance(70_000);
    w.run();
    assert!(osis_chat::links(&a, c).unwrap().is_empty(), "a kick ends the link");
    assert!(matches!(w.until(join(&e, &l, osis::internals::WAIT), 1000, 30), Err(osis::Error::Invalid(_))), "and says so");
    assert!(matches!(w.until(join(&d, &l, osis::internals::WAIT), 1000, 30), Err(osis::Error::Invalid(_))), "the kicked person stays out");
    let fresh = link(&a, c, Role::Write, false).unwrap();
    w.run();
    w.until(join(&e, &fresh, osis::internals::WAIT), 1000, 30).unwrap();
    w.run();
    post(&e, c, "by the new link").unwrap();
    post(&b, c, "still here").unwrap();
    w.run();
    let t = texts(&a, c);
    assert!(t.contains(&"by the new link".to_string()) && t.contains(&"still here".to_string()), "{t:?}");
}

// spec/permissions.md §8: a link past its `until` is shown as none
#[test]
fn expired_link_not_shown_spec_perm_8() {
    let mut w = World::new();
    let host = w.add_host();
    let (a, _) = w.person(1, &[host]);
    w.run();
    let c = create(&a, &Options::default()).unwrap();
    a.make_link(c, Role::Write, osis::LinkOpts { until: Some(osis::WallMs(a.now().unwrap().0 + 1000)), single_use: false, direct: false }).unwrap();
    w.run();
    assert_eq!(osis_chat::links(&a, c).unwrap().len(), 1);
    w.advance(2000);
    assert!(osis_chat::links(&a, c).unwrap().is_empty());
}

// spec/permissions.md §8: `participants` lists the people who joined by a link, not its actor; a direct participant learns a joiner from its first post; kicking a joiner ends the link, the others stay; a single-use link leaves its joiner a participant
#[test]
fn link_joiners_are_participants_spec_perm_8() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    let (d, _) = w.person(3, &[0]);
    let (e, _) = w.person(4, &[0]);
    let (f, _) = w.person(5, &[0]);
    w.run();
    let l = link(&a, c, Role::Read, false).unwrap();
    let once = link(&a, c, Role::Write, true).unwrap();
    w.run();
    assert_eq!(osis_chat::links(&a, c).unwrap().len(), 2);
    assert_eq!(participants(&a, c).unwrap().into_keys().collect::<BTreeSet<_>>(), BTreeSet::from([a.me(), bob]), "a link no one used is nobody");
    w.until(join(&d, &l, osis::internals::WAIT), 1000, 30).unwrap();
    w.until(join(&e, &l, osis::internals::WAIT), 1000, 30).unwrap();
    w.until(join(&f, &once, osis::internals::WAIT), 1000, 30).unwrap();
    w.run();
    assert_eq!(participants(&a, c).unwrap().into_keys().collect::<BTreeSet<_>>(), BTreeSet::from([a.me(), bob, d.me(), e.me(), f.me()]));
    assert!(participants(&d, c).unwrap().contains_key(&e.me()), "a joiner sees the link's other joiners");
    assert_eq!(participants(&a, c).unwrap().get(&d.me()), Some(&Role::Read), "the link's role");
    assert_eq!(participants(&a, c).unwrap().get(&f.me()), Some(&Role::Write));
    assert_eq!(osis_chat::links(&a, c).unwrap().len(), 1, "the single-use link is spent");
    post(&f, c, "from a joiner").unwrap();
    w.run();
    assert!(participants(&b, c).unwrap().contains_key(&f.me()), "a direct participant, from the post");
    w.until(kick(&a, c, d.me(), None, SyncFirst::Skip, osis::internals::PRESYNC), 1000, 10).unwrap();
    w.run();
    let left = participants(&a, c).unwrap();
    assert!(!left.contains_key(&d.me()) && left.contains_key(&e.me()), "{left:?}");
    assert!(osis_chat::links(&a, c).unwrap().is_empty(), "kicking a joiner ended the link");
    // a rotation naming K's keyset: a direct participant and a joiner go on
    let (g, _) = w.person(6, &[0]);
    let gid = meet(&mut w, &a, &g);
    add(&a, c, gid, Role::Write).unwrap();
    w.run();
    w.until(kick(&a, c, bob, None, SyncFirst::Skip, osis::internals::PRESYNC), 1000, 10).unwrap();
    w.run();
    post(&g, c, "after the rotation").unwrap();
    post(&f, c, "and from a joiner").unwrap();
    w.run();
    for db in [&a, &g, &e, &f] {
        let t = texts(db, c);
        assert!(t.contains(&"after the rotation".to_string()) && t.contains(&"and from a joiner".to_string()), "{t:?}");
    }
}

// spec/permissions.md §8, §5.2: joining by link on a store in use: the joiner is its own verified sender, its name and reply come through; a cursor gives what is new, an edit of an older message as that message; kicking a joiner leaves the link's other joiners
#[test]
fn link_join_name_reply_cursor_spec_perm_8() {
    let mut w = World::new();
    let host = w.add_host();
    let (a, _) = w.person(1, &[host]);
    let (b, _) = w.person(2, &[host]);
    let (d, _) = w.person(3, &[host]);
    w.run();
    let c = create(&a, &Options::default()).unwrap();
    let l = link(&a, c, Role::Write, false).unwrap();
    let first = send(&a, c, &Draft { text: "hi".into(), name: Some("alice".into()), reply_to: None }).unwrap();
    w.run();
    assert_eq!(w.until(join(&b, &l, osis::internals::WAIT), 1000, 30).unwrap(), c);
    assert_eq!(w.until(join(&d, &l, osis::internals::WAIT), 1000, 30).unwrap(), c);
    w.run();
    assert_eq!(texts(&b, c), ["hi"]);
    w.advance(10);
    let cursor = since(&b, c, None, 10).unwrap().cursor.unwrap();
    assert_eq!(cursor, first);
    let r = send(&b, c, &Draft { text: "hello".into(), name: Some("bob".into()), reply_to: Some(first) }).unwrap();
    w.run();
    let m = newest(&a, c);
    assert_eq!((m.id, m.sender, m.name.as_deref(), m.reply_to), (r, b.me(), Some("bob"), Some(first)));
    let new = since(&a, c, Some(&cursor), 10).unwrap();
    assert_eq!(new.messages.iter().map(|m| m.id).collect::<Vec<_>>(), [r]);
    let cursor = new.cursor.unwrap();
    assert!(since(&a, c, Some(&cursor), 10).unwrap().messages.is_empty());
    w.advance(10);
    edit(&a, c, &find(&a, c, &first).unwrap().unwrap(), "hi!").unwrap();
    w.run();
    let again = since(&b, c, Some(&cursor), 10).unwrap();
    assert_eq!(again.messages.len(), 1);
    assert_eq!((again.messages[0].id, again.messages[0].name.as_deref(), &again.messages[0].body), (first, Some("alice"), &Body::Text("hi!".into())));
    w.until(kick(&a, c, b.me(), None, SyncFirst::Skip, osis::internals::PRESYNC), 1000, 10).unwrap();
    w.run();
    assert!(post(&b, c, "after").is_err());
    post(&d, c, "still here").unwrap();
    w.run();
    assert_eq!(newest(&a, c).body, Body::Text("still here".into()));
    assert_eq!(texts(&b, c).len(), 2, "the kicked joiner's copy");
}

/// Post and read on a chat of 10^4 messages and 100 participants (notes/chat.md Costs).
#[test]
#[ignore = "timing: --release"]
fn scale_post_read() {
    scale(100, 10_000);
}

#[test]
#[ignore = "probe"]
fn scale_long() {
    scale(1, 10_000);
}

#[test]
#[ignore = "probe"]
fn scale_small() {
    scale(20, 2000);
}

fn scale(n_participants: u64, n_msgs: usize) {
    use std::time::Instant;
    let mut w = World::new();
    let host = w.add_host();
    let (a, _) = w.person(1, &[host]);
    w.run();
    let c = create(&a, &Options::default()).unwrap();
    let t = Instant::now();
    let mut ms = Vec::new();
    for i in 0..n_participants {
        let (m, _) = w.person(100 + i, &[host]);
        w.run();
        let p = meet(&mut w, &a, &m);
        add(&a, c, p, Role::Write).unwrap();
        w.run();
        ms.push(m);
    }
    eprintln!("join {n_participants}: {:?}", t.elapsed());
    let b = &ms[0];
    assert_eq!(participants(b, c).unwrap().len(), n_participants as usize + 1);
    let t = Instant::now();
    let before = w.traffic(&a);
    for i in 0..n_msgs {
        post(&a, c, &format!("message number {i}")).unwrap();
        w.advance(1);
        if i % 100 == 99 {
            w.run();
        }
    }
    w.run();
    let after = w.traffic(&a);
    eprintln!("post+sync {n_msgs} to {n_participants}: {:?}, up {} B/msg", t.elapsed(), (after.up - before.up) / n_msgs as u64);
    let t = Instant::now();
    for i in 0..100 {
        post(&a, c, &format!("x{i}")).unwrap();
    }
    eprintln!("post (local): {:?} each", t.elapsed() / 100);
    let t = Instant::now();
    for _ in 0..100 {
        let p = Timeline::new(b, c).unwrap().older(b, 50).unwrap();
        assert_eq!(p.messages.len(), 50);
    }
    eprintln!("read newest 50: {:?}", t.elapsed() / 100);
    let t = Instant::now();
    let mut tl = Timeline::new(b, c).unwrap();
    let (mut n, mut more) = (0, true);
    while more {
        let p = tl.older(b, 50).unwrap();
        n += p.messages.len();
        more = p.more;
    }
    eprintln!("read all {n}: {:?}", t.elapsed());
    let t = Instant::now();
    let m = find(b, c, &Timeline::new(b, c).unwrap().older(b, n_msgs / 2).unwrap().messages[n_msgs / 2 - 1].id).unwrap().unwrap();
    eprintln!("find 5000 back: {:?}", t.elapsed());
    let t = Instant::now();
    delete(&a, c, &find(&a, c, &m.id).unwrap().unwrap()).unwrap();
    w.run();
    eprintln!("delete + sync: {:?}", t.elapsed());
    let new = w.person(99, &[host]).0;
    w.run();
    let p = meet(&mut w, &a, &new);
    let before = w.traffic(&new);
    let t = Instant::now();
    add(&a, c, p, Role::Write).unwrap();
    w.run();
    let after = w.traffic(&new);
    eprintln!("newcomer fetch: {:?}, down {} MB; first page complete {}", t.elapsed(), (after.down - before.down) / 1_000_000, Timeline::new(&new, c).unwrap().older(&new, 1).unwrap().complete);
    let t = Instant::now();
    let kicked = participants(&a, c).unwrap().into_keys().find(|k| *k != a.me()).unwrap();
    w.until(kick(&a, c, kicked, None, SyncFirst::Skip, osis::internals::PRESYNC), 1000, 10).unwrap();
    w.run();
    eprintln!("kick: {:?}", t.elapsed());
}

// spec/permissions.md §3 (Keep): leaving keeps by the chat's default, the others keep its messages; a new participant gets the tombstones and history; a participant promoted to moderator deletes another's
#[test]
fn leave_promote_newcomer_spec_perm_3() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    let (d, _) = w.person(3, &[0]);
    w.run();
    let dee = meet(&mut w, &a, &d);
    post(&b, c, "from bob").unwrap();
    let gone = post(&a, c, "gone").unwrap();
    w.run();
    delete(&a, c, &find(&a, c, &gone).unwrap().unwrap()).unwrap();
    w.run();
    add(&a, c, dee, Role::Write).unwrap();
    w.run();
    assert_eq!(texts(&d, c).len(), 2, "history and tombstone for a newcomer: {:?}", texts(&d, c));
    assert!(texts(&d, c).contains(&"<deleted>".to_string()));
    add(&a, c, dee, Role::Admin).unwrap();
    w.run();
    assert_eq!(participants(&b, c).unwrap().get(&dee), Some(&Role::Admin));
    let his = post(&b, c, "moderate me").unwrap();
    w.run();
    delete(&d, c, &find(&d, c, &his).unwrap().unwrap()).unwrap();
    w.run();
    assert!(matches!(find(&a, c, &his).unwrap().unwrap().body, Body::Deleted { .. }));
    leave(&b, c).unwrap();
    w.run();
    assert_eq!(participants(&a, c).unwrap().get(&bob), None);
    assert!(post(&b, c, "gone").is_err());
    assert!(texts(&b, c).contains(&"from bob".to_string()), "the leaver's copy");
    assert!(texts(&a, c).contains(&"from bob".to_string()), "the others keep it");
    post(&a, c, "unseen").unwrap();
    w.run();
    assert!(!texts(&b, c).contains(&"unseen".to_string()));
    // the kick's pre-sync on a live chat
    w.until(kick(&a, c, dee, None, SyncFirst::Required, osis::internals::PRESYNC), 1000, 60).unwrap();
    w.run();
    assert_eq!(participants(&a, c).unwrap().len(), 1);
}

// notes/chat-designs/e.md What is different: per-year aspects: reads merge across the new year; a watch hears the next year's first message; a new device gets both
#[test]
fn across_a_new_year_spec_data_model_2() {
    let Room { mut w, a, b, c, .. } = room(Options::default());
    let (tx, rx) = std::sync::mpsc::channel();
    let _s = watch(&b, c, move |_, e| tx.send(e).unwrap()).unwrap();
    let old = post(&a, c, "last year").unwrap();
    w.run();
    // T0 is mid-November 2023
    w.advance(60 * 86_400_000);
    w.run();
    let new = post(&b, c, "new year").unwrap();
    w.run();
    a.settle();
    assert_eq!(new.year, old.year + 1);
    for db in [&a, &b] {
        assert_eq!(texts(db, c), ["last year", "new year"]);
    }
    b.settle();
    assert!(rx.try_iter().any(|e| matches!(e, Event::Entry(e) if e.id == new)));
    let e = edit(&a, c, &find(&a, c, &old).unwrap().unwrap(), "edited across").unwrap();
    assert_eq!(e.year, new.year);
    w.run();
    assert_eq!(texts(&b, c), ["edited across", "new year"]);
    let page = entries(&b, c, HistoryFrom::Oldest, 1).unwrap();
    assert_eq!(page.entries[0].id, old);
    assert!(page.more);
}

/// `chats` lists the chats a node syncs, not its other synced groups (Bob's profile group from
/// his contact card), a new chat once it is here; not one left (at once) or kicked from with a
/// kept copy.
#[test]
fn chats_lists_held_chats() {
    let mut r = room(Options::default());
    assert!(r.b.status().unwrap().groups.contains_key(&r.b.profile().unwrap()));
    assert_eq!(chats(&r.a).unwrap(), vec![r.c]);
    assert_eq!(chats(&r.b).unwrap(), vec![r.c]);
    let c2 = create(&r.a, &Options::default()).unwrap();
    r.w.run();
    let mut both = vec![r.c, c2];
    both.sort();
    assert_eq!(chats(&r.a).unwrap(), both);
    assert_eq!(chats(&r.b).unwrap(), vec![r.c]);
    leave(&r.b, r.c).unwrap();
    assert!(chats(&r.b).unwrap().is_empty(), "left, before a host has it");
    r.w.run();
    assert!(chats(&r.b).unwrap().is_empty());

    let Room { mut w, a, b, c, bob } = room(Options::default());
    w.until(kick(&a, c, bob, None, SyncFirst::Skip, osis::internals::PRESYNC), 1000, 10).unwrap();
    w.run();
    assert_eq!(b.kept_copies().unwrap(), vec![c]);
    assert!(chats(&b).unwrap().is_empty());
}

// spec: none. notes/chat.md: joining a chat already held gives the chat: its maker or a participant pasting a link, a used single-use link, a joiner's second redemption (each failed or hung before); a used link still fails for someone outside
#[test]
fn join_held_chat() {
    let Room { mut w, a, b, c, .. } = room(Options::default());
    let l = link(&a, c, Role::Write, false).unwrap();
    let one = link(&a, c, Role::Write, true).unwrap();
    let (d, _) = w.person(3, &[0]);
    let (e, _) = w.person(4, &[0]);
    w.run();
    assert_eq!(w.until(join(&a, &l, osis::internals::WAIT), 1000, 30).unwrap(), c, "its maker");
    assert_eq!(w.until(join(&b, &l, osis::internals::WAIT), 1000, 30).unwrap(), c, "a participant");
    assert_eq!(w.until(join(&d, &one, osis::internals::WAIT), 1000, 30).unwrap(), c);
    w.run();
    assert_eq!(w.until(join(&d, &one, osis::internals::WAIT), 1000, 30).unwrap(), c, "used up, by this person");
    assert_eq!(w.until(join(&d, &l, osis::internals::WAIT), 1000, 30).unwrap(), c);
    w.run();
    assert_eq!(w.until(join(&d, &l, osis::internals::WAIT), 1000, 30).unwrap(), c, "again");
    assert!(matches!(w.until(join(&e, &one, osis::internals::WAIT), 1000, 30), Err(osis::Error::Invalid(_))), "used up, for someone else");
}

// spec: none. notes/chat.md: a link whose target names a held chat but whose key is another chat's opens the held chat and redeems nothing; once kicked with a kept copy the chat is not held, so that link fails and joins nothing, and an honest one rejoins
#[test]
fn join_held_target_redeems_nothing_kicked_rejoins() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    let c2 = create(&a, &Options::default()).unwrap();
    let l = link(&a, c, Role::Write, false).unwrap();
    let l2 = link(&a, c2, Role::Write, false).unwrap();
    w.run();
    let mut crafted = osis_label::ShareLink::from_text(&l2.to_string()).unwrap();
    crafted.target = c;
    let crafted: osis::ShareLink = crafted.to_text().unwrap().parse().unwrap();
    assert_eq!(w.until(join(&b, &crafted, osis::internals::WAIT), 1000, 30).unwrap(), c);
    w.run();
    assert_eq!(chats(&b).unwrap(), vec![c], "c2 not joined");

    w.until(kick(&a, c, bob, None, SyncFirst::Skip, osis::internals::PRESYNC), 1000, 10).unwrap();
    w.run();
    assert_eq!(b.kept_copies().unwrap(), vec![c]);
    assert!(matches!(w.until(join(&b, &crafted, osis::internals::WAIT), 1000, 200), Err(osis::Error::Invalid(_))), "known, not held: the link's own key does not reach it");
    w.run();
    assert!(chats(&b).unwrap().is_empty(), "c2 not joined");
    assert_eq!(w.until(join(&b, &l, osis::internals::WAIT), 1000, 30).unwrap(), c);
    w.run();
    assert_eq!(chats(&b).unwrap(), vec![c], "rejoined");
    assert!(b.kept_copies().unwrap().is_empty());
}
