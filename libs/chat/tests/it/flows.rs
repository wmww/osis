//! Chat end to end on the sim. spec: none (a client surface specified in notes/chat.md).

use osis_chat::*;
use osis::core::REQUIRED;
use osis::{Body, CommitEvent, CommitFrom, CommitId, CommitKind, CommitPos, CommitQuery, LinkOpts, Osis, Part, PurgeBy, Role, SetRoleOpts, ShareLink, Subscription, Tid, Value};
use osis_sim::world::World;
use schema::{EditMode, MSG};
use std::collections::BTreeSet;
use std::time::Duration;

/// A message of `text`.
fn msg(text: &str) -> schema::Message {
    schema::Message { text: text.into(), name: None, reply_to: None, edit: None }
}

/// Fires `m` on chat `c`: its place.
fn send(db: &Osis, c: Tid, m: &schema::Message) -> osis::Result<CommitPos> {
    let mut w = db.write();
    w.at(c, MSG).fire(m)?;
    Ok(w.commit()?.unwrap().pos())
}

fn post(db: &Osis, c: Tid, text: &str) -> osis::Result<CommitPos> {
    send(db, c, &msg(text))
}

/// A write claiming to edit `original`, answering for `prior`, past `edit`'s checks.
fn claim(db: &Osis, c: Tid, text: &str, original: CommitPos, prior: &[CommitPos]) -> CommitPos {
    let edit = schema::Edit { original: original.to_string(), prior: prior.iter().map(CommitPos::to_string).collect() };
    send(db, c, &schema::Message { edit: Some(edit), ..msg(text) }).unwrap()
}

fn kick(db: &Osis, c: Tid, who: Tid, retain_copy: Option<bool>) -> osis::Result<()> {
    db.set_role(c, who, None, SetRoleOpts { retain_copy })
}

fn link(db: &Osis, c: Tid, role: Role, single_use: bool) -> ShareLink {
    db.make_link(c, role, LinkOpts { until: None, single_use, direct: false }).unwrap()
}

/// Sets the disappearing timer: the rules, written whole, with the message rule's expiry.
fn disappear(db: &Osis, c: Tid, d: Option<Duration>) {
    let mut rules = db.at(c, REQUIRED).get().unwrap().unwrap();
    rules.rules.get_mut(&MSG.name()).unwrap().expires = d;
    let mut w = db.write();
    w.at(c, REQUIRED).set(&rules).unwrap();
    w.commit().unwrap();
}

/// This account's own writes on `c` turned invalid, as their commits.
fn on_rejected(db: &Osis, c: Tid, tx: std::sync::mpsc::Sender<CommitId>) -> Subscription {
    db.on_diagnostic(move |_, d| {
        if let osis::Diagnostic::OwnWriteInvalid { commit, things, .. } = d
            && things.contains(&c)
        {
            tx.send(commit).unwrap();
        }
    })
    .unwrap()
}

/// What `c`'s watch hears.
fn watch(db: &Osis, c: Tid) -> (Subscription, std::sync::mpsc::Receiver<CommitEvent>) {
    let (tx, rx) = std::sync::mpsc::channel();
    (db.at(c, MSG).on_fire(move |_, e| tx.send(e).unwrap()).unwrap(), rx)
}

/// The message part at `id`, as listed here.
fn part_at(db: &Osis, c: Tid, id: &CommitPos) -> Option<Part<schema::Message>> {
    let page = db.at(c, MSG).fired(&CommitQuery { from: CommitFrom::After(CommitPos::time(id.at())), ..Default::default() }).unwrap();
    page.commits.iter().find(|k| k.pos() == *id).and_then(|k| k.at(c, MSG))
}

fn text(b: &Body<schema::Message>) -> Option<&str> {
    match b {
        Body::Held(Some(m)) => Some(&m.text),
        _ => None,
    }
}

fn name(m: &Message) -> Option<&str> {
    match &m.body {
        Body::Held(Some(x)) => x.name.as_deref(),
        _ => None,
    }
}

/// A world with one peer, Alice and Bob who know each other, and Alice's chat with Bob in it.
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
    w.until(a.import_contact(&card), 1000, 10).unwrap()
}

fn room(o: Options) -> Room {
    let mut w = World::new();
    let host = w.add_host();
    let a = w.account(1, &[host]);
    let b = w.account(2, &[host]);
    w.run();
    let bob = meet(&mut w, &a, &b);
    let c = create(&a, &o).unwrap();
    a.grant(c, bob, Role::Write, Default::default()).unwrap();
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
            Body::Held(Some(x)) => x.text.clone(),
            Body::Purged { .. } => "<deleted>".into(),
            b => format!("<{b:?}>"),
        })
        .collect();
    out.reverse();
    out
}

fn newest(db: &Osis, c: Tid) -> Message {
    Timeline::new(db, c).unwrap().older(db, 1).unwrap().messages.remove(0)
}

// spec/permissions.md §1, §5.2 and spec/commits.md §5: a chat in one flow: this account its first admin, synced, required retention; a post reaches a participant with its verified sender; identical posts are two messages; paging both ways
#[test]
fn create_post_read_spec_commits_5() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    assert_eq!(a.grants(c).unwrap().get(&a.me()).map(|e| e.role), Some(Role::Admin), "its first admin");
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
    let page = |from| a.at(c, MSG).fired(&CommitQuery { from, limit: Some(2), kinds: vec![CommitKind::Content], ..Default::default() }).unwrap();
    let rest = page(CommitFrom::Oldest);
    assert!(rest.more && rest.complete);
    let next = page(CommitFrom::After(rest.commits[1].pos()));
    assert_eq!(next.commits.len(), 1);
    assert!(!next.more);
}

// notes/chat.md Edit, spec/permissions.md §5.2: edits: newest wins in any arrival order; the old text purged by default with no stray tombstone; a repeat edit still answers for the old one; another's edit is its own message, not an edit; off mode ignores replaces; keep mode shows versions
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
        assert!(matches!(part_at(db, c, &o).unwrap().body, Body::Purged { .. }));
    }
    // Bob's forged edit of Alice's message: a message of his own
    let forged = claim(&b, c, "forged", o, &[o]);
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
    assert_eq!(text(&m.body), Some("three"));
    let e: Vec<_> = m.earlier.iter().map(|e| e.1.text.as_str()).collect();
    assert_eq!(e, ["two", "one"]);
    // an edit deleted takes every version
    delete(&a, c, &m).unwrap();
    w.run();
    assert!(texts(&b, c).iter().all(|t| t == "<deleted>"), "{:?}", texts(&b, c));
    let Room { w: _, a, c, .. } = room(Options { edit: EditMode::Off, ..Options::default() });
    post(&a, c, "fixed").unwrap();
    assert!(edit(&a, c, &newest(&a, c), "x").is_err());
    let o = newest(&a, c).id;
    claim(&a, c, "a plain message", o, &[o]);
    assert_eq!(texts(&a, c), ["fixed", "a plain message"]);
}

// notes/chat.md Edit: two nodes' edits arrive in either order; the same newest wins
#[test]
fn concurrent_edits_agree_spec_crdt_1() {
    let mut w = World::new();
    let host = w.add_host();
    let a = w.account(1, &[host]);
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
    assert_eq!(texts(&a2, c), ["base"], "a new node of a participant");
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

// spec/commits.md §5, spec/sync.md §6: delete for everyone by author and moderator; a participant cannot delete another's; a tombstone reaches a new node with its sender
#[test]
fn delete_for_everyone_spec_commits_5() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    let mine = post(&a, c, "mine").unwrap();
    w.advance(10);
    let his = post(&b, c, "his").unwrap();
    w.advance(10);
    post(&b, c, "retained").unwrap();
    w.run();
    let at = |db: &Osis, id: &CommitPos| find(db, c, id).unwrap().unwrap();
    assert!(matches!(delete(&b, c, &at(&b, &mine)), Err(osis::Error::Permission { .. })));
    // past the library: osis refuses the request too, so nothing is sent
    let mut x = b.write();
    x.at(c, MSG).purge(osis::Purge::Commit(mine.commit().unwrap())).unwrap();
    assert!(matches!(x.commit(), Err(osis::Error::Permission { .. })));
    w.run();
    assert!(matches!(at(&a, &mine).body, Body::Held(Some(_))));
    delete(&b, c, &at(&b, &his)).unwrap();
    w.run();
    assert_eq!(texts(&a, c), ["mine", "<deleted>", "retained"]);
    delete(&a, c, &at(&a, &mine)).unwrap();
    w.run();
    assert_eq!(texts(&b, c), ["<deleted>", "<deleted>", "retained"]);
    // a moderator's delete of Bob's
    delete(&a, c, &newest(&a, c)).unwrap();
    w.run();
    assert_eq!(texts(&b, c), ["<deleted>"; 3]);
    let by = |db: &Osis, id: &CommitPos| match at(db, id).body {
        Body::Purged { actor, .. } => actor,
        x => panic!("{x:?}"),
    };
    assert_eq!((by(&b, &his), by(&a, &mine)), (Some(bob), Some(a.me())), "who deleted, by its signed header");
    let offer = b.pair_offer().unwrap();
    let join = osis::internals::pair(w.cfg(5, &[]), &offer).unwrap();
    let req: osis::PairRequest = join.request().to_string().parse().unwrap();
    let (_, reply) = b.pair_accept(&req).unwrap();
    let b2 = join.finish(&reply).unwrap();
    w.run();
    assert_eq!(texts(&b2, c), ["<deleted>"; 3], "tombstones on a new node");
    assert_eq!(newest(&b2, c).sender, bob);
    assert_eq!(by(&b2, &his), Some(bob), "on a new node too");
}

// spec/permissions.md §6: purge sets: author only keeps a moderator out; nobody is a permanent chat; admin only keeps an author out
#[test]
fn purge_sets_spec_perm_6() {
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

// spec/permissions.md §3 (Retain), §5.1: a kicked participant keeps a read-only copy, sees nothing new and writes nothing others accept; the override erases; purge by author erases its messages for those left
#[test]
fn kick_keep_erase_purge_spec_perm_3() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    post(&b, c, "before").unwrap();
    post(&a, c, "hello").unwrap();
    w.run();
    kick(&a, c, bob, None).unwrap();
    w.run();
    assert_eq!(b.retained_copies().unwrap(), vec![c]);
    assert_eq!(texts(&b, c).len(), 2, "retained");
    assert!(post(&b, c, "after").is_err(), "the copy is read-only");
    post(&a, c, "new").unwrap();
    w.run();
    assert_eq!(texts(&b, c).len(), 2, "nothing new");
    assert_eq!(texts(&a, c).len(), 3);
    let mut x = a.write();
    x.at(c, MSG).purge(osis::Purge::Author(bob)).unwrap();
    x.commit().unwrap();
    w.run();
    assert!(texts(&a, c).contains(&"<deleted>".to_string()) && !texts(&a, c).contains(&"before".to_string()));

    let Room { mut w, a, b, c, bob } = room(Options::default());
    post(&a, c, "hello").unwrap();
    w.run();
    kick(&a, c, bob, Some(false)).unwrap();
    w.run();
    assert!(b.retained_copies().unwrap().is_empty());
    assert!(texts(&b, c).is_empty(), "erased");
    assert!(!b.has_content(c).unwrap());
}

// spec/commits.md §5: required retention refuses a participant's other retention: refused at its writer, and if forged past it, invalid and unshown; every other aspect too; a stale writer is told
#[test]
fn required_and_stale_writer_spec_commits_5() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    post(&a, c, "x").unwrap();
    w.run();
    let k = MSG.name();
    let mut x = b.write();
    let bad = osis::Retention { by: PurgeBy::Nobody, history: Some(osis::History::FOREVER) };
    assert!(x.at(c, osis::DynamicAspectKey::untyped(k.clone())).retention(bad).set(&Value::Str("x".into())).is_err() || x.commit().is_err(), "refused at its writer");
    let (tx, rx) = std::sync::mpsc::channel();
    let _s = on_rejected(&b, c, tx);
    // Bob offline: the timer changes, he posts under the old rule
    w.set_online(&b, false);
    w.advance(1000);
    disappear(&a, c, Some(Duration::from_secs(60)));
    w.run();
    w.advance(1000);
    let stale = post(&b, c, "stale").unwrap();
    let stale2 = post(&b, c, "stale too").unwrap();
    w.set_online(&b, true);
    w.advance(60_000);
    w.run();
    b.settle();
    let told: Vec<_> = rx.try_iter().collect();
    let ids: Vec<CommitId> = told.clone();
    assert!(ids.contains(&stale.commit().unwrap()) && ids.contains(&stale2.commit().unwrap()), "told of both: {told:?}");
    assert!(!texts(&a, c).iter().any(|t| t.starts_with("stale")), "others do not show it");
    let mine = find(&b, c, &stale).unwrap().unwrap();
    assert!(!mine.valid, "its sender sees it did not go");
    assert_eq!(text(&mine.body), Some("stale"), "and can send it again");
    assert_eq!(participants(&a, c).unwrap().get(&bob), Some(&Role::Write));
    let Body::Held(Some(again)) = &mine.body else { panic!() };
    let again = send(&b, c, again).unwrap();
    w.run();
    assert_eq!(texts(&a, c).last().unwrap(), "stale", "it went this time");
    assert!(find(&b, c, &again).unwrap().unwrap().valid);
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
    disappear(&a, c, Some(Duration::from_secs(3600)));
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
    disappear(&a, c, Some(Duration::from_secs(60)));
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
    let (_s, rx) = watch(&b, c);
    let o = post(&a, c, "one").unwrap();
    w.run();
    b.settle();
    let heard = |rx: &std::sync::mpsc::Receiver<CommitEvent>| rx.try_iter().filter_map(|e| if let CommitEvent::Commit { commit: Some(k), .. } = e { Some(k) } else { None }).collect::<Vec<_>>();
    let got = heard(&rx);
    assert!(got.iter().any(|k| k.pos() == o && k.at(c, MSG).is_some_and(|p| text(&p.body) == Some("one"))), "{got:?}");
    let e = edit(&a, c, &newest(&a, c), "two").unwrap();
    w.run();
    b.settle();
    let got = heard(&rx);
    assert!(got.iter().any(|k| k.pos() == e && edit_of(&b, c, k).unwrap() == Some(o)), "{got:?}");
    assert!(got.iter().any(|k| k.pos() == o && k.at(c, MSG).is_some_and(|p| matches!(p.body, Body::Purged { .. }))), "{got:?}");
}

/// Every link in `v`.
fn links(v: &Value, out: &mut Vec<osis::internals::schema::osis_base::Link>) {
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
        let row = b.engine(|e| e.held_part(&c, &MSG.name(), &osis::internals::CommitRaw::raw(&id.commit().unwrap()), usize::MAX)).unwrap().unwrap();
        let osis::internals::node::engine::listing::PartBody::Held(Some(v)) = &row.body else { panic!("{:?}", row.body) };
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
    let (_s, rx) = watch(&b, c);
    for id in &ids {
        assert_eq!(part_at(&b, c, id).unwrap().body, Body::NotFetched);
    }
    for (i, (blob, bytes)) in lost.into_iter().enumerate() {
        b.engine(|e| e.put_blobs(vec![(blob, bytes)])).unwrap();
        b.settle();
        let got: Vec<_> = rx.try_iter().collect();
        let body = |e: &CommitEvent| match e {
            CommitEvent::Commit { commit: Some(k), .. } => k.at(c, MSG).map(|p| (k.pos(), p.body)),
            _ => None,
        };
        let shown = || got.iter().map(|e| format!("{:?}", body(e)).chars().take(40).collect()).collect::<Vec<String>>();
        assert!(got.iter().filter_map(body).any(|(id, b)| id == ids[i] && text(&b) == Some(bigs[i].as_str())), "{i}: {:?}", shown());
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
    let a = osis::internals::create(cfg.clone()).unwrap();
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
    let k = MSG.name();
    let mut x = b.write();
    x.act_as(a.me());
    x.at(c, osis::DynamicAspectKey::untyped(k)).fire(&Value::Str("as alice".into())).unwrap();
    assert!(matches!(x.commit(), Err(osis::Error::Permission { .. })));
}

// spec/permissions.md §5.1, spec/commits.md §4: a participant offline at the kick: what it wrote after the stamp turns invalid everywhere it is held, its own node says so; others never show it; what it wrote before the pre-sync reached the kicker drops too (design E: accepted without Required)
#[test]
fn kicked_while_offline_spec_perm_5() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    post(&b, c, "seen").unwrap();
    w.run();
    let (tx, rx) = std::sync::mpsc::channel();
    let _s = on_rejected(&b, c, tx);
    w.set_online(&b, false);
    w.advance(1000);
    kick(&a, c, bob, None).unwrap();
    w.run();
    let late = post(&b, c, "late").unwrap();
    w.set_online(&b, true);
    w.advance(60_000);
    w.run();
    b.settle();
    assert_eq!(texts(&a, c), ["seen"]);
    assert!(rx.try_iter().any(|x| x == late.commit().unwrap()), "told");
    assert!(!find(&b, c, &late).unwrap().unwrap().valid);
    assert!(post(&b, c, "more").is_err(), "the kick arrived");
    // a re-grant: the copy ends, it follows again; the late post stays what design E says: revived
    a.grant(c, bob, Role::Write, Default::default()).unwrap();
    w.run();
    assert!(b.retained_copies().unwrap().is_empty());
    post(&b, c, "back").unwrap();
    w.run();
    assert_eq!(texts(&a, c).last().unwrap(), "back");
    assert!(texts(&a, c).contains(&"late".to_string()), "a known forced yes: re-adding revives it (notes/chat-cases.md)");
}

// spec/permissions.md §3 (Retain): a kept copy's node of the kicked participant; a new node sees nothing of it (the design's forced "no")
#[test]
fn new_node_of_a_participant_sees_history_spec_sync_6() {
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
    post(&d, c, "from the new node").unwrap();
    w.run();
    assert_eq!(newest(&a, c).sender, bob, "one sender across nodes");
    assert_eq!(text(&newest(&a, c).body), Some("from the new node"));
    // a node removed erases, a kicked account's new node gets nothing
    kick(&a, c, bob, None).unwrap();
    w.run();
    let late = new_device(&mut w, 8);
    assert!(texts(&late, c).is_empty(), "known forced no: notes/chat-cases.md");
}

// spec/commits.md §6, spec/permissions.md §3 (Retain): a disappearing message leaves a kept copy at its time too
#[test]
fn kept_copy_still_disappears_spec_commits_6() {
    let Room { mut w, a, b, c, bob } = room(Options { disappear: Some(Duration::from_secs(60)), ..Options::default() });
    post(&a, c, "short").unwrap();
    w.run();
    kick(&a, c, bob, None).unwrap();
    w.run();
    assert_eq!(b.retained_copies().unwrap(), vec![c]);
    assert_eq!(texts(&b, c), ["short"]);
    w.advance(120_000);
    w.run();
    assert!(texts(&a, c).is_empty());
    assert!(texts(&b, c).is_empty(), "gone from the copy: {:?}", texts(&b, c));
}

// spec/permissions.md §1 (admins all equal): a later admin may kick the creator; with no admin left participants still post; two admins kicking each other, neither having seen the other's kick, each keep their own side (spec/permissions.md §5.1 Trust set: a node holds its own write first; notes/disputes-plan.md step 4)
#[test]
fn admins_are_equal_spec_perm_1() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    a.grant(c, bob, Role::Admin, Default::default()).unwrap();
    w.run();
    kick(&b, c, a.me(), None).unwrap();
    w.run();
    assert!(post(&a, c, "no").is_err());
    post(&b, c, "mine now").unwrap();
    assert_eq!(participants(&b, c).unwrap().len(), 1);

    let Room { mut w, a, b, c, bob } = room(Options::default());
    a.grant(c, bob, Role::Admin, Default::default()).unwrap();
    w.run();
    w.set_online(&b, false);
    kick(&a, c, bob, None).unwrap();
    kick(&b, c, a.me(), None).unwrap();
    w.set_online(&b, true);
    w.advance(60_000);
    w.run();
    let (pa, pb) = (participants(&a, c).unwrap(), participants(&b, c).unwrap());
    assert!(pa.contains_key(&a.me()) && !pa.contains_key(&bob), "{pa:?}");
    assert!(pb.contains_key(&bob) && !pb.contains_key(&a.me()), "{pb:?}");
}

// spec/permissions.md §3 (Retain): an erased participant added again gets the chat back
#[test]
fn erased_then_added_again_spec_perm_3() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    post(&a, c, "one").unwrap();
    w.run();
    kick(&a, c, bob, Some(false)).unwrap();
    w.run();
    assert!(texts(&b, c).is_empty());
    post(&a, c, "two").unwrap();
    w.run();
    a.grant(c, bob, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(texts(&b, c), ["one", "two"]);
    post(&b, c, "back").unwrap();
    w.run();
    assert_eq!(texts(&a, c), ["one", "two", "back"]);
}

// spec/sync.md §2-3: the creator's node paired after the chat exists finds it, unplaced as it is
#[test]
fn creator_on_a_new_node_spec_sync_3() {
    let mut w = World::new();
    let host = w.add_host();
    let a = w.account(1, &[host]);
    w.run();
    let c = create(&a, &Options::default()).unwrap();
    post(&a, c, "hello").unwrap();
    w.run();
    w.until(a.wait_synced(osis::SyncScope::AllWithSavedPeers), 1000, 60).unwrap();
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
}

// spec/permissions.md §5.1, §5.2: a participant's write stamped after its kick reaches another participant before the kick does: once the kick is there it is hidden from others, an edit of the participant's older message by it answers for nothing; its own node shows it, marked; a watch says it turned invalid
#[test]
fn turned_invalid_at_a_reader_spec_perm_5() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    let d = w.account(3, &[0]);
    w.run();
    let dee = meet(&mut w, &a, &d);
    a.grant(c, dee, Role::Write, Default::default()).unwrap();
    w.run();
    let old = post(&b, c, "old").unwrap();
    w.run();
    w.advance(1000);
    w.set_online(&a, false);
    kick(&a, c, bob, None).unwrap();
    w.advance(1000);
    let m = find(&b, c, &old).unwrap().unwrap();
    let edit_id = edit(&b, c, &m, "rewritten").unwrap();
    let late = post(&b, c, "late").unwrap();
    w.run();
    assert_eq!(texts(&d, c).last().unwrap(), "late", "there before the kick");
    assert_eq!(text(&find(&d, c, &edit_id).unwrap().unwrap().body), Some("rewritten"));
    let (_s, rx) = watch(&d, c);
    w.set_online(&a, true);
    w.advance(60_000);
    w.run();
    d.settle();
    let t = texts(&d, c);
    assert!(!t.contains(&"late".to_string()) && !t.contains(&"rewritten".to_string()), "{t:?}");
    assert!(rx.try_iter().any(|e| matches!(e, CommitEvent::Commit { id, commit: None } if Some(id) == late.commit())), "another's invalid write leaves the timeline");
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
    claim(&b, c, "his, edited", his, &[hers, his]);
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
    assert!(late < seen);
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

// spec/permissions.md §7, §3: a link joiner leaves: its edge is on the link's key, so `leave` goes there; it writes no more, keeps its copy, the link's other joiner stays
#[test]
fn link_joiner_leaves_spec_perm_7() {
    let mut w = World::new();
    let host = w.add_host();
    let a = w.account(1, &[host]);
    let b = w.account(2, &[host]);
    let d = w.account(3, &[host]);
    w.run();
    let c = create(&a, &Options::default()).unwrap();
    let l = link(&a, c, Role::Write, false);
    post(&a, c, "hi").unwrap();
    w.run();
    w.until(b.redeem(&l), 1000, 30).unwrap();
    w.until(d.redeem(&l), 1000, 30).unwrap();
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

// spec/permissions.md §7, spec/sync.md §2: a link shared in advance keeps working: someone joins by it and leaves, the next account joins by it, reads, posts; a leaver comes back by it; a kick ends it, says so, and a new link works
#[test]
fn link_after_leave_and_kick_spec_perm_7() {
    let mut w = World::new();
    let host = w.add_host();
    let a = w.account(1, &[host]);
    let b = w.account(2, &[host]);
    let d = w.account(3, &[host]);
    let e = w.account(4, &[host]);
    w.run();
    let c = create(&a, &Options::default()).unwrap();
    let l = link(&a, c, Role::Write, false);
    post(&a, c, "hi").unwrap();
    w.run();
    w.until(b.redeem(&l), 1000, 30).unwrap();
    w.run();
    leave(&b, c).unwrap();
    w.run();
    w.advance(70_000);
    w.run();
    assert_eq!(osis_chat::links(&a, c).unwrap().len(), 1, "a leave ends no link");
    w.until(d.redeem(&l), 1000, 30).unwrap();
    w.run();
    assert_eq!(texts(&d, c), ["hi"]);
    post(&d, c, "joined after the leave").unwrap();
    w.run();
    assert_eq!(texts(&a, c), ["hi", "joined after the leave"]);
    assert!(!texts(&b, c).contains(&"joined after the leave".to_string()), "what the leave protects");
    w.until(b.redeem(&l), 1000, 30).unwrap();
    w.run();
    assert!(texts(&b, c).contains(&"joined after the leave".to_string()), "the link text brings a leaver back");
    kick(&a, c, d.me(), None).unwrap();
    w.run();
    w.advance(70_000);
    w.run();
    assert!(osis_chat::links(&a, c).unwrap().is_empty(), "a kick ends the link");
    assert!(matches!(w.until(e.redeem(&l), 1000, 30), Err(osis::Error::Invalid(_))), "and says so");
    assert!(matches!(w.until(d.redeem(&l), 1000, 30), Err(osis::Error::Invalid(_))), "the kicked account stays out");
    let fresh = link(&a, c, Role::Write, false);
    w.run();
    w.until(e.redeem(&fresh), 1000, 30).unwrap();
    w.run();
    post(&e, c, "by the new link").unwrap();
    post(&b, c, "still here").unwrap();
    w.run();
    let t = texts(&a, c);
    assert!(t.contains(&"by the new link".to_string()) && t.contains(&"still here".to_string()), "{t:?}");
}

// spec/permissions.md §7: a link past its `until` is shown as none
#[test]
fn expired_link_not_shown_spec_perm_7() {
    let mut w = World::new();
    let host = w.add_host();
    let a = w.account(1, &[host]);
    w.run();
    let c = create(&a, &Options::default()).unwrap();
    a.make_link(c, Role::Write, osis::LinkOpts { until: Some(osis::Time(a.now().unwrap().0 + 1000)), single_use: false, direct: false }).unwrap();
    w.run();
    assert_eq!(osis_chat::links(&a, c).unwrap().len(), 1);
    w.advance(2000);
    assert!(osis_chat::links(&a, c).unwrap().is_empty());
}

// spec/permissions.md §7: `participants` lists the accounts who joined by a link, not its actor; a direct participant learns a joiner from its first post; kicking a joiner ends the link, the others stay; a single-use link leaves its joiner a participant
#[test]
fn link_joiners_are_participants_spec_perm_7() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    let d = w.account(3, &[0]);
    let e = w.account(4, &[0]);
    let f = w.account(5, &[0]);
    w.run();
    let l = link(&a, c, Role::Read, false);
    let once = link(&a, c, Role::Write, true);
    w.run();
    assert_eq!(osis_chat::links(&a, c).unwrap().len(), 2);
    assert_eq!(participants(&a, c).unwrap().into_keys().collect::<BTreeSet<_>>(), BTreeSet::from([a.me(), bob]), "a link no one used is nobody");
    w.until(d.redeem(&l), 1000, 30).unwrap();
    w.until(e.redeem(&l), 1000, 30).unwrap();
    w.until(f.redeem(&once), 1000, 30).unwrap();
    w.run();
    assert_eq!(participants(&a, c).unwrap().into_keys().collect::<BTreeSet<_>>(), BTreeSet::from([a.me(), bob, d.me(), e.me(), f.me()]));
    assert!(participants(&d, c).unwrap().contains_key(&e.me()), "a joiner sees the link's other joiners");
    assert_eq!(participants(&a, c).unwrap().get(&d.me()), Some(&Role::Read), "the link's role");
    assert_eq!(participants(&a, c).unwrap().get(&f.me()), Some(&Role::Write));
    assert_eq!(osis_chat::links(&a, c).unwrap().len(), 1, "the single-use link is spent");
    post(&f, c, "from a joiner").unwrap();
    w.run();
    assert!(participants(&b, c).unwrap().contains_key(&f.me()), "a direct participant, from the post");
    kick(&a, c, d.me(), None).unwrap();
    w.run();
    let left = participants(&a, c).unwrap();
    assert!(!left.contains_key(&d.me()) && left.contains_key(&e.me()), "{left:?}");
    assert!(osis_chat::links(&a, c).unwrap().is_empty(), "kicking a joiner ended the link");
    // a rotation naming K's keyset: a direct participant and a joiner go on
    let g = w.account(6, &[0]);
    let gid = meet(&mut w, &a, &g);
    a.grant(c, gid, Role::Write, Default::default()).unwrap();
    w.run();
    kick(&a, c, bob, None).unwrap();
    w.run();
    post(&g, c, "after the rotation").unwrap();
    post(&f, c, "and from a joiner").unwrap();
    w.run();
    for db in [&a, &g, &e, &f] {
        let t = texts(db, c);
        assert!(t.contains(&"after the rotation".to_string()) && t.contains(&"and from a joiner".to_string()), "{t:?}");
    }
}

// spec/permissions.md §7, §5.2: joining by link on a store in use: the joiner is its own verified sender, its name and reply come through; a cursor gives what is new, an edit of an older message as that message; kicking a joiner leaves the link's other joiners
#[test]
fn link_join_name_reply_cursor_spec_perm_7() {
    let mut w = World::new();
    let host = w.add_host();
    let a = w.account(1, &[host]);
    let b = w.account(2, &[host]);
    let d = w.account(3, &[host]);
    w.run();
    let c = create(&a, &Options::default()).unwrap();
    let l = link(&a, c, Role::Write, false);
    let first = send(&a, c, &schema::Message { name: Some("alice".into()), ..msg("hi") }).unwrap();
    w.run();
    assert_eq!(w.until(b.redeem(&l), 1000, 30).unwrap(), c);
    assert_eq!(w.until(d.redeem(&l), 1000, 30).unwrap(), c);
    w.run();
    assert_eq!(texts(&b, c), ["hi"]);
    w.advance(10);
    let cursor = since(&b, c, None, 10).unwrap().cursor.unwrap();
    assert_eq!(cursor, first);
    let r = send(&b, c, &schema::Message { name: Some("bob".into()), reply_to: Some(first.to_string()), ..msg("hello") }).unwrap();
    w.run();
    let m = newest(&a, c);
    assert_eq!((m.id, m.sender, name(&m), m.reply_to()), (r, b.me(), Some("bob"), Some(first)));
    let new = since(&a, c, Some(&cursor), 10).unwrap();
    assert_eq!(new.messages.iter().map(|m| m.id).collect::<Vec<_>>(), [r]);
    let cursor = new.cursor.unwrap();
    assert!(since(&a, c, Some(&cursor), 10).unwrap().messages.is_empty());
    w.advance(10);
    edit(&a, c, &find(&a, c, &first).unwrap().unwrap(), "hi!").unwrap();
    w.run();
    let again = since(&b, c, Some(&cursor), 10).unwrap();
    assert_eq!(again.messages.len(), 1);
    assert_eq!((again.messages[0].id, name(&again.messages[0]), text(&again.messages[0].body)), (first, Some("alice"), Some("hi!")));
    kick(&a, c, b.me(), None).unwrap();
    w.run();
    assert!(post(&b, c, "after").is_err());
    post(&d, c, "still here").unwrap();
    w.run();
    assert_eq!(text(&newest(&a, c).body), Some("still here"));
    assert_eq!(texts(&b, c).len(), 2, "the kicked joiner's copy");
}

// spec: none (cost, spec/requirements.md Scale: no operation O(history)): the bytes a post sends
// do not grow with the messages before it, n against 10n (counted traffic).
#[test]
fn post_upload_flat_in_history() {
    let per_post = |before: usize| {
        let Room { mut w, a, c, .. } = room(Options::default());
        for i in 0..before {
            post(&a, c, &format!("message number {i}")).unwrap();
            w.advance(1);
            if i % 10 == 9 {
                w.run();
            }
        }
        w.run();
        let t0 = w.traffic(&a);
        for i in 0..5 {
            post(&a, c, &format!("later message {i}")).unwrap();
            w.advance(1);
            w.run();
        }
        (w.traffic(&a).up - t0.up) / 5
    };
    let (small, big) = (per_post(10), per_post(100));
    assert!(big <= small + small / 5, "up bytes per post: {small} after 10 messages, {big} after 100");
}

// spec/permissions.md §3 (Retain): leaving keeps by the chat's default, the others keep its messages; a new participant gets the tombstones and history; a participant promoted to moderator deletes another's
#[test]
fn leave_promote_newcomer_spec_perm_3() {
    let Room { mut w, a, b, c, bob } = room(Options::default());
    let d = w.account(3, &[0]);
    w.run();
    let dee = meet(&mut w, &a, &d);
    post(&b, c, "from bob").unwrap();
    let gone = post(&a, c, "gone").unwrap();
    w.run();
    delete(&a, c, &find(&a, c, &gone).unwrap().unwrap()).unwrap();
    w.run();
    a.grant(c, dee, Role::Write, Default::default()).unwrap();
    w.run();
    assert_eq!(texts(&d, c).len(), 2, "history and tombstone for a newcomer: {:?}", texts(&d, c));
    assert!(texts(&d, c).contains(&"<deleted>".to_string()));
    a.grant(c, dee, Role::Admin, Default::default()).unwrap();
    w.run();
    assert_eq!(participants(&b, c).unwrap().get(&dee), Some(&Role::Admin));
    let his = post(&b, c, "moderate me").unwrap();
    w.run();
    delete(&d, c, &find(&d, c, &his).unwrap().unwrap()).unwrap();
    w.run();
    assert!(matches!(find(&a, c, &his).unwrap().unwrap().body, Body::Purged { .. }));
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
    kick(&a, c, dee, None).unwrap();
    w.run();
    assert_eq!(participants(&a, c).unwrap().len(), 1);
}

// spec: none. notes/chat.md Message, notes/api-design.md (stored data never fails a read): a message id is text another writer chose: what does not parse is no reply, a claim to replace what does not parse reads as a plain odd entry, and neither fails anyone's read, a delete or a kick
#[test]
fn odd_ids_from_another_writer_fail_no_read() {
    let Room { mut w, a, b, c, .. } = room(Options::default());
    let good = post(&a, c, "good").unwrap();
    let raw = |m: &schema::Message| {
        let mut x = b.write();
        x.at(c, MSG).fire(m).unwrap();
        x.commit().unwrap();
    };
    let odd = |reply_to: Option<&str>, edit: Option<&str>| schema::Message { text: "odd".into(), name: None, reply_to: reply_to.map(Into::into), edit: edit.map(|e| schema::Edit { original: e.into(), prior: [e.to_string()].into() }) };
    let junk = ["", "x", "1", "1/", "x/y", "1/zz", "1/ephemeral:zz:1", "1/1/00", &format!("{}/{}", u64::MAX, "0".repeat(64))];
    // parses, and names nothing here: a time's place, an ephemeral commit
    let places = [format!("{}/{}", 1u64 << 20, "0".repeat(64)), format!("{}/ephemeral:{}:1", 1u64 << 20, "0".repeat(32))];
    for j in junk.into_iter().chain(places.iter().map(String::as_str)) {
        raw(&odd(Some(j), None));
        raw(&odd(None, Some(j)));
    }
    // no message at all: another shape on the aspect
    let key = osis::DynamicAspectKey::untyped(MSG.name());
    for v in [Value::Bytes(vec![1]), Value::Map([(Value::Int(0), Value::Int(3))].into())] {
        let mut x = b.write();
        x.at(c, key.clone()).fire(&v).unwrap();
        x.commit().unwrap();
    }
    w.run();
    for db in [&a, &b] {
        let t = texts(db, c);
        assert!(t.contains(&"good".to_string()) && t.contains(&"odd".to_string()), "{t:?}");
        assert_eq!(find(db, c, &good).unwrap().unwrap().id, good);
        // the other shapes read as odd entries
        let page = db.at(c, MSG).fired(&CommitQuery { limit: Some(2), ..Default::default() }).unwrap();
        assert!(page.commits.iter().all(|k| k.at(c, MSG).is_some_and(|p| p.body == Body::Held(None))));
    }
    // what reads as messages can be deleted, whatever others claimed
    let m = newest(&b, c);
    delete(&b, c, &m).unwrap();
    edit(&a, c, &find(&a, c, &good).unwrap().unwrap(), "better").unwrap();
    w.run();
    assert!(texts(&a, c).contains(&"better".to_string()));
}
