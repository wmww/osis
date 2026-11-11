//! Chat end to end on the sim. spec: none (a client surface specified in notes/chat.md).

use osis_chat::*;
use super::{leave, link_actors, participants};
use osis::core::RETENTION;
use osis::{Body, Commit, CommitEvent, CommitFrom, CommitId, CommitKind, CommitQuery, LinkOpts, Osis, Part, PurgeBy, Role, SetRoleOpts, ShareLink, Subscription, Tid, Value};
use osis_sim::world::World;
use schema::{EditMode, MSG};
use std::collections::BTreeSet;
use std::time::Duration;

/// A message of `text`.
fn msg(text: &str) -> schema::Message {
    schema::Message { text: text.into(), name: None, reply_to: None }
}

/// Fires `m` on chat `c`: its id.
fn send(db: &Osis, c: Tid, m: &schema::Message) -> osis::Result<CommitId> {
    osis_chat::send(db, c, m)
}

fn post(db: &Osis, c: Tid, text: &str) -> osis::Result<CommitId> {
    send(db, c, &msg(text))
}

/// Deletes message `id`, every version here, in one purge.
fn delete(db: &Osis, c: Tid, id: CommitId) -> osis::Result<()> {
    let mut w = db.write();
    w.at(c, MSG).purge(osis::Purge::Commit(id))?;
    w.commit().map(drop)
}

/// `db`'s own replacement of `id` past osis-chat's `edit`: refused at commit unless osis honors it.
fn replace(db: &Osis, c: Tid, id: CommitId, text: &str) -> osis::Result<()> {
    let mut w = db.write();
    w.at(c, MSG).replace(id, &msg(text))?;
    w.commit().map(drop)
}

fn kick(db: &Osis, c: Tid, who: Tid, retain_copy: Option<bool>) -> osis::Result<()> {
    db.set_role(c, who, None, SetRoleOpts { retain_copy })
}

fn link(db: &Osis, c: Tid, role: Role, single_use: bool) -> ShareLink {
    db.make_link(c, role, LinkOpts { until: None, single_use, direct: false }).unwrap()
}

/// Sets the disappearing timer: the setting, written whole, with the message entry's expiry.
fn disappear(db: &Osis, c: Tid, d: Option<Duration>) {
    let mut rules = db.at(c, RETENTION).get().unwrap().unwrap();
    rules.rules.get_mut(&MSG.name()).unwrap().expires = d;
    let mut w = db.write();
    w.at(c, RETENTION).set(&rules).unwrap();
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

/// Message `id` as listed here.
fn find(db: &Osis, c: Tid, id: CommitId) -> Option<Commit> {
    db.at(c, MSG).commit(id).unwrap()
}

/// Message `id`'s part as listed here.
fn part(db: &Osis, c: Tid, id: CommitId) -> Part<schema::Message> {
    find(db, c, id).unwrap().at(c, MSG).unwrap()
}

fn text(b: &Body<schema::Message>) -> Option<&str> {
    match b {
        Body::Held(Some(m)) => Some(&m.text),
        _ => None,
    }
}

fn shown(b: &Body<schema::Message>) -> String {
    match b {
        Body::Held(Some(x)) => x.text.clone(),
        Body::Purged { .. } => "<deleted>".into(),
        b => format!("<{b:?}>"),
    }
}

fn content(from: CommitFrom) -> CommitQuery {
    CommitQuery { from, kinds: vec![CommitKind::Content], ..Default::default() }
}

/// Every message, oldest first, each its newest text.
fn texts(db: &Osis, c: Tid) -> Vec<String> {
    db.at(c, MSG).fired(&content(CommitFrom::Oldest)).unwrap().commits.iter().map(|k| shown(&k.at(c, MSG).unwrap().body)).collect()
}

/// Message `id`'s versions, newest first, each as written.
fn versions(db: &Osis, c: Tid, id: CommitId) -> Vec<String> {
    db.at(c, MSG).versions(id, &content(CommitFrom::Newest)).unwrap().commits.iter().map(|k| shown(&k.at(c, MSG).unwrap().body)).collect()
}

fn newest(db: &Osis, c: Tid) -> Commit {
    db.at(c, MSG).fired(&CommitQuery { limit: Some(1), ..content(CommitFrom::Newest) }).unwrap().commits.remove(0)
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
        assert_eq!(newest(db, c).stamp.actor, bob);
    }
    let page = |from| a.at(c, MSG).fired(&CommitQuery { from, limit: Some(2), kinds: vec![CommitKind::Content], ..Default::default() }).unwrap();
    let rest = page(CommitFrom::Oldest);
    assert!(rest.more && rest.complete);
    let next = page(CommitFrom::After(rest.commits[1].pos()));
    assert_eq!(next.commits.len(), 1);
    assert!(!next.more);
}

// notes/chat.md Edit, spec/permissions.md §5.2: edits: the message keeps its id and place, reads its newest text, marked; the old text purged by default (its versions tombstones, one message shown); another's edit is refused at its writer; keep mode keeps the versions, and one delete takes them all; off refuses edits
#[test]
fn edit_modes_spec_perm_5() {
    let Room { mut w, a, b, c, .. } = room(Options::default());
    let o = post(&a, c, "orginal").unwrap();
    w.run();
    edit(&a, c, o, "origina").unwrap();
    w.run();
    edit(&a, c, o, "original").unwrap();
    w.run();
    for db in [&a, &b] {
        assert_eq!(texts(db, c), ["original"], "one message");
        let m = newest(db, c);
        assert_eq!(m.stamp.id, o);
        assert!(m.at(c, MSG).unwrap().edited.is_some());
        assert_eq!(versions(db, c, o), ["original", "<deleted>", "<deleted>"], "the old text is gone");
    }
    assert!(matches!(edit(&b, c, o, "x"), Err(osis::Error::Invalid(_))), "Bob's edit of Alice's message");
    assert!(matches!(replace(&b, c, o, "forged"), Err(osis::Error::Invalid(_))), "osis refuses it too, so nothing is sent");
    w.run();
    assert_eq!(texts(&a, c), ["original"]);
    let Room { mut w, a, b, c, .. } = room(Options { edit: Some(EditMode::Keep), ..Options::default() });
    let o = post(&a, c, "one").unwrap();
    edit(&a, c, o, "two").unwrap();
    edit(&a, c, o, "three").unwrap();
    w.run();
    assert_eq!(texts(&b, c), ["three"]);
    assert_eq!(versions(&b, c, o), ["three", "two", "one"]);
    delete(&a, c, o).unwrap();
    w.run();
    assert_eq!(texts(&b, c), ["<deleted>"], "a delete takes every version");
    assert_eq!(versions(&b, c, o), ["<deleted>"; 3]);
    let Room { w: _, a, c, .. } = room(Options { edit: None, ..Options::default() });
    let o = post(&a, c, "fixed").unwrap();
    assert!(matches!(edit(&a, c, o, "x"), Err(osis::Error::Invalid(_))));
    assert_eq!(texts(&a, c), ["fixed"]);
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
    let c = create(&a, &Options { edit: Some(EditMode::Keep), ..Options::default() }).unwrap();
    let m = post(&a, c, "base").unwrap();
    w.run();
    assert_eq!(texts(&a2, c), ["base"], "a new node of a participant");
    w.set_online(&a2, false);
    edit(&a, c, m, "from one").unwrap();
    w.advance(1000);
    edit(&a2, c, m, "from two").unwrap();
    w.set_online(&a2, true);
    w.advance(60_000);
    w.run();
    assert_eq!(texts(&a, c), texts(&a2, c));
    assert_eq!(texts(&a, c), ["from two"]);
    assert_eq!(versions(&a, c, m), versions(&a2, c, m));
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
    assert!(matches!(delete(&b, c, mine), Err(osis::Error::Permission { .. })), "osis refuses the request, so nothing is sent");
    w.run();
    assert!(matches!(part(&a, c, mine).body, Body::Held(Some(_))));
    delete(&b, c, his).unwrap();
    w.run();
    assert_eq!(texts(&a, c), ["mine", "<deleted>", "retained"]);
    delete(&a, c, mine).unwrap();
    w.run();
    assert_eq!(texts(&b, c), ["<deleted>", "<deleted>", "retained"]);
    // a moderator's delete of Bob's
    delete(&a, c, newest(&a, c).stamp.id).unwrap();
    w.run();
    assert_eq!(texts(&b, c), ["<deleted>"; 3]);
    let by = |db: &Osis, id: CommitId| match part(db, c, id).body {
        Body::Purged { actor, .. } => actor,
        x => panic!("{x:?}"),
    };
    assert_eq!((by(&b, his), by(&a, mine)), (Some(bob), Some(a.me())), "who deleted, by its signed header");
    let offer = b.pair_offer().unwrap();
    let join = osis::internals::pair(w.cfg(5, &[]), &offer).unwrap();
    let req: osis::PairRequest = join.request().to_string().parse().unwrap();
    let (_, reply) = b.pair_accept(&req).unwrap();
    let b2 = join.finish(&reply).unwrap();
    w.run();
    assert_eq!(texts(&b2, c), ["<deleted>"; 3], "tombstones on a new node");
    assert_eq!(newest(&b2, c).stamp.actor, bob);
    assert_eq!(by(&b2, his), Some(bob), "on a new node too");
}

// spec/permissions.md §6: purge sets: admin only keeps an author out; author or admin lets both;
// any writer lets another participant delete too; admins may always purge
#[test]
fn purge_sets_spec_perm_6() {
    for (by, author, admin) in [(PurgeBy::Admin, false, true), (PurgeBy::AuthorOrAdmin, true, true)] {
        let Room { mut w, a, b, c, .. } = room(Options { purge: by, ..Options::default() });
        post(&b, c, "x").unwrap();
        w.run();
        assert_eq!(delete(&b, c, newest(&b, c).stamp.id).is_ok(), author, "{by:?}");
        w.run();
        assert_eq!(texts(&a, c) == ["<deleted>"], author);
        if !author {
            assert_eq!(delete(&a, c, newest(&a, c).stamp.id).is_ok(), admin, "{by:?}");
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

// spec/commits.md §5 Expiry default, §6: a message expires as its sender saw the setting: a stale
// sender's message, written before the timer reached it, is shown everywhere and keeps the expiry
// it carries (none); once the timer reaches it, its messages disappear on time
#[test]
fn stale_writer_keeps_its_expiry_spec_commits_6() {
    let Room { mut w, a, b, c, .. } = room(Options::default());
    post(&a, c, "x").unwrap();
    w.run();
    // Bob offline: the timer changes, he posts under the old setting
    w.set_online(&b, false);
    w.advance(1000);
    disappear(&a, c, Some(Duration::from_secs(60)));
    w.run();
    w.advance(1000);
    let stale = post(&b, c, "stale").unwrap();
    w.set_online(&b, true);
    w.run();
    w.advance(61_000);
    w.run();
    assert_eq!(texts(&a, c).last().unwrap(), "stale", "valid, and it carries no expiry");
    assert!(part(&a, c, stale).valid);
    post(&b, c, "fresh").unwrap();
    w.run();
    assert_eq!(texts(&a, c).last().unwrap(), "fresh");
    w.advance(61_000);
    w.run();
    assert_eq!(texts(&a, c).last().unwrap(), "stale", "the fresh one disappeared on time");
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
    // edit (purging the old text in the same commit) and delete in a disappearing chat; an edit
    // ends with its message
    disappear(&a, c, Some(Duration::from_secs(60)));
    w.run();
    let o = post(&a, c, "orginal").unwrap();
    edit(&a, c, o, "original").unwrap();
    w.run();
    assert_eq!(texts(&b, c), ["original"]);
    assert_eq!(versions(&b, c, o), ["original", "<deleted>"]);
    delete(&a, c, o).unwrap();
    let brief = post(&a, c, "brief").unwrap();
    w.advance(30_000);
    edit(&a, c, brief, "brief!").unwrap();
    w.run();
    assert_eq!(texts(&b, c), ["<deleted>", "brief!"]);
    w.advance(31_000);
    w.run();
    assert!(!texts(&b, c).iter().any(|t| t.starts_with("brief")), "{:?}", texts(&b, c));
}

// notes/api.md Signals: a watch hears a post; its edit once, as the message under its id with the new text (the old text's purge in the same commit no event of its own); a deletion under the same id
#[test]
fn watch_spec_none() {
    let Room { mut w, a, b, c, .. } = room(Options::default());
    let (_s, rx) = watch(&b, c);
    let o = post(&a, c, "one").unwrap();
    w.run();
    b.settle();
    let heard = |rx: &std::sync::mpsc::Receiver<CommitEvent>| rx.try_iter().map(|e| match e {
        CommitEvent::Commit { id, commit: Some(k) } => (id, Some(k.at(c, MSG).unwrap())),
        CommitEvent::Commit { id, commit: None } => (id, None),
        e => panic!("{e:?}"),
    }).collect::<Vec<_>>();
    let got = heard(&rx);
    assert!(got.iter().any(|(id, p)| *id == o && p.as_ref().is_some_and(|p| text(&p.body) == Some("one"))), "{got:?}");
    edit(&a, c, o, "two").unwrap();
    w.run();
    b.settle();
    let got = heard(&rx);
    assert!(!got.is_empty() && got.iter().all(|(id, p)| *id == o && p.as_ref().is_some_and(|p| text(&p.body) == Some("two") && p.edited.is_some())), "{got:?}");
    delete(&a, c, o).unwrap();
    w.run();
    b.settle();
    let got = heard(&rx);
    assert!(!got.is_empty() && got.iter().all(|(id, p)| *id == o && p.as_ref().is_some_and(|p| matches!(p.body, Body::Purged { .. }))), "{got:?}");
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
        let row = b.engine(|e| e.held_part(&c, &MSG.name(), &osis::internals::CommitRaw::raw(&id), usize::MAX)).unwrap().unwrap();
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
    for id in ids {
        assert_eq!(part(&b, c, id).body, Body::NotFetched);
    }
    for (i, (blob, bytes)) in lost.into_iter().enumerate() {
        b.engine(|e| e.put_blobs(vec![(blob, bytes)])).unwrap();
        b.settle();
        let got: Vec<_> = rx.try_iter().collect();
        let body = |e: &CommitEvent| match e {
            CommitEvent::Commit { commit: Some(k), .. } => k.at(c, MSG).map(|p| (k.stamp.id, p.body)),
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
    assert!(rx.try_iter().any(|x| x == late), "told");
    assert!(!part(&b, c, late).valid);
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
    // paging back by small pages reaches the same
    let (mut n, mut from) = (0, CommitFrom::Newest);
    loop {
        let p = d.at(c, MSG).fired(&CommitQuery { limit: Some(7), ..content(from) }).unwrap();
        assert!(p.complete);
        n += p.commits.len();
        match p.commits.last() {
            Some(l) if p.more => from = CommitFrom::Before(l.pos()),
            _ => break,
        }
    }
    assert_eq!(n, 200);
    post(&d, c, "from the new node").unwrap();
    w.run();
    assert_eq!(newest(&a, c).stamp.actor, bob, "one sender across nodes");
    assert_eq!(text(&newest(&a, c).at(c, MSG).unwrap().body), Some("from the new node"));
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
    w.until(a.wait_synced(osis::SyncScope::All), 1000, 60).unwrap();
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

// spec/permissions.md §5.1, §5.2: a participant's write stamped after its kick reaches another participant before the kick does: once the kick is there it is hidden from others, and its edit of its older message is no longer honored (the old text shows again); its own node shows it, marked; a watch says it turned invalid
#[test]
fn turned_invalid_at_a_reader_spec_perm_5() {
    let Room { mut w, a, b, c, bob } = room(Options { edit: Some(EditMode::Keep), ..Options::default() });
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
    edit(&b, c, old, "rewritten").unwrap();
    let late = post(&b, c, "late").unwrap();
    w.run();
    assert_eq!(texts(&d, c), ["rewritten", "late"], "there before the kick");
    let (_s, rx) = watch(&d, c);
    w.set_online(&a, true);
    w.advance(60_000);
    w.run();
    d.settle();
    assert_eq!(texts(&d, c), ["old"]);
    let told: Vec<_> = rx.try_iter().collect();
    assert!(told.iter().any(|e| matches!(e, CommitEvent::Commit { id, commit: None } if *id == late)), "another's invalid write leaves the timeline: {told:?}");
    assert!(told.iter().any(|e| matches!(e, CommitEvent::Commit { id, commit: Some(k) } if *id == old && text(&k.at(c, MSG).unwrap().body) == Some("old"))), "the edit's message, as it reads now: {told:?}");
    b.settle();
    assert!(!part(&b, c, late).valid, "its own, marked");
    assert_eq!(text(&part(&b, c, old).body), Some("old"), "an invalid edit replaces nothing");
}

// spec: none (notes/chat.md Read): a cursor goes by arrival: a participant's post made offline, stamped before what the reader has seen, comes after the cursor; nothing new reads as nothing; an edit comes as its message again
#[test]
fn late_post_comes_after_a_cursor_spec_none() {
    let Room { mut w, a, b, c, .. } = room(Options::default());
    let first = post(&a, c, "first").unwrap();
    w.run();
    let at = since(&a, c, None, 10).unwrap().cursor;
    w.set_online(&b, false);
    w.advance(1000);
    let late = post(&b, c, "from the train").unwrap();
    w.advance(1000);
    let seen = post(&a, c, "seen").unwrap();
    w.run();
    let ids = |s: &Since| s.messages.iter().map(|k| k.stamp.id).collect::<Vec<_>>();
    let got = since(&a, c, at.as_ref(), 10).unwrap();
    assert_eq!(ids(&got), [seen]);
    let at = got.cursor.unwrap();
    assert_eq!(cursor(&a, c).unwrap(), Some(at));
    w.set_online(&b, true);
    w.advance(60_000);
    w.run();
    assert!(find(&a, c, late).unwrap().pos() < find(&a, c, seen).unwrap().pos());
    let got = since(&a, c, Some(&at), 10).unwrap();
    assert_eq!(ids(&got), [late]);
    let at = got.cursor.unwrap();
    assert_eq!(cursor(&a, c).unwrap(), Some(at), "it arrived last");
    assert!(since(&a, c, Some(&at), 10).unwrap().messages.is_empty());
    assert_eq!(at.to_string().parse::<Cursor>().unwrap(), at, "its text form");
    // by the page: one at a time, none lost
    let page = since(&a, c, None, 2).unwrap();
    assert!(page.more);
    assert_eq!(ids(&page), [first, seen]);
    let rest = since(&a, c, page.cursor.as_ref(), 2).unwrap();
    assert_eq!(ids(&rest), [late]);
    w.advance(10);
    edit(&a, c, first, "first!").unwrap();
    let again = since(&a, c, Some(&at), 10).unwrap();
    assert_eq!(again.messages.iter().map(|k| (k.stamp.id, shown(&k.at(c, MSG).unwrap().body))).collect::<Vec<_>>(), [(first, "first!".to_string())]);
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
    assert_eq!(link_actors(&a, c).unwrap().len(), 1, "a leave ends no link");
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
    assert!(link_actors(&a, c).unwrap().is_empty(), "a kick ends the link");
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
    assert_eq!(link_actors(&a, c).unwrap().len(), 1);
    w.advance(2000);
    assert!(link_actors(&a, c).unwrap().is_empty());
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
    assert_eq!(link_actors(&a, c).unwrap().len(), 2);
    assert_eq!(participants(&a, c).unwrap().into_keys().collect::<BTreeSet<_>>(), BTreeSet::from([a.me(), bob]), "a link no one used is nobody");
    w.until(d.redeem(&l), 1000, 30).unwrap();
    w.until(e.redeem(&l), 1000, 30).unwrap();
    w.until(f.redeem(&once), 1000, 30).unwrap();
    w.run();
    assert_eq!(participants(&a, c).unwrap().into_keys().collect::<BTreeSet<_>>(), BTreeSet::from([a.me(), bob, d.me(), e.me(), f.me()]));
    assert!(participants(&d, c).unwrap().contains_key(&e.me()), "a joiner sees the link's other joiners");
    assert_eq!(participants(&a, c).unwrap().get(&d.me()), Some(&Role::Read), "the link's role");
    assert_eq!(participants(&a, c).unwrap().get(&f.me()), Some(&Role::Write));
    assert_eq!(link_actors(&a, c).unwrap().len(), 1, "the single-use link is spent");
    post(&f, c, "from a joiner").unwrap();
    w.run();
    assert!(participants(&b, c).unwrap().contains_key(&f.me()), "a direct participant, from the post");
    kick(&a, c, d.me(), None).unwrap();
    w.run();
    let left = participants(&a, c).unwrap();
    assert!(!left.contains_key(&d.me()) && left.contains_key(&e.me()), "{left:?}");
    assert!(link_actors(&a, c).unwrap().is_empty(), "kicking a joiner ended the link");
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
    let all = since(&b, c, None, 10).unwrap();
    assert_eq!(all.messages.iter().map(|k| k.stamp.id).collect::<Vec<_>>(), [first]);
    let cursor = all.cursor.unwrap();
    let r = send(&b, c, &schema::Message { name: Some("bob".into()), reply_to: Some(first.to_string()), ..msg("hello") }).unwrap();
    w.run();
    let m = newest(&a, c);
    let Body::Held(Some(body)) = m.at(c, MSG).unwrap().body else { panic!() };
    assert_eq!((m.stamp.id, m.stamp.actor, body.name.as_deref(), body.reply()), (r, b.me(), Some("bob"), Some(first)));
    let new = since(&b, c, Some(&cursor), 10).unwrap();
    assert_eq!(new.messages.iter().map(|k| k.stamp.id).collect::<Vec<_>>(), [r]);
    let cursor = new.cursor.unwrap();
    assert!(since(&b, c, Some(&cursor), 10).unwrap().messages.is_empty());
    w.advance(10);
    edit(&a, c, first, "hi!").unwrap();
    w.run();
    let again = since(&b, c, Some(&cursor), 10).unwrap();
    assert_eq!(again.messages.len(), 1);
    let Body::Held(Some(body)) = again.messages[0].at(c, MSG).unwrap().body else { panic!() };
    assert_eq!((again.messages[0].stamp.id, body.name.as_deref(), body.text.as_str()), (first, Some("alice"), "hi!"), "the edit keeps the name");
    kick(&a, c, b.me(), None).unwrap();
    w.run();
    assert!(post(&b, c, "after").is_err());
    post(&d, c, "still here").unwrap();
    w.run();
    assert_eq!(text(&newest(&a, c).at(c, MSG).unwrap().body), Some("still here"));
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
    delete(&a, c, gone).unwrap();
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
    delete(&d, c, his).unwrap();
    w.run();
    assert!(matches!(part(&a, c, his).body, Body::Purged { .. }));
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

// spec: none. notes/chat.md Message, notes/api-design.md (stored data never fails a read): a reply id is text another writer chose: what does not parse is no reply, one naming no message here quotes nothing; another shape on the aspect reads `Held(None)`; none fails anyone's read, a delete or an edit
#[test]
fn odd_ids_from_another_writer_fail_no_read() {
    let Room { mut w, a, b, c, .. } = room(Options::default());
    let good = post(&a, c, "good").unwrap();
    let junk = ["", "x", "1", "zz", &"0".repeat(63), &"0".repeat(65), &format!("1/{good}")];
    for j in junk {
        let m = send(&b, c, &schema::Message { reply_to: Some(j.into()), ..msg("odd") }).unwrap();
        let Body::Held(Some(body)) = part(&b, c, m).body else { panic!() };
        assert_eq!(body.reply(), None, "{j:?}");
    }
    // parses, and names no message here
    let none = "0".repeat(64);
    let m = send(&b, c, &schema::Message { reply_to: Some(none.clone()), ..msg("odd") }).unwrap();
    let Body::Held(Some(body)) = part(&b, c, m).body else { panic!() };
    assert!(find(&b, c, body.reply().unwrap()).is_none());
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
        assert_eq!(find(db, c, good).unwrap().stamp.id, good);
        // the other shapes read as odd entries
        let page = db.at(c, MSG).fired(&CommitQuery { limit: Some(2), ..Default::default() }).unwrap();
        assert!(page.commits.iter().all(|k| k.at(c, MSG).is_some_and(|p| p.body == Body::Held(None))));
    }
    // what is listed can be deleted and edited, whatever others wrote
    delete(&b, c, newest(&b, c).stamp.id).unwrap();
    edit(&a, c, good, "better").unwrap();
    w.run();
    assert!(texts(&a, c).contains(&"better".to_string()));
}
