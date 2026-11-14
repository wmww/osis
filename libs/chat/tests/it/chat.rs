use super::*;
use osis::core::RETENTION;
use osis::{Body, Commit, CommitFrom, CommitId, CommitQuery, Error, History, PurgeBy, Role, Tid};
use osis_chat::schema::{self, Deletes, EditMode, MSG, SETTINGS};
use osis_chat::*;

fn msg(text: &str) -> schema::Message {
    schema::Message { text: text.into(), name: Some("me".into()), reply_to: None }
}

fn post(db: &Osis, c: Tid, text: &str) -> CommitId {
    send(db, c, &msg(text)).unwrap()
}

fn text(b: &Body<schema::Message>) -> String {
    match b {
        Body::Held(Some(m)) => m.text.clone(),
        b => format!("{b:?}"),
    }
}

/// Each version of message `id`, oldest first, as its text.
fn versions(db: &Osis, c: Tid, id: CommitId) -> Vec<String> {
    let q = CommitQuery { from: CommitFrom::Newest, ..Default::default() };
    let mut v: Vec<String> = db.at(c, MSG).versions(id, &q).unwrap().commits.iter().map(|k| text(&k.at(c, MSG).unwrap().body)).collect();
    v.reverse();
    v
}

/// Message `id` as listed: its newest text, and whether it reads edited.
fn shown(db: &Osis, c: Tid, id: CommitId) -> (String, bool) {
    let k: Commit = db.at(c, MSG).commit(id).unwrap().unwrap();
    let p = k.at(c, MSG).unwrap();
    (text(&p.body), p.edited.is_some())
}

// notes/chat.md Create, spec/commits.md §6 (a write is one commit), spec/commits.md §5 (The
// setting): a chat is one commit holding its record, its settings and its `retention^.0`
// (messages kept for good, the disappearing expiry, replacements refused when editing is off,
// the retain default), this account its admin; a purge set chat cannot keep is `Invalid`,
// nothing written.
#[test]
fn create_is_one_whole_commit_spec_commits_2() {
    let db = node(1, &clock());
    let day = std::time::Duration::from_secs(86_400);
    let n = commits(&db);
    let c = create(&db, &Options { name: "room".into(), purge: PurgeBy::Admin, edit: None, disappear: Some(day), retain_copies: false }).unwrap();
    assert_eq!(commits(&db), n + 1, "one commit");
    assert_eq!(db.role_on(c).unwrap(), Some(Role::Admin));
    let s = db.at(c, SETTINGS).get().unwrap().unwrap();
    assert_eq!((s.name.as_str(), s.purge), ("room", Some(Deletes::Admins)));
    let r = db.at(c, RETENTION).get().unwrap().unwrap();
    let e = &r.rules[&MSG.name()];
    assert_eq!((e.history, e.expires, e.refuse_replace, r.retain_copies), (Some(History::FOREVER), Some(day), true, false));
    let d = create(&db, &Options::default()).unwrap();
    let r = db.at(d, RETENTION).get().unwrap().unwrap();
    let e = &r.rules[&MSG.name()];
    assert_eq!((e.expires, e.refuse_replace, r.retain_copies), (None, false, true), "the defaults");
    assert_eq!(db.at(d, SETTINGS).get().unwrap().unwrap().purge, None, "author or admin");
    let n = commits(&db);
    assert!(matches!(create(&db, &Options { purge: PurgeBy::Nobody, ..Options::default() }), Err(Error::Invalid(_))));
    assert_eq!(commits(&db), n, "nothing written");
}

// notes/chat.md Edit, spec/permissions.md §5.2: an edit keeps the message's id and reads its
// newest text, marked edited; by default (`EditMode::Purge`) the old text is purged in the same
// commit, under `Keep` it stays as a version; with editing off the edit is `Invalid`.
#[test]
fn edit_modes_spec_permissions_5_2() {
    let db = node(1, &clock());
    for mode in [Some(EditMode::Purge), Some(EditMode::Keep), None] {
        let c = create(&db, &Options { edit: mode.clone(), ..Options::default() }).unwrap();
        let id = post(&db, c, "first");
        if mode.is_none() {
            assert!(matches!(edit(&db, c, id, "second"), Err(Error::Invalid(_))));
            assert_eq!(shown(&db, c, id), ("first".into(), false));
            continue;
        }
        edit(&db, c, id, "second").unwrap();
        assert_eq!(shown(&db, c, id), ("second".into(), true), "{mode:?}");
        let k = db.at(c, MSG).commit(id).unwrap().unwrap();
        let m = match k.at(c, MSG).unwrap().body {
            Body::Held(Some(m)) => m,
            b => panic!("{b:?}"),
        };
        assert_eq!(m.name.as_deref(), Some("me"), "the name kept");
        let v = versions(&db, c, id);
        match mode {
            Some(EditMode::Purge) => assert!(v.len() == 2 && v[0].starts_with("Purged") && v[1] == "second", "{v:?}"),
            _ => assert_eq!(v, ["first", "second"]),
        }
    }
}

// notes/chat.md Edit, spec/permissions.md §6 (the right; a delta's retention names who may purge it): an edit is of one's own message only
// (another's is `Invalid`); a writer the purge set does not let purge (`Admin`) edits all the same
// and the old text stays; where it does (author or admin), the old text goes. Bob's node is
// Alice's chat's writer, commits carried by hand.
#[test]
fn edit_is_own_and_purges_as_the_set_lets_spec_permissions_6() {
    let c0 = clock();
    let (alice, bob) = (node(1, &c0), node(2, &c0));
    deliver(&bob, &alice);
    for (purge, gone) in [(PurgeBy::Admin, false), (PurgeBy::AuthorOrAdmin, true)] {
        let c = create(&alice, &Options { purge, ..Options::default() }).unwrap();
        alice.grant(c, bob.me(), Role::Write, Default::default()).unwrap();
        let hers = post(&alice, c, "hers");
        deliver(&alice, &bob);
        assert!(matches!(edit(&bob, c, hers, "forged"), Err(Error::Invalid(_))), "another's message");
        let his = post(&bob, c, "first");
        edit(&bob, c, his, "second").unwrap();
        assert_eq!(shown(&bob, c, his), ("second".into(), true));
        let v = versions(&bob, c, his);
        assert_eq!(v[0].starts_with("Purged"), gone, "{purge:?}: {v:?}");
    }
}

// notes/chat.md Read: `since` goes by arrival at this node, not by stamp: a post made offline,
// stamped before what the reader has seen, comes after the cursor; an edit comes as its message
// again, with its new text; nothing new reads as nothing; `n` bounds a read and `more` says
// there is more. A cursor's text reads back; other text is `Invalid`.
// spec: none (client surface, notes/chat.md)
#[test]
fn since_goes_by_arrival() {
    let c0 = clock();
    let (alice, bob) = (node(1, &c0), node(2, &c0));
    deliver(&bob, &alice);
    let c = create(&alice, &Options::default()).unwrap();
    alice.grant(c, bob.me(), Role::Write, Default::default()).unwrap();
    deliver(&alice, &bob);
    c0.advance(10);
    let late = post(&bob, c, "made offline");
    c0.advance(10);
    let first = post(&alice, c, "first");
    let r = since(&alice, c, None, 10).unwrap();
    assert_eq!(r.messages.iter().map(|k| k.stamp.id).collect::<Vec<_>>(), [first]);
    let cur = r.cursor.unwrap();
    assert_eq!(cur.to_string().parse::<Cursor>().unwrap(), cur);
    assert!(matches!("x".parse::<Cursor>(), Err(Error::Invalid(_))));
    assert_eq!(since(&alice, c, Some(&cur), 10).unwrap().messages, [], "nothing new");
    c0.advance(10);
    deliver(&bob, &alice);
    let r = since(&alice, c, Some(&cur), 10).unwrap();
    assert_eq!(r.messages.iter().map(|k| k.stamp.id).collect::<Vec<_>>(), [late], "arrived after the cursor");
    let cur = r.cursor.unwrap();
    c0.advance(10);
    edit(&alice, c, first, "edited").unwrap();
    let second = post(&alice, c, "second");
    let r = since(&alice, c, Some(&cur), 1).unwrap();
    assert_eq!(r.messages.iter().map(|k| (k.stamp.id, text(&k.at(c, MSG).unwrap().body))).collect::<Vec<_>>(), [(first, "edited".into())], "an edit is its message again");
    assert!(r.more);
    let r = since(&alice, c, r.cursor.as_ref(), 10).unwrap();
    assert_eq!(r.messages.iter().map(|k| k.stamp.id).collect::<Vec<_>>(), [second]);
    assert_eq!(cursor(&alice, c).unwrap(), r.cursor);
}

// notes/chat.md Message: a reply id is text another writer chose: one naming a commit is a reply,
// anything else is none.
// spec: none (client surface, notes/chat.md)
#[test]
fn a_reply_names_a_commit_or_nothing() {
    let db = node(1, &clock());
    let c = create(&db, &Options::default()).unwrap();
    let id = post(&db, c, "first");
    let reply = |r: &str| schema::Message { text: String::new(), name: None, reply_to: Some(r.into()) }.reply();
    assert_eq!(reply(&id.to_string()), Some(id));
    assert_eq!(reply("not an id"), None);
    assert_eq!(msg("x").reply(), None);
}
