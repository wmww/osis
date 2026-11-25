//! osis stores an app's data on the user's own machines and keeps it in sync between them and with
//! whoever it is shared with, directly, with no server required. Apps read and write
//! plain values locally, online or not, and are told when anything changes.
//!
//! The data is made of **things**. A thing has an identity (a `Tid`) and any number of **aspects**,
//! each one typed value under a name like `note:title.0`, so many apps can share one thing and each
//! read the parts it understands. A thing references others in its values; a node holds what its
//! node root reaches by strong references.
//! A running osis with its own store is a **node**, and `Osis` is a handle to one. A node writes as
//! its own thing, its **node thing** (`node()`), and holds roles as it. A person, an organization or
//! a shared space is a thing like any other, holding roles on others; an account (a person's
//! identity held by a set of nodes) is an arrangement of things a library makes (osis-account).
//!
//! # A first write
//! A thing is minted with an admin, its mint admin, usually the thing it lives in: whoever reads that reads
//! it. A thing is made only where something holds it: a strong reference from a thing this node
//! holds, written in the same write. Here the node thing is both.
//! ```
//! use osis::{Config, MemStore, Osis, Store, Value};
//! let db = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! let mut w = db.write();
//! let note = w.create(db.node(), None)?;
//! w.hold(db.node(), note)?;
//! w.at(note, db.aspect_key("note:title.0")?).set(&Value::Str("Groceries".into()))?;
//! w.commit()?;
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Keys and reads
//! An aspect key says which aspect, and what type its values are. Code generated from a schema gives
//! typed constants (`Aspect<T>`, `Signal<T>` for a signal); `db.aspect_key(name)` gives one at run
//! time, its values `Value`s. An absent aspect reads as `None`.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, Value};
//! # let db = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! let title = db.aspect_key("note:title.0")?;
//! let mut w = db.write();
//! let t = w.create(db.node(), None)?;
//! # w.hold(db.node(), t)?;
//! w.at(t, title.clone()).set(&Value::Str("Groceries".into()))?;
//! w.commit()?;
//! assert_eq!(db.at(t, title.clone()).get()?, Some(Value::Str("Groceries".into())));
//! assert_eq!(db.at(t, db.aspect_key("note:other.0")?).get()?, None);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! A key can say what its values look like, for code that handles aspects it was not generated for.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, ValueType};
//! # let db = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! db.register_schema("t.osis", "revision 1; aspect t:done.0: bool;")?;
//! assert_eq!(db.aspect_key("t:done.0")?.value_type().map(|t| t.get()), Some(ValueType::Bool));
//! assert_eq!(db.aspect_key("t:other.0")?.value_type(), None);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Paths
//! `at(tid, key).path(p![..])` reads or writes one position inside a value; only that position is
//! loaded.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, Value, p};
//! # let db = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! let tags = db.aspect_key("note:tags.0")?;
//! let mut w = db.write();
//! let t = w.create(db.node(), None)?;
//! # w.hold(db.node(), t)?;
//! w.at(t, tags.clone()).path(p!["color"]).set(&"red".to_string())?;
//! w.commit()?;
//! let c: Option<String> = db.at(t, tags).path(p!["color"]).get()?;
//! assert_eq!(c.as_deref(), Some("red"));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Set, edit, overwrite
//! Others may be writing the same value. `edit(base, new)` writes only what the user changed since
//! `base`, so their change to another field survives: use it, or path writes, for anything a user
//! edits. `set` makes the value equal to what you pass: fields you did not touch are written back,
//! and an equal value writes nothing. `overwrite` always writes the whole value, for where each write
//! counts, such as a message in a log.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, Value};
//! # use osis::ValueMap;
//! # let db = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! let form = db.aspect_key("app:form.0")?;
//! let shown = Value::Map(ValueMap::from([(Value::Int(0), Value::Str("a".into())), (Value::Int(1), Value::Int(1))]));
//! let mut w = db.write();
//! let t = w.create(db.node(), None)?;
//! # w.hold(db.node(), t)?;
//! w.at(t, form.clone()).set(&shown)?;
//! w.commit()?;
//! let mut edited = shown.clone();
//! if let Value::Map(m) = &mut edited { m.insert(Value::Int(1), Value::Int(2)); }
//! let mut w = db.write();
//! w.at(t, form.clone()).edit(&shown, &edited)?;
//! w.commit()?;
//! assert_eq!(db.at(t, form).get()?, Some(edited));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # One write, one commit
//! A `Write` is one commit, whole at every node, or it fails `Invalid` before anything applies, saying
//! what cannot share a commit. Writing several commits is up to you. Keys marked `+` are
//! **ephemeral**: shared with other nodes, held in memory, never stored.
//! ```
//! # use osis::{Config, Error, Expiry, MemStore, Osis, Store, Value};
//! # let db = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! let (title, typing) = (db.aspect_key("app:title.0")?, db.aspect_key("app:typing+.0")?);
//! let mut w = db.write();
//! let t = w.create(db.node(), None)?;
//! # w.hold(db.node(), t)?;
//! w.at(t, title.clone()).set(&Value::Str("note".into()))?;
//! w.commit()?;
//! // memory and disk are two commits: a peer could see one without the other
//! let mut w = db.write();
//! w.at(t, title.clone()).set(&Value::Str("edited".into()))?;
//! w.at(t, typing.clone()).set(&Value::Bool(true))?;
//! assert!(matches!(w.commit(), Err(Error::Invalid(_))));
//! // a commit has one expiry
//! let mut w = db.write();
//! w.expires(Expiry::In(std::time::Duration::from_secs(5)));
//! w.at(t, typing).set(&Value::Bool(true))?;
//! w.commit()?;
//! // a thing that expires goes whole at every node, and its commit with it
//! let mut w = db.write();
//! let brief = w.create(db.node(), Some(Expiry::In(std::time::Duration::from_secs(5))))?;
//! # w.hold(db.node(), brief)?;
//! w.at(brief, title).set(&Value::Str("gone soon".into()))?;
//! w.commit()?;
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Watching
//! `on_change` calls you with the current value, then after every change, wherever it came from.
//! Callbacks run one at a time on a thread osis starts, or on your thread when you call `settle`
//! (`Dispatcher::Pump`), and may call anything. Dropping the `Subscription` unsubscribes.
//! ```
//! # use osis::{Config, MemStore, Origin, Osis, Store, Value};
//! # let db = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! let k = db.aspect_key("app:count.0")?;
//! let mut w = db.write();
//! let t = w.create(db.node(), None)?;
//! # w.hold(db.node(), t)?;
//! w.commit()?;
//! let (tx, rx) = std::sync::mpsc::channel();
//! let sub = db.at(t, k.clone()).on_change(move |_db, c| { let _ = tx.send(c); })?;
//! let mut w = db.write();
//! w.at(t, k.clone()).set(&Value::Int(1))?;
//! w.commit()?;
//! assert_eq!(rx.recv().unwrap().origin, Origin::Initial);
//! let c = rx.recv().unwrap();
//! assert!(matches!(c.origin, Origin::Local(_)));
//! assert_eq!(c.value, Ok(Some(Value::Int(1))));
//! drop(sub);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! `path(p).on_change` listens at a position inside a value, at any depth: a write elsewhere in
//! the aspect does not call it.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, Value, p};
//! # let db = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! let k = db.aspect_key("app:scores.0")?;
//! let mut w = db.write();
//! let t = w.create(db.node(), None)?;
//! # w.hold(db.node(), t)?;
//! w.commit()?;
//! let (tx, rx) = std::sync::mpsc::channel();
//! let _sub = db.at(t, k.clone()).path(p!["ann"]).on_change::<i64>(move |_db, c| { let _ = tx.send(c.value); })?;
//! let mut w = db.write();
//! w.at(t, k.clone()).path(p!["bob"]).set(&Value::Int(3))?;
//! w.at(t, k.clone()).path(p!["ann"]).set(&Value::Int(5))?;
//! w.commit()?;
//! db.settle();
//! assert_eq!(rx.try_iter().collect::<Vec<_>>(), vec![Ok(None), Ok(Some(5))]);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! From async code, forward `on_change` to a channel of whichever runtime you use and await that.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, Value};
//! # let db = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! let k = db.aspect_key("app:count.0")?;
//! let mut w = db.write();
//! let t = w.create(db.node(), None)?;
//! # w.hold(db.node(), t)?;
//! w.commit()?;
//! let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
//! let _sub = db.at(t, k.clone()).on_change(move |_db, c| { let _ = tx.send(c.value); })?;
//! let mut w = db.write();
//! w.at(t, k.clone()).set(&Value::Int(1))?;
//! w.commit()?;
//! tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
//!     assert_eq!(rx.recv().await, Some(Ok(None)));
//!     assert_eq!(rx.recv().await, Some(Ok(Some(Value::Int(1)))));
//! });
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! A `ReadSet` listens to what you read: reads through `db.tracking(&set)` subscribe as they read,
//! at the read's own address, with no gap between reading and listening.
//! ```
//! # use osis::{Config, MemStore, Osis, ReadSet, Store, Value};
//! # let db = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! let k = db.aspect_key("app:count.0")?;
//! let mut w = db.write();
//! let t = w.create(db.node(), None)?;
//! # w.hold(db.node(), t)?;
//! w.commit()?;
//! let (tx, rx) = std::sync::mpsc::channel();
//! let set = ReadSet::new(move |_db| { let _ = tx.send(()); });
//! let reading = db.tracking(&set);
//! assert_eq!(reading.at(t, k.clone()).get()?, None);
//! let mut w = db.write();
//! w.at(t, k.clone()).set(&Value::Int(1))?;
//! w.commit()?;
//! db.settle();
//! assert!(rx.try_recv().is_ok());
//! set.sweep(); // drops listeners not read since the last sweep
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Backlinks
//! A value names a thing only by a reference, and the writer always says which kind: a `Strong`
//! says the target belongs with the thing holding it, a `Weak` only points. `Tid` converts into
//! either with `.into()`.
//! `backlinks(t, query)` pages through the things whose current values reference `t`, with the
//! aspect and the kind. `on_backlinks_change` hears a page now and on each change.
//! ```
//! # use osis::{BacklinkQuery, Config, MemStore, Osis, RefKind, Store, Value, Weak};
//! # let db = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! let link = db.aspect_key("note:link.0")?;
//! let mut w = db.write();
//! let (a, b) = (w.create(db.node(), None)?, w.create(db.node(), None)?);
//! # w.hold(db.node(), a)?;
//! # w.hold(db.node(), b)?;
//! w.at(a, link.clone()).set(&Weak(b).into())?;
//! w.commit()?;
//! let page = db.backlinks(b, &BacklinkQuery::default())?;
//! let found: Vec<_> = page.backlinks.iter().map(|l| (l.tid, l.ak.as_str(), l.kind)).collect();
//! assert!(found.contains(&(a, "note:link.0", RefKind::Weak)));
//! assert!(found.contains(&(db.node(), "holds.0", RefKind::Strong)), "what holds b");
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Commits, undo, redo, revert
//! `writes` lists the commits in a scope, anyone's, each with its parts: those still in the read or
//! kept by history (`fired` lists a signal's). `undo` and `redo` revert this actor's own newest
//! commit or undo in a scope; `revert` reverts any commit. Only a commit in kept history is undone
//! (the thing's setting, `core::RETENTION`, set by its admins), and only from kept history is
//! anything written back: without a setting keeping it, any undo is `NotUndoable`, on every node.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, Value, Scope, CommitQuery, CommitKind, History, Time};
//! # use osis::core::{RETENTION, RetentionEntry, RetentionSetting};
//! # use std::time::Duration;
//! # let db = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! db.register_schema("app.osis", "revision 1; aspect app:x.0: int;")?;
//! let k = db.aspect_key("app:x.0")?;
//! let mut w = db.write();
//! let t = w.create(db.node(), None)?;
//! # w.hold(db.node(), t)?;
//! // what is replaced stays a day, so an undo can write it back
//! let day = History::Keep { until: Time(0), after_replaced: Duration::from_secs(86_400) };
//! let entry = RetentionEntry { history: Some(day), ..Default::default() };
//! w.at(t, RETENTION).set(&RetentionSetting { default: Some(entry), ..Default::default() })?;
//! w.at(t, k.clone()).set(&Value::Int(1))?;
//! w.commit()?;
//! let mut w = db.write();
//! w.at(t, k.clone()).set(&Value::Int(2))?;
//! w.commit()?;
//! let u = db.undo(&Scope::Thing(t))?.unwrap();
//! assert_eq!(db.at(t, k.clone()).get()?, Some(Value::Int(1)));
//! let undos = db.writes(&Scope::Thing(t), &CommitQuery { kinds: vec![CommitKind::Revert], ..Default::default() })?;
//! assert_eq!(undos.commits[0], u);
//! db.redo(&Scope::Thing(t))?;
//! assert_eq!(db.at(t, k).get()?, Some(Value::Int(2)));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Sync
//! Everything works with nobody online; sync catches up whenever two nodes meet. A node syncs what
//! its account holds with every node it reaches that holds it too; `status` says how that stands.
//! ```
//! # use osis::{Config, MemStore, Osis, Store};
//! let db = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! assert_eq!(db.status()?.connected, 0);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! A call that waits for another node is `async`, works on any runtime or none, and lasts until it is
//! done or dropped: to give up, wrap it in your runtime's timeout. Dropping one leaves nothing half
//! done. When it is known that it can never finish it fails instead (`Stranded`, `Network`, `Closed`).
//! ```no_run
//! # use osis::{Osis, SyncScope};
//! # use std::time::Duration;
//! # async fn demo(db: Osis) {
//! match tokio::time::timeout(Duration::from_secs(10), db.wait_synced(SyncScope::All)).await {
//!     Ok(Ok(())) => println!("caught up with every connected node"),
//!     Ok(Err(e)) => println!("cannot sync: {e}"),
//!     Err(_) => println!("not yet: see db.status()"),
//! }
//! # }
//! ```
//!
//! # Sharing
//! A role says who may; sync says where the data goes. `grant` gives an actor a role on a thing and
//! needs the actor's keys (a card of it, a shared thing). `set_role` changes or removes a role.
//! A link needs no keys. A grant to `Tid::PUBLIC` lets everyone read the thing, and
//! `public_link` hands out a way to it; `set_card` puts a thing's card on another, so whoever
//! reads that one can grant to it.
//! ```
//! # use osis::{Config, GrantOpts, MemStore, Osis, Role, Store};
//! let db = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! let mut w = db.write();
//! let (g, team) = (w.create(db.node(), None)?, w.create(db.node(), None)?);
//! # w.hold(db.node(), g)?;
//! # w.hold(db.node(), team)?;
//! w.at(g, osis::core::NAME).set(&"Trip".to_string())?;
//! w.commit()?;
//! // grant, and later change or remove with `set_role`
//! db.grant(g, team, Role::Read, GrantOpts::default())?;
//! assert_eq!(db.grants(g)?[&team].role, Role::Read);
//! // who holds `g`, and who holds it through what
//! assert!(db.holders(g)?.iter().any(|h| h.actor == team && h.through.is_empty()));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! Two admins who remove each other without having seen the other's removal start a dispute that
//! every node settles for itself: `disputes` lists them with the side this node took (by default,
//! whichever removal it held first), `on_dispute` tells when one is found, `choose_side` switches.
//!
//! Lowering or removing a role writes at once. It keeps what this node and every other writer had
//! received of the holder's work by then (the writers vouch for it); what reached no writer is undone
//! until the holder is granted the role again. To keep more, sync first, for at most so long:
//! ```no_run
//! # use osis::{Osis, Role, SetRoleOpts, SyncScope, Tid};
//! # use std::time::Duration;
//! # async fn demo(db: Osis, g: Tid, bob: Tid) -> osis::Result<()> {
//! let _ = tokio::time::timeout(Duration::from_secs(30), db.wait_synced(SyncScope::Thing(g))).await;
//! db.set_role(g, bob, Some(Role::Read), SetRoleOpts::default())?;
//! # Ok(()) }
//! ```
//!
//! # Using a node from another program
//! A client is a program using a node from outside its process. A thin client has no store of its
//! own: `Osis::connect` and `Osis::connect_socket` make one, and it reads and writes at the node as if
//! it were local. A node can be a client too (`Osis::connect_node`).
//! ```no_run
//! # use osis::{AppConfig, NodeLogin, Osis};
//! # async fn demo(node: &Osis, addr: osis::Address) -> osis::Result<()> {
//! let (actor, secret) = node.add_client(None)?;
//! // on the other program, given `addr` and `secret`:
//! let client = Osis::connect(&[NodeLogin { addr, secret }], AppConfig::default()).await?;
//! assert_eq!(client.author(), actor);
//! assert!(!client.has_store());
//! # Ok(()) }
//! ```
//!
//! # Signals
//! A key marked `~` is a signal: it has no current value, so it is fired (`fire`), not written,
//! and its fires are listed (`fired`) and heard (`on_fire`), not read. Code generated from a schema
//! gives it as a `Signal<T>`, on which value calls (`get`, `on_change`, `set`, ...) do not compile,
//! as signal calls do not on an `Aspect<T>`; a key from `aspect_key` takes both, its reads of the
//! other kind finding nothing and its writes of the other kind failing `commit` with `Invalid`.
//! Each fire is a commit `on_fire` hears once where it applies. An ephemeral one (`+~`)
//! reaches only the nodes connected now that read the thing, and nobody holds it: its listener
//! hears it as it was fired, and no page shows it. Otherwise each fire is listed by `fired` as
//! long as its thing's setting (`core::RETENTION`) keeps the key's history, and a purge removes
//! one; a fire the setting keeps no history for is `Invalid`; an undo leaves it (the key reads
//! absent before and after).
//! ```
//! # use osis::{Body, CommitEvent, Config, MemStore, Osis, Store, Value};
//! let db = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! let mut w = db.write();
//! let t = w.create(db.node(), None)?;
//! # w.hold(db.node(), t)?;
//! w.commit()?;
//! let ring = db.aspect_key("app:ring+~0")?;
//! let (tx, rx) = std::sync::mpsc::channel();
//! let key = ring.clone();
//! let _sub = db.at(t, ring.clone()).on_fire(move |_, e| {
//!     if let CommitEvent::Commit { commit: Some(c), .. } = e { let _ = tx.send(c.at(t, key.clone()).map(|p| p.body)); }
//! })?;
//! let mut w = db.write();
//! w.at(t, ring.clone()).fire(&Value::Bool(true))?;
//! w.commit()?;
//! assert_eq!(rx.recv().unwrap(), Some(Body::Held(Some(Value::Bool(true)))));
//! assert_eq!(db.at(t, ring).get()?, None);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! A durable fire can be replaced by its author (`replace`): it then reads as its newest
//! replacement, in its place and under its own id, everywhere a fire is read: pages, `commit`
//! (one fire by id, as a reply quoting it reads it) and `on_fire`. Its history is `versions`, and
//! `Purge::Commit` of the fire deletes every version of it.
//! ```
//! # use osis::{Body, CommitQuery, Config, MemStore, Osis, Store, Value};
//! # let db = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! // the thing keeps its fires for good
//! let keep = osis::core::RetentionEntry { history: Some(osis::History::FOREVER), ..Default::default() };
//! let mut w = db.write();
//! let t = w.create(db.node(), None)?;
//! # w.hold(db.node(), t)?;
//! w.at(t, osis::core::RETENTION).set(&osis::core::RetentionSetting { default: Some(keep), ..Default::default() })?;
//! w.commit()?;
//! let say = db.aspect_key("app:say~0")?;
//! let mut w = db.write();
//! w.at(t, say.clone()).fire(&Value::Str("helo".into()))?;
//! let msg = w.commit()?.unwrap().stamp.id;
//! let mut w = db.write();
//! w.at(t, say.clone()).replace(msg, &Value::Str("hello".into()))?;
//! w.commit()?;
//! let shown = db.at(t, say.clone()).commit(msg)?.unwrap();
//! let part = shown.at(t, say.clone()).unwrap();
//! assert_eq!(part.body, Body::Held(Some(Value::Str("hello".into()))));
//! assert!(part.edited.is_some());
//! assert_eq!(db.at(t, say).versions(msg, &CommitQuery::default())?.commits.len(), 2);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Large values and text
//! A read fails `TooLarge` when it would hold more than `AppConfig::read_limit` rather than run out
//! of memory: read a large string or blob by `stream`, a large collection by path. Text a user types goes through a session,
//! which commits once per pause rather than per keystroke.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, p};
//! # use std::io::Read;
//! let db = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! let k = db.aspect_key("app:body.0")?;
//! let mut w = db.write();
//! let t = w.create(db.node(), None)?;
//! # w.hold(db.node(), t)?;
//! w.at(t, k.clone()).path(p![]).set_stream(&b"some bytes"[..])?;
//! w.commit()?;
//! let mut s = String::new();
//! db.at(t, k.clone()).path(p![]).stream()?.unwrap().read_to_string(&mut s).unwrap();
//! assert_eq!(s, "some bytes");
//! let title = db.aspect_key("app:title.0")?;
//! let ed = db.at(t, title.clone()).path(p![]).edit_text()?;
//! // each keystroke: the text the field showed, and what the user made of it
//! ed.edit("", "Hello")?;
//! ed.edit("Hello", "Hello world")?;
//! ed.commit()?; // one commit for the whole pause
//! assert_eq!(db.at(t, title).get()?, Some(osis::Value::Str("Hello world".into())));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Errors
//! One `Error`, with stable categories. Roles are checked before a write is signed, so a write that
//! fails here was never sent. What another node does wrong is a `Diagnostic`, never an error.
//! ```
//! # use osis::{Config, MemStore, Osis, Error, Store};
//! let a = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! let b = Osis::create(Store::Memory(MemStore::new()), Config::default())?;
//! let mut w = a.write();
//! w.at(b.node(), a.aspect_key("app:x.0")?).set(&osis::Value::Int(1))?;
//! assert!(matches!(w.commit(), Err(Error::UnknownThing { .. })));
//! # Ok::<(), osis::Error>(())
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod backlinks;
mod commit_id;
mod clients;
mod diagnostic;
mod error;
mod handle;
#[doc(hidden)]
pub mod internals;
mod keep;
mod keys;
mod large;
mod net;
mod port;
mod disputes;
mod read;
mod retention;
mod share;
mod syncing;
mod sources;
mod text;
mod commits;
mod value_type;
mod track;
mod watch;
mod write;

pub use backlinks::{Backlink, BacklinkPage, BacklinkQuery};
pub use commit_id::{CommitFrom, CommitId, CommitPos};
pub use clients::{Client, ClientSecret};
pub use error::{Error, Result};
pub use diagnostic::Diagnostic;
pub use disputes::{Dispute, DisputeId, Side};
pub use handle::{Close, Config, AppConfig, MemStore, Osis, ReadOnly, Store, WeakOsis};
pub use net::{Lan, Runtime};
pub use keep::KeepAlive;
pub use keys::{DynamicAspectKey, core};
pub use large::ValueStream;
pub use read::{AspectRef, Grant, Grants, PathRef, Stamp};
pub use retention::History;
pub use share::{Address, GrantOpts, Holder, HolderKind, Keys, LinkId, LinkInfo, Link, LinkOpts, Offer, Reads, SetRoleOpts, Url};
pub use syncing::{Status, SyncScope, SyncState, UnitSync};
pub use sources::{UnitSource, NodeLogin};
pub use text::{Splice, TextSession};
pub use commits::{Body, Commit, CommitEvent, CommitKind, CommitPage, CommitQuery, NotUndoableReason, Part, Scope};
pub use value_type::{NestedType, RecordField, TypeCase, ValueType};
pub use track::ReadSet;
pub use watch::{Change, DerivedFrom, Dispatcher, Origin, Subscription};
pub use write::{AspectWrite, Expiry, PathWrite, Purge, SpliceItems, Write};

pub use osis_base::{Ak, Float, Ref, RefKind, Role, Strong, Tid, Value, ValueMap, ValueSet, Weak};
pub use osis_base::{AkError, Time, TidParseError};
pub use osis_schema::{Aspect, AspectKey, CaseId, Codec, FieldId, Path, PathError, PathErrorKind, PurgeBy, Signal, SignalKey, Step, ValueKey, p};

/// What code generated from a schema (`osis schema gen`) refers to: `use osis::generated as
/// osis_schema;` beside the `include!`.
#[doc(hidden)]
pub mod generated {
    pub use osis_schema::{Aspect, CaseId, Codec, FieldId, Signal, StaticSchema, codec_enum, codec_struct, ids, named_type};

    /// The value types generated code names.
    pub mod osis_base {
        pub use osis_base::{Float, Ref, Strong, Tid, Value, Weak};
    }
}
