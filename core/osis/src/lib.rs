//! osis stores an app's data on the user's own machines and keeps it in sync between them and with
//! whoever it is shared with, directly, with no server required. Apps read and write
//! plain values locally, online or not, and are told when anything changes.
//!
//! The data is made of **things**. A thing has an identity (a `Tid`) and any number of **aspects**,
//! each one typed value under a name like `note:title.0`, so many apps can share one thing and each
//! read the parts it understands. **Groups** are things that list other things; they are what syncs.
//! A running osis with its own store is a **node**, and `Osis` is a handle to one. An **account** is
//! an identity held by a set of nodes: a person's, a team's, a bot's. Anything that can hold a role and
//! act (an account, a node, a shared space) is an **actor**.
//!
//! # A first write
//! You are the first admin of a thing you create. `me()` is your account, and also a group synced to
//! all your nodes. A new thing is a **draft**, in memory, until its first durable write.
//! ```
//! use osis::{Config, Member, MemStore, Osis, Store, Value};
//! let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let mut w = db.write();
//! let note = w.create()?;
//! w.group(db.me()).add(Member::Item(note))?;
//! w.at(note, db.aspect_key("note:title.0")?).set(&Value::Str("Groceries".into()))?;
//! w.commit()?;
//! assert!(db.members(db.me())?.contains(&Member::Item(note)));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Keys and reads
//! An aspect key says which aspect, and what type its values are. Code generated from a schema gives
//! typed constants (`Aspect<T>`); `db.aspect_key(name)` gives one at run time, its values `Value`s. An
//! absent aspect reads as `None`.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, Value};
//! # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let title = db.aspect_key("note:title.0")?;
//! let mut w = db.write();
//! let t = w.create()?;
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
//! # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! db.register_schema("t.osis", "version 1; aspect t:done.0: bool;")?;
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
//! # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let tags = db.aspect_key("note:tags.0")?;
//! let mut w = db.write();
//! let t = w.create()?;
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
//! # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let form = db.aspect_key("app:form.0")?;
//! let shown = Value::Map(ValueMap::from([(Value::Int(0), Value::Str("a".into())), (Value::Int(1), Value::Int(1))]));
//! let mut w = db.write();
//! let t = w.create()?;
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
//! what cannot share a commit. Writing several commits is up to you. Keys ending in `~` are
//! **ephemeral**: shared with other nodes, held in memory, never stored.
//! ```
//! # use osis::{Config, Error, Expiry, MemStore, Osis, Store, Value};
//! # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let (title, typing) = (db.aspect_key("app:title.0")?, db.aspect_key("app:typing.0~")?);
//! let mut w = db.write();
//! let t = w.create()?;
//! w.at(t, title.clone()).set(&Value::Str("note".into()))?;
//! w.commit()?;
//! // memory and disk are two commits: a peer could see one without the other
//! let mut w = db.write();
//! w.at(t, title.clone()).set(&Value::Str("draft".into()))?;
//! w.at(t, typing.clone()).set(&Value::Bool(true))?;
//! assert!(matches!(w.commit(), Err(Error::Invalid(_))));
//! // a commit has one expiry
//! let mut w = db.write();
//! w.expires(Expiry::In(std::time::Duration::from_secs(5)));
//! w.at(t, typing).set(&Value::Bool(true))?;
//! let done = w.commit()?.unwrap();
//! db.revert(done.id)?;
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Watching
//! `on_change` calls you with the current value, then after every change, wherever it came from.
//! Callbacks run one at a time on a thread osis starts, or on your thread when you call `settle`
//! (`Dispatcher::Pump`), and may call anything. Dropping the `Subscription` unsubscribes.
//! ```
//! # use osis::{Config, MemStore, Origin, Osis, Store, Value};
//! # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let k = db.aspect_key("app:count.0")?;
//! let mut w = db.write();
//! let t = w.create()?;
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
//! From async code, forward `on_change` to a channel of whichever runtime you use and await that.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, Value};
//! # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let k = db.aspect_key("app:count.0")?;
//! let mut w = db.write();
//! let t = w.create()?;
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
//! # Commits, undo, redo, revert
//! `commits` lists the commits held here, anyone's. `undo` and `redo` revert this actor's own newest
//! commit or undo in a scope; `revert` reverts any commit.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, Value, Scope, CommitQuery, CommitKind};
//! # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let k = db.aspect_key("app:x.0")?;
//! let mut w = db.write();
//! let t = w.create()?;
//! w.at(t, k.clone()).set(&Value::Int(1))?;
//! w.commit()?;
//! let mut w = db.write();
//! w.at(t, k.clone()).set(&Value::Int(2))?;
//! w.commit()?;
//! let u = db.undo(&Scope::Thing(t))?.unwrap();
//! assert_eq!(db.at(t, k.clone()).get()?, Some(Value::Int(1)));
//! let undos = db.commits(&CommitQuery { scope: Some(Scope::Thing(t)), kinds: vec![CommitKind::Revert], ..Default::default() })?;
//! assert_eq!(undos[0].commit.id, u.id);
//! db.redo(&Scope::Thing(t))?;
//! assert_eq!(db.at(t, k).get()?, Some(Value::Int(2)));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Sync and peers
//! Everything works with nobody online; sync catches up whenever two nodes meet. Two kinds of node
//! carry a group, for now:
//! - Other nodes that read it find each other and sync directly (`Config::direct_sync`,
//!   `ShareAddress`), with feature `iroh`, and on a LAN with feature `lan`. Neither is on by default.
//! - **Saved peers**, named by address: nodes that serve data for others at a fixed address
//!   (`set_serving`, `serving_address`), whether or not they can read it: another of your machines,
//!   a friend's, a rented box. What a peer cannot read reaches it encrypted.
//!
//! Only a saved peer can confirm anything: `wait_synced`, catching up before lowering a role, and
//! recovery count on one, and `status` shows a group with none as `NoPeers` or `Connected`.
//!
//! Sync runs on a runtime (`Runtime::Own`, or your tokio handle); without one everything local still
//! works, and a call that waits for another node fails `Network`. `Osis::create` given peers also
//! returns a recovery card, the only copy of the key that restores the account on a new node.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, SyncState};
//! let (db, card) = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?;
//! assert!(card.is_none(), "no saved peers: no card");
//! assert_eq!(db.status()?.groups[&db.me()].state, SyncState::NoPeers);
//! # Ok::<(), osis::Error>(())
//! ```
//! ```no_run
//! # use osis::{Config, MemStore, Osis, Runtime, Store, SyncScope};
//! # async fn demo() -> osis::Result<()> {
//! let cfg = Config { runtime: Runtime::Own, ..Default::default() };
//! let peers = ["quic://example.org:4433#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse()?];
//! let (db, card) = Osis::create(Store::Memory(MemStore::new()), &peers, cfg.clone())?;
//! db.wait_synced(SyncScope::AllWithSavedPeers).await?;
//! // on a fresh node: the same account from the card
//! let again = Osis::restore(Store::Memory(MemStore::new()), &[], &card.unwrap(), cfg).await?;
//! assert_eq!(again.me(), db.me());
//! # Ok(()) }
//! ```
//!
//! A call that waits for another node is `async`, works on any runtime or none, and lasts until it is
//! done or dropped: to give up, wrap it in your runtime's timeout. Dropping one leaves nothing half
//! done. When it is known that it can never finish it fails instead (`Unsynced`, `Network`, `Closed`).
//! ```no_run
//! # use osis::{Osis, SyncScope};
//! # use std::time::Duration;
//! # async fn demo(db: Osis) {
//! match tokio::time::timeout(Duration::from_secs(10), db.wait_synced(SyncScope::AllWithSavedPeers)).await {
//!     Ok(Ok(())) => println!("reached the saved peers"),
//!     Ok(Err(e)) => println!("cannot sync: {e}"),
//!     Err(_) => println!("not yet: see db.status()"),
//! }
//! # }
//! ```
//!
//! # Sharing
//! A role says who may; sync says where the data goes. `grant` gives an actor a role on a thing and
//! needs the actor's keys (a contact card, a shared group). The holder reads once a synced group it
//! reads holds the thing, or the thing's own `sync` carries it. `set_role` changes or removes a role.
//! A link needs no keys and syncs its thing. Being in a group grants nothing: `add_with_grant` adds a
//! member and lets the group's holders read it.
//! ```
//! # use osis::{Address, Config, GrantOpts, MemStore, Osis, Role, LinkOpts, Store, Value};
//! // a link names peers (or is direct, `LinkOpts::direct`)
//! let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! db.add_peer(&Address::new(&"quic://example.org:4433".parse()?, [7; 32]))?;
//! let mut w = db.write();
//! let g = w.create()?;
//! w.at(g, osis::core::NAME).set(&"Trip".to_string())?;
//! w.commit()?;
//! db.sync(g, &[])?;
//! let link = db.make_link(g, Role::Write, LinkOpts { single_use: true, ..Default::default() })?;
//! assert!(link.to_string().starts_with("osis://link/"));
//! let links = db.links()?;
//! assert_eq!(links.iter().filter(|l| l.target == g).count(), 1);
//! // who holds `g`, and who holds it through what
//! assert!(db.holders(g)?.iter().any(|h| h.actor == links[0].id.actor() && h.through.is_empty()));
//! // grant, and later change or remove: `db.set_role(g, holder, Some(Role::Read), SetRoleOpts::default()).await`
//! db.grant(g, db.node(), Role::Read, GrantOpts::default())?;
//! assert_eq!(db.grants(g)?[&db.node()].role, Role::Read);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # A second node for an account
//! Pairing needs no connection: your app carries the offer to the new node, its request back, and the
//! reply to it (a QR code, the clipboard, a local socket).
//! ```
//! # use osis::{Config, MemStore, Osis, Store};
//! let phone = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let offer = phone.pair_offer()?;
//! let joining = Osis::pair(Store::Memory(MemStore::new()), &[], &offer, Config::default())?;
//! let (node, reply) = phone.pair_accept(joining.request())?;
//! let laptop = joining.finish(&reply)?;
//! assert_eq!(laptop.me(), phone.me());
//! assert!(phone.nodes()?.iter().any(|n| n.node == node));
//! # Ok::<(), osis::Error>(())
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
//! assert_eq!(client.me(), actor);
//! assert!(!client.has_store());
//! # Ok(()) }
//! ```
//!
//! # Signals
//! A key ending in `*` holds nothing: each set fires every callback on it once, here and on the nodes
//! connected now that read the thing.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, Value};
//! let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let mut w = db.write();
//! let t = w.create()?;
//! w.commit()?;
//! let ring = db.aspect_key("app:ring.0*")?;
//! let (tx, rx) = std::sync::mpsc::channel();
//! let _sub = db.at(t, ring.clone()).on_change(move |_, c| { let _ = tx.send(c.value); })?;
//! assert_eq!(rx.recv().unwrap(), Ok(None));
//! let mut w = db.write();
//! w.at(t, ring.clone()).set(&Value::Bool(true))?;
//! w.commit()?;
//! assert_eq!(rx.recv().unwrap(), Ok(Some(Value::Bool(true))));
//! assert_eq!(db.at(t, ring).get()?, None);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Large values and text
//! A read fails `TooLarge` above `AppConfig::read_limit` rather than run out of memory: read a large
//! string or blob by `stream`, a large collection by path. Text a user types goes through a session,
//! which commits once per pause rather than per keystroke.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, p};
//! # use std::io::Read;
//! let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let k = db.aspect_key("app:body.0")?;
//! let mut w = db.write();
//! let t = w.create()?;
//! w.at(t, k.clone()).path(p![]).set_stream(&b"some bytes"[..])?;
//! w.commit()?;
//! let mut s = String::new();
//! db.at(t, k.clone()).path(p![]).stream()?.unwrap().read_to_string(&mut s).unwrap();
//! assert_eq!(s, "some bytes");
//! let title = db.aspect_key("app:title.0")?;
//! let ed = db.at(t, title.clone()).path(p![]).edit_text()?;
//! ed.splice(0..0, "Hello")?;
//! ed.splice(5..5, " world")?;
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
//! let a = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let b = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let mut w = a.write();
//! w.at(b.me(), a.aspect_key("app:x.0")?).set(&osis::Value::Int(1))?;
//! assert!(matches!(w.commit(), Err(Error::UnknownThing { .. })));
//! # Ok::<(), osis::Error>(())
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod commit_id;
mod clients;
mod diagnostic;
mod error;
mod handle;
mod serving;
#[doc(hidden)]
pub mod internals;
mod keep;
mod keys;
mod large;
mod net;
mod account;
mod read;
mod retention;
mod share;
mod sources;
mod text;
mod commits;
mod history;
mod value_type;
mod watch;
mod write;

mod port;
pub use commit_id::{CommitId, HistoryFrom, HistoryPos};
pub use clients::{Client, ClientSecret};
pub use error::{Error, Result};
pub use diagnostic::Diagnostic;
pub use serving::{Admit, ServingCaps, Serving, ServingPolicy, SyncId};
pub use handle::{Close, Config, AppConfig, MemStore, Osis, Store, WeakOsis};
pub use net::{Runtime, ShareAddress, SyncMode, SyncOptions};
pub use account::{Joining, PairOffer, PairReply, PairRequest};
pub use keep::KeepAlive;
pub use keys::{DynamicAspectKey, core};
pub use large::ValueStream;
pub use read::{AspectRef, Grant, Grants, GroupsOf, PathRef, Stamp, ThingStamp};
pub use retention::{Bound, Retention};
pub use share::{AccountNode, Address, ContactCard, GrantOpts, GroupSync, Holder, InviteId, LinkId, LinkInfo, LinkOpts, Member, RecoveryCard, SetRoleOpts, ShareLink, Status, SyncFirst, SyncScope, SyncState, Url};
pub use sources::{GroupSource, NodeLogin, NodeConnection};
pub use text::{Splice, TextSession};
pub use commits::{CommitEntry, CommitKind, CommitQuery, NotUndoableReason, Scope};
pub use history::{HistoryBody, HistoryEntry, HistoryEvent, HistoryPage};
pub use value_type::{NestedType, RecordField, TypeCase, ValueType};
pub use watch::{Change, DerivedFrom, Dispatcher, Origin, Subscription};
pub use write::{AspectWrite, Commit, Expiry, GroupWrite, PathWrite, Purge, SpliceItems, Write};

pub use osis_base::{Ak, Float, Role, Tid, Value, ValueMap, ValueSet};
pub use osis_base::{AkError, Time, TidParseError};
pub use osis_schema::{Aspect, AspectKey, CaseId, Codec, FieldId, Lifetime, Path, PathError, PathErrorKind, PurgeBy, Step, p};

/// What code generated from a schema (`osis schema gen`) refers to: `use osis::generated as
/// osis_schema;` beside the `include!`.
#[doc(hidden)]
pub mod generated {
    pub use osis_schema::{Aspect, CaseId, Codec, FieldId, StaticSchema, codec_enum, codec_struct, ids, named_type};

    /// The value types generated code names.
    pub mod osis_base {
        pub use osis_base::{Float, Tid, Value};
    }
}
