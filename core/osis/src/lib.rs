//! osis is a decentralized, reactive data layer for interconnected applications. Apps read and
//! write structured data locally, online or not; osis syncs it between a user's devices and the
//! people it is shared with, and tells apps when it changes.
//!
//! # Open a database
//! You are the first admin of a thing you create. Things sync through groups: `me()` is a group
//! synced to all your devices, and any thing becomes a group with its first member. A new thing
//! lives in memory until its first durable write.
//! ```
//! use osis::{Config, Member, MemStore, Osis, Store, Value};
//! let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let mut w = db.write();
//! let note = w.create()?;
//! w.group(db.me()).add(Member::Item(note))?;
//! w.at(note, db.key("note:title.0")?).set(&Value::Str("Groceries".into()))?;
//! w.commit()?;
//! assert!(db.members(db.me())?.contains(&Member::Item(note)));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Keys and reads
//! Generated keys (`Aspect<T>`) read and write typed values; `db.key(name)` is the key of that
//! name, its values `Value`s, typed by a schema if one is registered. An absent aspect reads as
//! `None`.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, Value};
//! # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let title = db.key("note:title.0")?;
//! let mut w = db.write();
//! let t = w.create()?;
//! w.at(t, title.clone()).set(&Value::Str("Groceries".into()))?;
//! w.commit()?;
//! assert_eq!(db.at(t, title.clone()).get()?, Some(Value::Str("Groceries".into())));
//! assert_eq!(db.at(t, db.key("note:other.0")?).get()?, None);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Paths
//! `at(tid, key).path(p![..])` reads or writes one position; only that position is
//! materialized.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, Value, p};
//! # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let tags = db.key("note:tags.0")?;
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
//! `set` makes the value equal to what you pass, writing only what differs (fields you did not
//! touch are written back, and an equal value writes nothing). `edit(base, new)` writes only what
//! the user changed since `base`, so a concurrent change to another field survives: use it for
//! what users edit. `overwrite` always writes, the whole value: use it where each write counts,
//! such as a message in a log, where a set equal to the last one would be lost.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, Value};
//! # use osis::ValueMap;
//! # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let form = db.key("app:form.0")?;
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
//! # Watching
//! Callbacks run on one dispatcher (a thread, or the app's thread calling `settle` with
//! `Dispatcher::Pump`), after the commit is durable, never under a lock;
//! dropping the `Subscription` unsubscribes. `on_change` first delivers the current value.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, Value, Source};
//! # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let k = db.key("app:count.0")?;
//! let mut w = db.write();
//! let t = w.create()?;
//! w.commit()?;
//! let (tx, rx) = std::sync::mpsc::channel();
//! let sub = db.at(t, k.clone()).on_change(move |_db, c| { let _ = tx.send(c); })?;
//! let mut w = db.write();
//! w.at(t, k.clone()).set(&Value::Int(1))?;
//! w.commit()?;
//! assert_eq!(rx.recv().unwrap().source, Source::Initial);
//! let c = rx.recv().unwrap();
//! assert!(matches!(c.source, Source::Local(_)));
//! assert_eq!(c.value, Ok(Some(Value::Int(1))));
//! drop(sub);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Watching from async code
//! Forward `on_change` to a channel of whichever runtime you use and await that. The current
//! value comes first and no change is missed between reading it and subscribing.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, Value};
//! # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let k = db.key("app:count.0")?;
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
//! `commits` queries the held commits (anyone's); undo and redo revert this actor's own
//! newest change or undo in a scope; `revert` reverts any commit.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, Value, Scope, CommitQuery, CommitKind};
//! # let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let k = db.key("app:x.0")?;
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
//! # Sync, hosts and the recovery card
//! `create` makes a person, with a recovery key, whose home group is synced on the hosts
//! given; it returns the recovery card, the only copy of that key. Sync runs on a runtime
//! (`Runtime::Own`, or the app's tokio handle); without one everything works locally, and hosts are
//! refused. Status, waiting until synced and restoring from the card are the network-facing calls.
//!
//! A call that waits for another node is `async`, works on any runtime or none, and lasts until it
//! is done or dropped: to give up, wrap it in your runtime's timeout. Dropping one leaves nothing
//! half done; where a part of it stands, its doc says so. When it is known that it can never finish
//! it fails (a group with no way to sync: `Unsynced`; sync stopped: `Network`; a closed database:
//! `Closed`), so a wait that lasts has something that may yet answer it, such as a host out of reach.
//! ```no_run
//! # use osis::{Osis, SyncScope};
//! # use std::time::Duration;
//! # async fn demo(db: Osis) {
//! match tokio::time::timeout(Duration::from_secs(10), db.wait_synced(SyncScope::All)).await {
//!     Ok(Ok(())) => println!("at a host"),
//!     Ok(Err(e)) => println!("cannot sync: {e}"),
//!     Err(_) => println!("not yet: see db.status()"),
//! }
//! # }
//! ```
//! ```no_run
//! # use osis::{Config, MemStore, Osis, Runtime, Store, SyncScope};
//! # async fn demo() -> osis::Result<()> {
//! let cfg = Config { runtime: Runtime::Own, ..Default::default() };
//! let hosts = ["quic://example.org:4433#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse()?];
//! let (db, card) = Osis::create(Store::Memory(MemStore::new()), &hosts, cfg.clone())?;
//! db.wait_synced(SyncScope::All).await?;
//! // on a fresh device: the same person from the card
//! let again = Osis::restore(Store::Memory(MemStore::new()), &[], &card.unwrap(), cfg).await?;
//! assert_eq!(again.me(), db.me());
//! # Ok(()) }
//! ```
//! ```
//! # use osis::{Config, MemStore, Osis, Store, SyncState};
//! let (db, card) = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?;
//! assert!(card.is_none(), "no hosts: nothing to restore from");
//! assert_eq!(db.status()?.groups[&db.me()].state, SyncState::NoHosts);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Using a node from another program
//! A client is a program using a node through the client protocol. A thin client has no store of
//! its own: `Osis::connect` and `Osis::connect_socket` make one, and it reads and writes at the
//! node as if it were local. A node can be a client too (`Osis::connect_node`).
//! ```no_run
//! # use osis::{ClientConfig, NodeLogin, Osis};
//! # async fn demo(node: &Osis, addr: osis::HostAddr) -> osis::Result<()> {
//! let (actor, secret) = node.add_client(None)?;
//! // on the other program, given `addr` and `secret`:
//! let client = Osis::connect(&[NodeLogin { addr, secret }], ClientConfig::default()).await?;
//! assert_eq!(client.me(), actor);
//! assert!(!client.has_store());
//! # Ok(()) }
//! ```
//!
//! # Pairing a device
//! Transport-agnostic: the app carries the offer to the new device, its request back, and the
//! reply to it (QR, clipboard, a local socket).
//! ```
//! # use osis::{Config, MemStore, Osis, Store};
//! let phone = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let offer = phone.pair_offer()?;
//! let joining = Osis::pair(Store::Memory(MemStore::new()), &[], &offer, Config::default())?;
//! let (node, reply) = phone.pair_accept(joining.request())?;
//! let laptop = joining.finish(&reply)?;
//! assert_eq!(laptop.me(), phone.me());
//! assert!(phone.devices()?.iter().any(|d| d.node == node));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Sharing
//! A role says who may; sync says where the data goes. `grant` records a role and needs the
//! holder's keys (a contact card, a shared group); the holder reads once a synced group it reads
//! holds the thing, or the thing's own `sync` carries it. `set_role` changes or removes a role. A
//! link needs no keys and syncs its thing. Being in a group grants nothing: `add_with_grant` adds
//! a member and lets the group's holders read it.
//! ```
//! # use osis::{Config, GrantOpts, MemStore, Osis, Role, LinkOpts, HostAddr, Store, Value};
//! // a link names hosts (or is direct, `LinkOpts::direct`)
//! let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! db.add_host(&HostAddr::new(&"quic://example.org:4433".parse()?, [7; 32]))?;
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
//! # Signals
//! A signal aspect (key marker `*`) holds nothing: each set fires every callback on it once, here and on the
//! devices connected now that read the thing.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, Value};
//! let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let mut w = db.write();
//! let t = w.create()?;
//! w.commit()?;
//! let ring = db.key("app:ring.0*")?;
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
//! # Large values and text sessions
//! A string or blob above the bound streams; text edited by a user goes through a session that
//! commits once per pause.
//! ```
//! # use osis::{Config, MemStore, Osis, Store, p};
//! # use std::io::Read;
//! let db = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let k = db.key("app:body.0")?;
//! let mut w = db.write();
//! let t = w.create()?;
//! w.at(t, k.clone()).path(p![]).set_stream(&b"some bytes"[..])?;
//! w.commit()?;
//! let mut s = String::new();
//! db.at(t, k.clone()).path(p![]).stream()?.unwrap().read_to_string(&mut s).unwrap();
//! assert_eq!(s, "some bytes");
//! let title = db.key("app:title.0")?;
//! let ed = db.at(t, title.clone()).path(p![]).edit_text()?;
//! ed.splice(0..0, "Hello")?;
//! ed.splice(5..5, " world")?;
//! ed.commit()?; // one commit for the whole pause
//! assert_eq!(db.at(t, title).get()?, Some(osis::Value::Str("Hello world".into())));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Errors
//! One `Error` with stable categories; rights are checked locally before signing.
//! ```
//! # use osis::{Config, MemStore, Osis, Error, Store};
//! let a = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let b = Osis::create(Store::Memory(MemStore::new()), &[], Config::default())?.0;
//! let mut w = a.write();
//! w.at(b.me(), a.key("app:x.0")?).set(&osis::Value::Int(1))?;
//! assert!(matches!(w.commit(), Err(Error::UnknownThing { .. })));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Footguns closed
//! - Read-modify-write clobber: use `edit(base, new)` or path ops for what users edit; `set`
//!   is for "must be exactly this".
//! - Out of memory on a huge value: reads fail `TooLarge` past `Config::materialize_limit`;
//!   read by path instead.
//! - A thing that never syncs: membership is a group op (`NotSynced` diagnostic).
//! - A forgotten unsubscribe: `Subscription` is RAII, and dropping it at once is a lint:
//! ```compile_fail
//! #![deny(unused_must_use)]
//! let db = osis::Osis::create(osis::Store::Memory(osis::MemStore::new()), &[], osis::Config::default()).unwrap().0;
//! db.on_diagnostic(|_, _| {}).unwrap();
//! ```
//! - A forgotten commit: `Write` is `#[must_use]`:
//! ```compile_fail
//! #![deny(unused_must_use)]
//! let db = osis::Osis::create(osis::Store::Memory(osis::MemStore::new()), &[], osis::Config::default()).unwrap().0;
//! db.write();
//! ```
#![forbid(unsafe_code)]

mod clients;
mod diagnostic;
mod error;
mod handle;
mod hosting;
#[doc(hidden)]
pub mod internals;
mod keep;
mod keys;
mod large;
mod net;
mod person;
mod read;
mod share;
mod sources;
mod text;
mod commits;
mod history;
mod watch;
mod write;

mod port;
pub use osis_node::sync::MAX_CONNS_PER_CLIENT;
pub use clients::{Client, ClientSecret};
pub use port::{HISTORY_DIRTY_BYTES, HISTORY_SEND, MAX_SCHEMA_BYTES, SIGNAL_BYTES, STREAM_CHUNK, WRITE_NONCES, socket_path};
pub use port::client::SOCK_FILE;
#[doc(hidden)]
pub use port::client::{own_uid, socket_dir};
pub use error::{Error, Result};
pub use diagnostic::Diagnostic;
pub use hosting::{Admit, HostCaps, HostPolicy, Hosting, LabelId};
pub use handle::{ClientConfig, Close, Config, DEFAULT_IDLE_COMMIT, DEFAULT_LIMIT, MemStore, Osis, Store, WeakOsis};
pub use net::{Reach, Runtime, SyncMode, SyncOptions, Transport};
pub use person::{Joining, OFFER_LIFETIME_MS, PairOffer, PairReply, PairRequest};
pub use keep::{KeepAlive, REFRESH_DIVISOR};
pub use keys::{Key, core};
pub use large::ValueStream;
pub use read::{AspectRef, Grant, Grants, GroupsOf, PathRef, Stamp, ThingStamp};
pub use share::{ContactCard, Device, GrantOpts, GroupSync, Holder, HostAddr, InviteId, LinkId, LinkInfo, LinkOpts, Member, RecoveryCard, SetRoleOpts, ShareLink, Status, SyncFirst, SyncScope, SyncState, Url};
pub use sources::{GroupSource, NodeLogin, RemoteStatus};
pub use text::{Splice, TextSession};
pub use commits::{CommitEntry, CommitKind, CommitQuery, DropReason, Scope};
pub use history::{HISTORY_PAGE, HistoryBody, HistoryEntry, HistoryEvent, HistoryFrom, HistoryPage, HistoryPos};
pub use watch::{Change, Dispatcher, Source, Subscription};
pub use write::{AspectWrite, Committed, ExpiringGroupWrite, Expiry, GroupWrite, PathWrite, Purge, SpliceItems, Write};

/// Keep at least this, as an absolute time: for good (`Retention.at_least.abs`).
pub use osis_commit::FOREVER;
pub use osis_base::{Ak, Clock, CommitId, CreationRecord, ManualClock, Role, Tid, Ts, Value, ValueMap, ValueSet, WallMs};
pub use osis_node::{Cause, ChangeId, EphemeralId};
pub use osis_schema::AspectKey;
pub use osis_schema::{Aspect, CaseId, Codec, FieldId, Path, PathError, Lifetime, Retention, Schema, Step, p};

/// The schema layer, for generated code (`use osis::schema as osis_schema;`).
pub use osis_schema as schema;
