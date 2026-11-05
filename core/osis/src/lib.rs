//! osis is a decentralized, reactive data layer for interconnected applications. Apps read and
//! write structured data locally, online or not; osis syncs it between a user's devices and the
//! people it is shared with, and tells apps when it changes.
//!
//! # Open a database
//! You are the first admin of a thing you create. Things sync through groups: `me()` is a group
//! synced to all your devices, and any thing becomes a group with its first member. A new thing
//! lives in memory until its first durable write.
//! ```
//! use osis::{Ak, Config, Member, Osis, Value};
//! let db = Osis::create(Config::memory())?.0;
//! let mut w = db.write();
//! let note = w.create()?;
//! w.group(db.me()).add(Member::Item(note))?;
//! w.at(note, Ak::new("note:title.0").unwrap()).set(&Value::Str("Groceries".into()))?;
//! w.commit()?;
//! assert!(db.members(db.me())?.contains(&Member::Item(note)));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Keys and reads
//! Generated keys (`Aspect<T>`) read and write typed values; an `Ak` is the untyped key. An
//! absent aspect reads as `None`.
//! ```
//! # use osis::{Config, Osis, Ak, Value};
//! # let db = Osis::create(Config::memory())?.0;
//! let title = Ak::new("note:title.0").unwrap();
//! let mut w = db.write();
//! let t = w.create()?;
//! w.at(t, title.clone()).set(&Value::Str("Groceries".into()))?;
//! w.commit()?;
//! assert_eq!(db.at(t, title.clone()).get()?, Some(Value::Str("Groceries".into())));
//! assert_eq!(db.at(t, Ak::new("note:other.0").unwrap()).get()?, None);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Paths
//! `at(tid, key).path(p![..])` reads or writes one position; only that position is
//! materialized.
//! ```
//! # use osis::{Config, Osis, Ak, Value, p};
//! # let db = Osis::create(Config::memory())?.0;
//! let tags = Ak::new("note:tags.0").unwrap();
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
//! # use osis::{Config, Osis, Ak, Value};
//! # use osis::ValueMap;
//! # let db = Osis::create(Config::memory())?.0;
//! let form = Ak::new("app:form.0").unwrap();
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
//! # use osis::{Config, Osis, Ak, Value, Source};
//! # let db = Osis::create(Config::memory())?.0;
//! let k = Ak::new("app:count.0").unwrap();
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
//! # use osis::{Config, Osis, Ak, Value};
//! # let db = Osis::create(Config::memory())?.0;
//! let k = Ak::new("app:count.0").unwrap();
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
//! # use osis::{Config, Osis, Ak, Value, Scope, CommitQuery, CommitKind};
//! # let db = Osis::create(Config::memory())?.0;
//! let k = Ak::new("app:x.0").unwrap();
//! let mut w = db.write();
//! let t = w.create()?;
//! w.at(t, k.clone()).set(&Value::Int(1))?;
//! w.commit()?;
//! let mut w = db.write();
//! w.at(t, k.clone()).set(&Value::Int(2))?;
//! w.commit()?;
//! let u = db.undo(&Scope::Thing(t))?.unwrap();
//! assert_eq!(db.at(t, k.clone()).get()?, Some(Value::Int(1)));
//! let undos = db.commits(&CommitQuery::new().scope(Scope::Thing(t)).kind(CommitKind::Revert))?;
//! assert_eq!(undos[0].commit.id, u.id);
//! db.redo(&Scope::Thing(t))?;
//! assert_eq!(db.at(t, k).get()?, Some(Value::Int(2)));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Sync, hosts and the recovery card
//! `create` makes a person (owned by a recovery key) whose home group is synced on
//! `Config.hosts`; it returns the recovery card, the only copy of that key. Sync runs on a
//! runtime (`Runtime::Own`, or the app's tokio handle); without one everything works locally, and
//! `Config.hosts` is refused.
//! Status, waiting until synced and restoring from the card are the network-facing calls.
//! ```no_run
//! # use osis::{Config, Osis, Runtime, HostAddr, SyncScope};
//! # async fn demo() -> osis::Result<()> {
//! let mut cfg = Config::memory();
//! cfg.runtime = Runtime::Own;
//! cfg.hosts = vec!["quic://example.org:4433#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse()?];
//! let (db, card) = Osis::create(cfg.clone())?;
//! db.wait_synced(SyncScope::All, std::time::Duration::from_secs(10)).await?;
//! // on a fresh device: the same person from the card
//! let again = Osis::restore(Config { store: osis::StoreAt::Memory(osis::MemStore::new()), ..cfg }, &card.unwrap()).await?;
//! assert_eq!(again.me(), db.me());
//! # Ok(()) }
//! ```
//! ```
//! # use osis::{Config, Osis, SyncState};
//! let (db, card) = Osis::create(Config::memory())?;
//! assert!(card.is_none(), "no hosts: nothing to restore from");
//! assert_eq!(db.status()?.groups[&db.me()].state, SyncState::NoHosts);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Pairing a device
//! Transport-agnostic: the app carries the offer to the new device, its request back, and the
//! reply to it (QR, clipboard, a local socket).
//! ```
//! # use osis::{Config, Osis};
//! let phone = Osis::create(Config::memory())?.0;
//! let offer = phone.pair_offer()?;
//! let joining = Osis::pair(Config::memory(), &offer)?;
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
//! # use osis::{Config, GrantOpts, Osis, Role, LinkOpts, HostAddr, Value};
//! // a link names hosts (or is direct, `LinkOpts::direct`)
//! let db = Osis::create(Config::memory())?.0;
//! db.add_host(&HostAddr::new("quic://example.org:4433", [7; 32]))?;
//! let mut w = db.write();
//! let g = w.create()?;
//! w.at(g, osis::core::NAME).set(&"Trip".to_string())?;
//! w.commit()?;
//! db.sync(g, &[])?;
//! let link = db.make_link(g, Role::Write, LinkOpts { until: None, single_use: true, direct: false })?;
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
//! # use osis::{Config, Osis, Ak, Value};
//! let db = Osis::create(Config::memory())?.0;
//! let mut w = db.write();
//! let t = w.create()?;
//! w.commit()?;
//! let ring = Ak::new("app:ring.0*").unwrap();
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
//! # use osis::{Config, Osis, Ak, p};
//! # use std::io::Read;
//! let db = Osis::create(Config::memory())?.0;
//! let k = Ak::new("app:body.0").unwrap();
//! let mut w = db.write();
//! let t = w.create()?;
//! w.at(t, k.clone()).path(p![]).set_stream(&b"some bytes"[..])?;
//! w.commit()?;
//! let mut s = String::new();
//! db.at(t, k.clone()).path(p![]).stream()?.unwrap().read_to_string(&mut s).unwrap();
//! assert_eq!(s, "some bytes");
//! let title = Ak::new("app:title.0").unwrap();
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
//! # use osis::{Config, Osis, Error};
//! let a = Osis::create(Config::memory())?.0;
//! let b = Osis::create(Config::memory())?.0;
//! let mut w = a.write();
//! w.at(b.me(), osis::Ak::new("app:x.0").unwrap()).set(&osis::Value::Int(1))?;
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
//! let db = osis::Osis::create(osis::Config::memory()).unwrap().0;
//! db.on_diagnostic(|_, _| {}).unwrap();
//! ```
//! - A forgotten commit: `Write` is `#[must_use]`:
//! ```compile_fail
//! #![deny(unused_must_use)]
//! let db = osis::Osis::create(osis::Config::memory()).unwrap().0;
//! db.write();
//! ```
#![forbid(unsafe_code)]

mod clients;
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
pub use hosting::{Admit, HostCaps, Hosting, LabelId};
pub use handle::{Close, Config, DEFAULT_IDLE_COMMIT, DEFAULT_WAIT, DEFAULT_LIMIT, MemStore, Osis, StoreAt, WeakOsis};
pub use net::{GroupPolicy, Runtime, Transport};
pub use person::{Joining, OFFER_LIFETIME_MS, PairOffer, PairReply, PairRequest};
pub use keep::{KeepAlive, REFRESH_DIVISOR};
pub use keys::{Key, core};
pub use large::ValueStream;
pub use read::{AspectRef, Grant, Grants, GroupsOf, PathRef, Stamp};
pub use share::{ContactCard, Device, GrantOpts, GroupSync, Holder, HostAddr, InviteId, LinkId, LinkInfo, LinkOpts, Member, PRESYNC_WAIT, RecoveryCard, SetRoleOpts, ShareLink, Status, SyncFirst, SyncScope, SyncState};
pub use sources::{GroupSource, RemoteConfig, RemoteStatus};
pub use text::{Splice, TextSession};
pub use commits::{CommitEntry, CommitKind, CommitQuery, DropReason, Next, Scope};
pub use history::{HISTORY_PAGE, HistoryBody, HistoryEntry, HistoryEvent, HistoryFrom, HistoryPage, HistoryPos};
pub use watch::{Change, CommitInfo, Dispatcher, Source, Subscription};
pub use write::{AspectWrite, Committed, ExpiringGroupWrite, Expiry, GroupWrite, PathWrite, Purge, SpliceItems, Write};

/// Keep at least this, as an absolute time: for good (`Retention.at_least.abs`).
pub use osis_commit::FOREVER;
pub use osis_base::{Ak, Clock, CommitId, CreationRecord, ManualClock, Role, Tid, Ts, Value, ValueMap, ValueSet, WallMs};
pub use osis_node::{Cause, ChangeId, Diagnostic, DiagnosticKind, EphemeralId};
pub use osis_schema::{Aspect, AspectKey, CaseId, Codec, FieldId, Path, PathError, Lifetime, Retention, Schema, Step, p};

/// The schema layer, for generated code (`use osis::schema as osis_schema;`).
pub use osis_schema as schema;
