//! osis: the public API, the only crate apps depend on. A synchronous local data API over the
//! node engine: typed aspect keys, reads with paths and a materialization bound, RAII watches
//! on one dispatcher thread, the `Write` batch, undo and history, signals, diagnostics, one
//! `Error`. Layer 8 (notes/architecture.md). Design: notes/api.md.
//!
//! # Open a database
//! The owner of a new thing is always explicit; `me()` is the usual owner. Placement is a group
//! op in the same batch. A new thing lives in memory until its first durable write.
//! ```
//! use osis::{Config, Osis};
//! let db = Osis::create(Config::memory())?.0;
//! let mut w = db.write();
//! let note = w.create(db.me())?;
//! w.place(note, db.home())?;
//! w.commit()?;
//! assert!(db.groups_of(note).item_of.contains(&db.home()));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Keys and reads
//! Generated keys (`Aspect<T>`) read and write typed values; an `Ak` is the untyped key. An
//! absent aspect reads as `None`.
//! ```
//! # use osis::{Config, Osis, Ak, Value};
//! # let db = Osis::create(Config::memory())?.0;
//! let title = Ak::new("/note/title").unwrap();
//! let t = db.write_with(|w| {
//!     let t = w.create(db.me())?;
//!     w.at(t, title.clone()).set(&Value::Str("Groceries".into()))?;
//!     Ok(t)
//! })?;
//! assert_eq!(db.get(t, title.clone())?, Some(Value::Str("Groceries".into())));
//! assert_eq!(db.get(t, Ak::new("/note/other").unwrap())?, None);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Paths
//! `at(tid, key).path(p![..])` reads or writes one position; only that position is
//! materialized.
//! ```
//! # use osis::{Config, Osis, Ak, Value, p};
//! # let db = Osis::create(Config::memory())?.0;
//! let tags = Ak::new("/note/tags").unwrap();
//! let mut w = db.write();
//! let t = w.create(db.me())?;
//! w.at(t, tags.clone()).path(p![]).put(&"color".to_string(), &"red".to_string())?;
//! w.commit()?;
//! let c: Option<String> = db.at(t, tags).path(p!["color"]).get()?;
//! assert_eq!(c.as_deref(), Some("red"));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Edit, not set, for what users edit
//! `set` makes the value equal to what you pass (fields you did not touch are written back);
//! `edit(base, new)` writes only what the user changed since `base`, so a concurrent change to
//! another field survives.
//! ```
//! # use osis::{Config, Osis, Ak, Value};
//! # use std::collections::BTreeMap;
//! # let db = Osis::create(Config::memory())?.0;
//! let form = Ak::new("/app/form").unwrap();
//! let shown = Value::Map(BTreeMap::from([(Value::Int(0), Value::Str("a".into())), (Value::Int(1), Value::Int(1))]));
//! let mut w = db.write();
//! let t = w.create(db.me())?;
//! w.at(t, form.clone()).set(&shown)?;
//! w.commit()?;
//! let mut edited = shown.clone();
//! if let Value::Map(m) = &mut edited { m.insert(Value::Int(1), Value::Int(2)); }
//! db.write_with(|w| w.at(t, form.clone()).edit(&shown, &edited))?;
//! assert_eq!(db.get(t, form)?, Some(edited));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Watching
//! Callbacks run on one dispatcher thread, after the commit is durable, never under a lock;
//! dropping the `Subscription` unsubscribes. `on_change` first delivers the current value.
//! ```
//! # use osis::{Config, Osis, Ak, Value, Source};
//! # let db = Osis::create(Config::memory())?.0;
//! let k = Ak::new("/app/count").unwrap();
//! let mut w = db.write();
//! let t = w.create(db.me())?;
//! w.commit()?;
//! let (tx, rx) = std::sync::mpsc::channel();
//! let sub = db.at(t, k.clone()).on_change(move |_db, c| { let _ = tx.send(c); })?;
//! db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(1)))?;
//! assert_eq!(rx.recv().unwrap().source, Source::Initial);
//! let c = rx.recv().unwrap();
//! assert!(matches!(c.source, Source::Local(_)));
//! assert_eq!(c.value, Ok(Some(Value::Int(1))));
//! drop(sub);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Commits, undo, redo, revert
//! `commits` queries the held commits (anyone's); undo and redo revert this actor's own
//! newest change or undo in a scope; `revert` reverts any commit.
//! ```
//! # use osis::{Config, Osis, Ak, Value, Scope, CommitQuery, CommitKind};
//! # let db = Osis::create(Config::memory())?.0;
//! let k = Ak::new("/app/x").unwrap();
//! let mut w = db.write();
//! let t = w.create(db.me())?;
//! w.at(t, k.clone()).set(&Value::Int(1))?;
//! w.commit()?;
//! db.write_with(|w| w.at(t, k.clone()).set(&Value::Int(2)))?;
//! let u = db.undo(&Scope::Thing(t))?.unwrap();
//! assert_eq!(db.get(t, k.clone())?, Some(Value::Int(1)));
//! let undos = db.commits(&CommitQuery::new().scope(Scope::Thing(t)).kind(CommitKind::Revert))?;
//! assert_eq!(undos[0].commit.id, u.id);
//! db.redo(&Scope::Thing(t))?;
//! assert_eq!(db.get(t, k)?, Some(Value::Int(2)));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Sync, servers and the recovery card
//! `create` makes a person (owned by a recovery key) whose home group is synced on
//! `Config.servers`; it returns the recovery card, the only copy of that key. Sync runs on a
//! runtime (`Runtime::Own`, or the app's tokio handle); without one everything works locally.
//! Status, waiting until synced and restoring from the card are the network-facing calls.
//! ```no_run
//! # use osis::{Config, Osis, Runtime, ServerAddr, SyncScope};
//! # async fn demo() -> osis::Result<()> {
//! let mut cfg = Config::memory();
//! cfg.runtime = Runtime::Own;
//! cfg.servers = vec!["quic://example.org:4433#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse()?];
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
//! assert!(card.is_none(), "no servers: nothing to restore from");
//! assert_eq!(db.status()?.groups[&db.home()].state, SyncState::NoServers);
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
//! Grants need the member's keys (a contact card, a shared group); links need nothing. Things a
//! group owns are what its members read: create shared things with the group as owner.
//! ```
//! # use osis::{Config, Osis, Role, LinkOpts, ServerAddr};
//! // a link names servers (or is direct, `LinkOpts::direct`)
//! let mut cfg = Config::memory();
//! cfg.servers = vec![ServerAddr::new("quic://example.org:4433", [7; 32])];
//! let db = Osis::create(cfg)?.0;
//! let mut w = db.write();
//! let g = w.create(db.me())?;
//! w.make_group(g)?;
//! w.commit()?;
//! db.sync(g, &[])?;
//! let link = db.make_link(g, Role::Write, LinkOpts { until: None, single_use: true, direct: false })?;
//! assert!(link.to_string().starts_with("osis://link/"));
//! assert_eq!(db.links(g).len(), 1);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Signals
//! A `signal` aspect holds nothing: each set fires every callback on it once, here and on the
//! devices connected now that read the thing.
//! ```
//! # use osis::{Config, Osis, Ak, Value, Lifetimes};
//! let db = Osis::create(Config::memory())?.0;
//! let t = db.write_with(|w| w.create(db.me()))?;
//! let ring = Ak::new("/app/ring").unwrap().signal();
//! let (tx, rx) = std::sync::mpsc::channel();
//! let _sub = db.at(t, ring.clone()).on_change(move |_, c| { let _ = tx.send(c.value); })?;
//! assert_eq!(rx.recv().unwrap(), Ok(None));
//! db.write_with(|w| w.at(t, ring.clone()).set(&Value::Bool(true)))?;
//! assert_eq!(rx.recv().unwrap(), Ok(Some(Value::Bool(true))));
//! assert_eq!(db.get(t, ring)?, None);
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Large values and text sessions
//! A string or blob above the bound streams; text edited by a user goes through a session that
//! commits once per pause.
//! ```
//! # use osis::{Config, Osis, Ak, Path};
//! # use std::io::Read;
//! let db = Osis::create(Config::memory())?.0;
//! let k = Ak::new("/app/body").unwrap();
//! let mut w = db.write();
//! let t = w.create(db.me())?;
//! w.at(t, k.clone()).set_stream(&b"some bytes"[..])?;
//! w.commit()?;
//! let mut s = String::new();
//! db.at(t, k.clone()).stream()?.unwrap().read_to_string(&mut s).unwrap();
//! assert_eq!(s, "some bytes");
//! let title = Ak::new("/app/title").unwrap();
//! let ed = db.edit_text(t, title.clone(), Path::root())?;
//! ed.insert(0, "Hello")?;
//! ed.insert(5, " world")?;
//! ed.commit()?; // one commit for the whole pause
//! assert_eq!(db.get(t, title)?, Some(osis::Value::Str("Hello world".into())));
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
//! assert!(matches!(w.create(b.me()), Err(Error::UnknownThing { .. })));
//! # Ok::<(), osis::Error>(())
//! ```
//!
//! # Footguns closed
//! - Read-modify-write clobber: use `edit(base, new)` or path ops for what users edit; `set`
//!   is for "must be exactly this".
//! - Out of memory on a huge value: reads fail `TooLarge` past `Config::materialize_limit`;
//!   read by path instead.
//! - A thing that never syncs, or owned by the device: the owner is always explicit, placement a group op (`NotSynced` diagnostic).
//! - A forgotten unsubscribe: `Subscription` is RAII, and dropping it at once is a lint:
//! ```compile_fail
//! #![deny(unused_must_use)]
//! let db = osis::Osis::create(osis::Config::memory()).unwrap().0;
//! db.on_diagnostic(|_, _| {});
//! ```
//! - A forgotten commit: `Write` is `#[must_use]`:
//! ```compile_fail
//! #![deny(unused_must_use)]
//! let db = osis::Osis::create(osis::Config::memory()).unwrap().0;
//! db.write();
//! ```
#![forbid(unsafe_code)]

mod error;
mod handle;
mod keys;
mod large;
mod net;
mod person;
mod read;
mod share;
mod text;
mod commits;
mod watch;
mod write;

pub use error::{Error, Result};
pub use handle::{CLOSE_WAIT, Config, DEFAULT_IDLE_COMMIT, DEFAULT_WAIT, DEFAULT_LIMIT, MemStore, Osis, StoreAt, WeakOsis};
pub use net::{GroupPolicy, ManualNet, Runtime, Transport};
pub use person::{Joining, OFFER_LIFETIME_MS, PairOffer, PairReply, PairRequest};
pub use keys::{Key, core};
pub use large::ValueStream;
pub use read::{AspectRef, Created, Edge, GroupsOf, PathRef, Reader, Roster};
pub use share::{ContactCard, Demotion, Device, EdgeOpts, GroupSync, LinkInfo, LinkOpts, Lower, PRESYNC_WAIT, RecoveryCard, ServerAddr, ShareLink, Status, SyncScope, SyncState, WaitForSync};
pub use text::TextSession;
pub use commits::{CommitEntry, CommitKind, CommitQuery, DropReason, Scope};
pub use watch::{Change, Changed, CommitInfo, Source, Subscription, Watch};
pub use write::{AspectWrite, Committed, PathWrite, Write};

pub use osis_base::{Ak, Clock, CommitId, CreationRecord, ManualClock, Role, Tid, Ts, Value, WallMs};
pub use osis_node::{Cause, ChangeId, Diagnostic, DiagnosticKind, EphemeralId};
pub use osis_schema::{Aspect, AspectKey, CaseId, Codec, FieldId, Path, PathError, Lifetime, Lifetimes, Retention, Schema, Step, Untyped, p};

/// The schema layer, for generated code (`use osis::schema as osis_schema;`).
pub use osis_schema as schema;
/// The engine, for inspection (CLI) and tests only.
#[doc(hidden)]
pub use osis_node as node;
