//! Values that live while their author is there (notes/ephemeral.md Values that live while
//! their author is there): an ephemeral aspect with a default expiry, rewritten by its author
//! before each write expires. When the author's device goes away the rewrites stop and the
//! value expires everywhere by its last write's expiry; nobody needs to notice the departure.

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::read::ak_of;
use crate::watch::lock;
use osis_base::{Tid, Value};
use osis_schema::{AspectKey, Codec, Path};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

/// A kept-alive value is rewritten every `1 / REFRESH_DIVISOR` of its key's default expiry.
/// Minor consequence: the rest of the expiry is the slack a rewrite has to reach the holders
/// (upload, delivery, the nodes' clock differences) before the last write expires; past it the
/// value blinks off at a holder until the rewrite arrives. 1 (no slack): it blinks at every
/// refresh; infinity: a write per moment. Each rewrite supersedes the one before (spec/sync.md
/// §9), so holders and hosts keep about one write per kept value.
pub const REFRESH_DIVISOR: u32 = 2;

struct Kept {
    tid: Tid,
    key: crate::Key,
    path: Path,
    value: Value,
    /// Writes made (tests).
    writes: u64,
}

/// A value its author keeps alive (`Osis::keep_alive`): rewritten until this is dropped.
pub struct KeepAlive {
    db: Osis,
    st: Arc<Mutex<Kept>>,
}

impl std::fmt::Debug for KeepAlive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = lock(&self.st);
        write!(f, "KeepAlive({} {})", s.tid, s.key.ak)
    }
}

/// Validates `v` at `path` of `key` against its schema (untyped keys: anything).
fn check<K: AspectKey>(key: &K, path: &Path, v: &Value) -> Result<()> {
    let (Some(s), Some(ty)) = (key.schema(), key.ty()) else { return Ok(()) };
    let (t, _) = osis_schema::type_at(s, ty, path)?;
    osis_schema::validate_write(s, v, &t)?;
    Ok(())
}

/// Writes the value afresh: a new entry at a map key, a new register write elsewhere (so its
/// expiry starts over; a `set` of an equal value writes nothing).
fn write(db: &Osis, k: &mut Kept) -> Result<()> {
    let mut w = db.write();
    w.raw_op(k.tid, &k.key, osis_crdt::PathOp { path: crate::write::segs(&k.path)?, op: osis_crdt::Op::Put(k.value.clone()) })?;
    w.commit()?;
    k.writes += 1;
    Ok(())
}

/// Rewrites every `every` while the `KeepAlive` lives; a failed rewrite is reported and ends it.
fn arm(db: &Osis, st: Weak<Mutex<Kept>>, every: Duration) -> bool {
    let w = db.downgrade();
    db.inner.net.after(
        every,
        Box::new(move || {
            let (Some(db), Some(st)) = (w.hold(), st.upgrade()) else { return };
            let mut s = lock(&st);
            if let Err(e) = write(&db, &mut s) {
                let d = osis_node::Diagnostic { kind: osis_node::DiagnosticKind::Uncommitted, tids: vec![s.tid], commit: None, peer: None, detail: format!("kept-alive value not rewritten: {e}") };
                db.engine(|en| en.report(d));
                return;
            }
            drop(s);
            arm(&db, Arc::downgrade(&st), every);
        }),
    )
}

impl Osis {
    /// Writes `value` at `path` of an aspect (a map key, such as this device's key `node()` in a
    /// cursor map, or a register position) and rewrites it every half of the key's default
    /// expiry while the returned `KeepAlive` lives. Two devices keeping one path alive (a
    /// person's key) overwrite each other at every rewrite: key by device. The key must be
    /// ephemeral (`~`) with a default expiry (schema `[expires: ...]`) well above the
    /// network delay and the clock differences between nodes; the database needs its runtime (a
    /// `Config::transport`) for the timer. Nothing outlives the process: after a restart the app
    /// calls this again.
    pub fn keep_alive<K: AspectKey, U: Codec>(&self, tid: Tid, key: K, path: Path, value: &U) -> Result<KeepAlive> {
        if let crate::sources::Source::Remote(_) = self.route(tid) {
            return Err(Error::Unsupported("keep_alive through the attached node".into()));
        }
        let d = key.defaults();
        let Some(exp) = d.expires.filter(|_| key.lifetime() == osis_schema::Lifetime::Ephemeral) else {
            return Err(Error::Invalid(format!("{} is not an ephemeral key with a default expiry", key.ak())));
        };
        let value = value.to_value();
        check(&key, &path, &value)?;
        let key = crate::Key { ak: ak_of(&key)?, schema: key.schema().map(|s| Arc::new(s.clone())) };
        let mut k = Kept { tid, key, path, value, writes: 0 };
        write(self, &mut k)?;
        let st = Arc::new(Mutex::new(k));
        let every = Duration::from_millis((exp / u64::from(REFRESH_DIVISOR)).max(1));
        if !arm(self, Arc::downgrade(&st), every) {
            return Err(Error::Invalid("keep_alive needs the database's runtime".into()));
        }
        Ok(KeepAlive { db: self.clone(), st })
    }
}

impl KeepAlive {
    /// Writes `value` now (validated against the key's schema) and keeps that alive from now on.
    pub fn set<U: Codec>(&self, value: &U) -> Result<()> {
        let mut s = lock(&self.st);
        let v = value.to_value();
        check(&s.key, &s.path, &v)?;
        let old = std::mem::replace(&mut s.value, v);
        if let Err(e) = write(&self.db, &mut s) {
            s.value = old;
            return Err(e);
        }
        Ok(())
    }

    /// Writes made so far (tests).
    #[doc(hidden)]
    pub fn writes(&self) -> u64 {
        lock(&self.st).writes
    }
}
