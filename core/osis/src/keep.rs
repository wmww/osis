//! Values that live while their author is there (notes/ephemeral.md Values that live while
//! their author is there): an ephemeral aspect with a default expiry, rewritten by its author
//! before each write expires, on the runtime that runs sync.

use crate::error::{Error, Result};
use crate::handle::WeakOsis;
use crate::read::{AspectRef, PathRef};
use osis_base::{Tid, Value};
use osis_schema::{Codec, Path, ValueKey};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// A value its author keeps alive (`PathRef::keep_alive`): rewritten until this is dropped.
#[derive(Debug)]
pub struct KeepAlive {
    alive: Arc<AtomicBool>,
}

impl Drop for KeepAlive {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
    }
}

/// One rewrite, then the next one scheduled, while `alive`.
fn renew<K: ValueKey + Clone + Send + Sync + 'static>(db: WeakOsis, alive: Arc<AtomicBool>, tid: Tid, key: K, path: Path, v: Value, every: Duration) {
    let Some(h) = db.hold() else { return };
    let again = (db.clone(), alive.clone(), key.clone(), path.clone(), v.clone());
    h.inner.after(
        every,
        Box::new(move || {
            let (db, alive, key, path, v) = again;
            if !alive.load(Ordering::Acquire) {
                return;
            }
            let Some(h) = db.hold() else { return };
            let mut w = h.write();
            // an overwrite: a `set` of the value it reads writes nothing, and the value would
            // expire; a failed rewrite is told as any write's (diagnostics), the next one tries again
            let _ = w.at(tid, key.clone()).path(path.clone()).overwrite(&v).and_then(|()| w.commit().map(drop));
            drop(h);
            renew(db, alive, tid, key, path, v, every);
        }),
    );
}

impl<K: ValueKey + Clone + Send + Sync + 'static> PathRef<'_, '_, K> {
    /// Writes `value` here (a map key, such as this node's key `node()` in a cursor map, or a
    /// register position) and writes it again every half of the key's default expiry while the
    /// returned `KeepAlive` lives. The key must be ephemeral (`+`) with a default expiry
    /// (`Invalid` otherwise); the rewrites need a runtime (`Network` without one).
    pub fn keep_alive<U: Codec>(&self, value: &U) -> Result<KeepAlive> {
        let (db, tid, key, path) = self.parts();
        db.local_at(tid, "keep_alive")?;
        let Some(exp) = key.defaults().expires.filter(|_| key.ephemeral()) else {
            return Err(Error::Invalid(format!("{} is not an ephemeral key with a default expiry", key.ak())));
        };
        if !db.inner.timers {
            return Err(Error::Network("keep_alive needs a runtime (Config.runtime)".into()));
        }
        let v = value.to_value();
        let mut w = db.write();
        w.at(tid, key.clone()).path(path.clone()).overwrite(&v)?;
        w.commit()?;
        let alive = Arc::new(AtomicBool::new(true));
        renew(db.downgrade(), alive.clone(), tid, key.clone(), path.clone(), v, Duration::from_millis((exp / 2).max(1)));
        Ok(KeepAlive { alive })
    }
}

impl<K: ValueKey + Clone + Send + Sync + 'static> AspectRef<'_, K> {
    /// The same as `path(Path::root()).keep_alive(value)`, but for checking `value`'s type at
    /// compile time.
    pub fn keep_alive(&self, value: &K::T) -> Result<KeepAlive> {
        self.path(Path::root()).keep_alive(&self.key.encode(value))
    }
}
