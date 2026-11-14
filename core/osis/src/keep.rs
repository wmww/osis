//! Values that live while their author is there (notes/ephemeral.md Values that live while
//! their author is there): an ephemeral aspect with a default expiry, rewritten by its author
//! before each write expires, on the runtime that runs sync. Sync is not built yet, so
//! `keep_alive` fails `NotBuilt`.

use crate::error::{Error, Result};
use crate::read::{AspectRef, PathRef};
use osis_schema::{Codec, Path, ValueKey};

/// A value its author keeps alive (`PathRef::keep_alive`): rewritten until this is dropped.
#[derive(Debug)]
pub struct KeepAlive {
    _private: (),
}

impl<K: ValueKey> PathRef<'_, '_, K> {
    /// Writes `value` here (a map key, such as this node's key `node()` in a cursor map, or a
    /// register position) and writes it again every half of the key's default expiry while the
    /// returned `KeepAlive` lives. The key must be ephemeral (`+`) with a default expiry
    /// (`Invalid` otherwise). `NotBuilt`.
    pub fn keep_alive<U: Codec>(&self, _value: &U) -> Result<KeepAlive> {
        let (_, _, key, _) = self.parts();
        if key.defaults().expires.is_none() || !key.ephemeral() {
            return Err(Error::Invalid(format!("{} is not an ephemeral key with a default expiry", key.ak())));
        }
        Err(Error::NotBuilt)
    }
}

impl<K: ValueKey> AspectRef<'_, K> {
    /// The same as `path(Path::root()).keep_alive(value)`, but for checking `value`'s type at
    /// compile time.
    pub fn keep_alive(&self, value: &K::T) -> Result<KeepAlive> {
        self.path(Path::root()).keep_alive(&self.key.encode(value))
    }
}
