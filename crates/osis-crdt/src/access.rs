//! Read-only views into fragments for the node (perm adapts `/members` entries into edge
//! writes, spec/permissions.md §5.1): map entries with their keys and fragments.

use crate::fragment::{Fragment, Map};
use crate::stamp::{Dot, Stamp};
use osis_core::Value;

impl Map {
    /// Entries by dot: (dot, entry reset, key if carried, fragment if carried).
    pub fn entries(&self) -> impl Iterator<Item = (&Dot, Option<&Stamp>, Option<&Value>, Option<&Fragment>)> {
        self.entries.iter().map(|(d, e)| (d, e.reset.as_ref(), e.key.as_ref(), e.frag.as_deref()))
    }
}
