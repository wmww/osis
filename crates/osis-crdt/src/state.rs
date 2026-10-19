//! Join, prune, presence and read over fragments (spec/crdt.md §4, §5, §7). Filled by
//! plans/crdt-core.md step 2; the signatures are the recursion points sequences use.

use crate::changes::Changes;
use crate::fragment::Fragment;
use crate::stamp::Stamp;
use osis_core::Value;

impl Fragment {
    /// Joins `other` (any encoding) into `self` under the parent's effective reset `e_parent`
    /// (§4.1, §4.2, §7), touching only what `other` carries and what a raised reset prunes.
    pub fn join_into(&mut self, _other: Fragment, _e_parent: Option<&Stamp>, _ch: &mut Changes) {}

    /// Drops every write below the effective reset `max(e_parent, own reset)` (§4.2).
    pub fn prune(&mut self, _e_parent: Option<&Stamp>, _ch: &mut Changes) {}

    /// Presence stamp `written` (§4.3).
    pub fn written(&self) -> Option<Stamp> {
        None
    }

    /// Present iff `written` survives (§4.3).
    pub fn present(&self) -> bool {
        self.written().is_some()
    }

    /// No surviving write and no record at any depth (§4.2 Emptiness).
    pub fn is_empty(&self) -> bool {
        true
    }

    /// The read (§4.4, §5); `None` is absent.
    pub fn read(&self) -> Option<Value> {
        None
    }
}
