//! Delta shape checks for writers' rules on typed aspects (spec/permissions.md §3).

use crate::fragment::{Fragment, Slots};

impl Fragment {
    /// A struct fragment with no root reset (alone or as the only member of its slots): it
    /// writes fields only, never the whole value.
    pub fn is_plain_struct(&self) -> bool {
        match self {
            Fragment::Struct(s) => s.meta.reset.is_none(),
            Fragment::Slots(Slots { reg: None, members }) => members.len() == 1 && members.values().all(Fragment::is_plain_struct),
            _ => false,
        }
    }

    /// A map fragment holding only new keyed entries (puts, §5.6): no reset of the map or of any
    /// entry and no write into an entry it does not create. Checkable from the delta alone.
    pub fn is_put_only_map(&self) -> bool {
        match self {
            Fragment::Map(m) => m.meta.reset.is_none() && m.entries.values().all(|e| e.reset.is_none() && e.key.is_some() && e.frag.is_some()),
            Fragment::Slots(Slots { reg: None, members }) => members.len() == 1 && members.values().all(Fragment::is_put_only_map),
            _ => false,
        }
    }
}
