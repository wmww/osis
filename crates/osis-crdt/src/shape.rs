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
}
