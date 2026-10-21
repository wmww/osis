//! Delta shape checks for writers' rules on typed aspects (spec/permissions.md §3).

use crate::fragment::{Fragment, Slots};
use crate::stamp::Dot;

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

    /// Whether the fragment carries its own reset (a register's or a composite's).
    pub fn has_reset(&self) -> bool {
        match self {
            Fragment::Register(r) => r.reset.is_some(),
            Fragment::Slots(Slots { reg, members }) => reg.as_ref().is_some_and(|r| r.reset.is_some()) || members.values().any(Fragment::has_reset),
            f => f.meta().is_some_and(|m| m.reset.is_some()),
        }
    }

    /// A map fragment holding only new keyed entries (puts, §5.6): no reset of the map or of any
    /// entry, and every entry's dot is one this delta creates (`own`: its source and counter
    /// range), so no write goes into an existing entry. Checkable from the delta alone.
    pub fn is_put_only_map(&self, own: &dyn Fn(&Dot) -> bool) -> bool {
        match self {
            Fragment::Map(m) => m.meta.reset.is_none() && m.entries.iter().all(|(d, e)| own(d) && e.reset.is_none() && e.key.is_some() && e.frag.is_some()),
            Fragment::Slots(Slots { reg: None, members }) => members.len() == 1 && members.values().all(|f| f.is_put_only_map(own)),
            _ => false,
        }
    }
}
