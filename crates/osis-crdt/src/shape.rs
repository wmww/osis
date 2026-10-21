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

    /// Whether a sequence anywhere in it holds a bare anchor (a record whose writes were all
    /// pruned, §5.7): only snapshots may carry one (§3.3 rule 7).
    pub fn has_bare_anchors(&self) -> bool {
        use crate::seq::SeqContent;
        match self {
            Fragment::Seq(s) => s.elems().values().any(|e| {
                (e.created.is_none() && matches!(e.content, SeqContent::None) && e.pos.is_empty() && e.deleted.is_none()) || matches!(&e.content, SeqContent::Frag(f) if f.has_bare_anchors())
            }),
            Fragment::Struct(s) => s.fields.values().any(Fragment::has_bare_anchors),
            Fragment::Enum(e) => e.payloads.values().any(Fragment::has_bare_anchors),
            Fragment::Map(m) => m.entries.values().any(|e| e.frag.as_deref().is_some_and(Fragment::has_bare_anchors)),
            Fragment::Slots(Slots { members, .. }) => members.values().any(Fragment::has_bare_anchors),
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
