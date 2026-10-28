//! Read-only views into fragments for the node (perm adapts `/members` entries into edge
//! writes, spec/permissions.md §5.1): map entries with their keys and fragments.

use crate::fragment::{Fragment, Map};
use crate::state::MemberRef;
use crate::stamp::{Dot, Stamp};
use osis_base::Value;

impl Map {
    /// Entries by dot: (dot, entry reset, key if carried, fragment if carried).
    pub fn entries(&self) -> impl Iterator<Item = (&Dot, Option<&Stamp>, Option<&Value>, Option<&Fragment>)> {
        self.entries.iter().map(|(d, e)| (d, e.reset.as_ref(), e.key.as_ref(), e.frag.as_deref()))
    }

    /// The live entries of key `k` by dot (O(log n + their number)).
    pub fn live(&self, k: &Value) -> Vec<(&Dot, &Fragment)> {
        self.live_dots(k).into_iter().filter_map(|d| Some((d, self.entries.get(d)?.frag.as_deref()?))).collect()
    }
}

impl crate::fragment::Struct {
    /// A field's fragment.
    pub fn field(&self, id: u64) -> Option<&Fragment> {
        self.fields.get(&id)
    }
}

impl Fragment {
    /// The position at `path` as a read sees it: a struct field, the current case's payload, what
    /// a map key reads as (its live entries joined, §5.6), a list element by index. Only that
    /// position is copied; a key costs O(log n).
    pub fn at(&self, path: &[crate::ops::PathSeg]) -> Option<Fragment> {
        use crate::ops::PathSeg;
        let Some((seg, rest)) = path.split_first() else { return Some(self.clone()) };
        let MemberRef::Frag(f) = self.chosen_member() else { return None };
        match (seg, f) {
            (PathSeg::Field(id), Fragment::Struct(s)) => s.fields.get(id)?.at(rest),
            (PathSeg::Case(id), Fragment::Enum(e)) if e.case.as_ref().and_then(|c| c.case) == Some(*id) => e.payloads.get(id)?.at(rest),
            (PathSeg::Key(k), Fragment::Map(m)) => match m.live_dots(k).as_slice() {
                // one live entry: read in place
                [d] => m.entries.get(*d)?.frag.as_deref()?.at(rest),
                ds => crate::ops::key_state(m, ds)?.at(rest),
            },
            (PathSeg::Index(i), Fragment::Seq(s)) => crate::seq::element_at(s, *i)?.1?.at(rest),
            _ => None,
        }
    }
}
