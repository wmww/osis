//! Delta shape checks for writers' rules on typed aspects (spec/permissions.md §3).

use crate::fragment::{Fragment, Slots};
use crate::seq::{Anchor, Seq, SeqContent, SeqElem};
use crate::stamp::Dot;
use std::collections::{BTreeMap, BTreeSet};

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

impl Fragment {
    /// Every dot a sequence record anywhere in it anchors at (creation and position writes).
    pub fn anchors(&self) -> BTreeSet<Dot> {
        let mut out = BTreeSet::new();
        self.walk_seqs(&mut |s| {
            for e in s.elems().values() {
                for (_, a) in e.created.iter().chain(e.pos.iter()) {
                    if let Anchor::Dot(d) = a {
                        out.insert(d.clone());
                    }
                }
            }
        });
        out
    }

    /// Drops the bare anchors (records whose writes were all pruned, §5.7) whose dot is not in
    /// `keep`: an import carries only those its writes reference (spec/permissions.md §7).
    pub fn drop_bare_except(&mut self, keep: &BTreeSet<Dot>) {
        self.walk_seqs_mut(&mut |s| {
            let bare = |e: &SeqElem| e.created.is_none() && matches!(e.content, SeqContent::None) && e.pos.is_empty() && e.deleted.is_none();
            if !s.elems().values().any(bare) {
                return;
            }
            let old = std::mem::take(s.elems_mut());
            let mut out = BTreeMap::new();
            for (d, e) in old {
                if !bare(&e) {
                    out.insert(d, e);
                    continue;
                }
                let last = Dot::new(d.src.clone(), d.ctr.saturating_add(e.span - 1));
                for k in keep.range(d.clone()..=last) {
                    if k.src == d.src {
                        let (x, y) = crate::seq_span::piece(&d, &e, k.ctr - d.ctr, 1);
                        out.insert(x, y);
                    }
                }
            }
            *s.elems_mut() = out;
        });
    }

    fn walk_seqs(&self, f: &mut dyn FnMut(&Seq)) {
        match self {
            Fragment::Seq(s) => {
                f(s);
                for e in s.elems().values() {
                    if let SeqContent::Frag(x) = &e.content {
                        x.walk_seqs(f);
                    }
                }
            }
            Fragment::Struct(s) => s.fields.values().for_each(|x| x.walk_seqs(f)),
            Fragment::Enum(e) => e.payloads.values().for_each(|x| x.walk_seqs(f)),
            Fragment::Map(m) => m.entries.values().filter_map(|e| e.frag.as_deref()).for_each(|x| x.walk_seqs(f)),
            Fragment::Slots(Slots { members, .. }) => members.values().for_each(|x| x.walk_seqs(f)),
            _ => {}
        }
    }

    fn walk_seqs_mut(&mut self, f: &mut dyn FnMut(&mut Seq)) {
        match self {
            Fragment::Seq(s) => {
                f(s);
                if s.elems().values().any(|e| matches!(e.content, SeqContent::Frag(_))) {
                    for e in s.elems_mut().values_mut() {
                        if let SeqContent::Frag(x) = &mut e.content {
                            x.walk_seqs_mut(f);
                        }
                    }
                }
            }
            Fragment::Struct(s) => s.fields.values_mut().for_each(|x| x.walk_seqs_mut(f)),
            Fragment::Enum(e) => e.payloads.values_mut().for_each(|x| x.walk_seqs_mut(f)),
            Fragment::Map(m) => m.entries.values_mut().filter_map(|e| e.frag.as_deref_mut()).for_each(|x| x.walk_seqs_mut(f)),
            Fragment::Slots(Slots { members, .. }) => members.values_mut().for_each(|x| x.walk_seqs_mut(f)),
            _ => {}
        }
    }
}

