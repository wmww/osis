//! Delta shape checks for writers' rules on typed aspects (spec/permissions.md §3).

use crate::fragment::{Fragment, Slots};
use crate::seq::{Anchor, Seq, SeqContent};
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
    /// The sequence elements a copy of this state needs to place what it shows (spec/crdt.md
    /// §6): every element it shows, and every element their creation and position writes
    /// anchor at, transitively (a creation chain's earlier elements included).
    pub fn shown(&self) -> Shown {
        let mut recs = BTreeMap::new();
        let mut work = Vec::new();
        self.walk_seqs(&mut |s| {
            for (d, e) in s.elems() {
                let anchors: Vec<Dot> = e.created.iter().chain(e.pos.iter()).filter_map(|(_, a)| if let Anchor::Dot(x) = a { Some(x.clone()) } else { None }).collect();
                let shown = crate::seq::is_visible(e, s.text);
                if shown {
                    work.extend(anchors.iter().cloned());
                }
                recs.insert(d.clone(), Rec { span: e.span, shown, chain: e.created.is_some(), anchors, prefix: if shown { e.span } else { 0 }, single: BTreeSet::new() });
            }
        });
        let mut out = Shown { recs };
        while let Some(x) = work.pop() {
            let Some((d, r)) = out.find_mut(&x) else { continue };
            let j = x.ctr - d.ctr;
            if r.chain {
                if r.prefix > j {
                    continue;
                }
                let first = r.prefix == 0;
                r.prefix = j + 1;
                if first {
                    work.extend(r.anchors.iter().cloned());
                }
            } else if r.single.insert(j) && j == 0 {
                work.extend(r.anchors.iter().cloned());
            }
        }
        out
    }

    /// Drops the sequence elements `shown` (of the importer's state) does not need, and the
    /// content of those it keeps only as anchors (not shown there): an import carries no
    /// element nothing it shows depends on, and no erased content (spec/permissions.md §7).
    pub fn keep_shown(&mut self, shown: &Shown) {
        self.seqs_mut(&mut |s| {
            if s.elems().iter().all(|(d, e)| shown.all_kept(d, e.span, !matches!(e.content, SeqContent::None))) {
                return;
            }
            let old = std::mem::take(s.elems_mut());
            let mut out = BTreeMap::new();
            for (d, e) in old {
                let mut off = 0;
                while off < e.span {
                    let (keep, len, hidden) = shown.stretch(&crate::seq_span::nth(&d, off), e.span - off);
                    if keep {
                        let (x, mut y) = crate::seq_span::piece(&d, &e, off, len);
                        if hidden {
                            y.content = SeqContent::None;
                        }
                        out.insert(x, y);
                    }
                    off += len;
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
}

/// A state record for `Fragment::shown`.
struct Rec {
    span: u64,
    /// The state shows it (one element).
    shown: bool,
    /// A creation chain: element `j > 0` anchors at element `j - 1`.
    chain: bool,
    /// The first element's anchors.
    anchors: Vec<Dot>,
    /// Chain: the needed prefix length (all of it for a shown element).
    prefix: u64,
    /// Not a chain: the needed offsets.
    single: BTreeSet<u64>,
}

/// The elements of a state a copy needs (`Fragment::shown`).
pub struct Shown {
    recs: BTreeMap<Dot, Rec>,
}

impl Shown {
    fn find_mut(&mut self, x: &Dot) -> Option<(&Dot, &mut Rec)> {
        let (d, r) = self.recs.range_mut(..=x).next_back()?;
        crate::seq_span::holds(d, r.span, x).then_some((d, r))
    }

    fn find(&self, x: &Dot) -> Option<(&Dot, &Rec)> {
        let (d, r) = self.recs.range(..=x).next_back()?;
        crate::seq_span::holds(d, r.span, x).then_some((d, r))
    }

    /// From element `x`, at most `max` elements: whether they are kept, how many share that,
    /// and whether they are kept only as anchors (not shown).
    fn stretch(&self, x: &Dot, max: u64) -> (bool, u64, bool) {
        let Some((d, r)) = self.find(x) else {
            // not in the state: not needed, up to the next record
            let next = self.recs.range(x.clone()..).next().filter(|(d, _)| d.src == x.src).map_or(max, |(d, _)| d.ctr - x.ctr);
            return (false, next.clamp(1, max), true);
        };
        let j = x.ctr - d.ctr;
        let rest = (r.span - j).min(max);
        if r.chain {
            return if j < r.prefix { (true, (r.prefix - j).min(rest), !r.shown) } else { (false, rest, true) };
        }
        let keep = r.single.contains(&j);
        let len = (j + 1..j + rest).take_while(|k| r.single.contains(k) == keep).count() as u64 + 1;
        (keep, len, !r.shown)
    }

    /// Whether record `(d, span)` stays as it is: every element kept, and its content (`content`)
    /// shown.
    fn all_kept(&self, d: &Dot, span: u64, content: bool) -> bool {
        let (keep, len, hidden) = self.stretch(d, span);
        keep && len == span && !(content && hidden)
    }
}
