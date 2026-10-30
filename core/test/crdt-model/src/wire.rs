//! Wire encoding of fragments (spec §3): canonical CBOR items. A delta is self-contained:
//! `[nonce, Sources, Commits, Fragment]`, a snapshot adds `Frontiers`.
use crate::cbor::{self, Error, Item};
use crate::stamp::{Dot, Source, Stamp, Ts};
use crate::state::{Anchor, BagKind, Composite, Content, Elem, Entry, Frag, SeqElem};
use crate::value::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Runs never exceed this many elements (§3.3 rule 3).
pub const MAX_RUN: usize = 1 << 16;
/// A list run closes once its content reaches this many bytes (§3.3 rule 3; spec/wire.md `CHUNK_MAX`).
pub const CHUNK_MAX: usize = 256 * 1024;

/// What the commit header provides (§2.4) plus the delta's own tables (§3.2).
#[derive(Clone, Debug)]
pub struct Ctx {
    pub ts: Ts,
    pub own: Source,
    /// Start of the own counter range (header).
    pub lo: u64,
    /// End of the own counter range for a writer's delta: enables the range checks and the writer-only rules of
    /// §2.3 and §3.3 rule 7. `None` for snapshot and import deltas.
    pub hi: Option<u64>,
    /// `Sources` of the delta: wire index i is `sources[i-1]`, 0 is `own`.
    pub sources: Vec<Source>,
    /// Decoding a snapshot (bare-anchor runs allowed, §3.3 rule 7); set by `decode_snapshot`.
    pub snapshot: bool,
    /// Commit table of the delta: wire index i is `commits[i-1]`; index 0 is (ts, own, lo).
    /// `base` is the counter a bare commit index stands for. Sorted by (source index, ts).
    pub commits: Vec<(Ts, Source, u64)>,
}

/// Wire order of sources (§3.3 rule 2): §2.2 order, except that a commit-form delta's own source sorts below every
/// other commit ID (its writer encodes before the commit ID exists).
pub fn wire_src_cmp(a: &Source, b: &Source, own: &Source) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    if !matches!(own, Source::Commit(_)) || a == b {
        return crate::stamp::base_cmp(a, b);
    }
    match (a, b) {
        (Source::Commit(_), Source::Commit(_)) if a == own => Ordering::Less,
        (Source::Commit(_), Source::Commit(_)) if b == own => Ordering::Greater,
        _ => crate::stamp::base_cmp(a, b),
    }
}
/// Wire order of dots: §2.2 dot order over `wire_src_cmp`.
pub fn wire_cmp(a: &Dot, b: &Dot, own: &Source) -> std::cmp::Ordering {
    crate::stamp::dot_cmp(a, b, &|x, y| wire_src_cmp(x, y, own))
}
/// Map entry records in wire order: by dot, then the key-erased record, then by key.
pub fn entries_sorted<'a, T>(m: &'a BTreeMap<crate::state::Eid, T>, own: &Source) -> Vec<(&'a crate::state::Eid, &'a T)> {
    let mut v: Vec<(&crate::state::Eid, &T)> = m.iter().collect();
    v.sort_by(|a, b| wire_cmp(&a.0 .0, &b.0 .0, own).then_with(|| a.0 .1.cmp(&b.0 .1)));
    v
}
/// Map entries in wire order.
pub fn wire_sorted<'a, T>(m: &'a BTreeMap<Dot, T>, own: &Source) -> Vec<(&'a Dot, &'a T)> {
    let mut v: Vec<(&Dot, &T)> = m.iter().collect();
    v.sort_by(|a, b| wire_cmp(a.0, b.0, own));
    v
}

/// A reference to a stamp or dot as it appears in the encoding.
#[derive(Clone, Copy, Debug)]
pub enum Ref<'a> {
    Stamp(&'a Stamp),
    /// A position write's sibling key (§5.7): a stamp, not a write.
    Key(&'a Stamp),
    Dot(&'a Dot),
}

impl Ctx {
    pub fn new(ts: Ts, own: Source, lo: u64) -> Ctx {
        Ctx { ts, own, lo, hi: None, snapshot: false, sources: Vec::new(), commits: Vec::new() }
    }
    /// Context of a writer's own delta with range `[lo, hi)`.
    pub fn writer(ts: Ts, own: Source, lo: u64, hi: u64) -> Ctx {
        Ctx { ts, own, lo, hi: Some(hi), snapshot: false, sources: Vec::new(), commits: Vec::new() }
    }
    fn index(&mut self, s: &Source) -> u64 {
        if *s == self.own {
            return 0;
        }
        if let Source::Derived(d) = s {
            self.index(&d.source); // the underlying source precedes (§3.3 rule 1)
        }
        if let Some(i) = self.sources.iter().position(|x| x == s) {
            return i as u64 + 1;
        }
        self.sources.push(s.clone());
        self.sources.len() as u64
    }
    fn source(&self, i: u64) -> Result<Source, Error> {
        if i == 0 {
            return Ok(self.own.clone());
        }
        self.sources.get(i as usize - 1).cloned().ok_or(Error::Bad("source index"))
    }
    fn idx_of(&self, s: &Source) -> u64 {
        if *s == self.own {
            0
        } else {
            self.sources.iter().position(|x| x == s).expect("source collected") as u64 + 1
        }
    }
    /// Fill `sources` and `commits` from a fragment (§3.3 rule 1): sources in order of first appearance in the
    /// fragment's encoding, then `extra` (a snapshot's frontier-only sources); commits grouped by source index,
    /// ascending ts, base = smallest counter of that commit's stamps in the fragment.
    fn collect(&mut self, f: &Frag, extra: &[Source]) {
        self.sources.clear();
        self.commits.clear();
        let mut commits: Vec<(Ts, Source, u64)> = Vec::new();
        f.walk_own(&self.own.clone(), &mut |r| match r {
            Ref::Dot(d) => {
                self.index(&d.source);
            }
            Ref::Stamp(s) | Ref::Key(s) => {
                self.index(&s.dot.source);
                if s.ts == self.ts && s.dot.source == self.own {
                    return;
                }
                match commits.iter_mut().find(|(t, x, _)| *t == s.ts && *x == s.dot.source) {
                    Some(c) => c.2 = c.2.min(s.dot.ctr),
                    None => commits.push((s.ts, s.dot.source.clone(), s.dot.ctr)),
                }
            }
        });
        // frontier-only sources come last, by ascending source (§3.3 rule 1)
        let mut extra: Vec<&Source> = extra.iter().collect();
        extra.sort();
        for s in extra {
            self.index(s);
        }
        commits.sort_by_key(|c| (self.idx_of(&c.1), c.0));
        self.commits = commits;
    }
    fn commit_index(&self, ts: Ts, s: &Source) -> Option<(u64, u64)> {
        if ts == self.ts && *s == self.own {
            return Some((0, self.lo));
        }
        self.commits.iter().position(|(t, x, _)| *t == ts && x == s).map(|i| (i as u64 + 1, self.commits[i].2))
    }
    fn commit(&self, i: u64) -> Result<(Ts, Source, u64), Error> {
        if i == 0 {
            return Ok((self.ts, self.own.clone(), self.lo));
        }
        self.commits.get(i as usize - 1).cloned().ok_or(Error::Bad("commit index"))
    }
    /// `Sources := [Source*]`, `Source := bytes(15) | bytes(32) | [Src, ctr]`.
    pub fn sources_item(&self) -> Item {
        Item::Array(
            self.sources
                .iter()
                .map(|s| match s {
                    Source::Node(b) => Item::Bytes(b.to_vec()),
                    Source::Commit(b) => Item::Bytes(b.to_vec()),
                    Source::Derived(d) => Item::Array(vec![u(self.idx_of(&d.source)), u(d.ctr)]),
                })
                .collect(),
        )
    }
    fn load_sources(&mut self, it: &Item) -> Result<(), Error> {
        self.sources.clear();
        for s in it.array()? {
            let src = match s {
                Item::Bytes(b) if b.len() == 15 => Source::Node(b[..].try_into().unwrap()),
                Item::Bytes(b) if b.len() == 32 => Source::Commit(b[..].try_into().unwrap()),
                Item::Array(a) if a.len() == 2 => {
                    let d = Dot { source: self.source(a[0].uint()?)?, ctr: nonzero(a[1].uint()?)? };
                    if matches!(d.source, Source::Derived(_)) {
                        return Err(Error::Bad("derived of derived"));
                    }
                    Source::Derived(Box::new(d))
                }
                _ => return Err(Error::Bad("source")),
            };
            if src == self.own || self.sources.contains(&src) {
                return Err(Error::Bad("non-canonical sources"));
            }
            self.sources.push(src);
        }
        Ok(())
    }
    /// `[[src, [[dwall, logical, base]*]]*]`: grouped by source in index order, ascending ts; `dwall` is the
    /// wall-ms difference to the previous entry of the group (absolute for the first).
    pub fn commits_item(&self) -> Item {
        let mut groups: Vec<(u64, Vec<Item>)> = Vec::new();
        let mut prev: Option<(u64, u64)> = None; // (src idx, wall)
        for (t, s, b) in &self.commits {
            let si = self.idx_of(s);
            let (wall, logical) = (t >> 16, t & 0xffff);
            let dwall = match prev {
                Some((ps, pw)) if ps == si => wall - pw,
                _ => wall,
            };
            prev = Some((si, wall));
            let entry = Item::Array(vec![u(dwall), u(logical), u(*b)]);
            match groups.last_mut() {
                Some((g, v)) if *g == si => v.push(entry),
                _ => groups.push((si, vec![entry])),
            }
        }
        Item::Array(groups.into_iter().map(|(si, v)| Item::Array(vec![u(si), Item::Array(v)])).collect())
    }
    fn load_commits(&mut self, it: &Item) -> Result<(), Error> {
        self.commits.clear();
        let mut last_src: Option<u64> = None;
        for g in it.array()? {
            let g = g.array()?;
            if g.len() != 2 {
                return Err(Error::Bad("commit group"));
            }
            let si = g[0].uint()?;
            if last_src.map_or(false, |l| l >= si) {
                return Err(Error::Bad("commit group order"));
            }
            last_src = Some(si);
            let src = self.source(si)?;
            let mut wall = 0u64;
            let mut last_ts: Option<Ts> = None;
            let entries = g[1].array()?;
            if entries.is_empty() {
                return Err(Error::Bad("empty commit group"));
            }
            for c in entries {
                let a = c.array()?;
                if a.len() != 3 {
                    return Err(Error::Bad("commit entry"));
                }
                let (dwall, logical, base) = (a[0].uint()?, a[1].uint()?, nonzero(a[2].uint()?)?);
                if logical > 0xffff {
                    return Err(Error::Bad("logical"));
                }
                wall = wall.checked_add(dwall).ok_or(Error::Bad("wall overflow"))?;
                if wall >= 1 << 47 {
                    return Err(Error::Bad("wall range"));
                }
                let ts = (wall << 16) | logical;
                if last_ts.map_or(false, |l| l >= ts) || (ts == self.ts && src == self.own) {
                    return Err(Error::Bad("non-canonical commit table"));
                }
                last_ts = Some(ts);
                self.commits.push((ts, src.clone(), base));
            }
        }
        Ok(())
    }
    /// After decoding: the declared tables must be exactly what the fragment (plus `extra`) yields (§3.3 rule 1),
    /// and a writer's delta obeys §2.3 and the writer-only rules of §3.3 rule 7.
    fn check(&self, f: &Frag, extra: &[Source]) -> Result<(), Error> {
        let mut again = Ctx::new(self.ts, self.own.clone(), self.lo);
        again.collect(f, extra);
        if again.sources != self.sources {
            return Err(Error::Bad("non-canonical sources"));
        }
        if again.commits != self.commits {
            return Err(Error::Bad("non-canonical commit table"));
        }
        if let Some(hi) = self.hi {
            // every write stamp is this commit's; the table names only sibling keys' commits (§3.3 rule 7)
            let mut err = None;
            f.walk(&mut |r| {
                let ok = match r {
                    Ref::Stamp(s) if s.ts != self.ts || s.dot.source != self.own => {
                        err = Some(Error::Bad("foreign stamps in a writer's delta"));
                        return;
                    }
                    Ref::Stamp(s) => (self.lo..hi).contains(&s.dot.ctr),
                    Ref::Key(_) => true,
                    Ref::Dot(d) => d.source != self.own || d.ctr < hi,
                };
                if !ok {
                    err = Some(Error::Bad("own counter out of range"));
                }
            });
            if let Some(e) = err {
                return Err(e);
            }
            let mut used = BTreeSet::new();
            f.check_writer(&self.own, hi, &mut used)?;
        }
        Ok(())
    }
}

fn u(n: u64) -> Item {
    Item::Int(n as i64)
}
fn nonzero(n: u64) -> Result<u64, Error> {
    if n == 0 {
        Err(Error::Bad("counter 0"))
    } else {
        Ok(n)
    }
}

/// Text: content goes on the wire for elements that are not deleted (§3.3 rule 5). List: for elements whose
/// fragment exists (a reset element with newer nested writes included).
fn has_content(e: &SeqElem) -> bool {
    match &e.content {
        Content::None => false,
        Content::Char(_) => !e.deleted.as_ref().map_or(false, |d| d.1),
        Content::Frag(_) => true,
    }
}
/// "Carries something" (§3.3 rule 3): deleted (text) or reset (list), or has content. An undeleted text element
/// whose char is gone (expired) carries nothing, so it never sits in a run whose `Content` would have to list it.
fn carries(e: &SeqElem) -> bool {
    e.deleted.as_ref().map_or(false, |d| d.1) || !matches!(e.content, Content::None)
}

/// Maximal runs (§3.3 rule 3) as `(start, n)` over the dot-ordered elements. List runs are uniform in
/// `has_content` so the decoder knows which elements the `Content` array describes.
fn runs(text: bool, v: &[(&Dot, &SeqElem)]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < v.len() {
        let (d0, e0) = v[i];
        let cr = e0.created.is_some();
        let mut n = 1;
        while i + n < v.len() && n < MAX_RUN {
            let (d, e) = v[i + n];
            let (dp, _) = v[i + n - 1];
            if d.source != d0.source || d.ctr != dp.ctr + 1 || carries(e) != carries(e0) || (!text && has_content(e) != has_content(e0)) {
                break;
            }
            let ok = if cr {
                matches!(&e.created, Some((_, Anchor::Dot(a))) if a == dp)
            } else {
                e.created.is_none() && e.pos.is_empty() && e0.pos.is_empty() && e.deleted == e0.deleted
            };
            if !ok {
                break;
            }
            n += 1;
        }
        out.push((i, n));
        i += n;
    }
    out
}

impl Frag {
    /// Every stamp and dot reference of the fragment, in canonical encoding order.
    pub fn walk(&self, f: &mut dyn FnMut(Ref)) {
        self.walk_own(&Source::node(0), f)
    }

    /// `walk` with collections in the wire order of a delta whose own source is `own`.
    pub fn walk_own(&self, own: &Source, f: &mut dyn FnMut(Ref)) {
        fn opt(s: &Option<Stamp>, f: &mut dyn FnMut(Ref)) {
            if let Some(s) = s {
                f(Ref::Stamp(s));
            }
        }
        fn elems(e: &BTreeMap<Dot, Elem>, own: &Source, f: &mut dyn FnMut(Ref)) {
            for (d, el) in wire_sorted(e, own) {
                f(Ref::Dot(d));
                opt(&el.reset, f);
                if let Some(fr) = &el.frag {
                    fr.walk_own(own, f);
                }
            }
        }
        fn anchor(a: &Anchor, f: &mut dyn FnMut(Ref)) {
            if let Anchor::Dot(d) = a {
                f(Ref::Dot(d));
            }
        }
        match self {
            Frag::Slots { reg, slots } => {
                reg.iter().for_each(|r| r.walk_own(own, f));
                slots.values().for_each(|s| s.walk_own(own, f));
            }
            Frag::Register { reset, write } => {
                opt(reset, f);
                if let Some(w) = write {
                    f(Ref::Stamp(&w.0));
                }
            }
            Frag::Bag { c, elems: e, .. } | Frag::Set { c, elems: e } => {
                opt(&c.reset, f);
                opt(&c.w, f);
                elems(e, own, f);
            }
            Frag::Struct { c, fields } => {
                opt(&c.reset, f);
                opt(&c.w, f);
                fields.values().for_each(|x| x.walk_own(own, f));
            }
            Frag::Enum { c, case, payloads } => {
                opt(&c.reset, f);
                opt(&c.w, f);
                if let Some(k) = case {
                    f(Ref::Stamp(&k.0));
                }
                payloads.values().for_each(|x| x.walk_own(own, f));
            }
            Frag::Map { c, entries } => {
                opt(&c.reset, f);
                opt(&c.w, f);
                for ((d, _), en) in entries_sorted(entries, own) {
                    f(Ref::Dot(d));
                    opt(&en.created, f);
                    opt(&en.reset, f);
                    if let Some(fr) = &en.frag {
                        fr.walk_own(own, f);
                    }
                }
            }
            Frag::Seq { text, c, elems: e } => {
                opt(&c.reset, f);
                opt(&c.w, f);
                let v: Vec<(&Dot, &SeqElem)> = wire_sorted(e, own);
                for (start, n) in runs(*text, &v) {
                    let run = &v[start..start + n];
                    f(Ref::Dot(run[0].0));
                    if let Some((_, a)) = &run[0].1.created {
                        anchor(a, f);
                        for (_, el) in run {
                            f(Ref::Stamp(&el.created.as_ref().unwrap().0));
                        }
                    }
                    for (_, el) in run {
                        if let (Content::Frag(fr), true) = (&el.content, has_content(el)) {
                            fr.walk_own(own, f);
                        }
                    }
                    for (d, el) in run {
                        for p in &el.pos {
                            if p.0.dot != **d {
                                f(Ref::Stamp(&p.0));
                                anchor(&p.1, f);
                                if let Some(k) = &p.2 {
                                    f(Ref::Key(k));
                                }
                            }
                        }
                    }
                    for (_, el) in run {
                        if let Some((s, _)) = &el.deleted {
                            f(Ref::Stamp(s));
                        }
                    }
                }
            }
        }
    }

    /// Every stamp carried by the fragment, in canonical encoding order.
    pub fn stamps(&self, out: &mut Vec<Stamp>) {
        self.walk(&mut |r| {
            if let Ref::Stamp(s) = r {
                out.push(s.clone());
            }
        });
    }

    /// Writer-only rules (§2.3, §3.3 rule 7): no `Slots`, no `Derived` creation runs, own sequence element dots
    /// below `hi`, and the writer's creations and position writes use distinct counters.
    fn check_writer(&self, own: &Source, hi: u64, used: &mut BTreeSet<u64>) -> Result<(), Error> {
        fn take(used: &mut BTreeSet<u64>, ctr: u64) -> Result<(), Error> {
            if used.insert(ctr) {
                Ok(())
            } else {
                Err(Error::Bad("repeated own counter"))
            }
        }
        match self {
            Frag::Slots { .. } => return Err(Error::Bad("slots in a writer's delta")),
            Frag::Register { .. } => {}
            Frag::Bag { elems, .. } | Frag::Set { elems, .. } => {
                for (d, el) in elems {
                    if d.source == *own && el.frag.is_some() {
                        take(used, d.ctr)?;
                    }
                    if let Some(f) = &el.frag {
                        f.check_writer(own, hi, used)?;
                    }
                }
            }
            Frag::Struct { fields, .. } => {
                for f in fields.values() {
                    f.check_writer(own, hi, used)?;
                }
            }
            Frag::Enum { payloads, .. } => {
                for f in payloads.values() {
                    f.check_writer(own, hi, used)?;
                }
            }
            Frag::Map { entries, .. } => {
                for ((d, _), en) in entries {
                    if d.source == *own && en.frag.is_some() {
                        take(used, d.ctr)?;
                    }
                    if let Some(f) = &en.frag {
                        f.check_writer(own, hi, used)?;
                    }
                }
            }
            Frag::Seq { elems, .. } => {
                for (d, el) in elems {
                    // §2.3: every element of a run is an identity (`walk` yields only a run's first dot)
                    if d.source == *own && d.ctr >= hi {
                        return Err(Error::Bad("own counter out of range"));
                    }
                    if el.created.is_some() {
                        if matches!(d.source, Source::Derived(_)) {
                            return Err(Error::Bad("derived creation in a writer's delta"));
                        }
                        if d.source == *own {
                            take(used, d.ctr)?;
                        }
                    }
                    for p in &el.pos {
                        if p.0.dot != *d && p.0.dot.source == *own {
                            take(used, p.0.dot.ctr)?;
                        }
                    }
                    if let Content::Frag(f) = &el.content {
                        f.check_writer(own, hi, used)?;
                    }
                }
            }
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ encode

fn enc_dot(d: &Dot, cx: &Ctx) -> Item {
    let i = cx.idx_of(&d.source);
    if i == 0 {
        u(d.ctr)
    } else {
        Item::Array(vec![u(i), u(d.ctr)])
    }
}
fn enc_stamp(s: &Stamp, cx: &Ctx) -> Item {
    let (ci, base) = cx.commit_index(s.ts, &s.dot.source).expect("commit table collected");
    if s.dot.ctr == base {
        u(ci)
    } else {
        Item::Array(vec![u(ci), u(s.dot.ctr)])
    }
}
fn enc_opt_stamp(s: &Option<Stamp>, cx: &Ctx) -> Item {
    Item::Array(s.iter().map(|s| enc_stamp(s, cx)).collect())
}
/// `W` goes on the wire whenever the state holds one (§4.3): dropping it when a greater stamp sits inside would
/// make un-merge of that stamp's author lose the presence it recorded.
fn enc_w(c: &Composite, cx: &Ctx) -> Item {
    enc_opt_stamp(&c.w, cx)
}
fn enc_anchor(a: &Anchor, cx: &Ctx) -> Item {
    match a {
        Anchor::Head => u(0),
        Anchor::Dot(d) => enc_dot(d, cx),
    }
}
fn enc_elems(elems: &BTreeMap<Dot, Elem>, cx: &Ctx) -> Item {
    Item::Array(
        wire_sorted(elems, &cx.own)
            .into_iter()
            .map(|(d, e)| Item::Array(vec![enc_dot(d, cx), enc_opt_stamp(&e.reset, cx), Item::Array(e.frag.iter().map(|f| encode(f, cx)).collect())]))
            .collect(),
    )
}

/// Encode a fragment; `cx` must have been collected (see `encode_delta`).
pub fn encode(f: &Frag, cx: &Ctx) -> Item {
    let enc = u(f.enc() as u64);
    match f {
        Frag::Register { reset, write } => {
            let mut a = vec![enc, enc_opt_stamp(reset, cx)];
            if let Some((s, v)) = write {
                a.push(enc_stamp(s, cx));
                a.extend(v.iter().map(|v| v.to_item()));
            }
            Item::Array(a)
        }
        Frag::Bag { c, elems, .. } | Frag::Set { c, elems } => Item::Array(vec![enc, enc_opt_stamp(&c.reset, cx), enc_w(c, cx), enc_elems(elems, cx)]),
        Frag::Struct { c, fields } => {
            let m = fields.iter().map(|(k, v)| (u(*k), encode(v, cx))).collect();
            Item::Array(vec![enc, enc_opt_stamp(&c.reset, cx), enc_w(c, cx), cbor::sorted_map(m)])
        }
        Frag::Enum { c, case, payloads } => {
            let case_i = Item::Array(case.iter().map(|(s, id)| Item::Array([enc_stamp(s, cx)].into_iter().chain(id.map(u)).collect())).collect());
            let m = payloads.iter().map(|(k, v)| (u(*k), encode(v, cx))).collect();
            Item::Array(vec![enc, enc_opt_stamp(&c.reset, cx), enc_w(c, cx), case_i, cbor::sorted_map(m)])
        }
        Frag::Map { c, entries } => {
            let es = entries_sorted(entries, &cx.own)
                .into_iter()
                .map(|((d, key), e)| {
                    let mut a = vec![enc_dot(d, cx)];
                    // a foreign creation carries its commit (snapshots, imports); this commit's own
                    // is implied
                    if let Some(c) = e.created.as_ref().filter(|c| !(c.ts == cx.ts && c.dot.source == cx.own)) {
                        a.push(u(cx.commit_index(c.ts, &d.source).expect("commit table collected").0));
                    }
                    a.push(enc_opt_stamp(&e.reset, cx));
                    a.extend(key.iter().map(|k| k.to_item()));
                    a.push(Item::Array(e.frag.iter().map(|f| encode(f, cx)).collect()));
                    Item::Array(a)
                })
                .collect();
            Item::Array(vec![enc, enc_opt_stamp(&c.reset, cx), enc_w(c, cx), Item::Array(es)])
        }
        Frag::Seq { text, c, elems } => Item::Array(vec![enc, enc_opt_stamp(&c.reset, cx), enc_w(c, cx), enc_runs(*text, elems, cx)]),
        Frag::Slots { reg, slots } => Item::Array(vec![enc, Item::Array(reg.iter().map(|r| encode(r, cx)).collect()), Item::Array(slots.values().map(|s| encode(s, cx)).collect())]),
    }
}

fn enc_runs(text: bool, elems: &BTreeMap<Dot, SeqElem>, cx: &Ctx) -> Item {
    let v: Vec<(&Dot, &SeqElem)> = wire_sorted(elems, &cx.own);
    let mut out = Vec::new();
    let mut cut: Vec<(&[(&Dot, &SeqElem)], Option<Vec<Item>>)> = Vec::new();
    for (start, n) in runs(text, &v) {
        let run = &v[start..start + n];
        if text || !run.iter().any(|(_, e)| has_content(e)) {
            cut.push((run, None));
            continue;
        }
        // a list run also closes once its content reaches CHUNK_MAX bytes (§3.3 rule 3)
        let (mut from, mut size, mut fs) = (0, 0, Vec::new());
        for (j, (_, e)) in run.iter().enumerate() {
            let it = match &e.content {
                Content::Frag(f) => encode(f, cx),
                _ => unreachable!("list runs are uniform in content"),
            };
            size += cbor::encode(&it).len();
            fs.push(it);
            if size >= CHUNK_MAX || j + 1 == run.len() {
                cut.push((&run[from..=j], Some(std::mem::take(&mut fs))));
                from = j + 1;
                size = 0;
            }
        }
    }
    for (run, fs) in cut {
        let n = run.len();
        let (d0, e0) = run[0];
        let first = enc_dot(d0, cx);
        let creation_i = match &e0.created {
            None => Item::Array(vec![]),
            Some((_, a)) => {
                // segments of consecutive elements created by the same commit
                let mut segs: Vec<(u64, u64)> = Vec::new();
                for (d, e) in run {
                    let ts = e.created.as_ref().unwrap().0.ts;
                    let (ci, _) = cx.commit_index(ts, &d.source).expect("commit table collected");
                    match segs.last_mut() {
                        Some((c, k)) if *c == ci => *k += 1,
                        _ => segs.push((ci, 1)),
                    }
                }
                Item::Array(vec![enc_anchor(a, cx), Item::Array(segs.into_iter().map(|(c, k)| Item::Array(vec![u(c), u(k)])).collect())])
            }
        };
        let content = if let Some(fs) = fs {
            Item::Array(fs)
        } else if !run.iter().any(|(_, e)| has_content(e)) {
            Item::Array(vec![])
        } else if text {
            Item::Text(run.iter().filter(|(_, e)| has_content(e)).map(|(_, e)| match &e.content {
                Content::Char(c) => *c,
                _ => unreachable!(),
            }).collect())
        } else {
            unreachable!("list content is encoded above")
        };
        let mut posw = Vec::new();
        for (k, (d, e)) in run.iter().enumerate() {
            for p in &e.pos {
                if p.0.dot != **d {
                    let mut w = vec![u(k as u64), enc_stamp(&p.0, cx), enc_anchor(&p.1, cx)];
                    w.extend(p.2.as_ref().map(|k| enc_stamp(k, cx)));
                    posw.push(Item::Array(w));
                }
            }
        }
        let mut flagw = Vec::new();
        let mut k = 0;
        while k < run.len() {
            if let Some((s, b)) = &run[k].1.deleted {
                let mut j = k;
                while j + 1 < run.len() && run[j + 1].1.deleted.as_ref() == Some(&(s.clone(), *b)) {
                    j += 1;
                }
                flagw.push(Item::Array(vec![u(k as u64), u(j as u64), enc_stamp(s, cx), Item::Bool(*b)]));
                k = j + 1;
            } else {
                k += 1;
            }
        }
        out.push(Item::Array(vec![first, u(n as u64), creation_i, content, Item::Array(posw), Item::Array(flagw)]));
    }
    Item::Array(out)
}

// ------------------------------------------------------------------ decode

fn dec_dot(it: &Item, cx: &Ctx) -> Result<Dot, Error> {
    match it {
        Item::Int(_) => Ok(Dot { source: cx.own.clone(), ctr: nonzero(it.uint()?)? }),
        Item::Array(a) if a.len() == 2 => {
            let i = a[0].uint()?;
            if i == 0 {
                return Err(Error::Bad("non-canonical dot"));
            }
            Ok(Dot { source: cx.source(i)?, ctr: nonzero(a[1].uint()?)? })
        }
        _ => Err(Error::Bad("dot")),
    }
}
fn dec_stamp(it: &Item, cx: &Ctx) -> Result<Stamp, Error> {
    match it {
        Item::Int(_) => {
            let (ts, src, base) = cx.commit(it.uint()?)?;
            Ok(Stamp::new(ts, src, base))
        }
        Item::Array(a) if a.len() == 2 => {
            let (ts, src, base) = cx.commit(a[0].uint()?)?;
            let ctr = nonzero(a[1].uint()?)?;
            if ctr == base {
                return Err(Error::Bad("non-canonical stamp"));
            }
            Ok(Stamp::new(ts, src, ctr))
        }
        _ => Err(Error::Bad("stamp")),
    }
}
fn dec_opt_stamp(it: &Item, cx: &Ctx) -> Result<Option<Stamp>, Error> {
    match it.array()? {
        [] => Ok(None),
        [s] => Ok(Some(dec_stamp(s, cx)?)),
        _ => Err(Error::Bad("opt stamp")),
    }
}
fn dec_anchor(it: &Item, cx: &Ctx) -> Result<Anchor, Error> {
    match it {
        Item::Int(0) => Ok(Anchor::Head),
        _ => Ok(Anchor::Dot(dec_dot(it, cx)?)),
    }
}
fn dec_opt_frag(it: &Item, cx: &Ctx) -> Result<Option<Box<Frag>>, Error> {
    match it.array()? {
        [] => Ok(None),
        [f] => Ok(Some(Box::new(decode_at(f, cx, false)?))),
        _ => Err(Error::Bad("opt frag")),
    }
}
fn dec_elems(it: &Item, cx: &Ctx) -> Result<BTreeMap<Dot, Elem>, Error> {
    let mut m = BTreeMap::new();
    let mut last: Option<Dot> = None;
    for e in it.array()? {
        let a = e.array()?;
        if a.len() != 3 {
            return Err(Error::Bad("elem"));
        }
        let d = dec_dot(&a[0], cx)?;
        if last.as_ref().map_or(false, |l| wire_cmp(l, &d, &cx.own).is_ge()) {
            return Err(Error::Bad("elem order"));
        }
        last = Some(d.clone());
        let frag = dec_opt_frag(&a[2], cx)?;
        // a set or bag element's value is one register (spec §3.2)
        if frag.as_deref().map_or(false, |f| !matches!(f, Frag::Register { .. })) {
            return Err(Error::Bad("set or bag element not a register"));
        }
        m.insert(d, Elem { reset: dec_opt_stamp(&a[1], cx)?, frag });
    }
    Ok(m)
}
fn dec_fields(it: &Item, cx: &Ctx) -> Result<BTreeMap<u64, Frag>, Error> {
    let mut m = BTreeMap::new();
    for (k, v) in it.map()? {
        m.insert(k.uint()?, decode_at(v, cx, false)?);
    }
    Ok(m)
}
fn composite(a: &[Item], cx: &Ctx) -> Result<Composite, Error> {
    Ok(Composite { reset: dec_opt_stamp(&a[1], cx)?, w: dec_opt_stamp(&a[2], cx)? })
}

/// Empty in the sense of §4.2 Emptiness: no surviving write and no record at any depth (a struct
/// or enum whose children are all empty holds none).
fn deep_empty(f: &Frag) -> bool {
    match f {
        Frag::Struct { fields, .. } => f.all_max().is_none() && fields.values().all(deep_empty),
        Frag::Enum { payloads, .. } => f.all_max().is_none() && payloads.values().all(deep_empty),
        _ => f.is_empty(),
    }
}

/// Decode a fragment at an aspect root.
pub fn decode(it: &Item, cx: &Ctx) -> Result<Frag, Error> {
    decode_at(it, cx, true)
}

/// Decode a fragment; `top`: an aspect root or a `Slots` member, the only registers that carry a reset (§3.3 rule 7).
fn decode_at(it: &Item, cx: &Ctx, top: bool) -> Result<Frag, Error> {
    let a = it.array()?;
    if a.is_empty() {
        return Err(Error::Bad("fragment"));
    }
    let enc = a[0].uint()?;
    let f = match (enc, a.len()) {
        (0, 2) => Frag::Register { reset: dec_opt_stamp(&a[1], cx)?, write: None },
        (0, 3) => Frag::Register { reset: dec_opt_stamp(&a[1], cx)?, write: Some((dec_stamp(&a[2], cx)?, None)) },
        (0, 4) => Frag::Register { reset: dec_opt_stamp(&a[1], cx)?, write: Some((dec_stamp(&a[2], cx)?, Some(Value::from_item(&a[3])?))) },
        (1..=3, 4) => {
            let kind = [BagKind::Counter, BagKind::Max, BagKind::Min][enc as usize - 1];
            Frag::Bag { kind, c: composite(a, cx)?, elems: dec_elems(&a[3], cx)? }
        }
        (4, 4) => Frag::Struct { c: composite(a, cx)?, fields: dec_fields(&a[3], cx)? },
        (5, 5) => {
            let case = match a[3].array()? {
                [] => None,
                [c] => match c.array()? {
                    [s] => Some((dec_stamp(s, cx)?, None)),
                    [s, id] => Some((dec_stamp(s, cx)?, Some(id.uint()?))),
                    _ => return Err(Error::Bad("case")),
                },
                _ => return Err(Error::Bad("case")),
            };
            Frag::Enum { c: composite(a, cx)?, case, payloads: dec_fields(&a[4], cx)? }
        }
        (6, 4) => Frag::Set { c: composite(a, cx)?, elems: dec_elems(&a[3], cx)? },
        (7, 4) => {
            let mut entries = BTreeMap::new();
            let mut last: Option<(Dot, Option<Value>)> = None;
            for e in a[3].array()? {
                let x = e.array()?;
                let ci = match x.get(1) {
                    Some(Item::Int(_)) => Some(x[1].uint()?),
                    _ => None,
                };
                let x: Vec<Item> = if ci.is_some() { std::iter::once(x[0].clone()).chain(x[2..].iter().cloned()).collect() } else { x.to_vec() };
                let (key, frag) = match x.len() {
                    3 => (None, dec_opt_frag(&x[2], cx)?),
                    4 => (Some(Value::from_item(&x[2])?), dec_opt_frag(&x[3], cx)?),
                    _ => return Err(Error::Bad("entry")),
                };
                let d = dec_dot(&x[0], cx)?;
                if last.as_ref().map_or(false, |(l, lk)| wire_cmp(l, &d, &cx.own).then_with(|| lk.cmp(&key)).is_ge()) {
                    return Err(Error::Bad("entry order"));
                }
                last = Some((d.clone(), key.clone()));
                let created = match (ci, cx.hi) {
                    (Some(_), Some(_)) => return Err(Error::Bad("creation commit in a writer's delta")),
                    (Some(_), None) if frag.is_none() => return Err(Error::Bad("creation commit on a tombstone")),
                    (Some(ci), None) => {
                        let (ts, src, _) = cx.commit(ci)?;
                        if ci == 0 || src != d.source {
                            return Err(Error::Bad("creation commit"));
                        }
                        Some(Stamp { ts, dot: d.clone() })
                    }
                    (None, Some(hi)) if frag.is_some() && d.source == cx.own && cx.lo <= d.ctr && d.ctr < hi => Some(Stamp { ts: cx.ts, dot: d.clone() }),
                    _ => None,
                };
                entries.insert((d, key), Entry { reset: dec_opt_stamp(&x[1], cx)?, frag, created });
            }
            Frag::Map { c: composite(a, cx)?, entries }
        }
        (8 | 9, 4) => Frag::Seq { text: enc == 9, c: composite(a, cx)?, elems: dec_runs(enc == 9, &a[3], cx)? },
        (10, 3) => {
            let reg = match a[1].array()? {
                [] => None,
                [r] => match decode_at(r, cx, true)? {
                    f @ Frag::Register { .. } => Some(Box::new(f)),
                    _ => return Err(Error::Bad("slots register")),
                },
                _ => return Err(Error::Bad("slots register")),
            };
            let mut slots = BTreeMap::new();
            let mut last = 0u8;
            for it in a[2].array()? {
                let f = decode_at(it, cx, true)?;
                let e = f.enc();
                if e == 0 || e == 10 || e <= last {
                    return Err(Error::Bad("slot order"));
                }
                last = e;
                slots.insert(e, f);
            }
            if reg.iter().count() + slots.len() < 2 {
                return Err(Error::Bad("slots arity"));
            }
            Frag::Slots { reg, slots }
        }
        _ => return Err(Error::Bad("encoding or arity")),
    };
    if !derived_ok(&f) {
        return Err(Error::Bad("write with a Derived stamp"));
    }
    if let Frag::Register { reset: Some(_), .. } = &f {
        if !top {
            return Err(Error::Bad("nested register reset"));
        }
    }
    if let Frag::Slots { .. } = &f {
        // §7 canonical form (§3.3 rule 7): pruning changes nothing the wire carries (every member holds the
        // register's embedding, none is empty or adds nothing to it, nothing lies below the position's one reset);
        // the chars of deleted embedded elements are restored by the embedding but never carried (rule 5)
        // the pruned form is the result, so those chars are held again (a content-less undelete reads them)
        let mut pruned = f.clone();
        pruned.prune(None);
        let mut c = pruned.clone();
        crate::state::drop_deleted_chars(&mut c);
        if c != f {
            return Err(Error::Bad("non-canonical slots"));
        }
        return Ok(pruned);
    }
    Ok(f)
}

/// §3.3 rule 7: only a text element's creation (and that creation as a position write) carries a `Derived` stamp.
/// Checks `f`'s own level; nested fragments were checked when decoded.
fn derived_ok(f: &Frag) -> bool {
    let ok = |s: Option<&Stamp>| !s.map_or(false, |s| matches!(s.dot.source, Source::Derived(_)));
    let comp = |c: &Composite| ok(c.reset.as_ref()) && ok(c.w.as_ref());
    match f {
        Frag::Register { reset, write } => ok(reset.as_ref()) && ok(write.as_ref().map(|w| &w.0)),
        Frag::Bag { c, elems, .. } | Frag::Set { c, elems } => comp(c) && elems.values().all(|e| ok(e.reset.as_ref())),
        Frag::Struct { c, .. } => comp(c),
        Frag::Enum { c, case, .. } => comp(c) && ok(case.as_ref().map(|x| &x.0)),
        Frag::Map { c, entries } => comp(c) && entries.values().all(|e| ok(e.reset.as_ref()) && ok(e.created.as_ref())),
        Frag::Seq { text, c, elems } => {
            comp(c)
                && elems.values().all(|e| {
                    let created = e.created.as_ref().map(|x| &x.0);
                    ok(e.deleted.as_ref().map(|d| &d.0)) && (*text || ok(created)) && e.pos.iter().all(|(p, _, _)| ok(Some(p)) || Some(p) == created)
                })
        }
        Frag::Slots { .. } => true,
    }
}

fn dec_runs(text: bool, it: &Item, cx: &Ctx) -> Result<BTreeMap<Dot, SeqElem>, Error> {
    let mut m: BTreeMap<Dot, SeqElem> = BTreeMap::new();
    let mut last: Option<Dot> = None;
    let mut got: Vec<(Dot, usize)> = Vec::new();
    for r in it.array()? {
        let a = r.array()?;
        if a.len() != 6 {
            return Err(Error::Bad("run"));
        }
        let first = dec_dot(&a[0], cx)?;
        let n = nonzero(a[1].uint()?)? as usize;
        if n > MAX_RUN {
            return Err(Error::Bad("run length"));
        }
        if last.as_ref().map_or(false, |l| wire_cmp(l, &first, &cx.own).is_ge()) {
            return Err(Error::Bad("run order"));
        }
        got.push((first.clone(), n));
        // a bare-anchor run (nothing but dots) never in a writer's delta (§3.3 rule 7)
        let empty = |i: usize| a[i].array().map_or(false, |x| x.is_empty());
        if cx.hi.is_some() && empty(2) && empty(3) && empty(4) && empty(5) {
            return Err(Error::Bad("bare anchors in a writer's delta"));
        }
        let mut elems: Vec<SeqElem> = (0..n).map(|_| SeqElem::write(Content::None, vec![], None)).collect();
        match a[2].array()? {
            [] => {}
            [anchor, segs] => {
                let mut prev = dec_anchor(anchor, cx)?;
                let mut i = 0usize;
                let mut last_ci = None;
                for seg in segs.array()? {
                    let s = seg.array()?;
                    if s.len() != 2 {
                        return Err(Error::Bad("segment"));
                    }
                    let (ci, k) = (s[0].uint()?, nonzero(s[1].uint()?)? as usize);
                    if last_ci == Some(ci) {
                        return Err(Error::Bad("non-canonical segments"));
                    }
                    last_ci = Some(ci);
                    let (ts, src, _) = cx.commit(ci)?;
                    if src != first.source {
                        return Err(Error::Bad("segment source"));
                    }
                    if i + k > n {
                        return Err(Error::Bad("segments exceed run"));
                    }
                    for e in &mut elems[i..i + k] {
                        let d = Dot { source: first.source.clone(), ctr: first.ctr + i as u64 };
                        let st = Stamp { ts, dot: d.clone() };
                        e.created = Some((st.clone(), prev.clone()));
                        e.pos.push((st, prev, None));
                        prev = Anchor::Dot(d);
                        i += 1;
                    }
                }
                if i != n {
                    return Err(Error::Bad("segments short"));
                }
            }
            _ => return Err(Error::Bad("creation")),
        }
        let mut last_pos: Option<(usize, Stamp)> = None;
        for p in a[4].array()? {
            let p = p.array()?;
            if p.len() != 3 && p.len() != 4 {
                return Err(Error::Bad("posw"));
            }
            let i = p[0].uint()? as usize;
            if i >= n {
                return Err(Error::Bad("posw index"));
            }
            let s = dec_stamp(&p[1], cx)?;
            // sorted by i, then stamp descending (§3.3 rule 2)
            if let Some((li, ls)) = &last_pos {
                if i < *li || (i == *li && s >= *ls) {
                    return Err(Error::Bad("posw order"));
                }
            }
            last_pos = Some((i, s.clone()));
            // the write stamped with the element's own dot is its creation (§3.3 rule 5: never a `PosW`)
            if s.dot.source == first.source && s.dot.ctr == first.ctr + i as u64 {
                return Err(Error::Bad("creation as a position write"));
            }
            // a sibling key is an older commit's write stamp (§5.7): its ts below the write's
            let key = match p.get(3) {
                Some(k) => Some(dec_stamp(k, cx)?),
                None => None,
            };
            if key.as_ref().map_or(false, |k| k.ts >= s.ts) {
                return Err(Error::Bad("sibling key not below its stamp's ts"));
            }
            elems[i].pos.push((s, dec_anchor(&p[2], cx)?, key));
        }
        let mut last_flag: Option<(usize, Stamp, bool)> = None;
        for fl in a[5].array()? {
            let x = fl.array()?;
            if x.len() != 4 {
                return Err(Error::Bad("flagw"));
            }
            let (i, j) = (x[0].uint()? as usize, x[1].uint()? as usize);
            if i > j || j >= n {
                return Err(Error::Bad("flagw range"));
            }
            let s = dec_stamp(&x[2], cx)?;
            let b = match &x[3] {
                Item::Bool(b) => *b,
                _ => return Err(Error::Bad("flag")),
            };
            if !text && !b {
                return Err(Error::Bad("undelete of a list element"));
            }
            // sorted by `i_from` (ranges never overlap), and maximal: an adjacent range of the same write
            // continues the previous one (§3.3 rule 2)
            if let Some((to, ls, lb)) = &last_flag {
                if i <= *to || (i == *to + 1 && *ls == s && *lb == b) {
                    return Err(Error::Bad("flagw order"));
                }
            }
            last_flag = Some((j, s.clone(), b));
            for e in &mut elems[i..=j] {
                // one surviving flag write per element: canonical ranges never overlap
                if e.deleted.is_some() {
                    return Err(Error::Bad("overlapping flag writes"));
                }
                e.deleted = Some((s.clone(), b));
            }
        }
        match &a[3] {
            Item::Array(v) if v.is_empty() => {}
            Item::Text(s) if text => {
                // no char carried is `[]`, never an empty string (§3.2 Content)
                if s.is_empty() {
                    return Err(Error::Bad("empty content string"));
                }
                let live: Vec<usize> = (0..n).filter(|i| !elems[*i].deleted.as_ref().map_or(false, |d| d.1)).collect();
                let cs: Vec<char> = s.chars().collect();
                if cs.len() != live.len() {
                    return Err(Error::Bad("content length"));
                }
                for (k, i) in live.iter().enumerate() {
                    elems[*i].content = Content::Char(cs[k]);
                }
            }
            Item::Array(v) if !text => {
                // a list run with content carries one fragment per element
                if v.len() != n {
                    return Err(Error::Bad("content length"));
                }
                for (i, it) in v.iter().enumerate() {
                    // only non-empty fragments are carried (§3.2 Content, §4.2 Emptiness)
                    let f = decode_at(it, cx, false)?;
                    if deep_empty(&f) {
                        return Err(Error::Bad("empty element fragment"));
                    }
                    elems[i].content = Content::Frag(Box::new(f));
                }
            }
            _ => return Err(Error::Bad("content")),
        }
        for (i, mut e) in elems.into_iter().enumerate() {
            let d = Dot { source: first.source.clone(), ctr: first.ctr + i as u64 };
            // `pos` is the top two position writes, the creation's included (§5.7); a `PosW` outside them is
            // not on the wire (the creation stays in `created` once pushed out)
            e.pos.sort_by(|a, b| b.0.cmp(&a.0));
            e.pos.dedup_by(|a, b| a.0 == b.0);
            if e.pos.iter().skip(2).any(|p| p.0.dot != d) {
                return Err(Error::Bad("position write outside the top two"));
            }
            e.pos.truncate(2);
            last = Some(d.clone());
            m.insert(d, e);
        }
    }
    // runs are maximal (§3.3 rule 3): the decoded elements regroup into exactly the runs read
    let v = wire_sorted(&m, &cx.own);
    let want: Vec<(Dot, usize)> = runs(text, &v).into_iter().map(|(i, n)| (v[i].0.clone(), n)).collect();
    if want != got {
        return Err(Error::Bad("runs not maximal"));
    }
    Ok(m)
}

/// Full delta: `[nonce, Sources, Commits, Fragment]` (§3.2). Fills `cx.sources` and `cx.commits`.
pub fn encode_delta(f: &Frag, nonce: [u8; 16], cx: &mut Ctx) -> Vec<u8> {
    cx.collect(f, &[]);
    let frag = encode(f, cx);
    cbor::encode(&Item::Array(vec![Item::Bytes(nonce.to_vec()), cx.sources_item(), cx.commits_item(), frag]))
}
/// `cx` carries ts, own, lo (and hi for a writer's delta); the tables are read from the delta and checked.
pub fn decode_delta(bytes: &[u8], cx: &mut Ctx) -> Result<Frag, Error> {
    let it = cbor::decode(bytes)?;
    match it.array()? {
        [Item::Bytes(n), sources, commits, f] if n.len() == 16 => {
            cx.load_sources(sources)?;
            cx.load_commits(commits)?;
            let frag = decode(f, cx)?;
            cx.check(&frag, &[])?;
            Ok(frag)
        }
        _ => Err(Error::Bad("delta")),
    }
}

/// Snapshot delta: `[nonce, Sources, Commits, Fragment, Frontiers, Absorbed]`, `Frontiers := [[Src, ctr]*]` sorted
/// by `Src`, one entry per `Node` source (§8). The caller strips the values of expiring deltas first (§4.7).
/// Frontier-only sources come last in `Sources`. `Absorbed` (absorbed commit-form commits) is always empty here:
/// the model keeps no per-commit receipts.
pub fn encode_snapshot(f: &Frag, frontiers: &[(Source, u64)], nonce: [u8; 16], cx: &mut Ctx) -> Vec<u8> {
    encode_snapshot_authors(f, frontiers, &BTreeMap::new(), nonce, cx)
}

/// Per `Commit` source, the node (tid bytes) and `ts` its writes are judged as (§8 `Authors`).
pub type Authors = BTreeMap<[u8; 32], ([u8; 15], Ts)>;

/// A snapshot with `Authors` (entries for sources the fragment does not hold are dropped; the
/// array is omitted when empty).
pub fn encode_snapshot_authors(f: &Frag, frontiers: &[(Source, u64)], authors: &Authors, nonce: [u8; 16], cx: &mut Ctx) -> Vec<u8> {
    let extra: Vec<Source> = frontiers
        .iter()
        .map(|(s, c)| {
            assert!(matches!(s, Source::Node(_)) && *c >= 1, "frontiers name node sources");
            s.clone()
        })
        .collect();
    cx.collect(f, &extra);
    let frag = encode(f, cx);
    let mut fr: Vec<(u64, u64)> = frontiers.iter().map(|(s, c)| (cx.idx_of(s), *c)).collect();
    fr.sort();
    let fr = Item::Array(fr.into_iter().map(|(i, c)| Item::Array(vec![u(i), u(c)])).collect());
    let mut top = vec![Item::Bytes(nonce.to_vec()), cx.sources_item(), cx.commits_item(), frag, fr, Item::Array(Vec::new())];
    let au: Vec<Item> = cx
        .sources
        .iter()
        .enumerate()
        .filter_map(|(i, s)| match s {
            Source::Commit(c) => authors.get(c).map(|(n, ts)| Item::Array(vec![u(i as u64 + 1), Item::Bytes(n.to_vec()), u(*ts)])),
            _ => None,
        })
        .collect();
    if !au.is_empty() {
        top.push(Item::Array(au));
    }
    cbor::encode(&Item::Array(top))
}

pub fn decode_snapshot(bytes: &[u8], cx: &mut Ctx) -> Result<(Frag, Vec<(Source, u64)>), Error> {
    decode_snapshot_authors(bytes, cx).map(|(f, fr, _)| (f, fr))
}

pub fn decode_snapshot_authors(bytes: &[u8], cx: &mut Ctx) -> Result<(Frag, Vec<(Source, u64)>, Authors), Error> {
    let it = cbor::decode(bytes)?;
    let (n, sources, commits, f, fr, ab, au) = match it.array()? {
        [n, sources, commits, f, fr, ab] => (n, sources, commits, f, fr, ab, None),
        [n, sources, commits, f, fr, ab, au] => (n, sources, commits, f, fr, ab, Some(au)),
        _ => return Err(Error::Bad("snapshot")),
    };
    if !ab.array()?.is_empty() {
        return Err(Error::Bad("absorbed commits (not modeled)"));
    }
    match (n, sources, commits, f, fr) {
        (Item::Bytes(n), sources, commits, f, fr) if n.len() == 16 => {
            cx.snapshot = true;
            cx.load_sources(sources)?;
            cx.load_commits(commits)?;
            let frag = decode(f, cx)?;
            let mut out = Vec::new();
            let mut last: Option<u64> = None;
            for e in fr.array()? {
                let (i, c) = match e.array()? {
                    [i, c] => (i.uint()?, nonzero(c.uint()?)?),
                    _ => return Err(Error::Bad("frontier")),
                };
                if last.map_or(false, |l| l >= i) {
                    return Err(Error::Bad("frontier order"));
                }
                last = Some(i);
                let s = cx.source(i)?;
                if !matches!(s, Source::Node(_)) {
                    return Err(Error::Bad("frontier source"));
                }
                out.push((s, c));
            }
            let extra: Vec<Source> = out.iter().map(|x| x.0.clone()).collect();
            cx.check(&frag, &extra)?;
            // a snapshot writes nothing itself (§2.4): no stamp of this commit (`Ci` 0)
            let mut own = false;
            frag.walk(&mut |r| own |= matches!(r, Ref::Stamp(s) | Ref::Key(s) if s.dot.source == cx.own && s.ts == cx.ts));
            if own {
                return Err(Error::Bad("own write in a snapshot"));
            }
            let mut authors = Authors::new();
            if let Some(au) = au {
                let mut last = 0u64;
                let es = au.array()?;
                if es.is_empty() {
                    return Err(Error::Bad("empty authors"));
                }
                for e in es {
                    let [i, Item::Bytes(t), ts] = e.array()? else { return Err(Error::Bad("author")) };
                    let i = i.uint()?;
                    if i <= last {
                        return Err(Error::Bad("authors order"));
                    }
                    last = i;
                    let Source::Commit(c) = cx.source(i)? else { return Err(Error::Bad("author of a non-commit source")) };
                    let t: [u8; 15] = t.as_slice().try_into().map_err(|_| Error::Bad("author tid"))?;
                    authors.insert(c, (t, ts.uint()?));
                }
            }
            Ok((frag, out, authors))
        }
        _ => Err(Error::Bad("snapshot")),
    }
}
