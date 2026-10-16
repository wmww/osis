//! Wire encoding of fragments (spec §3): canonical CBOR items with a commit context.
use crate::cbor::{self, Error, Item};
use crate::stamp::{Dot, Source, Stamp, Ts};
use crate::state::{Anchor, BagKind, Composite, Content, Elem, Entry, Frag, SeqElem};
use crate::value::Value;
use std::collections::BTreeMap;

/// What the commit header provides (§2.4) plus the delta's own commit table (§3.2).
#[derive(Clone, Debug)]
pub struct Ctx {
    pub ts: Ts,
    pub own: Source,
    /// The delta dot counter of the own delta (header range start).
    pub lo: u64,
    /// Foreign sources (header); wire index i is `sources[i-1]`, 0 is `own`.
    pub sources: Vec<Source>,
    /// Commit table of the delta: wire index i is `commits[i-1]`; index 0 is (ts, own, lo).
    /// `base` is the counter a bare commit index stands for. Sorted by (source index, ts).
    pub commits: Vec<(Ts, Source, u64)>,
}

impl Ctx {
    pub fn new(ts: Ts, own: Source, lo: u64) -> Ctx {
        Ctx { ts, own, lo, sources: Vec::new(), commits: Vec::new() }
    }
    fn index(&mut self, s: &Source) -> u64 {
        if *s == self.own {
            return 0;
        }
        if let Source::Derived(d) = s {
            self.index(&d.source); // the underlying source must be in the table first
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
            self.sources.iter().position(|x| x == s).unwrap() as u64 + 1
        }
    }
    /// Header representation of the sources table.
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
    /// Fill the commit table from a fragment: one entry per foreign (ts, source) in order of first appearance,
    /// base = smallest counter of that commit's stamps in the fragment (§3.3 rule 1).
    fn collect_commits(&mut self, f: &Frag) {
        let mut stamps = Vec::new();
        f.stamps(&mut stamps);
        for s in stamps {
            if s.ts == self.ts && s.dot.source == self.own {
                continue;
            }
            self.index(&s.dot.source);
            match self.commits.iter_mut().find(|(t, x, _)| *t == s.ts && *x == s.dot.source) {
                Some(c) => c.2 = c.2.min(s.dot.ctr),
                None => self.commits.push((s.ts, s.dot.source.clone(), s.dot.ctr)),
            }
        }
        let idx: Vec<u64> = self.commits.iter().map(|c| self.idx_of(&c.1)).collect();
        let mut order: Vec<usize> = (0..self.commits.len()).collect();
        order.sort_by_key(|&i| (idx[i], self.commits[i].0));
        self.commits = order.into_iter().map(|i| self.commits[i].clone()).collect();
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
    pub fn load_commits(&mut self, it: &Item) -> Result<(), Error> {
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

impl Frag {
    /// Every stamp carried by the fragment, in canonical encoding order.
    pub fn stamps(&self, out: &mut Vec<Stamp>) {
        fn elems(e: &BTreeMap<Dot, Elem>, out: &mut Vec<Stamp>) {
            for el in e.values() {
                out.extend(el.reset.iter().cloned());
                if let Some(f) = &el.frag {
                    f.stamps(out);
                }
            }
        }
        match self {
            Frag::Register { reset, write } => {
                out.extend(reset.iter().cloned());
                out.extend(write.iter().map(|w| w.0.clone()));
            }
            Frag::Bag { c, elems: e, .. } | Frag::Set { c, elems: e } => {
                out.extend(c.reset.iter().cloned());
                out.extend(explicit_w(self, c));
                elems(e, out);
            }
            Frag::Struct { c, fields } => {
                out.extend(c.reset.iter().cloned());
                out.extend(explicit_w(self, c));
                fields.values().for_each(|f| f.stamps(out));
            }
            Frag::Enum { c, case, payloads } => {
                out.extend(c.reset.iter().cloned());
                out.extend(explicit_w(self, c));
                out.extend(case.iter().map(|k| k.0.clone()));
                payloads.values().for_each(|f| f.stamps(out));
            }
            Frag::Map { c, entries } => {
                out.extend(c.reset.iter().cloned());
                out.extend(explicit_w(self, c));
                for en in entries.values() {
                    out.extend(en.reset.iter().cloned());
                    if let Some(f) = &en.frag {
                        f.stamps(out);
                    }
                }
            }
            Frag::Seq { c, elems: e, .. } => {
                out.extend(c.reset.iter().cloned());
                out.extend(explicit_w(self, c));
                for el in e.values() {
                    out.extend(el.created.iter().map(|c| c.0.clone()));
                    out.extend(el.pos.iter().map(|p| p.0.clone()));
                    out.extend(el.deleted.iter().map(|d| d.0.clone()));
                    // deleted elements never carry content (§3.3 rule 5)
                    if let (Content::Frag(f), false) = (&el.content, is_deleted(el)) {
                        f.stamps(out);
                    }
                }
            }
        }
    }
}

// ------------------------------------------------------------------ encode

fn enc_dot(d: &Dot, cx: &mut Ctx) -> Item {
    let i = cx.index(&d.source);
    if i == 0 {
        u(d.ctr)
    } else {
        Item::Array(vec![u(i), u(d.ctr)])
    }
}
fn enc_stamp(s: &Stamp, cx: &mut Ctx) -> Item {
    let (ci, base) = cx.commit_index(s.ts, &s.dot.source).expect("commit table collected");
    if s.dot.ctr == base {
        u(ci)
    } else {
        Item::Array(vec![u(ci), u(s.dot.ctr)])
    }
}
fn enc_opt_stamp(s: &Option<Stamp>, cx: &mut Ctx) -> Item {
    Item::Array(s.iter().map(|s| enc_stamp(s, cx)).collect())
}
/// Rule 4: `W` goes on the wire iff it is greater than every presence-counting stamp inside (or there is none).
fn explicit_w(f: &Frag, c: &Composite) -> Option<Stamp> {
    c.w.clone().filter(|w| f.inner_max(true).map_or(true, |m| *w > m))
}
fn enc_w(f: &Frag, c: &Composite, cx: &mut Ctx) -> Item {
    Item::Array(explicit_w(f, c).iter().map(|w| enc_stamp(w, cx)).collect())
}
fn enc_anchor(a: &Anchor, cx: &mut Ctx) -> Item {
    match a {
        Anchor::Head => u(0),
        Anchor::Dot(d) => enc_dot(d, cx),
    }
}
fn enc_elems(elems: &BTreeMap<Dot, Elem>, cx: &mut Ctx) -> Item {
    Item::Array(
        elems
            .iter()
            .map(|(d, e)| Item::Array(vec![enc_dot(d, cx), enc_opt_stamp(&e.reset, cx), Item::Array(e.frag.iter().map(|f| encode(f, cx)).collect())]))
            .collect(),
    )
}

/// Encode a fragment; `cx.commits` must have been collected (see `encode_delta`), or be empty when every stamp
/// is the own commit's.
pub fn encode(f: &Frag, cx: &mut Ctx) -> Item {
    if cx.commits.is_empty() {
        cx.collect_commits(f);
    }
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
        Frag::Bag { c, elems, .. } | Frag::Set { c, elems } => Item::Array(vec![enc, enc_opt_stamp(&c.reset, cx), enc_w(f, c, cx), enc_elems(elems, cx)]),
        Frag::Struct { c, fields } => {
            let m = fields.iter().map(|(k, v)| (u(*k), encode(v, cx))).collect();
            Item::Array(vec![enc, enc_opt_stamp(&c.reset, cx), enc_w(f, c, cx), cbor::sorted_map(m)])
        }
        Frag::Enum { c, case, payloads } => {
            let case_i = Item::Array(case.iter().map(|(s, id)| Item::Array([enc_stamp(s, cx)].into_iter().chain(id.map(u)).collect())).collect());
            let m = payloads.iter().map(|(k, v)| (u(*k), encode(v, cx))).collect();
            Item::Array(vec![enc, enc_opt_stamp(&c.reset, cx), enc_w(f, c, cx), case_i, cbor::sorted_map(m)])
        }
        Frag::Map { c, entries } => {
            let es = entries
                .iter()
                .map(|(d, e)| {
                    let mut a = vec![enc_dot(d, cx), enc_opt_stamp(&e.reset, cx)];
                    a.extend(e.key.iter().map(|k| k.to_item()));
                    a.push(Item::Array(e.frag.iter().map(|f| encode(f, cx)).collect()));
                    Item::Array(a)
                })
                .collect();
            Item::Array(vec![enc, enc_opt_stamp(&c.reset, cx), enc_w(f, c, cx), Item::Array(es)])
        }
        Frag::Seq { text, c, elems } => Item::Array(vec![enc, enc_opt_stamp(&c.reset, cx), enc_w(f, c, cx), enc_runs(*text, elems, cx)]),
    }
}

fn creation(_d: &Dot, e: &SeqElem) -> Option<(Stamp, Anchor)> {
    e.created.clone()
}
fn is_deleted(e: &SeqElem) -> bool {
    e.deleted.as_ref().map_or(false, |d| d.1)
}
/// Content goes on the wire only for elements that are not deleted (§3.3 rule 3).
fn has_content(e: &SeqElem) -> bool {
    !is_deleted(e) && !matches!(e.content, Content::None)
}
fn carries(e: &SeqElem) -> bool {
    is_deleted(e) || !matches!(e.content, Content::None)
}

fn enc_runs(text: bool, elems: &BTreeMap<Dot, SeqElem>, cx: &mut Ctx) -> Item {
    let v: Vec<(&Dot, &SeqElem)> = elems.iter().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < v.len() {
        let (d0, e0) = v[i];
        let cr = creation(d0, e0);
        let mut n = 1;
        while i + n < v.len() {
            let (d, e) = v[i + n];
            let (dp, _) = v[i + n - 1];
            if d.source != d0.source || d.ctr != dp.ctr + 1 || carries(e) != carries(e0) {
                break;
            }
            let ok = match &cr {
                Some(_) => matches!(creation(d, e), Some((_, Anchor::Dot(a))) if a == *dp),
                None => creation(d, e).is_none() && e.pos.is_empty() && e0.pos.is_empty() && e.deleted == e0.deleted,
            };
            if !ok {
                break;
            }
            n += 1;
        }
        let run = &v[i..i + n];
        let first = enc_dot(d0, cx);
        let creation_i = match &cr {
            None => Item::Array(vec![]),
            Some((_, a)) => {
                // segments of consecutive elements created by the same commit
                let mut segs: Vec<(u64, u64)> = Vec::new();
                for (d, e) in run {
                    let ts = creation(d, e).unwrap().0.ts;
                    let (ci, _) = cx.commit_index(ts, &d.source).expect("commit table collected");
                    match segs.last_mut() {
                        Some((c, k)) if *c == ci => *k += 1,
                        _ => segs.push((ci, 1)),
                    }
                }
                Item::Array(vec![enc_anchor(a, cx), Item::Array(segs.into_iter().map(|(c, k)| Item::Array(vec![u(c), u(k)])).collect())])
            }
        };
        let content = if !carries(e0) {
            Item::Array(vec![])
        } else if text {
            Item::Text(run.iter().filter(|(_, e)| has_content(e)).map(|(_, e)| match &e.content {
                Content::Char(c) => *c,
                _ => unreachable!(),
            }).collect())
        } else {
            Item::Array(run.iter().filter(|(_, e)| has_content(e)).map(|(_, e)| match &e.content {
                Content::Frag(f) => encode(f, cx),
                _ => unreachable!(),
            }).collect())
        };
        let mut posw = Vec::new();
        for (k, (d, e)) in run.iter().enumerate() {
            for p in &e.pos {
                if p.0.dot != **d {
                    posw.push(Item::Array(vec![u(k as u64), enc_stamp(&p.0, cx), enc_anchor(&p.1, cx)]));
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
        i += n;
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
        [f] => Ok(Some(Box::new(decode(f, cx)?))),
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
        if last.as_ref().map_or(false, |l| *l >= d) {
            return Err(Error::Bad("elem order"));
        }
        last = Some(d.clone());
        m.insert(d, Elem { reset: dec_opt_stamp(&a[1], cx)?, frag: dec_opt_frag(&a[2], cx)? });
    }
    Ok(m)
}
fn dec_fields(it: &Item, cx: &Ctx) -> Result<BTreeMap<u64, Frag>, Error> {
    let mut m = BTreeMap::new();
    for (k, v) in it.map()? {
        m.insert(k.uint()?, decode(v, cx)?);
    }
    Ok(m)
}
fn composite(a: &[Item], cx: &Ctx) -> Result<Composite, Error> {
    Ok(Composite { reset: dec_opt_stamp(&a[1], cx)?, w: dec_opt_stamp(&a[2], cx)? })
}

/// Decode a fragment.
pub fn decode(it: &Item, cx: &Ctx) -> Result<Frag, Error> {
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
                [c] => {
                    match c.array()? {
                        [s] => Some((dec_stamp(s, cx)?, None)),
                        [s, id] => Some((dec_stamp(s, cx)?, Some(id.uint()?))),
                        _ => return Err(Error::Bad("case")),
                    }
                }
                _ => return Err(Error::Bad("case")),
            };
            Frag::Enum { c: composite(a, cx)?, case, payloads: dec_fields(&a[4], cx)? }
        }
        (6, 4) => Frag::Set { c: composite(a, cx)?, elems: dec_elems(&a[3], cx)? },
        (7, 4) => {
            let mut entries = BTreeMap::new();
            let mut last: Option<Dot> = None;
            for e in a[3].array()? {
                let x = e.array()?;
                let (key, frag) = match x.len() {
                    3 => (None, dec_opt_frag(&x[2], cx)?),
                    4 => (Some(Value::from_item(&x[2])?), dec_opt_frag(&x[3], cx)?),
                    _ => return Err(Error::Bad("entry")),
                };
                if key.is_some() && frag.is_none() {
                    return Err(Error::Bad("tombstone with key"));
                }
                let d = dec_dot(&x[0], cx)?;
                if last.as_ref().map_or(false, |l| *l >= d) {
                    return Err(Error::Bad("entry order"));
                }
                last = Some(d.clone());
                entries.insert(d, Entry { reset: dec_opt_stamp(&x[1], cx)?, key, frag });
            }
            Frag::Map { c: composite(a, cx)?, entries }
        }
        (8 | 9, 4) => Frag::Seq { text: enc == 9, c: composite(a, cx)?, elems: dec_runs(enc == 9, &a[3], cx)? },
        _ => return Err(Error::Bad("encoding or arity")),
    };
    Ok(f)
}

fn dec_runs(text: bool, it: &Item, cx: &Ctx) -> Result<BTreeMap<Dot, SeqElem>, Error> {
    let mut m: BTreeMap<Dot, SeqElem> = BTreeMap::new();
    let mut last: Option<Dot> = None;
    for r in it.array()? {
        let a = r.array()?;
        if a.len() != 6 {
            return Err(Error::Bad("run"));
        }
        let first = dec_dot(&a[0], cx)?;
        let n = nonzero(a[1].uint()?)? as usize;
        if n > 1 << 24 {
            return Err(Error::Bad("run length"));
        }
        if last.as_ref().map_or(false, |l| *l >= first) {
            return Err(Error::Bad("run order"));
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
                        e.pos.push((st, prev));
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
        for p in a[4].array()? {
            let p = p.array()?;
            if p.len() != 3 {
                return Err(Error::Bad("posw"));
            }
            let i = p[0].uint()? as usize;
            if i >= n {
                return Err(Error::Bad("posw index"));
            }
            elems[i].pos.push((dec_stamp(&p[1], cx)?, dec_anchor(&p[2], cx)?));
        }
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
            for e in &mut elems[i..=j] {
                e.deleted = crate::state::max_pair(e.deleted.take(), Some((s.clone(), b)));
            }
        }
        let live: Vec<usize> = (0..n).filter(|i| !is_deleted(&elems[*i])).collect();
        match &a[3] {
            Item::Array(v) if v.is_empty() => {}
            Item::Text(s) if text => {
                let cs: Vec<char> = s.chars().collect();
                if cs.len() != live.len() {
                    return Err(Error::Bad("content length"));
                }
                for (k, i) in live.iter().enumerate() {
                    elems[*i].content = Content::Char(cs[k]);
                }
            }
            Item::Array(v) if !text => {
                if v.len() != live.len() {
                    return Err(Error::Bad("content length"));
                }
                for (k, i) in live.iter().enumerate() {
                    elems[*i].content = Content::Frag(Box::new(decode(&v[k], cx)?));
                }
            }
            _ => return Err(Error::Bad("content")),
        }
        for (i, mut e) in elems.into_iter().enumerate() {
            let d = Dot { source: first.source.clone(), ctr: first.ctr + i as u64 };
            e.pos.sort_by(|a, b| b.0.cmp(&a.0));
            e.pos.dedup_by(|a, b| a.0 == b.0);
            e.pos.truncate(2);
            last = Some(d.clone());
            m.insert(d, e);
        }
    }
    Ok(m)
}

/// Full delta: `[nonce, Commits, Fragment]` (§3.2). Fills `cx.sources` (header table) and `cx.commits`.
pub fn encode_delta(f: &Frag, nonce: [u8; 16], cx: &mut Ctx) -> Vec<u8> {
    cx.commits.clear();
    cx.collect_commits(f);
    let frag = encode(f, cx);
    cbor::encode(&Item::Array(vec![Item::Bytes(nonce.to_vec()), cx.commits_item(), frag]))
}
/// `cx` carries ts, own, lo and the header's sources table; the commit table is read from the delta.
pub fn decode_delta(bytes: &[u8], cx: &mut Ctx) -> Result<Frag, Error> {
    let it = cbor::decode(bytes)?;
    match it.array()? {
        [Item::Bytes(n), commits, f] if n.len() == 16 => {
            cx.load_commits(commits)?;
            decode(f, cx)
        }
        _ => Err(Error::Bad("delta")),
    }
}

/// Snapshot delta: `[nonce, Commits, Fragment, Frontiers]`, `Frontiers := [[Src, ctr]*]` sorted by `Src`, one entry
/// per `Node` source (§8). The caller strips the values of expiring commits first (§4.7). Frontier sources enter
/// the header table after the fragment's.
pub fn encode_snapshot(f: &Frag, frontiers: &[(Source, u64)], nonce: [u8; 16], cx: &mut Ctx) -> Vec<u8> {
    cx.commits.clear();
    cx.collect_commits(f);
    let frag = encode(f, cx);
    let mut fr: Vec<(u64, u64)> = frontiers
        .iter()
        .map(|(s, c)| {
            assert!(matches!(s, Source::Node(_)) && *c >= 1, "frontiers name node sources");
            (cx.index(s), *c)
        })
        .collect();
    fr.sort();
    let fr = Item::Array(fr.into_iter().map(|(i, c)| Item::Array(vec![u(i), u(c)])).collect());
    cbor::encode(&Item::Array(vec![Item::Bytes(nonce.to_vec()), cx.commits_item(), frag, fr]))
}

pub fn decode_snapshot(bytes: &[u8], cx: &mut Ctx) -> Result<(Frag, Vec<(Source, u64)>), Error> {
    let it = cbor::decode(bytes)?;
    match it.array()? {
        [Item::Bytes(n), commits, f, fr] if n.len() == 16 => {
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
            Ok((frag, out))
        }
        _ => Err(Error::Bad("snapshot")),
    }
}
