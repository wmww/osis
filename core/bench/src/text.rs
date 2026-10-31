//! Text editing traces replayed through osis-crdt (notes/crdt.md, Text size): a seeded synthetic
//! typist shaped like the automerge-paper trace, or that trace itself (`OSIS_TEXT_TRACE`, the
//! `pos \t del \t "ins"` lines `core/test/crdt-model/src/bin/text_bench.rs` reads).

use osis_base::{Tid, Ts, Value};
use osis_crdt::{Batch, DeltaCtx, DeltaKind, Fragment, Frontiers, Op, PathOp, Snapshot, Source, View, Writer, encode_snapshot};

/// One edit: delete `del` chars at `pos`, then insert `ins` there.
pub struct Edit {
    pub pos: usize,
    pub del: usize,
    pub ins: String,
}

/// `n` single-char edits of a typist: typing at the cursor, backspace bursts (about 30% of the
/// edits, as in the automerge-paper trace), an occasional jump of the cursor. Deterministic in
/// `seed`. Its shape, not the paper trace's, sets the synthetic budget.
pub fn synthetic(n: usize, seed: u64) -> Vec<Edit> {
    let mut x = seed | 1;
    let mut next = move |m: usize| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        (x % m.max(1) as u64) as usize
    };
    let (mut len, mut cur, mut burst) = (0usize, 0usize, 0usize);
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        if burst == 0 && next(1000) < 5 {
            cur = next(len + 1);
        }
        if burst == 0 && next(1000) < 50 {
            burst = 1 + next(16);
        }
        if burst > 0 && cur > 0 {
            burst -= 1;
            out.push(Edit { pos: cur - 1, del: 1, ins: String::new() });
            len -= 1;
            cur -= 1;
        } else {
            burst = 0;
            let c = (b'a' + next(26) as u8) as char;
            out.push(Edit { pos: cur, del: 0, ins: c.to_string() });
            len += 1;
            cur += 1;
        }
    }
    out
}

/// The trace of `OSIS_TEXT_TRACE`, if set and readable.
pub fn from_env() -> Option<Vec<Edit>> {
    let s = std::fs::read_to_string(std::env::var("OSIS_TEXT_TRACE").ok()?).ok()?;
    s.lines()
        .map(|l| {
            let mut it = l.split('\t');
            let pos = it.next()?.parse().ok()?;
            let del = it.next()?.parse().ok()?;
            Some(Edit { pos, del, ins: unescape(it.next()?)? })
        })
        .collect()
}

/// Minimal JSON string unescape (`\"`, `\\`, `\n`, `\t`, `\r`, `\uXXXX`).
fn unescape(s: &str) -> Option<String> {
    let inner = s.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::new();
    let mut cs = inner.chars();
    while let Some(c) = cs.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match cs.next()? {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'u' => {
                let h: String = (0..4).filter_map(|_| cs.next()).collect();
                out.push(char::from_u32(u32::from_str_radix(&h, 16).ok()?)?);
            }
            x => out.push(x),
        }
    }
    Some(out)
}

/// The writer's view: a text aspect.
struct TextView;

impl View for TextView {
    fn encoding(&self) -> Option<osis_crdt::Encoding> {
        Some(osis_crdt::Encoding::Text)
    }
    fn project<'a>(&self, v: &'a Value) -> Option<std::borrow::Cow<'a, Value>> {
        Some(std::borrow::Cow::Borrowed(v))
    }
    fn field(&self, _: u64) -> Option<Self> {
        None
    }
    fn field_default(&self, _: u64) -> Option<Value> {
        None
    }
    fn case(&self, _: u64) -> Option<Self> {
        None
    }
    fn element(&self) -> Option<Self> {
        None
    }
    fn key(&self) -> Option<Self> {
        None
    }
}

/// Replays `edits` as one writer, `per_commit` edits per commit (net effect, spec/crdt.md §4.5),
/// one commit every 2 s. Returns the state and the number of commits.
pub fn replay(edits: &[Edit], per_commit: usize) -> (Fragment, usize) {
    let src = Source::node(Tid::from_bytes([1; 15]));
    let mut state = Fragment::default();
    let mut lo = 1;
    let mut commits = 0;
    for (k, chunk) in edits.chunks(per_commit.max(1)).enumerate() {
        let ts = Ts::from_u64((1_760_000_000_000u64 + k as u64 * 2000) << 16).unwrap_or_default();
        let mut b = Batch::new(&state, Writer::new(ts, src.clone(), lo));
        for e in chunk {
            if e.del > 0 {
                let _ = b.apply(&PathOp { path: vec![], op: Op::Delete { at: e.pos, len: e.del } }, &TextView);
            }
            if !e.ins.is_empty() {
                let _ = b.apply(&PathOp { path: vec![], op: Op::Insert { at: e.pos, items: vec![Value::Str(e.ins.clone())] } }, &TextView);
            }
        }
        if let Some((d, range)) = b.finish() {
            lo = range.hi;
            state.join(d);
            commits += 1;
        }
    }
    (state, commits)
}

/// The final text of a trace.
pub fn final_text(edits: &[Edit]) -> String {
    let mut t: Vec<char> = Vec::new();
    for e in edits {
        let end = (e.pos + e.del).min(t.len());
        t.splice(e.pos.min(t.len())..end, e.ins.chars());
    }
    t.into_iter().collect()
}

/// Counts the bytes of the pages written.
struct Counting(osis_crdt::MemoryPages, usize);

impl osis_crdt::PageSink for Counting {
    fn put(&mut self, p: &[u8]) -> Result<osis_base::Link, osis_crdt::PageError> {
        self.1 += p.len();
        self.0.put(p)
    }
    fn params(&self) -> osis_crdt::PageParams {
        self.0.params()
    }
}

/// Bytes of the state as a foreign node's snapshot (§8), pages included.
pub fn snapshot_len(state: &Fragment) -> usize {
    let cx = DeltaCtx { ts: Ts::from_u64(u64::MAX >> 2).unwrap_or_default(), own: Source::node(Tid::from_bytes([9; 15])), range: osis_crdt::CounterRange::EMPTY, kind: DeltaKind::Snapshot };
    let mut pages = Counting(osis_crdt::MemoryPages::new(), 0);
    let s = Snapshot { absorbed: Default::default(), nonce: [0; 16], fragment: state.clone(), frontiers: Frontiers::default() };
    encode_snapshot(&s, &cx, Some(&mut pages)).map(|b| b.len() + pages.1).unwrap_or(usize::MAX)
}
