//! `crdt/deltas.vec`: delta and snapshot bytes (spec/crdt.md §3, §8) as osis-crdt writes them,
//! with what they read as, and rejections (§2.3, §3.3 rule 7). Case fields: `kind` (`writer` or
//! `snapshot`), the header facts `ts`, `own` (the delta's own source: a 15-byte tid, or a 32-byte
//! commit ID for commit form) and, for a writer, `range` (`lo,hi`); then `delta` (the bytes) with
//! `pages` (page plaintexts, comma-separated; a page link's content hash is the unkeyed BLAKE3 of
//! its plaintext) and `read` (canonical bytes of the read, or `absent`; `read-blake3` their
//! unkeyed BLAKE3 above 1 KiB), or `reject` (a rule ID: core/test/vectors/README.md).

use crate::file::{Record, VecFile};
use crate::subjects::generated_header;
use crate::subjects::case;
use crate::{hex, unhex, xof};
use osis_base::{Classified, CommitId, ErrorClass, Tid, Ts, Value};
use osis_crdt::{
    Batch, CounterRange, DeltaCtx, DeltaKind, Encoding, Fragment, Frontiers, Interner, MemoryPages, Op, PageSink, PageSource, PathOp, SESSION_NONCE_LEN, Session, Snapshot, Source, Undone, View, Writer, decode_delta, decode_snapshot,
    encode_delta, encode_snapshot, undo,
};
use std::borrow::Cow;
use std::collections::BTreeMap;

const SPEC: &str = "spec/crdt.md §3, §8";

/// A position's view: its encoding (`None`: `any`, the value's kind decides); children `any`.
#[derive(Clone, Copy)]
struct V(Option<Encoding>);

impl View for V {
    fn encoding(&self) -> Option<Encoding> {
        self.0
    }
    fn project<'a>(&self, v: &'a Value) -> Option<Cow<'a, Value>> {
        Some(Cow::Borrowed(v))
    }
    fn field(&self, _: u64) -> Option<V> {
        Some(V(None))
    }
    fn field_default(&self, _: u64) -> Option<Value> {
        None
    }
    fn case(&self, _: u64) -> Option<V> {
        Some(V(None))
    }
    fn element(&self) -> Option<V> {
        Some(V(None))
    }
    fn key(&self) -> Option<V> {
        Some(V(None))
    }
}

fn tid(n: u8) -> Tid {
    Tid::from_bytes([n; 15])
}
fn ts(wall: u64) -> Ts {
    Ts::from_u64(wall << 16).unwrap()
}
fn i(n: i64) -> Value {
    Value::Int(n)
}
fn l(v: Vec<Value>) -> Value {
    Value::List(v)
}
fn s(x: &str) -> Value {
    Value::Str(x.into())
}

/// One writer commit: session `n` (or commit `c` in commit form) at wall `wall`, counters from `lo`.
struct W {
    own: Source,
    own_bytes: Vec<u8>,
    ts: Ts,
    lo: u64,
}

/// Session `n` of node `n` (tid and nonce bytes all `n`).
fn session(n: u8) -> Session {
    Session { node: tid(n), nonce: [n; SESSION_NONCE_LEN] }
}

fn writer(n: u8, wall: u64, lo: u64) -> W {
    W { own: Source::session(session(n)), own_bytes: session(n).to_bytes().to_vec(), ts: ts(wall), lo }
}

/// Applies `ops` under `view` to `state`; the delta and its range.
fn write(state: &Fragment, w: &W, view: V, ops: Vec<PathOp>) -> (Fragment, CounterRange) {
    let mut b = Batch::new(state, Writer::new(w.ts, w.own.clone(), w.lo));
    for op in &ops {
        b.apply(op, &view).unwrap();
    }
    b.finish().unwrap()
}

fn root(op: Op) -> PathOp {
    PathOp { path: Vec::new(), op }
}

/// What a fragment reads as: `read` (canonical bytes, or `absent`), or `read-blake3` (their
/// unkeyed BLAKE3) above 1 KiB.
fn read_field(r: Record, v: Option<Value>) -> Record {
    match v.map(|v| osis_base::encode(&v)) {
        None => r.with("read", "absent"),
        Some(b) if b.len() > 1024 => r.with("read-blake3", hex(&osis_base::hash::hash(&b))),
        Some(b) => r.with("read", hex(&b)),
    }
}

fn pages_field(p: &[Vec<u8>]) -> String {
    p.iter().map(|x| hex(x)).collect::<Vec<_>>().join(",")
}

/// Page plaintexts in the order they were written.
#[derive(Default)]
struct Pages(Vec<Vec<u8>>, MemoryPages);

impl PageSink for Pages {
    fn put(&mut self, plaintext: &[u8]) -> Result<osis_base::Link, osis_crdt::PageError> {
        self.0.push(plaintext.to_vec());
        self.1.put(plaintext)
    }
}

/// A writer's delta case; checks it decodes back to itself.
fn writer_case(name: &str, spec: &str, w: &W, range: CounterRange, f: Fragment) -> Record {
    let cx = DeltaCtx { ts: w.ts, own: w.own.clone(), range, kind: DeltaKind::Writer };
    let d = osis_crdt::Delta { nonce: [7; 16], fragment: f };
    let bytes = encode_delta(&d, &cx, None).unwrap();
    assert_eq!(decode_delta(&bytes, &cx, &mut Interner::new(), None).unwrap(), d, "{name}");
    let mut st = Fragment::default();
    st.join(d.fragment);
    read_field(head(name, spec, "writer", w, Some(range)).with("delta", hex(&bytes)), st.read())
}

fn head(name: &str, spec: &str, kind: &str, w: &W, range: Option<CounterRange>) -> Record {
    let r = case(name, spec).with("kind", kind).with("ts", w.ts.to_u64().to_string()).with("own", hex(&w.own_bytes));
    match range {
        Some(c) => r.with("range", format!("{},{}", c.lo, c.hi)),
        None => r,
    }
}

/// A snapshot case by session 9 at wall 100 of `state`; checks it decodes back to itself.
fn snapshot_case(name: &str, spec: &str, state: &Fragment, frontiers: Frontiers, absorbed: BTreeMap<CommitId, Tid>) -> Record {
    let w = writer(9, 100, 0);
    let cx = DeltaCtx { ts: w.ts, own: w.own.clone(), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
    let snap = Snapshot { nonce: [3; 16], fragment: state.clone(), frontiers, absorbed };
    let mut pages = Pages::default();
    let bytes = encode_snapshot(&snap, &cx, Some(&mut pages)).unwrap();
    let back = decode_snapshot(&bytes, &cx, &mut Interner::new(), Some(&mut pages.1)).unwrap();
    assert_eq!(back.fragment.read(), state.read(), "{name}");
    let r = head(name, spec, "snapshot", &w, None).with("delta", hex(&bytes));
    let r = if pages.0.is_empty() { r } else { r.with("pages", pages_field(&pages.0)) };
    read_field(r, state.read())
}

/// A rejected input: `bytes` under the header of `w` (`range` for a writer).
fn reject_case(name: &str, spec: &str, w: &W, range: Option<CounterRange>, bytes: Vec<u8>, rule: &str) -> Record {
    let kind = if range.is_some() { "writer" } else { "snapshot" };
    let r = head(name, spec, kind, w, range).with("delta", hex(&bytes)).with("reject", rule);
    decode(&r).expect_err(name);
    r
}

fn delta_bytes(sources: Vec<Value>, commits: Vec<Value>, f: Value) -> Vec<u8> {
    osis_base::encode(&l(vec![Value::Bytes(vec![7; 16]), l(sources), l(commits), f]))
}
fn snapshot_bytes(sources: Vec<Value>, commits: Vec<Value>, f: Value) -> Vec<u8> {
    osis_base::encode(&l(vec![Value::Bytes(vec![3; 16]), l(sources), l(commits), f, l(vec![]), l(vec![])]))
}

pub fn deltas() -> VecFile {
    let mut cases = Vec::new();
    let text = V(Some(Encoding::Text));
    let any = V(None);

    // writer deltas
    let a1 = writer(1, 10, 1);
    let (typed, r1) = write(&Fragment::default(), &a1, text, vec![root(Op::Insert { at: 0, items: vec![s("FOOBAR")] })]);
    cases.push(writer_case("text typing: one creation run", "spec/crdt.md §3.2, §5.7", &a1, r1, typed.clone()));
    let mut st = typed.clone();
    let a2 = writer(1, 11, r1.hi);
    let (del, r2) = write(&st, &a2, text, vec![root(Op::Delete { at: 1, len: 3 })]);
    cases.push(writer_case("text delete: one flag range at the delta stamp", "spec/crdt.md §2.3, §3.2, §5.7", &a2, r2, del.clone()));
    st.join(del.clone());
    // undoing the delete: an undelete, its chars in the `FlagW` string
    let a4 = writer(1, 12, r2.hi);
    let mut wu = Writer::new(a4.ts, a4.own.clone(), a4.lo);
    let undone = Undone { delta: &del, source: &a2.own, range: r2 };
    let und = undo(&mut wu, &undone, &st, &typed, &text).unwrap().unwrap();
    cases.push(writer_case("text undelete: the chars ride the flag write", "spec/crdt.md §3.2, §5.7", &a4, wu.range(), und));
    let b1 = writer(2, 12, 1);
    let (ins, rb) = write(&st, &b1, text, vec![root(Op::Insert { at: 1, items: vec![s("xy")] })]);
    cases.push(writer_case("text insert anchored at another writer's element", "spec/crdt.md §3.2, §5.7", &b1, rb, ins.clone()));
    st.join(ins);

    let m = Value::Map([(s("a"), i(1)), (s("b"), l(vec![i(1), i(2)])), (s("c"), Value::Enum(2, Some(Box::new(s("z")))))].into_iter().collect());
    let a3 = writer(1, 13, 1);
    let (put, r3) = write(&Fragment::default(), &a3, any, vec![root(Op::Set(m))]);
    cases.push(writer_case("map of a register, a list and an enum", "spec/crdt.md §3.2, §5.4, §5.6, §5.7", &a3, r3, put));
    let set = Value::Set([i(1), i(2), s("x")].into_iter().collect());
    let (sf, rs) = write(&Fragment::default(), &a3, any, vec![root(Op::Set(set))]);
    cases.push(writer_case("set: element values at the delta stamp", "spec/crdt.md §2.3, §3.2, §5.5", &a3, rs, sf));
    let (cf, rc) = write(&Fragment::default(), &a3, V(Some(Encoding::Counter)), vec![root(Op::Inc(i(5)))]);
    cases.push(writer_case("counter contribution", "spec/crdt.md §3.2, §5.2", &a3, rc, cf));
    let (ef, re) = write(&Fragment::default(), &a3, any, vec![root(Op::Set(Value::Set(Default::default())))]);
    cases.push(writer_case("empty set: explicit W", "spec/crdt.md §3.3, §4.3", &a3, re, ef));
    let c = CommitId([0xc1; 32]);
    let cw = W { own: Source::commit(c), own_bytes: c.0.to_vec(), ts: ts(14), lo: 1 };
    let (cr, rcr) = write(&Fragment::default(), &cw, any, vec![root(Op::Replace(s("hello")))]);
    cases.push(writer_case("commit form: register replace", "spec/crdt.md §2.1, §5.1", &cw, rcr, cr.clone()));

    // snapshots
    let fr = |ns: &[(u8, u64)]| Frontiers { sessions: ns.iter().map(|(n, c)| (session(*n), *c)).collect() };
    cases.push(snapshot_case("snapshot of two writers' text: runs, segments, Commits and base", "spec/crdt.md §3.2, §3.3, §8", &st, fr(&[(1, r2.hi - 1), (2, rb.hi - 1)]), BTreeMap::new()));
    let mut slots = Fragment::default();
    let (reg, _) = write(&slots, &writer(1, 20, 1), any, vec![root(Op::Set(s("abc")))]);
    slots.join(reg);
    let (tx, rt) = write(&slots, &writer(2, 21, 1), text, vec![root(Op::Insert { at: 0, items: vec![s("Q")] })]);
    slots.join(tx);
    cases.push(snapshot_case("snapshot of a register and a text at one position: Slots", "spec/crdt.md §3.2, §7, §8", &slots, fr(&[(1, 1), (2, rt.hi - 1)]), BTreeMap::new()));
    let mut absorbed = Fragment::default();
    absorbed.join(cr);
    cases.push(snapshot_case("snapshot absorbing a commit-form commit", "spec/crdt.md §8", &absorbed, Frontiers::default(), BTreeMap::from([(c, tid(1))])));
    let big = Value::Set(xof("osis crdt pages", 136 * 512).chunks(512).map(|x| Value::Bytes(x.to_vec())).collect());
    let (bf, _) = write(&Fragment::default(), &writer(1, 30, 1), any, vec![root(Op::Set(big))]);
    let mut paged = Fragment::default();
    paged.join(bf);
    cases.push(snapshot_case("paged snapshot: a set above PAGE_TARGET", "spec/crdt.md §8, spec/wire.md §6", &paged, fr(&[(1, 136)]), BTreeMap::new()));

    // rejections
    let wr = |lo, hi| Some(CounterRange { lo, hi });
    let w = writer(1, 10, 3);
    let reg_at = |stamp: Value| l(vec![i(0), l(vec![]), stamp, i(1)]);
    cases.push(reject_case("register value off the delta stamp", "spec/crdt.md §2.3, §3.3", &w, wr(3, 6), delta_bytes(vec![], vec![], reg_at(l(vec![i(0), i(4)]))), "delta-stamp"));
    let set_of = |elems: Vec<Value>| l(vec![i(6), l(vec![]), l(vec![]), l(elems)]);
    let elem = |d: Value, ci: i64, v: i64| l(vec![d, l(vec![]), l(vec![l(vec![i(0), l(vec![]), i(ci), i(v)])])]);
    cases.push(reject_case("set elements unsorted", "spec/crdt.md §3.3", &w, wr(3, 6), delta_bytes(vec![], vec![], set_of(vec![elem(i(4), 0, 1), elem(i(3), 0, 2)])), "non-canonical"));
    let slot_reg = l(vec![i(0), l(vec![]), i(0), i(1)]);
    cases.push(reject_case("Slots in a writer's delta", "spec/crdt.md §3.3, §7", &w, wr(3, 6), delta_bytes(vec![], vec![], l(vec![i(10), l(vec![slot_reg]), l(vec![set_of(vec![elem(i(3), 0, 1)])])])), "slots"));
    let run0 = l(vec![i(3), i(0), l(vec![i(0), l(vec![l(vec![i(0), i(0)])])]), s(""), l(vec![]), l(vec![])]);
    cases.push(reject_case("run of zero elements", "spec/crdt.md §3.3", &w, wr(3, 6), delta_bytes(vec![], vec![], l(vec![i(9), l(vec![]), l(vec![]), l(vec![run0])])), "run-length"));
    let deep = (0..64).fold(i(1), |v, _| l(vec![v]));
    let st64 = l(vec![i(4), l(vec![]), l(vec![]), Value::Map([(i(1), l(vec![i(0), l(vec![]), i(0), deep]))].into_iter().collect())]);
    cases.push(reject_case("a value 64 deep below a struct field reads 65 deep", "spec/crdt.md §3.3, spec/data-model.md §5", &w, wr(3, 6), delta_bytes(vec![], vec![], st64), "read-depth"));
    // snapshots by session 9 at wall 100 of session 1's commit at wall 5, base 3
    let sw = writer(9, 100, 0);
    let n1 = || Value::Bytes(session(1).to_bytes().to_vec());
    let c1 = || l(vec![i(1), l(vec![l(vec![i(5), i(0), i(3)])])]);
    let reg_rs = l(vec![i(0), l(vec![i(1)]), l(vec![i(1), i(4)]), i(7)]);
    cases.push(reject_case("register reset below its own write", "spec/crdt.md §3.3, §4.2, §5.1", &sw, None, snapshot_bytes(vec![n1()], vec![c1()], reg_rs), "prune"));
    let pruned_child = l(vec![i(4), l(vec![l(vec![i(1), i(4)])]), l(vec![]), Value::Map([(i(1), l(vec![i(0), l(vec![]), i(1), i(7)]))].into_iter().collect())]);
    cases.push(reject_case("struct field below the struct's reset", "spec/crdt.md §3.3, §4.2", &sw, None, snapshot_bytes(vec![n1()], vec![c1()], pruned_child), "prune"));
    let n3 = Value::Bytes(session(3).to_bytes().to_vec());
    let c3 = l(vec![i(2), l(vec![l(vec![i(5), i(0), i(1)])])]);
    let foreign_value = set_of(vec![elem(l(vec![i(1), i(3)]), 1, 1)]);
    cases.push(reject_case("set element value written by another source", "spec/crdt.md §3.3, §5.5", &sw, None, snapshot_bytes(vec![n1(), n3], vec![c3], foreign_value), "element-source"));
    let bare = l(vec![i(3), i(2), l(vec![]), l(vec![]), l(vec![]), l(vec![])]);
    cases.push(reject_case("bare-anchor run in a writer's delta", "spec/crdt.md §3.3, §5.7", &w, wr(3, 6), delta_bytes(vec![], vec![], l(vec![i(9), l(vec![]), l(vec![]), l(vec![bare])])), "bare-anchor"));
    let text_runs = |run: Value| delta_bytes(vec![], vec![], l(vec![i(9), l(vec![]), l(vec![]), l(vec![run])]));
    let chars_only = l(vec![i(3), i(2), l(vec![]), s("ab"), l(vec![]), l(vec![])]);
    cases.push(reject_case("text chars without a creation", "spec/crdt.md §3.2, §3.3, §5.7", &w, wr(3, 6), text_runs(chars_only), "content-creation"));
    let del_chars = l(vec![i(3), i(1), l(vec![]), l(vec![]), l(vec![]), l(vec![l(vec![i(0), i(0), i(0), Value::Bool(true), s("a")])])]);
    cases.push(reject_case("chars on a delete's flag write", "spec/crdt.md §3.2, §3.3", &w, wr(3, 6), text_runs(del_chars), "flag-chars"));
    let short = l(vec![i(3), i(2), l(vec![]), l(vec![]), l(vec![]), l(vec![l(vec![i(0), i(1), i(0), Value::Bool(false), s("a")])])]);
    cases.push(reject_case("undelete chars short of the range", "spec/crdt.md §3.2, §3.3", &w, wr(3, 6), text_runs(short), "flag-chars"));

    VecFile { header: generated_header("crdt", SPEC), cases }
}

/// Decodes a case's `delta` under its header; the read.
fn decode(c: &Record) -> Result<Option<Value>, osis_crdt::Error> {
    let tsv = Ts::from_u64(c.req("ts").unwrap().parse().unwrap()).unwrap();
    let own = unhex(c.req("own").unwrap()).unwrap();
    let own = match <[u8; 31]>::try_from(own.as_slice()) {
        Ok(s) => Source::session(Session::from_bytes(&s)),
        Err(_) => Source::commit(CommitId(own.as_slice().try_into().unwrap())),
    };
    let bytes = unhex(c.req("delta").unwrap()).unwrap();
    let mut pages = MemoryPages::new();
    for p in c.get("pages").unwrap_or("").split(',').filter(|p| !p.is_empty()) {
        pages.put(&unhex(p).unwrap()).unwrap();
    }
    let mut st = Fragment::default();
    if c.req("kind").unwrap() == "writer" {
        let (lo, hi) = c.req("range").unwrap().split_once(',').unwrap();
        let cx = DeltaCtx { ts: tsv, own, range: CounterRange { lo: lo.parse().unwrap(), hi: hi.parse().unwrap() }, kind: DeltaKind::Writer };
        st.join(decode_delta(&bytes, &cx, &mut Interner::new(), Some(&mut pages as &mut dyn PageSource))?.fragment);
    } else {
        let cx = DeltaCtx { ts: tsv, own, range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
        st.join(decode_snapshot(&bytes, &cx, &mut Interner::new(), Some(&mut pages as &mut dyn PageSource))?.fragment);
    }
    Ok(st.read())
}

pub fn check(f: &VecFile) -> Result<(), String> {
    for c in f.live() {
        let name = c.name();
        let want = c.get("read").or(c.get("read-blake3"));
        match (decode(c), c.get("reject"), want) {
            (Ok(v), None, Some(r)) => {
                let got = read_field(Record::new(), v);
                let got = got.get("read").or(got.get("read-blake3")).unwrap_or_default().to_string();
                if got != r {
                    return Err(format!("{name}: reads {got}, expected {r}"));
                }
            }
            (Err(e), Some(_), None) if e.class() == ErrorClass::BadInput => {}
            (Err(e), _, _) => return Err(format!("{name}: rejected ({e})")),
            (Ok(_), Some(r), _) => return Err(format!("{name}: accepted, expected rejection {r}")),
            _ => return Err(format!("{name}: needs exactly one of read, reject")),
        }
    }
    Ok(())
}
