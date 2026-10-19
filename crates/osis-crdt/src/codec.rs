//! Fragment, delta and snapshot encode/decode (spec/crdt.md §3.2, §3.3, §8).
//!
//! Decoding checks the grammar and the rules of §2.3 and §3.3 rule 7, then re-encodes the result
//! and requires the input bytes back: every canonical-form rule (table order, bare forms, sort
//! order, maximal runs, `W`) is enforced by that one comparison.

use crate::error::Error;
use crate::fragment::{Bag, CaseWrite, Elem, Encoding, Entry, Enum, Fragment, Map, Meta, RegWrite, Register, Set, Slots, Struct};
use crate::page::{PageSink, PageSource};
use crate::seq::{self, Seq};
use crate::stamp::{Dot, Interner, Source};
use crate::wire::{Dec, Delta, DeltaCtx, DeltaKind, Enc, Frontiers, NONCE_LEN, Snapshot, as_array, as_uint, uint};
use osis_core::format::{MAX_BLOB, MAX_OBJECT_DEPTH, MAX_VALUE_DEPTH};
use osis_core::{Limits, Value};
use std::collections::BTreeMap;

const LIMITS: Limits = Limits { max_depth: MAX_OBJECT_DEPTH, max_bytes: MAX_BLOB };

// ---- encode

fn opt_frag(cx: &mut Enc, f: Option<&Fragment>) -> Result<Value, Error> {
    Ok(Value::List(match f {
        Some(f) => vec![encode_fragment(cx, f)?],
        None => Vec::new(),
    }))
}

/// An element array (paged above `PAGE_TARGET`, §8).
pub(crate) fn elems_value(_cx: &mut Enc, items: Vec<Value>) -> Result<Value, Error> {
    Ok(Value::List(items))
}

fn encode_elems(cx: &mut Enc, elems: &BTreeMap<Dot, Elem>) -> Result<Value, Error> {
    let mut items = Vec::with_capacity(elems.len());
    for (d, e) in cx.sorted(elems) {
        let dot = cx.dot(d);
        let r = cx.opt_stamp(e.reset.as_ref());
        let f = opt_frag(cx, e.frag.as_deref())?;
        items.push(Value::List(vec![dot, r, f]));
    }
    elems_value(cx, items)
}

fn head(cx: &mut Enc, enc: Encoding, meta: &Meta) -> Vec<Value> {
    vec![uint(u64::from(enc.id())), cx.opt_stamp(meta.reset.as_ref()), cx.opt_stamp(meta.w.as_ref())]
}

fn encode_children(cx: &mut Enc, c: &BTreeMap<u64, Fragment>) -> Result<Value, Error> {
    let mut m = BTreeMap::new();
    for (k, f) in c {
        m.insert(uint(*k), encode_fragment(cx, f)?);
    }
    Ok(Value::Map(m))
}

fn encode_register(cx: &mut Enc, r: &Register) -> Value {
    let mut a = vec![uint(0), cx.opt_stamp(r.reset.as_ref())];
    if let Some(w) = &r.write {
        a.push(cx.stamp(&w.stamp));
        if let Some(v) = &w.value {
            a.push(v.clone());
        }
    }
    Value::List(a)
}

pub(crate) fn encode_fragment(cx: &mut Enc, f: &Fragment) -> Result<Value, Error> {
    Ok(match f {
        Fragment::Register(r) => encode_register(cx, r),
        Fragment::Bag(Bag { kind, meta, elems }) => {
            let mut a = head(cx, kind.encoding(), meta);
            a.push(encode_elems(cx, elems)?);
            Value::List(a)
        }
        Fragment::Set(Set { meta, elems }) => {
            let mut a = head(cx, Encoding::Set, meta);
            a.push(encode_elems(cx, elems)?);
            Value::List(a)
        }
        Fragment::Struct(s) => {
            let mut a = head(cx, Encoding::Struct, &s.meta);
            a.push(encode_children(cx, &s.fields)?);
            Value::List(a)
        }
        Fragment::Enum(s) => {
            let mut a = head(cx, Encoding::Enum, &s.meta);
            let case = match &s.case {
                None => Vec::new(),
                Some(c) => {
                    let mut x = vec![cx.stamp(&c.stamp)];
                    x.extend(c.case.map(uint));
                    vec![Value::List(x)]
                }
            };
            a.push(Value::List(case));
            a.push(encode_children(cx, &s.payloads)?);
            Value::List(a)
        }
        Fragment::Map(m) => {
            let mut a = head(cx, Encoding::Map, &m.meta);
            let mut items = Vec::with_capacity(m.entries.len());
            for (d, e) in cx.sorted(&m.entries) {
                let mut x = vec![cx.dot(d), cx.opt_stamp(e.reset.as_ref())];
                x.extend(e.key.clone());
                x.push(opt_frag(cx, e.frag.as_deref())?);
                items.push(Value::List(x));
            }
            a.push(elems_value(cx, items)?);
            Value::List(a)
        }
        Fragment::Seq(s) => {
            let mut a = head(cx, s.encoding(), &s.meta);
            let runs = seq::encode_elems(s, cx)?;
            a.push(elems_value(cx, runs)?);
            Value::List(a)
        }
        Fragment::Slots(s) => {
            let reg = Value::List(s.reg.iter().map(|r| encode_register(cx, r)).collect());
            let mut members = Vec::with_capacity(s.members.len());
            for f in s.members.values() {
                members.push(encode_fragment(cx, f)?);
            }
            Value::List(vec![uint(u64::from(Encoding::Slots.id())), reg, Value::List(members)])
        }
    })
}

/// Runs the collecting pass and the real pass (§3.3 rule 1).
fn encode_top(cx: &DeltaCtx, f: &Fragment, frontiers: Option<&Frontiers>, pages: Option<&mut dyn PageSink>) -> Result<(Enc<'static>, Value, Option<Value>), Error> {
    let _ = pages;
    let mut enc = Enc::new(cx, None);
    encode_fragment(&mut enc, f)?;
    let extra: Vec<Source> = frontiers.map(|fr| fr.0.keys().map(|t| Source::node(*t)).collect()).unwrap_or_default();
    enc.finish_collecting(&extra);
    let frag = encode_fragment(&mut enc, f)?;
    let fr = frontiers.map(|fr| {
        let mut entries: Vec<(Value, u64)> = fr.0.iter().map(|(t, c)| (enc.src(&Source::node(*t)), *c)).collect();
        entries.sort_by_key(|(i, _)| match i {
            Value::Int(i) => *i,
            _ => i64::MAX,
        });
        Value::List(entries.into_iter().map(|(i, c)| Value::List(vec![i, uint(c)])).collect())
    });
    Ok((enc, frag, fr))
}

/// Encodes a delta (§3.2) against its header facts.
pub fn encode_delta(d: &Delta, cx: &DeltaCtx, pages: Option<&mut dyn PageSink>) -> Result<Vec<u8>, Error> {
    let (enc, frag, _) = encode_top(cx, &d.fragment, None, pages)?;
    let top = Value::List(vec![Value::Bytes(d.nonce.to_vec()), enc.sources_value(), enc.commits_value(), frag]);
    Ok(osis_core::encode(&top))
}

/// Encodes a snapshot delta (§8). The caller strips values of expiring deltas first (§4.7).
pub fn encode_snapshot(s: &Snapshot, cx: &DeltaCtx, pages: Option<&mut dyn PageSink>) -> Result<Vec<u8>, Error> {
    if s.frontiers.0.values().any(|c| *c == 0) {
        return Err(Error::Mismatch("frontier counter 0"));
    }
    let (enc, frag, fr) = encode_top(cx, &s.fragment, Some(&s.frontiers), pages)?;
    let fr = fr.unwrap_or(Value::List(Vec::new()));
    let top = Value::List(vec![Value::Bytes(s.nonce.to_vec()), enc.sources_value(), enc.commits_value(), frag, fr]);
    Ok(osis_core::encode(&top))
}

// ---- decode

fn opt_stamp_only<T>(v: &Value, f: impl FnOnce(&Value) -> Result<T, Error>) -> Result<Option<T>, Error> {
    match as_array(v)? {
        [] => Ok(None),
        [x] => f(x).map(Some),
        _ => Err(Error::Malformed("expected Opt(X)")),
    }
}

fn check_value(v: &Value) -> Result<(), Error> {
    if v.depth() > MAX_VALUE_DEPTH {
        return Err(Error::Malformed("value nests too deep"));
    }
    Ok(())
}

/// The items of an element array (pages resolved, §8).
pub(crate) fn elem_items<'v>(_cx: &mut Dec, v: &'v Value) -> Result<Vec<&'v Value>, Error> {
    let items = as_array(v)?;
    if items.iter().any(|i| matches!(i, Value::Link(_))) {
        return Err(Error::Unsupported("paged arrays (crdt-core step 5)"));
    }
    Ok(items.iter().collect())
}

fn decode_meta(cx: &mut Dec, r: &Value, w: &Value) -> Result<Meta, Error> {
    Ok(Meta { reset: cx.opt_stamp(r)?, w: cx.opt_stamp(w)? })
}

fn decode_elems(cx: &mut Dec, v: &Value) -> Result<BTreeMap<Dot, Elem>, Error> {
    let mut out = BTreeMap::new();
    for e in elem_items(cx, v)? {
        let [d, r, f] = as_array(e)? else { return Err(Error::Malformed("element")) };
        let dot = cx.dot(d)?;
        let reset = cx.opt_stamp(r)?;
        let frag = opt_stamp_only(f, |x| cx.fragment(x))?.map(Box::new);
        if frag.is_some() {
            cx.claim(&dot)?;
        }
        out.insert(dot, Elem { reset, frag });
    }
    Ok(out)
}

fn decode_children(cx: &mut Dec, v: &Value) -> Result<BTreeMap<u64, Fragment>, Error> {
    let Value::Map(m) = v else { return Err(Error::Malformed("expected a map")) };
    let mut out = BTreeMap::new();
    for (k, f) in m {
        out.insert(as_uint(k)?, cx.fragment(f)?);
    }
    Ok(out)
}

fn decode_register(cx: &mut Dec, a: &[Value], may_reset: bool) -> Result<Register, Error> {
    let (r, rest) = match a {
        [_, r, rest @ ..] => (r, rest),
        _ => return Err(Error::Malformed("register")),
    };
    let reset = cx.opt_stamp(r)?;
    if reset.is_some() && !may_reset {
        return Err(Error::Malformed("nested register with a reset"));
    }
    let write = match rest {
        [] => None,
        [s] => Some(RegWrite { stamp: cx.stamp(s)?, value: None }),
        [s, v] => {
            check_value(v)?;
            Some(RegWrite { stamp: cx.stamp(s)?, value: Some(v.clone()) })
        }
        _ => return Err(Error::Malformed("register arity")),
    };
    Ok(Register { reset, write })
}

/// Decodes a fragment; `may_reset` where a register may carry a reset (root, slot member).
pub(crate) fn decode_fragment(cx: &mut Dec, v: &Value, may_reset: bool) -> Result<Fragment, Error> {
    let a = as_array(v)?;
    let id = as_uint(a.first().ok_or(Error::Malformed("empty fragment"))?)?;
    let enc = Encoding::from_id(id).ok_or(Error::UnknownEncoding(id))?;
    Ok(match (enc, a) {
        (Encoding::Register, _) => Fragment::Register(decode_register(cx, a, may_reset)?),
        (Encoding::Counter | Encoding::Max | Encoding::Min, [_, r, w, e]) => {
            let kind = enc.bag_kind().ok_or(Error::Malformed("bag"))?;
            let meta = decode_meta(cx, r, w)?;
            Fragment::Bag(Bag { kind, meta, elems: decode_elems(cx, e)? })
        }
        (Encoding::Set, [_, r, w, e]) => {
            let meta = decode_meta(cx, r, w)?;
            Fragment::Set(Set { meta, elems: decode_elems(cx, e)? })
        }
        (Encoding::Struct, [_, r, w, c]) => {
            let meta = decode_meta(cx, r, w)?;
            Fragment::Struct(Struct { meta, fields: decode_children(cx, c)? })
        }
        (Encoding::Enum, [_, r, w, k, c]) => {
            let meta = decode_meta(cx, r, w)?;
            let case = opt_stamp_only(k, |c| match as_array(c)? {
                [s] => Ok(CaseWrite { stamp: cx.stamp(s)?, case: None }),
                [s, id] => Ok(CaseWrite { stamp: cx.stamp(s)?, case: Some(as_uint(id)?) }),
                _ => Err(Error::Malformed("case")),
            })?;
            Fragment::Enum(Enum { meta, case, payloads: decode_children(cx, c)? })
        }
        (Encoding::Map, [_, r, w, es]) => {
            let meta = decode_meta(cx, r, w)?;
            let mut entries = BTreeMap::new();
            for e in elem_items(cx, es)? {
                let x = as_array(e)?;
                let (d, r, key, f) = match x {
                    [d, r, f] => (d, r, None, f),
                    [d, r, k, f] => (d, r, Some(k), f),
                    _ => return Err(Error::Malformed("entry")),
                };
                let dot = cx.dot(d)?;
                let reset = cx.opt_stamp(r)?;
                let frag = opt_stamp_only(f, |x| cx.fragment(x))?.map(Box::new);
                if let Some(k) = key {
                    check_value(k)?;
                    if frag.is_none() {
                        return Err(Error::Malformed("keyed entry without a fragment"));
                    }
                }
                if frag.is_some() {
                    cx.claim(&dot)?;
                }
                entries.insert(dot, Entry { reset, key: key.cloned(), frag });
            }
            Fragment::Map(Map { meta, entries })
        }
        (Encoding::List | Encoding::Text, [_, r, w, es]) => {
            let meta = decode_meta(cx, r, w)?;
            let mut s = Seq { text: enc == Encoding::Text, meta, elems: BTreeMap::new() };
            let runs: Vec<Value> = elem_items(cx, es)?.into_iter().cloned().collect();
            seq::decode_elems(&mut s, &runs, cx)?;
            Fragment::Seq(s)
        }
        (Encoding::Slots, [_, reg, ms]) => {
            if cx.kind() == DeltaKind::Writer {
                return Err(Error::Malformed("slots in a writer's delta"));
            }
            let reg = opt_stamp_only(reg, |r| match decode_fragment(cx, r, true)? {
                Fragment::Register(r) => Ok(r),
                _ => Err(Error::Malformed("slots: first member is not a register")),
            })?;
            let mut members = BTreeMap::new();
            let mut last: Option<Encoding> = None;
            for m in as_array(ms)? {
                let f = decode_fragment(cx, m, true)?;
                let e = f.encoding();
                if matches!(e, Encoding::Register | Encoding::Slots) || last.is_some_and(|l| e <= l) {
                    return Err(Error::Malformed("slots: unsorted, repeated or nested members"));
                }
                last = Some(e);
                members.insert(e, f);
            }
            if usize::from(reg.is_some()) + members.len() < 2 {
                return Err(Error::Malformed("slots with fewer than two members"));
            }
            Fragment::Slots(Slots { reg, members })
        }
        _ => return Err(Error::Malformed("fragment arity")),
    })
}

fn nonce(v: &Value) -> Result<[u8; NONCE_LEN], Error> {
    match v {
        Value::Bytes(b) => <[u8; NONCE_LEN]>::try_from(b.as_slice()).map_err(|_| Error::Malformed("nonce length")),
        _ => Err(Error::Malformed("nonce")),
    }
}

/// Decodes a delta (§3.2) against its header facts; bad input unless canonical.
pub fn decode_delta<'a>(bytes: &[u8], cx: &DeltaCtx, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>) -> Result<Delta, Error> {
    let top = osis_core::decode(bytes, &LIMITS)?;
    let [n, sources, commits, frag] = as_array(&top)? else { return Err(Error::Malformed("delta arity")) };
    let mut dec = Dec::new(cx, interner, pages);
    dec.load_sources(sources)?;
    dec.load_commits(commits)?;
    let fragment = decode_fragment(&mut dec, frag, true)?;
    let d = Delta { nonce: nonce(n)?, fragment };
    if encode_delta(&d, cx, None)? != bytes {
        return Err(Error::Malformed("not canonical"));
    }
    Ok(d)
}

/// Decodes a snapshot delta (§8); bad input unless canonical.
pub fn decode_snapshot<'a>(bytes: &[u8], cx: &DeltaCtx, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>) -> Result<Snapshot, Error> {
    let top = osis_core::decode(bytes, &LIMITS)?;
    let [n, sources, commits, frag, fr] = as_array(&top)? else { return Err(Error::Malformed("snapshot arity")) };
    let mut dec = Dec::new(cx, interner, pages);
    dec.load_sources(sources)?;
    dec.load_commits(commits)?;
    let fragment = decode_fragment(&mut dec, frag, true)?;
    let mut frontiers = BTreeMap::new();
    for e in as_array(fr)? {
        let [i, c] = as_array(e)? else { return Err(Error::Malformed("frontier")) };
        let tid = dec.src(i)?.as_node().ok_or(Error::Malformed("frontier of a non-node source"))?;
        let c = as_uint(c)?;
        if c == 0 || frontiers.insert(tid, c).is_some() {
            return Err(Error::Malformed("frontier counter 0 or repeated"));
        }
    }
    let s = Snapshot { nonce: nonce(n)?, fragment, frontiers: Frontiers(frontiers) };
    if encode_snapshot(&s, cx, None)? != bytes {
        return Err(Error::Malformed("not canonical"));
    }
    Ok(s)
}
