//! A second decoder of spec/wire.md §11.2, written from the spec's layouts alone, against
//! `Msg::decode` on the examples mutated (values replaced, items dropped, duplicated, wrapped,
//! bytes flipped or cut). Property: the two accept the same bodies, and whatever is accepted
//! re-encodes to its bytes (spec/wire.md §1, §13). Embedded structures of other subsystems
//! (creation records, `box` values, AKs, value depth) are read by their own crates' rules.

use osis_base::format::{MAX_BLOB, MAX_MESSAGE, MAX_VALUE_DEPTH};
use osis_base::{Ak, CreationRecord, Limits, Value, cbor};
use osis_proto::Msg;
use osis_proto::examples::messages;
use osis_schema::Codec;
use osis_schema::core_types::SecretBox;

const REPLY_BUDGET: u64 = (MAX_MESSAGE - 64 * 1024) as u64;
const SMALL_REPLY: u64 = 16 * 1024;
const TOP: u64 = 1 << 31;

type R = Result<(), &'static str>;

fn ok(c: bool, why: &'static str) -> R {
    if c { Ok(()) } else { Err(why) }
}

fn uint(v: &Value) -> Option<u64> {
    match v {
        Value::Int(i) if *i >= 0 => Some(*i as u64),
        _ => None,
    }
}

fn u(v: &Value) -> R {
    ok(uint(v).is_some(), "uint")
}

fn b(v: &Value, n: usize) -> R {
    ok(matches!(v, Value::Bytes(x) if x.len() == n), "fixed bytes")
}

fn bmax(v: &Value, n: usize) -> R {
    ok(matches!(v, Value::Bytes(x) if x.len() <= n), "bytes")
}

fn boolean(v: &Value) -> R {
    ok(matches!(v, Value::Bool(_)), "bool")
}

fn arr(v: &Value) -> Result<&[Value], &'static str> {
    match v {
        Value::List(x) => Ok(x),
        _ => Err("array"),
    }
}

fn tuple(v: &Value, n: usize) -> Result<&[Value], &'static str> {
    let a = arr(v)?;
    ok(a.len() == n, "arity")?;
    Ok(a)
}

fn list(v: &Value, min: usize, max: usize, f: impl Fn(&Value) -> R) -> R {
    let a = arr(v)?;
    ok(a.len() >= min && a.len() <= max, "count")?;
    a.iter().try_for_each(f)
}

/// `Opt(X) := [] | [X]`; `Some(x)` when present.
fn opt(v: &Value) -> Result<Option<&Value>, &'static str> {
    match arr(v)? {
        [] => Ok(None),
        [x] => Ok(Some(x)),
        _ => Err("opt"),
    }
}

fn opt_of(v: &Value, f: impl Fn(&Value) -> R) -> R {
    opt(v)?.map_or(Ok(()), f)
}

/// Canonical bytes of one CBOR item, as a byte string.
fn canonical(v: &Value, max: usize) -> Result<Value, &'static str> {
    let Value::Bytes(x) = v else { return Err("embedded bytes") };
    ok(x.len() <= max, "embedded size")?;
    let d = cbor::decode(x, &Limits { max_depth: 512, max_bytes: MAX_MESSAGE }).map_err(|_| "embedded cbor")?;
    ok(cbor::encode(&d) == *x, "embedded canonical")?;
    Ok(d)
}

/// spec/wire.md §8 `Step`, its canonical bytes.
fn step(v: &Value) -> R {
    let s = canonical(v, MAX_MESSAGE)?;
    let a = tuple(&s, 9)?;
    b(&a[0], 16)?;
    opt_of(&a[1], |p| b(p, 32))?;
    a[2..8].iter().try_for_each(|k| b(k, 32))?;
    // the four role keys are Ed25519 public keys: bytes that are none are malformed
    a[2..6].iter().try_for_each(|k| ok(matches!(k, Value::Bytes(x) if osis_crypto::VerifyingKey::from_slice(x).is_ok()), "role key"))?;
    b(&a[8], 64)
}

/// spec/wire.md §7: an entry box is a `box` value in the sealed form.
fn sealed_box(v: &Value) -> R {
    let x = SecretBox::from_value(v).map_err(|_| "box")?;
    ok(matches!(x, SecretBox::Sealed(_)) && x.to_value() == *v, "entry box")
}

/// spec/wire.md §8 `ClaimSet := [[claim+], {entry: box}]`.
fn claim_set(v: &Value) -> R {
    let s = canonical(v, MAX_MESSAGE - 64 * 1024)?;
    let a = tuple(&s, 2)?;
    let claims = arr(&a[0])?;
    ok(claims.len().is_power_of_two() && claims.len() <= 65_536, "claim count")?;
    claims.iter().try_for_each(|c| b(c, 32))?;
    let Value::Map(m) = &a[1] else { return Err("entries") };
    m.iter().try_for_each(|(k, x)| {
        b(k, 32)?;
        ok(claims.contains(k), "entry not a claim")?;
        sealed_box(x)
    })
}

fn val(v: &Value) -> R {
    ok(!v.deeper_than(MAX_VALUE_DEPTH), "value depth")
}

fn creation(v: &Value) -> R {
    ok(CreationRecord::from_value(v).is_some(), "creation")
}

fn max_reply(v: &Value) -> R {
    ok(uint(v).is_some_and(|m| (SMALL_REPLY..=REPLY_BUDGET).contains(&m)), "max_reply")
}

fn sub_id(v: &Value) -> R {
    ok(uint(v).is_some_and(|i| i != 0 && i < 1 << 32), "sub id")
}

fn cursor(v: &Value) -> R {
    bmax(v, 256)
}

fn join(v: &Value) -> R {
    let a = tuple(v, 2)?;
    b(&a[0], 16)?;
    opt_of(&a[1], cursor)
}

/// `ditem := [blob_id, [[level, dsig]*], sig]`, levels ascending, distinct, within 1..3.
fn ditem(v: &Value) -> R {
    let a = tuple(v, 3)?;
    b(&a[0], 32)?;
    let mut last = 0;
    for p in arr(&a[1])? {
        let p = tuple(p, 2)?;
        let l = uint(&p[0]).ok_or("level")?;
        ok((1..=3).contains(&l) && l > last, "levels")?;
        last = l;
        b(&p[1], 64)?;
    }
    b(&a[2], 64)
}

fn event(v: &Value, cursorless: bool) -> R {
    let a = arr(v)?;
    match (a.first().and_then(uint), a.len()) {
        (Some(0), 5) => {
            b(&a[1], 32)?;
            opt_of(&a[2], |x| bmax(x, MAX_BLOB))?;
            b(&a[3], 57)?;
            opt_of(&a[4], |x| b(x, 64))
        }
        (Some(1), 2) => b(&a[1], 32),
        (Some(2), 2) => ok(cursorless, "full outside a cursorless stream").and(boolean(&a[1])),
        (Some(3), 2) => step(&a[1]),
        // "for anything but room": not 0 (taken) and not 12 (room is told by Full)
        (Some(4), 3) => ok(cursorless, "refused outside a cursorless stream").and(b(&a[1], 32)).and(ok(uint(&a[2]).is_some_and(|c| c != 0 && c != 12), "refused code")),
        _ => Err("event"),
    }
}

fn events(v: &Value, cursorless: bool) -> R {
    list(v, 0, usize::MAX, |e| {
        let a = tuple(e, 2)?;
        b(&a[0], 16)?;
        event(&a[1], cursorless)
    })
}

fn item(v: &Value) -> R {
    let a = arr(v)?;
    match (a.first().and_then(uint), a.len()) {
        (Some(0), 3) => b(&a[1], 32).and(opt_of(&a[2], |s| b(s, 64))),
        (Some(1), 3) => b(&a[1], 16).and(list(&a[2], 1, 256, |h| b(h, 32))),
        (Some(2), 5) => b(&a[1], 16).and(bmax(&a[2], MAX_BLOB)).and(b(&a[3], 57)).and(b(&a[4], 64)),
        (Some(3), 5) => b(&a[1], 16).and(opt_of(&a[2], |s| b(s, 32))).and(b(&a[3], 32)).and(b(&a[4], 64)),
        (Some(4), 4) => b(&a[1], 32).and(b(&a[2], 32)).and(b(&a[3], 64)),
        _ => Err("item"),
    }
}

fn grant(v: &Value) -> R {
    let a = tuple(v, 2)?;
    opt_of(&a[0], |e| canonical(e, MAX_MESSAGE).and_then(|x| sealed_box(&x)))?;
    list(&a[1], 1, usize::MAX, step)
}

/// A Shared answer: only code 0 carries anything, and a `sig` only beside a tag.
fn shared(v: &Value) -> R {
    let a = tuple(v, 4)?;
    let code = uint(&a[0]).ok_or("code")?;
    let tag = opt(&a[1])?;
    tag.map_or(Ok(()), |t| b(t, 32))?;
    let g = opt(&a[2])?;
    g.map_or(Ok(()), grant)?;
    let sig = opt(&a[3])?;
    sig.map_or(Ok(()), |s| b(s, 64))?;
    ok(code == 0 || (tag.is_none() && g.is_none() && sig.is_none()), "refusal carrying")?;
    ok(sig.is_none() || tag.is_some(), "sig without tag")
}

/// Rice parameter 8 over `[lo, hi)`: every gap complete, padding fewer than 8 zero bits.
fn gcs(bytes: &[u8], lo: u64, hi: u64) -> Result<u64, &'static str> {
    let bit = |i: usize| (bytes[i / 8] >> (7 - i % 8)) & 1;
    let total = bytes.len() * 8;
    let (mut pos, mut prev, mut n) = (0usize, lo, 0u64);
    loop {
        let rest = total - pos;
        if rest < 8 && (pos..total).all(|i| bit(i) == 0) {
            return Ok(n);
        }
        let mut q = 0u64;
        while pos < total && bit(pos) == 1 {
            q += 1;
            pos += 1;
        }
        ok(total - pos >= 9, "gap")?;
        pos += 1;
        let r = (0..8).fold(0u64, |r, _| {
            let x = (r << 1) | u64::from(bit(pos));
            pos += 1;
            x
        });
        prev = prev.checked_add(q * 256 + r).ok_or("overflow")?;
        ok(prev < hi, "past hi")?;
        n += 1;
    }
}

fn beacons(a: &[Value]) -> R {
    let [generation, base, f, lo, hi, g, more] = a else { return Err("arity") };
    u(generation)?;
    opt_of(base, u)?;
    let f = uint(f).ok_or("f")?;
    // f = ceil(log2 n) + 8 for n <= 2^22
    ok((8..=30).contains(&f), "width")?;
    let (lo, hi) = (uint(lo).ok_or("lo")?, uint(hi).ok_or("hi")?);
    ok(lo < hi && hi <= 1 << f, "range")?;
    let Value::Bytes(g) = g else { return Err("gcs") };
    ok(gcs(g, lo, hi)? <= 1 << 22, "entries")?;
    boolean(more)
}

/// A header-only copy `[Header, signature, Opt(inner), [signature*], []]`.
fn rotation(v: &Value) -> R {
    let a = tuple(v, 5)?;
    ok(arr(&a[4])?.is_empty(), "rotation sections")
}

fn records(v: &Value) -> R {
    let a = arr(v)?;
    let mut tids = Vec::new();
    for r in a {
        tids.push(CreationRecord::from_value(r).ok_or("record")?.tid());
    }
    ok(tids.windows(2).all(|w| w[0] < w[1]), "records order")
}

/// `None` when the kind is unknown (answered 11): a separate outcome from malformed.
fn spec_decode(body: &[u8]) -> Result<(), &'static str> {
    let v = cbor::decode(body, &Limits { max_depth: 512, max_bytes: MAX_MESSAGE }).map_err(|_| "cbor")?;
    let mut items = 0usize;
    cbor::visit_items(body, &Limits { max_depth: 512, max_bytes: MAX_MESSAGE }, &mut |_, _, _| items += 1).map_err(|_| "cbor")?;
    ok(items <= 1 << 20, "items")?;
    let all = arr(&v)?;
    ok(all.len() >= 2, "head")?;
    let kind = uint(&all[0]).ok_or("kind")?;
    let id = uint(&all[1]).filter(|i| *i < 1 << 32).ok_or("id")?;
    let a = &all[2..];
    // spec/wire.md §11.1, §11.2: pushes 0; requests and replies nonzero but an Error; the shared
    // set's and the stream's requests and answers (every Fetch) top-bit; NoRecord 2^31
    let push = matches!(kind, 29 | 43..=46);
    let id_ok = match kind {
        0 => true,
        _ if push => id == 0,
        19 | 20 | 36..=42 => id & TOP != 0 && (kind != 40 || id == TOP),
        _ => id != 0,
    };
    let n = |k: usize| ok(a.len() == k, "arity");
    let r: R = match kind {
        0 => n(1).and_then(|_| u(&a[0])),
        1 | 40 => n(0),
        2 | 3 => n(1).and_then(|_| u(&a[0])),
        7 => n(3).and_then(|_| b(&a[0], 16)).and_then(|_| step(&a[1])).and_then(|_| opt_of(&a[2], claim_set)),
        11 => n(1).and_then(|_| list(&a[0], 1, 1024, u)),
        14 => n(2).and_then(|_| b(&a[0], 16)).and_then(|_| list(&a[1], 1, 1024, ditem)),
        19 => n(3).and_then(|_| b(&a[0], 16)).and_then(|_| max_reply(&a[1])).and_then(|_| list(&a[2], 1, 1024, |x| b(x, 32))),
        20 => n(1).and_then(|_| {
            list(&a[0], 0, 1024, |x| {
                let p = tuple(x, 2)?;
                b(&p[0], 32)?;
                opt_of(&p[1], |e| {
                    let e = tuple(e, 3)?;
                    bmax(&e[0], MAX_BLOB)?;
                    b(&e[1], 57)?;
                    opt_of(&e[2], |s| b(s, 64))
                })
            })
        }),
        24 => n(2).and_then(|_| opt_of(&a[0], |s| b(s, 32))).and_then(|_| b(&a[1], 16)),
        25 => n(3).and_then(|_| max_reply(&a[0])).and_then(|_| u(&a[1])).and_then(|_| list(&a[2], 0, usize::MAX, val)),
        26 => n(1).and_then(|_| {
            let o = arr(&a[0])?;
            match (o.first().and_then(uint), o.len()) {
                (Some(0), 2) => val(&o[1]),
                (Some(1), l) if l >= 2 => u(&o[1]).and_then(|_| o[2..].iter().try_for_each(val)),
                _ => Err("outcome"),
            }
        }),
        27 => n(2).and_then(|_| max_reply(&a[0])).and_then(|_| val(&a[1])),
        28 => n(1).and_then(|_| sub_id(&a[0])),
        29 => n(2).and_then(|_| sub_id(&a[0])).and_then(|_| {
            let p = arr(&a[1])?;
            match (p.first().and_then(uint), p.len()) {
                (Some(0), 2) | (Some(2), 2) => val(&p[1]),
                (Some(1), 1) => Ok(()),
                _ => Err("payload"),
            }
        }),
        30 => n(4).and_then(|_| b(&a[0], 16)).and_then(|_| b(&a[1], 15)).and_then(|_| list(&a[2], 0, usize::MAX, |c| arr(c).map(|_| ()))).and_then(|_| records(&a[3])),
        31 => n(2).and_then(|_| b(&a[0], 16)).and_then(|_| {
            list(&a[1], 1, usize::MAX, |s| {
                let s = tuple(s, 3)?;
                b(&s[0], 15)?;
                ok(matches!(&s[1], Value::Str(t) if Ak::new(t.clone()).is_ok()), "ak")?;
                b(&s[2], 16)
            })
        }),
        32 | 33 => {
            let proofs = |v: &Value| {
                list(v, 0, 256, |p| {
                    let p = tuple(p, 3)?;
                    creation(&p[0])?;
                    b(&p[1], 32)?;
                    b(&p[2], 64)
                })
            };
            if kind == 32 { n(2).and_then(|_| proofs(&a[0])).and_then(|_| opt_of(&a[1], |r| list(r, 0, 256, rotation))) } else { n(1).and_then(|_| proofs(&a[0])) }
        }
        34 => n(2).and_then(|_| b(&a[0], 32)).and_then(|_| list(&a[1], 0, (MAX_MESSAGE - 64) / 34, |t| b(t, 32))),
        35 => n(2).and_then(|_| b(&a[0], 32)).and_then(|_| opt_of(&a[1], |t| b(t, 32))),
        36 => beacons(a),
        37 => n(1).and_then(|_| list(&a[0], 1, 1024, item)),
        38 => n(1).and_then(|_| list(&a[0], 1, 1024, join)),
        39 => n(1).and_then(|_| list(&a[0], 1, 1024, shared)),
        41 => n(6).and_then(|_| opt_of(&a[0], cursor)).and_then(|_| list(&a[1], 0, usize::MAX, join)).and_then(|_| u(&a[2])).and_then(|_| max_reply(&a[3])).and_then(|_| boolean(&a[4])).and_then(|_| boolean(&a[5])),
        42 => n(7).and_then(|_| events(&a[0], false)).and_then(|_| opt_of(&a[1], cursor)).and_then(|_| a[2..6].iter().try_for_each(boolean)).and_then(|_| list(&a[6], 0, usize::MAX, join)),
        43 => n(4).and_then(|_| {
            let c = opt(&a[1])?;
            c.map_or(Ok(()), cursor)?;
            events(&a[0], c.is_none())?;
            boolean(&a[2])?;
            let seq = uint(&a[3]).ok_or("seq")?;
            // a Stream with no cursor has seq 0, and nothing to report
            ok(c.is_some() || (seq == 0 && a[2] == Value::Bool(false)), "cursorless stream")
        }),
        44 => n(1).and_then(|_| cursor(&a[0])),
        45 => n(1).and_then(|_| b(&a[0], 32)),
        46 => n(2).and_then(|_| list(&a[0], 0, 4096, |s| b(s, 16))).and_then(|_| boolean(&a[1])),
        _ => return Err("unknown kind"),
    };
    ok(id_ok, "id")?;
    r
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn leaf(r: &mut Rng) -> Value {
    const INTS: [u64; 24] = [0, 1, 2, 3, 4, 7, 8, 9, 12, 13, 14, 16, 30, 31, 256, 16_383, 16_384, 1 << 30, 1 << 31, (1 << 31) + 1, 1 << 32, REPLY_BUDGET, REPLY_BUDGET + 1, i64::MAX as u64];
    const LENS: [usize; 20] = [0, 1, 14, 15, 16, 17, 31, 32, 33, 56, 57, 58, 63, 64, 65, 256, 257, 323, 324, 1024];
    match r.below(9) {
        0..=2 => Value::uint(INTS[r.below(INTS.len())]),
        3..=5 => Value::Bytes(vec![r.next() as u8; LENS[r.below(LENS.len())]]),
        6 => Value::Bool(r.next() & 1 == 1),
        7 => Value::Str(["t:reg.0", "x", ""][r.below(3)].into()),
        _ => Value::List(vec![]),
    }
}

/// Applies one mutation at the `at`-th node (preorder); returns whether it was reached.
fn mutate(v: &mut Value, at: &mut usize, r: &mut Rng) -> bool {
    if *at == 0 {
        match (r.below(7), &mut *v) {
            (1, Value::List(l)) if !l.is_empty() => {
                let i = r.below(l.len());
                l.remove(i);
            }
            (2, Value::List(l)) if !l.is_empty() => {
                let i = r.below(l.len());
                let x = l[i].clone();
                l.insert(i, x);
            }
            (3, _) => *v = Value::List(vec![v.clone()]),
            (4, Value::List(l)) if l.len() == 1 => *v = l[0].clone(),
            (5, Value::Int(i)) => *i = if r.next() & 1 == 1 { i.saturating_add(1) } else { i.saturating_sub(1) },
            (6, Value::Bytes(x)) if !x.is_empty() => match r.below(3) {
                0 => {
                    let i = r.below(x.len());
                    x[i] ^= 1 << r.below(8);
                }
                1 => {
                    x.pop();
                }
                _ => x.push(r.next() as u8),
            },
            _ => *v = leaf(r),
        }
        return true;
    }
    *at -= 1;
    match v {
        Value::List(l) => l.iter_mut().any(|x| mutate(x, at, r)),
        _ => false,
    }
}

fn nodes(v: &Value) -> usize {
    1 + match v {
        Value::List(l) => l.iter().map(nodes).sum(),
        _ => 0,
    }
}

/// Mutates also inside the canonical bytes a byte string carries (steps, claim sets, boxes),
/// so their layouts are reached.
fn mutate_embedded(v: &mut Value, r: &mut Rng) {
    fn paths(v: &Value, here: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        match v {
            Value::List(l) => {
                for (i, x) in l.iter().enumerate() {
                    here.push(i);
                    paths(x, here, out);
                    here.pop();
                }
            }
            Value::Bytes(b) if b.len() > 40 && cbor::decode(b, &Limits { max_depth: 512, max_bytes: MAX_MESSAGE }).is_ok_and(|d| matches!(d, Value::List(_))) => out.push(here.clone()),
            _ => {}
        }
    }
    let mut out = Vec::new();
    paths(v, &mut Vec::new(), &mut out);
    if out.is_empty() {
        return;
    }
    let path = &out[r.below(out.len())];
    let mut at = &mut *v;
    for i in path {
        let Value::List(l) = at else { return };
        at = &mut l[*i];
    }
    let Value::Bytes(bytes) = at else { return };
    let Ok(mut inner) = cbor::decode(bytes, &Limits { max_depth: 512, max_bytes: MAX_MESSAGE }) else { return };
    let mut k = r.below(nodes(&inner));
    mutate(&mut inner, &mut k, r);
    *bytes = cbor::encode(&inner);
}

// spec/wire.md §11.2, §13: an independent decoder written from the layouts accepts exactly
// what `Msg::decode` accepts, on every example and its mutations, and an accepted body
// re-encodes to its bytes
#[test]
fn decoder_agrees_with_the_spec_layouts_spec_wire_11_2() {
    let ms = messages();
    let cases = osis_base::testenv::large_n(200_000);
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    let mut diffs = Vec::new();
    let (mut accepted, mut total) = (0usize, 0usize);
    for case in 0..cases {
        let (name, m) = &ms[case as usize % ms.len()];
        let mut v = m.to_value();
        let body = match r.below(4) {
            0 => {
                let mut body = cbor::encode(&v);
                let i = r.below(body.len());
                if r.next() & 1 == 1 { body[i] = r.next() as u8 } else { body.truncate(i.max(1)) }
                body
            }
            1 => {
                mutate_embedded(&mut v, &mut r);
                cbor::encode(&v)
            }
            _ => {
                for _ in 0..1 + r.below(3) {
                    let mut k = r.below(nodes(&v));
                    mutate(&mut v, &mut k, &mut r);
                }
                cbor::encode(&v)
            }
        };
        total += 1;
        let ours = Msg::decode(&body);
        let spec = spec_decode(&body);
        if let Ok(m) = &ours {
            accepted += 1;
            assert_eq!(m.encode(), body, "{name}: accepted but not canonical");
        }
        if ours.is_ok() != spec.is_ok() && diffs.len() < 20 {
            diffs.push(format!("{name}: crate {:?}, spec {:?}, body {}", ours.as_ref().map(|_| ()).map_err(|e| &e.error), spec, osis_base::hex::encode(&body)));
        }
    }
    assert!(diffs.is_empty(), "{} differences:\n{}", diffs.len(), diffs.join("\n"));
    // the mutations reach both sides of the line
    assert!(accepted * 20 > total && accepted * 2 < total, "{accepted} of {total} accepted");
}

