//! Strict CBOR decoder (spec/data-model.md §5): never panics; accepted bytes are canonical
//! (re-encode to themselves) and every entry point agrees: `check` gives decode's verdict and
//! error, and an accepted value read in place (`Item`) reads as the decoded one.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_base::cbor::{Item, check};
use osis_base::{CanonicalBytes, Limits, Value, decode, decode_prefix, encode};

/// Every in-place read of `i` agrees with `v`, nested items included.
fn reads_as(i: Item, v: &Value) {
    assert_eq!(i.to_value().as_ref(), Ok(v));
    assert_eq!(i.as_uint(), v.as_uint());
    assert_eq!(i.as_bytes(), v.as_bytes());
    match (i.as_list(), v) {
        (Some(l), Value::List(w)) => {
            assert_eq!(l.len(), w.len());
            assert_eq!(l.iter().count(), w.len());
            l.iter().zip(w).for_each(|(a, b)| reads_as(a, b));
        }
        (l, _) => assert!(l.is_none()),
    }
    match (i.as_map(), v) {
        (Some(l), Value::Map(m)) => {
            let items: Vec<Item> = l.iter().collect();
            assert_eq!(items.len(), 2 * m.len());
            for (kv, (k, x)) in items.chunks(2).zip(m.iter()) {
                if let [a, b] = kv {
                    reads_as(*a, k);
                    reads_as(*b, x);
                }
            }
        }
        (l, _) => assert!(l.is_none()),
    }
}

fuzz_target!(|data: &[u8]| {
    let limits = Limits::DEFAULT;
    let whole = decode(data, &limits);
    assert_eq!(check(data, &limits), whole.as_ref().map(drop).map_err(|e| *e));
    if let Ok(v) = &whole {
        assert_eq!(encode(v), data, "accepted bytes must be canonical");
        assert_eq!(v.depth(), CanonicalBytes::parse(data.to_vec(), &limits).unwrap().depth());
        reads_as(Item::parse(data, &limits).unwrap(), v);
    } else {
        assert!(CanonicalBytes::parse(data.to_vec(), &limits).is_err());
    }
    if let Ok((v, used)) = decode_prefix(data, &limits) {
        assert_eq!(encode(&v), used);
        assert_eq!(whole.is_ok(), used.len() == data.len());
    }
});
