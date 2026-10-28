//! Signal envelope plaintext and publish authorization (spec/wire.md §9): never panic; accepted
//! items re-encode to the value they were read from. Input: `[SignalBody, signature]` bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_base::{Limits, Value, decode};
use osis_label::{PublishAuth, SignalBody};

fuzz_target!(|data: &[u8]| {
    let Ok(v) = decode(data, &Limits { max_depth: 512, max_bytes: 1 << 16 }) else { return };
    if let Value::List(items) = &v
        && let [body, _sig] = items.as_slice()
        && let Ok(b) = SignalBody::from_value(body)
    {
        assert_eq!(&b.to_value().unwrap(), body);
    }
    if let Ok(a) = PublishAuth::from_value(&v) {
        assert_eq!(a.to_value(), v);
    }
});
