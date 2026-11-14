//! Inbox blob payload decoder (spec/wire.md §9: an inbox payload, a boxes payload or a stranded
//! notice): never panics; an accepted payload re-encodes to the value it was read from.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_base::{Limits, decode};
use osis_label::Inbox;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = decode(data, &Limits { max_depth: 512, max_bytes: 1 << 23 }) else { return };
    if let Ok(p) = Inbox::from_value(v.clone()) {
        assert_eq!(p.to_value(), v);
    }
});
