//! Inbox payload decoder (spec/wire.md §9): never panics; an accepted payload re-encodes to the
//! value it was read from.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_core::{Limits, decode};
use osis_label::InboxPayload;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = decode(data, &Limits { max_depth: 512, max_bytes: 1 << 23 }) else { return };
    if let Ok(p) = InboxPayload::from_value(&v) {
        assert_eq!(p.to_value(), v);
    }
});
