//! Link layout and text form (spec/wire.md §10): never panic; an accepted link re-encodes to
//! the value it was read from. A leading 0 byte means text, else CBOR.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_base::{Limits, decode};
use osis_label::ShareLink;

fuzz_target!(|data: &[u8]| {
    if let Some((0, text)) = data.split_first() {
        if let Ok(s) = std::str::from_utf8(text) {
            if let Ok(l) = ShareLink::from_text(s) {
                assert_eq!(l.to_text().unwrap(), s);
            }
        }
        return;
    }
    let Ok(v) = decode(data, &Limits { max_depth: 8, max_bytes: 1 << 14 }) else { return };
    if let Ok(l) = ShareLink::from_value(&v) {
        assert_eq!(l.to_value().unwrap(), v);
    }
});
