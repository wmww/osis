//! Creation record read (spec/wire.md §3): never panics; an accepted record re-reads to the same
//! value and its tid is the BLAKE3 prefix of its bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_base::{CreationRecord, Limits, decode, encode, hash};

fuzz_target!(|data: &[u8]| {
    let Ok(v) = decode(data, &Limits::DEFAULT) else { return };
    if let Some(r) = CreationRecord::from_value(&v) {
        assert_eq!(r.to_value(), v);
        assert_eq!(&hash::hash(&encode(&v))[..15], r.tid().as_bytes());
    }
});
