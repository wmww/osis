//! Step decoder (spec/wire.md §8): never panics; an accepted step re-encodes to the bytes it was
//! parsed from.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_blob::Step;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = Step::parse(data) {
        assert_eq!(s.to_bytes(), data);
        let _ = s.verify_genesis();
    }
});
