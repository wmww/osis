//! Step and claim set decoders (spec/wire.md §8): never panic; an accepted step or claim set
//! re-encodes to the bytes it was parsed from.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_label::{ClaimSet, Step};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = Step::parse(data) {
        assert_eq!(s.to_bytes(), data);
        let _ = s.verify_genesis();
    }
    if let Ok(c) = ClaimSet::parse(data) {
        assert_eq!(c.to_bytes(), data);
    }
});
