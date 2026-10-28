//! Tid text form (spec/data-model.md §1): never panics; an accepted form round trips.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_core::Tid;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(t) = Tid::parse(s) {
        assert_eq!(t.to_string(), s.strip_prefix("osis://").unwrap_or(s));
        assert_eq!(Tid::parse(&t.to_uri()), Ok(t));
    }
});
