//! Blob prefix and unpad (spec/wire.md §5): never panic; an accepted prefix re-encodes to the
//! bytes it was parsed from; unpad accepts only what pad produces.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_label::{Prefix, server_prefix};

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = Prefix::parse(data) {
        assert_eq!(&p.to_bytes()[..], &data[..p.len()]);
    }
    let _ = server_prefix(data);
    if let Ok(p) = osis_crypto::unpad(data) {
        assert_eq!(osis_crypto::pad(p), data);
    }
});
