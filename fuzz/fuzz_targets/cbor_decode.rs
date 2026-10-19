//! Strict CBOR decoder (spec/data-model.md §5): never panics; accepted bytes are canonical
//! (re-encode to themselves) and every entry point agrees.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_core::{CanonicalBytes, Limits, decode, decode_prefix, encode};

fuzz_target!(|data: &[u8]| {
    let limits = Limits::DEFAULT;
    let whole = decode(data, &limits);
    if let Ok(v) = &whole {
        assert_eq!(encode(v), data, "accepted bytes must be canonical");
        assert_eq!(v.depth(), CanonicalBytes::parse(data.to_vec(), &limits).unwrap().depth());
    } else {
        assert!(CanonicalBytes::parse(data.to_vec(), &limits).is_err());
    }
    if let Ok((v, used)) = decode_prefix(data, &limits) {
        assert_eq!(encode(&v), used);
        assert_eq!(whole.is_ok(), used.len() == data.len());
    }
});
