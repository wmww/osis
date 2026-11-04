//! Commit header and commit blob plaintext decoders (spec/wire.md §4): never panic; accepted
//! bytes re-encode to themselves; validation, prefix groups and opening of an accepted blob
//! never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_commit::{CommitBlob, Envelope, Header, prefix_groups};

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = Header::decode(data) {
        assert_eq!(h.encode(), data);
        let _ = h.validate();
    }
    if let Ok(b) = CommitBlob::decode(data) {
        assert_eq!(b.encode(), data);
        let _ = b.header.validate();
        let _ = prefix_groups(&b.header, b.parts.iter().map(|p| p.ai));
        let _ = b.missing();
    }
    if let Ok(e) = Envelope::decode(data) {
        assert_eq!(e.encode(), data);
        let _ = prefix_groups(&e.header, e.ais());
        let _ = e.open(|_| vec![osis_crypto::Secret32::from_bytes([1; 32])]);
    }
});
