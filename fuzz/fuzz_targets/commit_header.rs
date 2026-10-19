//! Commit header and commit blob plaintext decoders (spec/wire.md §4): never panic; accepted
//! bytes re-encode to themselves; validation, prefix inputs and projection of an accepted blob
//! never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_commit::{CommitBlob, Header, prefix_inputs, project};

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = Header::decode(data) {
        assert_eq!(h.encode(), data);
        let _ = h.validate();
    }
    if let Ok(b) = CommitBlob::decode(data) {
        assert_eq!(b.encode(), data);
        let _ = b.header.validate();
        let parts: Vec<(usize, usize)> = b.parts.iter().map(|p| (p.ai, p.di)).collect();
        let _ = prefix_inputs(&b.header, &parts);
        let _ = project(&b, |ai| ai % 2);
        let _ = b.missing();
    }
});
