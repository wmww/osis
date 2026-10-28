//! Frames, Hello and every message (spec/wire.md §11.1, §11.2, §13): never panics; an accepted
//! Hello or message re-encodes to the same canonical bytes. The input is a stream of frames; a
//! seed without a valid length prefix is also tried as one frame body.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_proto::{FrameDecoder, Hello, Message};

fn body(b: &[u8]) {
    if let Ok(h) = Hello::decode(b) {
        assert_eq!(h.encode(), b);
    }
    if let Ok(m) = Message::decode(b) {
        assert_eq!(m.encode(), b);
    }
}

fuzz_target!(|data: &[u8]| {
    body(data);
    let mut d = FrameDecoder::new();
    for chunk in data.chunks(7) {
        d.push(chunk);
        while let Ok(Some(f)) = d.next_frame() {
            body(&f);
        }
    }
});
