//! Unpadded base64url (RFC 4648 §5): tid text form (spec/data-model.md §1), address, link and
//! card text forms (spec/wire.md §10).

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn value(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// Unpadded base64url of `data`.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let mut n = 0u32;
        for (i, b) in chunk.iter().enumerate() {
            n |= u32::from(*b) << (16 - 8 * i);
        }
        for i in 0..=chunk.len() {
            let idx = ((n >> (18 - 6 * i)) & 63) as usize;
            out.push(char::from(ALPHABET.get(idx).copied().unwrap_or(b'A')));
        }
    }
    out
}

/// Strict decoding: no padding, no other characters, zero trailing bits; `None` otherwise.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.as_bytes().chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            n |= value(*c)? << (18 - 6 * i);
        }
        let bytes = chunk.len() - 1;
        let [_, b0, b1, b2] = n.to_be_bytes();
        let got = [b0, b1, b2];
        // Bits below the last full byte must be zero (canonical form).
        if got.iter().skip(bytes).any(|b| *b != 0) {
            return None;
        }
        out.extend_from_slice(got.get(..bytes)?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // spec/wire.md §10: base64url known answers (RFC 4648 §10, url alphabet), strict decoding.
    #[test]
    fn known_answers() {
        for (raw, enc) in [("", ""), ("f", "Zg"), ("fo", "Zm8"), ("foo", "Zm9v"), ("foob", "Zm9vYg"), ("fooba", "Zm9vYmE"), ("foobar", "Zm9vYmFy")] {
            assert_eq!(encode(raw.as_bytes()), enc);
            assert_eq!(decode(enc).unwrap(), raw.as_bytes());
        }
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        assert!(decode("Zg==").is_none());
        assert!(decode("Zh").is_none());
        assert!(decode("Z").is_none());
        assert!(decode("Zm+v").is_none());
    }

    proptest! {
        // spec/wire.md §10: base64url round trip.
        #[test]
        fn round_trip(b in proptest::collection::vec(any::<u8>(), 0..100)) {
            prop_assert_eq!(decode(&encode(&b)).unwrap(), b);
        }
    }
}
