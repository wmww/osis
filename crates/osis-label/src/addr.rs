//! Server addresses (spec/sync.md §10, spec/data-model.md §9 `address`): strict value decoding,
//! the text form, and unpadded base64url.

use crate::Error;
use osis_core::Value;
use osis_core::format::MAX_URL_BYTES;
use osis_schema::Codec;
pub use osis_schema::core_types::Address;

/// An `address` value, strictly (re-encodes to itself), URL at most 256 bytes.
pub fn address_from_value(v: &Value) -> Result<Address, Error> {
    let a = Address::from_value(v).map_err(|_| Error::Malformed("address"))?;
    if a.to_value() != *v || a.url.len() > MAX_URL_BYTES {
        return Err(Error::Malformed("address"));
    }
    Ok(a)
}

/// Text form `<url>#<base64url key>` (provisional: client-side only, never on the wire).
pub fn address_to_text(a: &Address) -> String {
    format!("{}#{}", a.url, b64_encode(&a.key))
}

pub fn address_from_text(s: &str) -> Result<Address, Error> {
    let (url, key) = s.rsplit_once('#').ok_or(Error::Malformed("address text"))?;
    let key: [u8; 32] = b64_decode(key)?.try_into().map_err(|_| Error::Malformed("address key"))?;
    if url.is_empty() || url.len() > MAX_URL_BYTES {
        return Err(Error::Malformed("address url"));
    }
    Ok(Address { url: url.to_string(), key })
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url.
pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let mut n = 0u32;
        for (i, b) in chunk.iter().enumerate() {
            n |= u32::from(*b) << (16 - 8 * i);
        }
        for i in 0..=chunk.len() {
            let idx = usize::try_from((n >> (18 - 6 * i)) & 63).unwrap_or(0);
            out.push(char::from(B64.get(idx).copied().unwrap_or(b'A')));
        }
    }
    out
}

/// Strict unpadded base64url: no padding, no other characters, zero trailing bits.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, Error> {
    let bad = Error::Malformed("base64url");
    if s.len() % 4 == 1 {
        return Err(bad);
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.as_bytes().chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            let v = B64.iter().position(|x| x == c).ok_or(Error::Malformed("base64url"))?;
            n |= u32::try_from(v).unwrap_or(0) << (18 - 6 * i);
        }
        let bytes = chunk.len() - 1;
        let [_, b0, b1, b2] = n.to_be_bytes();
        let got = [b0, b1, b2];
        // Bits below the last full byte must be zero (canonical form).
        if got.iter().skip(bytes).any(|b| *b != 0) {
            return Err(bad);
        }
        out.extend_from_slice(got.get(..bytes).unwrap_or(&[]));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // spec/sync.md §10: an address is a URL and the server's 32-byte key; text form round trips.
    #[test]
    fn address_text() {
        let a = Address { url: "quic://example.org:4433".into(), key: [7; 32] };
        let t = address_to_text(&a);
        assert_eq!(address_from_text(&t).unwrap(), a);
        assert!(address_from_text("quic://x").is_err());
        assert!(address_from_text("quic://x#AAAA").is_err());
        assert!(address_from_text(&format!("{}#{}", "u".repeat(257), b64_encode(&[0; 32]))).is_err());
        assert_eq!(address_from_value(&a.to_value()).unwrap(), a);
        let long = Address { url: "u".repeat(257), key: [0; 32] };
        assert!(address_from_value(&long.to_value()).is_err());
    }

    // spec/wire.md §10: base64url known answers (RFC 4648 §10, url alphabet), strict decoding.
    #[test]
    fn base64url() {
        for (raw, enc) in [("", ""), ("f", "Zg"), ("fo", "Zm8"), ("foo", "Zm9v"), ("foob", "Zm9vYg"), ("fooba", "Zm9vYmE"), ("foobar", "Zm9vYmFy")] {
            assert_eq!(b64_encode(raw.as_bytes()), enc);
            assert_eq!(b64_decode(enc).unwrap(), raw.as_bytes());
        }
        assert_eq!(b64_encode(&[0xfb, 0xff]), "-_8");
        assert!(b64_decode("Zg==").is_err());
        assert!(b64_decode("Zh").is_err());
        assert!(b64_decode("Z").is_err());
        assert!(b64_decode("Zm+v").is_err());
    }

    proptest! {
        // spec/wire.md §10: base64url round trip.
        #[test]
        fn b64_round_trip(b in proptest::collection::vec(any::<u8>(), 0..100)) {
            prop_assert_eq!(b64_decode(&b64_encode(&b)).unwrap(), b);
        }
    }
}
