//! Server addresses (spec/sync.md §10, spec/data-model.md §9 `address`): strict value decoding,
//! the text form (key in osis-core's unpadded base64url).

use crate::Error;
use osis_core::{Value, base64url};
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
    format!("{}#{}", a.url, base64url::encode(&a.key))
}

pub fn address_from_text(s: &str) -> Result<Address, Error> {
    let (url, key) = s.rsplit_once('#').ok_or(Error::Malformed("address text"))?;
    let key: [u8; 32] = base64url::decode(key).ok_or(Error::Malformed("base64url"))?.try_into().map_err(|_| Error::Malformed("address key"))?;
    if url.is_empty() || url.len() > MAX_URL_BYTES {
        return Err(Error::Malformed("address url"));
    }
    Ok(Address { url: url.to_string(), key })
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/sync.md §10: an address is a URL and the server's 32-byte key; text form round trips.
    #[test]
    fn address_text() {
        let a = Address { url: "quic://example.org:4433".into(), key: [7; 32] };
        let t = address_to_text(&a);
        assert_eq!(address_from_text(&t).unwrap(), a);
        assert!(address_from_text("quic://x").is_err());
        assert!(address_from_text("quic://x#AAAA").is_err());
        assert!(address_from_text(&format!("{}#{}", "u".repeat(257), base64url::encode(&[0; 32]))).is_err());
        assert_eq!(address_from_value(&a.to_value()).unwrap(), a);
        let long = Address { url: "u".repeat(257), key: [0; 32] };
        assert!(address_from_value(&long.to_value()).is_err());
    }
}
