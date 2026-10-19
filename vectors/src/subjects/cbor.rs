//! `cbor/`: the canonical CBOR profile (spec/data-model.md §5). Case fields: `hex`, then `diag`
//! (accepted: decodes, re-encodes to `hex`, prints as `diag`) or `reject` (a rule ID below).

use crate::file::VecFile;
use crate::{diag::diag, unhex};
use osis_core::{DecodeError, Limits, decode, encode};

/// Language-neutral rule IDs for rejections (vectors/README.md).
pub fn rule(e: &DecodeError) -> &'static str {
    match e {
        DecodeError::Truncated => "truncated",
        DecodeError::TooLarge => "too-large",
        DecodeError::TooDeep => "too-deep",
        DecodeError::Trailing => "trailing",
        DecodeError::NonShortestHead => "non-shortest",
        DecodeError::Indefinite => "indefinite",
        DecodeError::ReservedInfo => "reserved-info",
        DecodeError::IntOutOfRange => "int-range",
        DecodeError::InvalidUtf8 => "utf8",
        DecodeError::MapKeyOrder => "map-order",
        DecodeError::SetOrder => "set-order",
        DecodeError::BadSimple => "simple",
        DecodeError::NonCanonicalNan => "nan",
        DecodeError::TagContent(_) => "tag-content",
    }
}

pub fn check(f: &VecFile) -> Result<(), String> {
    for c in f.live() {
        let name = c.name();
        let bytes = unhex(c.req("hex")?)?;
        let got = decode(&bytes, &Limits::DEFAULT);
        match (c.get("reject"), c.get("diag"), got) {
            (Some(r), None, Err(e)) if rule(&e) == r => {}
            (Some(r), None, Err(e)) => return Err(format!("{name}: rejected as {} ({e}), expected {r}", rule(&e))),
            (Some(r), None, Ok(v)) => return Err(format!("{name}: accepted {v:?}, expected rejection {r}")),
            (None, Some(d), Ok(v)) => {
                if encode(&v) != bytes {
                    return Err(format!("{name}: re-encoding differs"));
                }
                let got = diag(&bytes)?;
                if got != d {
                    return Err(format!("{name}: diag {got}, expected {d}"));
                }
            }
            (None, Some(_), Err(e)) => return Err(format!("{name}: rejected as {} ({e})", rule(&e))),
            _ => return Err(format!("{name}: needs exactly one of diag, reject")),
        }
    }
    Ok(())
}
