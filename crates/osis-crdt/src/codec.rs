//! Fragment encode/decode (spec/crdt.md §3.2, §3.3, §8). Filled by plans/crdt-core.md step 3.

use crate::error::Error;
use crate::fragment::Fragment;
use crate::wire::{Dec, Enc};
use osis_core::Value;

pub(crate) fn encode_fragment(_cx: &mut Enc, _f: &Fragment) -> Result<Value, Error> {
    Err(Error::Unsupported("fragment encoding (crdt-core step 3)"))
}

pub(crate) fn decode_fragment(_cx: &mut Dec, _v: &Value) -> Result<Fragment, Error> {
    Err(Error::Unsupported("fragment decoding (crdt-core step 3)"))
}
