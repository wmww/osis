//! The crdt codec as it was before it read and wrote bytes directly: every decode built a
//! `Value` tree from the bytes and walked it, every encode built a tree and serialized it. Kept
//! as the differential oracle of the direct codec (`tests_direct`): it must accept and reject
//! the same inputs, decode them alike and write the same bytes and pages.
#![allow(dead_code)]

pub(crate) mod codec;
pub(crate) mod seq_wire;
pub(crate) mod stream;
pub(crate) mod wire;
