//! First-party schemas over the core (notes/std.md): typed keys for contacts and events. Notes and
//! tags need only core aspects (`osis::core::{NAME, BODY, TAG}`). The scenario tests under
//! `tests/` show each standard shape over the `osis` API.
#![forbid(unsafe_code)]

/// Contacts and profiles (schemas/contact.osis).
#[allow(dead_code, clippy::all)]
pub mod contact {
    use osis::schema as osis_schema;
    include!(concat!(env!("OUT_DIR"), "/contact.rs"));
}

/// Calendar events (schemas/event.osis).
#[allow(dead_code, clippy::all)]
pub mod event {
    use osis::schema as osis_schema;
    include!(concat!(env!("OUT_DIR"), "/event.rs"));
}
