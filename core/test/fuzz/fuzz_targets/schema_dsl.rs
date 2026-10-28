//! Schema DSL parser and schema-as-data reader (spec/data-model.md §10): never panic. A leading
//! 0 byte makes the rest a CBOR schema value, anything else DSL text. An accepted schema
//! round-trips through its value form, and its canonical bytes read back to it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_base::{Limits, decode};
use osis_schema::{Schema, parse};

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else { return };
    let schema = if first == 0 {
        let Ok(v) = decode(rest, &Limits::DEFAULT) else { return };
        let Ok(s) = Schema::from_value(&v) else { return };
        s
    } else {
        let Ok(text) = std::str::from_utf8(rest) else { return };
        let Ok(s) = parse("fuzz.osis", text) else { return };
        s
    };
    let back = Schema::from_value(&schema.to_value()).expect("value form round trip");
    assert_eq!(back, schema);
});
