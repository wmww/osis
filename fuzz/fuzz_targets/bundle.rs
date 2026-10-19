//! Bundle reader and importer (spec/wire.md §12): never panic; every record read re-encodes to
//! a record that reads back equal.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_label::{BundleReader, Importer, Record};

fuzz_target!(|data: &[u8]| {
    let Ok(mut r) = BundleReader::new(data) else { return };
    let mut imp = Importer::new();
    for _ in 0..1000 {
        let Ok(Some(rec)) = r.next_record() else { return };
        if !matches!(rec, Record::Unknown(_)) {
            assert_eq!(Record::from_value(&rec.to_value().unwrap()).unwrap(), rec);
        }
        let _ = imp.import(rec);
    }
});
