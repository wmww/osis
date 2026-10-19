//! One test per vector file, plus the manifest and freeze policy (plans/test-infra.md; format
//! vectors/README.md). Each file's cases cite their spec sections.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_vectors::manifest::{self, Status};
use osis_vectors::subjects;

macro_rules! vector_files {
    ($($name:ident => $path:literal,)*) => {
        $(
            #[test]
            fn $name() {
                let r = subjects::run($path).unwrap_or_else(|e| panic!("{e}"));
                assert!(r.live > 0, "{}: no live cases", $path);
            }
        )*
        const FILES: &[&str] = &[$($path),*];
    };
}

// A file leaving `pending` in MANIFEST adds its line here.
vector_files! {
    cbor_values => "cbor/values.vec",
    tid_thing => "tid/thing.vec",
    chunker_gear => "chunker/gear.vec",
}

// spec: none (vectors/README.md, "Manifest and freezing": every file listed, frozen bytes
// unchanged, change notes).
#[test]
fn manifest_policy() {
    let entries = manifest::load().unwrap();
    let errs = manifest::check(&entries);
    assert!(errs.is_empty(), "{}", errs.join("\n"));
}

// spec: none (runner coverage).
#[test]
fn every_present_file_has_a_test_and_subject() {
    let present: Vec<String> =
        manifest::load().unwrap().into_iter().filter(|e| !matches!(e.status, Status::Pending(_))).map(|e| e.path).collect();
    let mut tested: Vec<String> = FILES.iter().map(|s| s.to_string()).collect();
    tested.sort();
    let mut present_sorted = present.clone();
    present_sorted.sort();
    assert_eq!(tested, present_sorted, "vector_files! must list exactly the non-pending MANIFEST entries");
    for p in &present {
        assert!(subjects::get(p).is_some(), "{p}: no subject");
    }
}

// spec: none (vectors/README.md, Files).
#[test]
fn format_round_trip() {
    let text = "subject: x\nspec: s\n\ncase: a\nspec: s\nhex: 00\n\ncase: b\nspec: s\npending: later\n";
    let f = osis_vectors::file::VecFile::parse(text).unwrap();
    assert_eq!(f.render(), text);
    assert_eq!(f.live().count(), 1);
    assert!(osis_vectors::file::VecFile::parse("subject: x\n\ncase: a\nspec: s\n\ncase: a\nspec: s\n").is_err());
}
