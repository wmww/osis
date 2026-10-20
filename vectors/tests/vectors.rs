//! One test per vector file, plus the manifest and freeze policy (notes/testing.md; format
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
    padme_padme => "padme/padme.vec",
    tid_key_actor => "tid/key-actor.vec",
    kdf_purposes => "kdf/purposes.vec",
    keys_seed => "keys/seed.vec",
    box_boxes => "box/boxes.vec",
    wrap_wrap => "wrap/wrap.vec",
    token_tokens => "token/tokens.vec",
    sign_signatures => "sign/signatures.vec",
    schema_core => "schema/core.vec",
    proto_messages => "proto/messages.vec",
    proto_reconcile => "proto/reconcile.vec",
    commit_headers => "commit/headers.vec",
    blob_prefix => "blob/prefix.vec",
    blob_blobs => "blob/blobs.vec",
    chunker_tree => "chunker/tree.vec",
    chunker_pages => "chunker/pages.vec",
    step_steps => "step/steps.vec",
    inbox_inbox => "inbox/inbox.vec",
    signal_signal => "signal/signal.vec",
    link_link => "link/link.vec",
    bundle_bundle => "bundle/bundle.vec",
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
