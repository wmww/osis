//! One test per hand-written file and per generator (notes/testing.md; format
//! core/test/vectors/README.md). Each file's cases cite their spec sections.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_vectors::subjects::{self, GENERATED, HAND_WRITTEN};

macro_rules! hand_written {
    ($($name:ident => $path:literal,)*) => {
        $(
            #[test]
            fn $name() {
                let r = subjects::run_hand_written($path).unwrap_or_else(|e| panic!("{e}"));
                assert!(r.live > 0, "{}: no live cases", $path);
            }
        )*
        const HAND: &[&str] = &[$($path),*];
    };
}

macro_rules! generated {
    ($($name:ident => $subject:literal,)*) => {
        $(
            #[test]
            fn $name() {
                let r = subjects::run_generated($subject).unwrap_or_else(|e| panic!("{e}"));
                assert!(r.live > 0, "{}: no live cases", $subject);
            }
        )*
        const GEN: &[&str] = &[$($subject),*];
    };
}

hand_written! {
    cbor_values => "cbor/values.vec",
    padme_padme => "padme/padme.vec",
}

// A new generator adds its line here.
generated! {
    crdt_deltas => "crdt/deltas",
    tid_thing => "tid/thing",
    tid_key_actor => "tid/key-actor",
    chunker_gear => "chunker/gear",
    chunker_tree => "chunker/tree",
    chunker_pages => "chunker/pages",
    kdf_purposes => "kdf/purposes",
    keys_seed => "keys/seed",
    box_boxes => "box/boxes",
    wrap_wrap => "wrap/wrap",
    delete_keys => "delete/keys",
    sign_signatures => "sign/signatures",
    schema_core => "schema/core",
    proto_messages => "proto/messages",
    proto_reconcile => "proto/reconcile",
    commit_headers => "commit/headers",
    blob_prefix => "blob/prefix",
    blob_blobs => "blob/blobs",
    step_steps => "step/steps",
    inbox_inbox => "inbox/inbox",
    link_link => "link/link",
    bundle_bundle => "bundle/bundle",
    lan_announce => "lan/announce",
}

// spec: none (runner coverage): every subject has its test.
#[test]
fn every_subject_has_a_test() {
    let mut hand: Vec<&str> = HAND_WRITTEN.iter().map(|h| h.0).collect();
    let mut gen_: Vec<&str> = GENERATED.iter().map(|g| g.name).collect();
    let (mut h, mut g) = (HAND.to_vec(), GEN.to_vec());
    for v in [&mut hand, &mut gen_, &mut h, &mut g] {
        v.sort();
    }
    assert_eq!(h, hand, "hand_written! must list exactly subjects::HAND_WRITTEN");
    assert_eq!(g, gen_, "generated! must list exactly subjects::GENERATED");
}

// spec: none (core/test/vectors/README.md, Files).
#[test]
fn format_round_trip() {
    let text = "subject: x\nspec: s\n\ncase: a\nspec: s\nhex: 00\n\ncase: b\nspec: s\npending: later\n";
    let f = osis_vectors::file::VecFile::parse(text).unwrap();
    assert_eq!(f.render(), text);
    assert_eq!(f.live().count(), 1);
    assert!(osis_vectors::file::VecFile::parse("subject: x\n\ncase: a\nspec: s\n\ncase: a\nspec: s\n").is_err());
}

// spec: none (core/test/fuzz/README.md): every fuzz target but the `arbitrary`-driven ones gets
// seeds, so a renamed subject or field cannot leave a corpus empty.
#[test]
fn every_fuzz_target_has_seeds() {
    for (target, seeds) in osis_vectors::corpus::seeds() {
        assert!(!seeds.is_empty(), "{target}: no seeds");
    }
}
