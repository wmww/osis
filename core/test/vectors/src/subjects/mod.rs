//! Per-file checkers and generators. A file has a checker (hand-written vectors: the
//! implementation must reproduce every case) or a generator (the implementation writes the file;
//! the committed bytes must equal a fresh generation), or both.

pub mod blob;
pub mod boxes;
pub mod bundle;
pub mod cbor;
pub mod chunker;
pub mod commit;
pub mod delete;
pub mod inbox;
pub mod kdf;
pub mod lan;
pub mod keys;
pub mod link;
pub mod padme;
pub mod proto;
pub mod sign;
pub mod signal;
pub mod step;
pub mod schema;
pub mod tid;
pub mod wrap;

use crate::file::VecFile;
use crate::root;

/// Checks every live case of a parsed file.
pub type Checker = fn(&VecFile) -> Result<(), String>;

pub struct Subject {
    pub generate: Option<fn() -> VecFile>,
    pub check: Option<Checker>,
}

/// The subject handling a manifest path. A new vector file adds its line here.
pub fn get(path: &str) -> Option<Subject> {
    Some(match path {
        "cbor/values.vec" => Subject { generate: None, check: Some(cbor::check) },
        "tid/thing.vec" => Subject { generate: Some(tid::thing), check: None },
        "chunker/gear.vec" => Subject { generate: Some(chunker::gear), check: None },
        "padme/padme.vec" => Subject { generate: None, check: Some(padme::check) },
        "tid/key-actor.vec" => Subject { generate: Some(tid::key_actor), check: None },
        "kdf/purposes.vec" => Subject { generate: Some(kdf::purposes), check: None },
        "keys/seed.vec" => Subject { generate: Some(keys::seed), check: None },
        "box/boxes.vec" => Subject { generate: Some(boxes::boxes), check: None },
        "wrap/wrap.vec" => Subject { generate: Some(wrap::wrap), check: None },
        "delete/keys.vec" => Subject { generate: Some(delete::keys), check: None },
        "sign/signatures.vec" => Subject { generate: Some(sign::signatures), check: None },
        "schema/core.vec" => Subject { generate: Some(schema::core), check: None },
        "proto/messages.vec" => Subject { generate: Some(proto::messages), check: None },
        "proto/reconcile.vec" => Subject { generate: Some(proto::reconcile), check: None },
        "commit/headers.vec" => Subject { generate: Some(commit::headers), check: None },
        "blob/prefix.vec" => Subject { generate: Some(blob::prefixes), check: None },
        "blob/blobs.vec" => Subject { generate: Some(blob::blobs), check: None },
        "chunker/tree.vec" => Subject { generate: Some(chunker::tree), check: None },
        "chunker/pages.vec" => Subject { generate: Some(chunker::pages), check: None },
        "step/steps.vec" => Subject { generate: Some(step::steps), check: None },
        "inbox/inbox.vec" => Subject { generate: Some(inbox::inbox), check: None },
        "signal/signal.vec" => Subject { generate: Some(signal::signal), check: None },
        "link/link.vec" => Subject { generate: Some(link::links), check: None },
        "lan/announce.vec" => Subject { generate: Some(lan::announce), check: None },
        "bundle/bundle.vec" => Subject { generate: Some(bundle::bundle), check: None },
        _ => return None,
    })
}

/// An rng handing out the listed bytes in order, so a vector names the randomness it consumes.
pub struct FixedRng(Vec<u8>);

impl FixedRng {
    pub fn new(parts: &[&[u8]]) -> FixedRng {
        FixedRng(parts.concat())
    }
}

impl osis_crypto::RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!("vectors draw bytes only")
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!("vectors draw bytes only")
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert!(self.0.len() >= dest.len(), "FixedRng exhausted");
        let rest = self.0.split_off(dest.len());
        dest.copy_from_slice(&self.0);
        self.0 = rest;
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), osis_crypto::RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl osis_crypto::CryptoRng for FixedRng {}

impl Drop for FixedRng {
    fn drop(&mut self) {
        // Unused randomness means the vector lists more than the computation drew.
        if !std::thread::panicking() {
            assert!(self.0.is_empty(), "FixedRng: {} bytes left over", self.0.len());
        }
    }
}

/// A 26-byte clear prefix, opaque to these vectors: framing version 1, salt 01*16, no expiry,
/// no commitments (layout spec/wire.md §5, vectors of osis-label).
pub const PREFIX: [u8; 26] = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// 32 repeated bytes (the fixed seeds of the vectors).
pub fn s32(b: u8) -> osis_crypto::Secret32 {
    osis_crypto::Secret32::from_bytes([b; 32])
}

/// A case record with its name and spec section.
pub fn case(name: &str, spec: &str) -> crate::file::Record {
    crate::file::Record::new().with("case", name).with("spec", spec)
}

/// Header shared by generated files.
pub fn generated_header(subject: &str, spec: &str) -> crate::file::Record {
    crate::file::Record::new()
        .with("subject", subject)
        .with("spec", spec)
        .with("source", "generated by `cargo run -p osis-vectors --bin gen-vectors`; do not edit")
}

/// Live and pending case counts of a file run.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub live: usize,
    pub pending: usize,
}

/// Runs one vector file: parse, generator comparison, checker.
pub fn run(path: &str) -> Result<Report, String> {
    let s = get(path).ok_or_else(|| format!("{path}: no subject registered (subjects::get)"))?;
    let text = std::fs::read_to_string(root().join(path)).map_err(|e| format!("{path}: {e}"))?;
    let file = VecFile::parse(&text).map_err(|e| format!("{path}: {e}"))?;
    if let Some(generate) = s.generate {
        let fresh = generate().render();
        if fresh != text {
            return Err(format!("{path}: implementation output differs from the committed vectors; regenerate (if provisional) or fix the implementation"));
        }
    }
    if let Some(check) = s.check {
        check(&file).map_err(|e| format!("{path}: {e}"))?;
    }
    let live = file.live().count();
    Ok(Report { live, pending: file.cases.len() - live })
}
