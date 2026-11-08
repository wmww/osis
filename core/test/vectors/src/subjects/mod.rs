//! Per-subject checkers and generators. A hand-written file has a checker (the implementation must
//! reproduce every case); a generator builds its file in memory (its asserts check the
//! implementation as it goes) and some have a checker run on what they build.

pub mod blob;
pub mod boxes;
pub mod bundle;
pub mod cbor;
pub mod chunker;
pub mod commit;
pub mod crdt;
pub mod delete;
pub mod inbox;
pub mod judgment;
pub mod kdf;
pub mod lan;
pub mod keys;
pub mod link;
pub mod padme;
pub mod proto;
pub mod sign;
pub mod step;
pub mod schema;
pub mod tid;
pub mod wrap;

use crate::file::VecFile;
use crate::root;

/// Checks every live case of a parsed file.
pub type Checker = fn(&VecFile) -> Result<(), String>;

/// The hand-written files (paths under core/test/vectors/) and their checkers.
pub const HAND_WRITTEN: [(&str, Checker); 2] = [("cbor/values.vec", cbor::check), ("padme/padme.vec", padme::check)];

/// A generated file: its name (`<subject>/<name>`), generator and the checker run on its output.
pub struct Generated {
    pub name: &'static str,
    pub generate: fn() -> VecFile,
    pub check: Option<Checker>,
}

/// Every generator. A new one adds its line here.
pub const GENERATED: [Generated; 23] = {
    const fn g(name: &'static str, generate: fn() -> VecFile) -> Generated {
        Generated { name, generate, check: None }
    }
    [
        g("tid/thing", tid::thing),
        g("tid/key-actor", tid::key_actor),
        g("chunker/gear", chunker::gear),
        g("chunker/tree", chunker::tree),
        g("chunker/pages", chunker::pages),
        g("kdf/purposes", kdf::purposes),
        g("keys/seed", keys::seed),
        g("box/boxes", boxes::boxes),
        g("wrap/wrap", wrap::wrap),
        g("delete/keys", delete::keys),
        g("sign/signatures", sign::signatures),
        g("schema/core", schema::core),
        g("proto/messages", proto::messages),
        g("proto/reconcile", proto::reconcile),
        g("commit/headers", commit::headers),
        g("blob/prefix", blob::prefixes),
        g("blob/blobs", blob::blobs),
        g("step/steps", step::steps),
        g("inbox/inbox", inbox::inbox),
        g("link/link", link::links),
        g("lan/announce", lan::announce),
        g("bundle/bundle", bundle::bundle),
        Generated { name: "crdt/deltas", generate: crdt::deltas, check: Some(crdt::check) },
    ]
};

/// The generated file `name`, or none.
pub fn generated(name: &str) -> Option<&'static Generated> {
    GENERATED.iter().find(|g| g.name == name)
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
    crate::file::Record::new().with("subject", subject).with("spec", spec).with("source", "osis-vectors generator")
}

/// Live and pending case counts of a file run.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub live: usize,
    pub pending: usize,
}

fn report(file: &VecFile) -> Report {
    let live = file.live().count();
    Report { live, pending: file.cases.len() - live }
}

/// Runs a hand-written file: parse, then its checker.
pub fn run_hand_written(path: &str) -> Result<Report, String> {
    let check = HAND_WRITTEN.iter().find(|h| h.0 == path).ok_or_else(|| format!("{path}: not a hand-written file"))?.1;
    let text = std::fs::read_to_string(root().join(path)).map_err(|e| format!("{path}: {e}"))?;
    let file = VecFile::parse(&text).map_err(|e| format!("{path}: {e}"))?;
    check(&file).map_err(|e| format!("{path}: {e}"))?;
    Ok(report(&file))
}

/// Runs a generator in memory, then its checker on what it built (also re-parsed from its text).
pub fn run_generated(name: &str) -> Result<Report, String> {
    let g = generated(name).ok_or_else(|| format!("{name}: no generator"))?;
    let file = (g.generate)();
    let parsed = VecFile::parse(&file.render()).map_err(|e| format!("{name}: {e}"))?;
    if let Some(check) = g.check {
        check(&parsed).map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(report(&parsed))
}
