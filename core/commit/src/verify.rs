//! Delta verification against the header (spec/commits.md §1, §4; spec/crdt.md §2.3, §2.4).

use crate::blob::{CommitBlob, Part};
use crate::header::{Form, Header};
use crate::Error;
use osis_core::{CommitId, Tid};
use osis_crdt::{CounterRange, Delta, DeltaCtx, DeltaKind, Interner, PageSource, Snapshot, Source, decode_delta, decode_snapshot};
use osis_crypto::{Secret32, VerifyingKey, delta_hash};

/// A verified, decoded delta.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decoded {
    Delta(Delta),
    Snapshot(Snapshot),
}

/// The header facts a delta of aspect `ai` is read against.
pub fn delta_ctx(h: &Header, id: &CommitId, ai: usize, interner: &mut Interner) -> Result<DeltaCtx, Error> {
    let a = h.aspects.get(ai).ok_or(Error::Malformed("aspect index out of range"))?;
    let own = match h.form {
        Form::Node => interner.node(h.author),
        Form::Commit => interner.commit(*id),
    };
    Ok(DeltaCtx { ts: h.ts, own, range: CounterRange { lo: a.lo, hi: a.hi }, kind: h.kind.delta_kind() })
}

/// The writer-side context for encoding a delta of `kind` in a commit (commit form uses a
/// placeholder own source: own dots are encoded without it).
pub fn writer_ctx(kind: crate::Kind, ts: osis_core::Ts, author: Tid, lo: u64, hi: u64) -> DeltaCtx {
    DeltaCtx { ts, own: Source::node(author), range: CounterRange { lo, hi }, kind: kind.delta_kind() }
}

/// Checks one part's delta hash under the dedup secret of its thing and decodes it against the
/// header facts (range check, spec/crdt.md §2.3). Pages of a paged delta come from `pages`.
pub fn verify_part<'a>(h: &Header, id: &CommitId, part: &Part, dedup: &Secret32, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>) -> Result<Decoded, Error> {
    let a = h.aspects.get(part.ai).ok_or(Error::Malformed("part aspect index out of range"))?;
    let want = a.hashes.get(part.di).ok_or(Error::Malformed("part delta index out of range"))?;
    if delta_hash(dedup, &part.delta) != *want {
        return Err(Error::DeltaHash { ai: part.ai, di: part.di });
    }
    let cx = delta_ctx(h, id, part.ai, interner)?;
    Ok(match cx.kind {
        DeltaKind::Snapshot => Decoded::Snapshot(decode_snapshot(&part.delta, &cx, interner, pages)?),
        DeltaKind::Writer | DeltaKind::Import => Decoded::Delta(decode_delta(&part.delta, &cx, interner, pages)?),
    })
}

/// Verifies a received commit blob whose header lists are resolved: signature under the
/// author's key, header rules, then every part (hash and range check). `dedup` gives each
/// thing's dedup secret. Returns the decoded deltas in part order.
pub fn verify_blob(
    blob: &CommitBlob,
    key: &VerifyingKey,
    dedup: &dyn Fn(&Tid) -> Option<Secret32>,
    mut pages: Option<&mut dyn PageSource>,
) -> Result<Vec<Decoded>, Error> {
    let id = blob.id();
    crate::verify_signature(&id, &blob.signature, key)?;
    blob.header.validate()?;
    let mut interner = Interner::new();
    let mut out = Vec::with_capacity(blob.parts.len());
    for p in &blob.parts {
        let a = blob.header.aspects.get(p.ai).ok_or(Error::Malformed("part aspect index out of range"))?;
        let d = dedup(&a.tid).ok_or(Error::Build("dedup secret not supplied"))?;
        let pg: Option<&mut dyn PageSource> = match &mut pages {
            Some(p) => Some(&mut **p),
            None => None,
        };
        out.push(verify_part(&blob.header, &id, p, &d, &mut interner, pg)?);
    }
    Ok(out)
}
