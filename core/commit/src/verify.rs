//! Delta verification against the header (spec/commits.md §1, §4; spec/crdt.md §2.3, §2.4).

use crate::blob::{CommitBlob, Part};
use crate::header::{Form, Header};
use crate::Error;
use osis_base::{CommitId, Tid};
use osis_crdt::{CounterRange, Delta, DeltaCtx, DeltaKind, Interner, PageSource, Piece, Snapshot, decode_delta, decode_snapshot, stream_delta, stream_snapshot};
use osis_crypto::{Secret32, VerifyingKey, delta_hash};

/// A verified, decoded delta.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decoded {
    Delta(Delta),
    Snapshot(Snapshot),
}

impl Decoded {
    /// The delta's or snapshot's fragment.
    pub fn fragment(&self) -> &osis_crdt::Fragment {
        match self {
            Decoded::Delta(x) => &x.fragment,
            Decoded::Snapshot(x) => &x.fragment,
        }
    }

    pub fn into_fragment(self) -> osis_crdt::Fragment {
        match self {
            Decoded::Delta(x) => x.fragment,
            Decoded::Snapshot(x) => x.fragment,
        }
    }
}

/// The header facts a delta of aspect `ai` is read against.
pub fn delta_ctx(h: &Header, id: &CommitId, ai: usize, interner: &mut Interner) -> Result<DeltaCtx, Error> {
    let a = h.aspects.get(ai).ok_or(Error::Malformed("aspect index out of range"))?;
    let own = match h.form {
        Form::Node => interner.node(h.author),
        Form::Commit => interner.commit(*id),
        Form::Session(nonce) => interner.session(osis_crdt::Session { node: h.author, nonce }),
    };
    Ok(DeltaCtx { ts: h.ts, own, range: CounterRange { lo: a.lo, hi: a.hi }, kind: h.kind.delta_kind() })
}

/// The writer-side context for encoding a delta of `kind` in a commit (commit form uses a
/// placeholder own source: own dots are encoded without it).
pub fn writer_ctx(form: Form, kind: crate::Kind, ts: osis_base::Ts, author: Tid, lo: u64, hi: u64) -> DeltaCtx {
    DeltaCtx { ts, own: form.own_source(author, CommitId([0; 32])), range: CounterRange { lo, hi }, kind: kind.delta_kind() }
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
    let d = match cx.kind {
        DeltaKind::Snapshot => Decoded::Snapshot(decode_snapshot(&part.delta, &cx, interner, pages)?),
        DeltaKind::Writer | DeltaKind::Import => Decoded::Delta(decode_delta(&part.delta, &cx, interner, pages)?),
    };
    check_entry_keys(a.ak.as_str(), d.fragment())?;
    check_types(a.ak.as_str(), d.fragment())?;
    Ok(d)
}

/// `verify_part` handing the delta to `each` one piece at a time (`osis_crdt::stream_delta`):
/// the skeleton, then each leaf page. Returns a snapshot's root tables (frontiers, `Absorbed`). Pieces
/// already handed over stay valid only if the whole call succeeds.
pub fn stream_part<'a>(h: &Header, id: &CommitId, part: &Part, dedup: &Secret32, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>, each: &mut dyn FnMut(osis_crdt::Fragment) -> Result<(), osis_crdt::Error>) -> Result<Option<osis_crdt::Head>, Error> {
    let a = h.aspects.get(part.ai).ok_or(Error::Malformed("part aspect index out of range"))?;
    let want = a.hashes.get(part.di).ok_or(Error::Malformed("part delta index out of range"))?;
    if delta_hash(dedup, &part.delta) != *want {
        return Err(Error::DeltaHash { ai: part.ai, di: part.di });
    }
    let cx = delta_ctx(h, id, part.ai, interner)?;
    // the keyed-removal and type rules hold of the whole iff of every piece (per record, per position); a bad
    // delta still streams to its end, so a decoding error wins as in `verify_part`
    let ak = a.ak.as_str();
    let mut keyed = Ok(());
    let mut each = |p: Piece| {
        let f = match p {
            Piece::Skeleton(f) | Piece::Page { fragment: f, .. } => f,
        };
        if keyed.is_ok() {
            keyed = check_entry_keys(ak, &f).and_then(|()| check_types(ak, &f));
        }
        if keyed.is_ok() { each(f) } else { Ok(()) }
    };
    let out = match cx.kind {
        DeltaKind::Snapshot => stream_snapshot(&part.delta, &cx, interner, pages, &mut each).map(Some)?,
        DeltaKind::Writer | DeltaKind::Import => stream_delta(&part.delta, &cx, interner, pages, &mut each).map(|_| None)?,
    };
    keyed?;
    Ok(out)
}

/// A keyed map removal or tombstone (a keyed entry record with a reset) outside the
/// role-class aspects is malformed: an app map's key must not outlive its entry
/// (spec/crdt.md §5.6).
pub fn check_entry_keys(ak: &str, f: &osis_crdt::Fragment) -> Result<(), Error> {
    if !osis_schema::core_types::is_role_class(ak) && f.keyed_resets() {
        return Err(Error::Malformed("keyed map removal outside a role-class aspect"));
    }
    Ok(())
}

/// A core-aspect delta must fit the core schema's type (`Fragment::fits`: encodings, values,
/// enum cases; a link only where the type takes one, spec/data-model.md §6): every node judges it
/// alike from the delta and its build's core schema, so a reader of the aspect never meets a
/// value its type does not take (one bad element would make a whole `group.0` unreadable).
pub fn check_types(ak: &str, f: &osis_crdt::Fragment) -> Result<(), Error> {
    match osis_schema::core_schema().view(ak) {
        Some(v) if !f.fits(&v) => Err(Error::Malformed("a value the core type does not take")),
        _ => Ok(()),
    }
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
