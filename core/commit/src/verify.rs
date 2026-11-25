//! Delta verification against the header (spec/commits.md §1, §4; spec/crdt.md §2.3, §2.4).

use crate::blob::{CommitBlob, Part};
use crate::header::{EphClass, Form, Header};
use crate::Error;
use osis_base::{CommitId, Tid};
use osis_crdt::{Checked, CounterRange, Delta, DeltaCtx, DeltaKind, Interner, PageSource, Piece, Snapshot, decode_checked, decode_delta, decode_snapshot, stream_checked, stream_delta, stream_snapshot};
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
    let a = h.aspects.get(ai).ok_or(Error::Malformed("part index out of range"))?;
    let own = match h.form {
        Form::Commit => interner.commit(*id),
        Form::Session(nonce) => interner.session(osis_crdt::Session { node: h.signer, nonce }),
    };
    Ok(DeltaCtx { ts: h.ts, own, range: CounterRange { lo: a.lo, hi: a.hi }, kind: h.kind.delta_kind() })
}

/// The writer-side context for encoding a delta of `kind` in a commit (commit form uses a
/// placeholder own source: own dots are encoded without it).
pub fn writer_ctx(form: Form, kind: crate::Kind, ts: osis_base::Ts, signer: Tid, lo: u64, hi: u64) -> DeltaCtx {
    DeltaCtx { ts, own: form.own_source(signer, CommitId([0; 32])), range: CounterRange { lo, hi }, kind: kind.delta_kind() }
}

/// The page source of a relay-only commit's deltas, which never page (spec/commits.md §2): any
/// page is bad input.
struct NoPages;

impl PageSource for NoPages {
    fn get(&mut self, _: &osis_base::Link) -> Result<Vec<u8>, osis_crdt::PageError> {
        Err(osis_crdt::PageError::Corrupt)
    }
    fn params(&self) -> osis_crdt::PageParams {
        osis_crdt::PageParams::FORMAT
    }
}

/// A delta's pages as its links name them, each link's delete keys checked against the delta's
/// (spec/crypto.md §7 Checked keys). Invariant: a page applies only where its link names exactly
/// the delete keys its delta lists. Pages are framed by their delta alone (never reused, spec/crdt.md §8), so
/// any other keys are a writer framing a page outside what the key check judges: whoever holds
/// them could delete it at stores. The blob's prefix bearing the link is the page source's
/// (osis-blob's `BlobReader::judging`).
struct Keyed<'a> {
    inner: &'a mut dyn PageSource,
    del: Option<osis_base::Del>,
}

impl PageSource for Keyed<'_> {
    fn get(&mut self, link: &osis_base::Link) -> Result<Vec<u8>, osis_crdt::PageError> {
        if self.del != Some(link.del) {
            return Err(osis_crdt::PageError::Framing);
        }
        self.inner.get(link)
    }
    fn params(&self) -> osis_crdt::PageParams {
        self.inner.params()
    }
}

/// The delete keys header `h` lists for its aspect `ai`, as a link names them (`None`: two at one
/// level, which no link names).
fn listed_del(h: &Header, ai: usize) -> Option<osis_base::Del> {
    let a = h.aspects.get(ai)?;
    osis_base::Del::from_keys(a.keys.iter().map(|&i| h.keys.get(i).map(|k| (k.level, k.key))).collect::<Option<Vec<_>>>()?)
}

/// The aspect key and context of `part` once its delta hash checks under `dedup`.
fn checked_ctx<'h>(h: &'h Header, id: &CommitId, part: &Part, dedup: &Secret32, interner: &mut Interner) -> Result<(&'h str, DeltaCtx), Error> {
    let a = h.aspects.get(part.ai).ok_or(Error::Malformed("part index out of range"))?;
    if delta_hash(dedup, &part.delta) != a.hash {
        return Err(Error::DeltaHash { ai: part.ai });
    }
    Ok((a.ak.as_str(), delta_ctx(h, id, part.ai, interner)?))
}

/// Checks one part's delta hash under the dedup secret of its thing and decodes it against the
/// header facts (range check, spec/crdt.md §2.3). Pages of a paged delta come from `pages`; a
/// relay-only commit's from `NoPages`.
pub fn verify_part<'a>(h: &Header, id: &CommitId, part: &Part, dedup: &Secret32, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>) -> Result<Decoded, Error> {
    let (ak, cx) = checked_ctx(h, id, part, dedup, interner)?;
    let mut none = NoPages;
    let pages: Option<&mut dyn PageSource> = if h.ephemeral == Some(EphClass::Relay) { Some(&mut none) } else { pages.map(|p| p as &mut dyn PageSource) };
    let mut keyed = pages.map(|inner| Keyed { inner, del: listed_del(h, part.ai) });
    let pages = keyed.as_mut().map(|k| k as &mut dyn PageSource);
    let d = match cx.kind {
        DeltaKind::Snapshot => Decoded::Snapshot(decode_snapshot(&part.delta, &cx, &mut *interner, pages)?),
        DeltaKind::Writer => Decoded::Delta(decode_delta(&part.delta, &cx, &mut *interner, pages)?),
    };
    check_fragment(ak, d.fragment())?;
    if pieced(h, ak) {
        PieceShape::of(d.fragment()).check(part.ai)?;
    }
    Ok(d)
}

/// `verify_part` handing the delta to `each` one piece at a time (`osis_crdt::stream_delta`):
/// the skeleton, then each leaf page. Returns a snapshot's root tables (frontiers, `Absorbed`). Pieces
/// already handed over stay valid only if the whole call succeeds.
pub fn stream_part<'a>(h: &Header, id: &CommitId, part: &Part, dedup: &Secret32, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>, each: &mut dyn FnMut(osis_crdt::Fragment) -> Result<(), osis_crdt::Error>) -> Result<Option<osis_crdt::Head>, Error> {
    let (ak, cx) = checked_ctx(h, id, part, dedup, interner)?;
    let mut none = NoPages;
    let pages: Option<&mut dyn PageSource> = if h.ephemeral == Some(EphClass::Relay) { Some(&mut none) } else { pages.map(|p| p as &mut dyn PageSource) };
    let mut keyed = pages.map(|inner| Keyed { inner, del: listed_del(h, part.ai) });
    let pages = keyed.as_mut().map(|k| k as &mut dyn PageSource);
    // `check_fragment` holds of the whole iff of every piece (per record, per position); a bad
    // delta still streams to its end, so a decoding error wins as in `verify_part`
    let mut keyed = Ok(());
    let mut shape = pieced(h, ak).then(PieceShape::default);
    let mut each = |p: Piece| {
        let f = match p {
            Piece::Skeleton(f) | Piece::Page { fragment: f, .. } => f,
        };
        if keyed.is_ok() {
            keyed = check_fragment(ak, &f);
        }
        if let Some(s) = &mut shape {
            s.add(&f);
        }
        if keyed.is_ok() { each(f) } else { Ok(()) }
    };
    let out = match cx.kind {
        DeltaKind::Snapshot => stream_snapshot(&part.delta, &cx, &mut *interner, pages, &mut each).map(Some)?,
        DeltaKind::Writer => stream_delta(&part.delta, &cx, &mut *interner, pages, &mut each).map(|_| None)?,
    };
    keyed?;
    shape.map_or(Ok(()), |s| s.check(part.ai))?;
    Ok(out)
}

/// `stream_part` of a part this node checked in full (`Checked`: the part of
/// aspect `ai`, its `delta`), decode-only: no hash, canonical or `check_fragment` check again.
/// `want`: only the pages it names (`stream_checked_some`).
#[allow(clippy::too_many_arguments)]
pub fn read_part<'a>(h: &Header, id: &CommitId, ai: usize, delta: Checked<'_>, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>, want: Option<osis_crdt::Want<'_>>, each: &mut dyn FnMut(Piece) -> Result<(), osis_crdt::Error>) -> Result<Option<osis_crdt::Head>, Error> {
    let cx = delta_ctx(h, id, ai, interner)?;
    let head = match want {
        Some(w) => osis_crdt::stream_checked_some(delta, &cx, interner, pages, w, each)?,
        None => stream_checked(delta, &cx, interner, pages, each)?,
    };
    Ok((cx.kind == DeltaKind::Snapshot).then_some(head))
}

/// `verify_part` of a part this node checked in full, decode-only (`read_part`).
pub fn read_part_whole<'a>(h: &Header, id: &CommitId, ai: usize, delta: Checked<'_>, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>) -> Result<Decoded, Error> {
    let cx = delta_ctx(h, id, ai, interner)?;
    let (head, fragment) = decode_checked(delta, &cx, interner, pages)?;
    Ok(match cx.kind {
        DeltaKind::Snapshot => Decoded::Snapshot(Snapshot { nonce: head.nonce, fragment, frontiers: head.frontiers, absorbed: head.absorbed, facts: head.facts }),
        DeltaKind::Writer => Decoded::Delta(Delta { nonce: head.nonce, fragment }),
    })
}

/// The rules a delta's fragment answers to by itself (spec/commits.md §4), per record and position.
/// Whether a delta of `ak` in `h` is a `secrets.0` piece, held to `PieceShape`: a role commit's
/// or a role compaction snapshot's (spec/wire.md §4 Pieces: pieced alike).
fn pieced(h: &Header, ak: &str) -> bool {
    matches!(h.kind, crate::Kind::Role | crate::Kind::RoleSnapshot) && ak == crate::header::PIECED
}

/// The holder a `secrets.0` box record's key names (`None`: no box key).
pub fn box_holder(k: &osis_base::Value) -> Option<Tid> {
    let t = osis_schema::typed_read(osis_schema::core_schema(), k, &osis_schema::Type::Named("box_key".into(), Vec::new())).ok()?;
    <osis_schema::core_types::BoxKey as osis_schema::Codec>::from_value(&t).ok().map(|b| b.holder.0)
}

/// Whether role commit `secrets.0` delta `f` is a piece (`PieceShape`).
pub fn is_piece(f: &osis_crdt::Fragment) -> bool {
    PieceShape::of(f).check(0).is_ok()
}

/// What a role commit's `secrets.0` delta holds, as its pieces are judged (spec/wire.md §4
/// Pieces): the holders its box records are keyed with, and whether it holds any other record
/// (history, whole-value or field writes, keyless records). A piece holds one holder's records
/// and nothing else, or none keyed with a holder; anything else holds nothing, as bytes not
/// matching the header (spec/commits.md §4). Invariant (security): a piece's readers are its
/// holder's (spec/permissions.md §4 Copies), so no piece that stands carries another holder's
/// records, whoever wrote it.
#[derive(Default)]
struct PieceShape {
    holders: std::collections::BTreeSet<Tid>,
    other: bool,
}

impl PieceShape {
    fn of(f: &osis_crdt::Fragment) -> PieceShape {
        let mut s = PieceShape::default();
        s.add(f);
        s
    }
    fn add(&mut self, f: &osis_crdt::Fragment) {
        self.other |= !f.only_keyed_in(0);
        for k in f.field_keys(0) {
            match box_holder(k) {
                Some(h) => {
                    self.holders.insert(h);
                }
                None => self.other = true,
            }
        }
    }
    /// As a delta not matching its hash (`Error::DeltaHash`): part `ai` holds nothing, dropped
    /// alone (spec/commits.md §4).
    fn check(&self, ai: usize) -> Result<(), Error> {
        match (self.holders.len(), self.other) {
            (0, _) | (1, false) => Ok(()),
            _ => Err(Error::DeltaHash { ai }),
        }
    }
}

fn check_fragment(ak: &str, f: &osis_crdt::Fragment) -> Result<(), Error> {
    check_entry_keys(ak, f)?;
    check_types(ak, f)?;
    // a role-class value stays inline (spec/data-model.md §6). Role kinds write only role-class
    // aspects and `created.0`, a record far below the threshold; content kinds write no
    // role-class one (`Header::validate`).
    if !osis_schema::core_types::is_role_class(ak) && f.holds_unchunked() {
        return Err(Error::Malformed("an unchunked value above CHUNK_THRESHOLD"));
    }
    Ok(())
}


/// A keyed map removal or tombstone (a keyed entry record with a reset) outside the
/// role-class aspects is malformed: an app map's key must not outlive its entry
/// (spec/crdt.md §5.6).
fn check_entry_keys(ak: &str, f: &osis_crdt::Fragment) -> Result<(), Error> {
    if !osis_schema::core_types::is_role_class(ak) && f.keyed_resets() {
        return Err(Error::Malformed("keyed map removal outside a role-class aspect"));
    }
    Ok(())
}

/// A core-aspect delta must fit the core schema's type (`Fragment::fits`: encodings, values,
/// enum cases; a link only where the type takes one, spec/data-model.md §6): every node judges it
/// alike from the delta and its build's core schema, so a reader of the aspect never meets a
/// value its type does not take (one bad element would make a whole `holds.0` unreadable).
fn check_types(ak: &str, f: &osis_crdt::Fragment) -> Result<(), Error> {
    match osis_schema::core_schema().view(ak) {
        Some(v) if !f.fits(&v) => Err(Error::Malformed("a value the core type does not take")),
        _ => Ok(()),
    }
}

/// Verifies a received commit blob whose header lists are resolved: signature under the
/// signer's key, header rules, then every part (hash and range check). `dedup` gives each
/// thing's dedup secret. Returns the decoded deltas in part order.
pub fn verify_blob(
    blob: &CommitBlob,
    key: &VerifyingKey,
    dedup: &dyn Fn(&Tid) -> Option<Secret32>,
    mut pages: Option<&mut dyn PageSource>,
) -> Result<Vec<Decoded>, Error> {
    let id = blob.id();
    crate::verify_signature(&id, &blob.sigs, key)?;
    blob.header.validate()?;
    blob.check_paths()?;
    let mut interner = Interner::new();
    let mut out = Vec::with_capacity(blob.parts.len());
    for p in &blob.parts {
        let a = blob.header.aspects.get(p.ai).ok_or(Error::Malformed("part index out of range"))?;
        let d = dedup(&a.tid).ok_or(Error::Build("dedup secret not supplied"))?;
        let pg: Option<&mut dyn PageSource> = match &mut pages {
            Some(p) => Some(&mut **p),
            None => None,
        };
        out.push(verify_part(&blob.header, &id, p, &d, &mut interner, pg)?);
    }
    Ok(out)
}
