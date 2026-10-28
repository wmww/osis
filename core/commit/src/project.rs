//! Projection of a commit into blobs, purge rewrite, prefix inputs (spec/sync.md §1, §3;
//! spec/commits.md §5; spec/wire.md §4, §5).

use crate::blob::{CommitBlob, Part, encode_parts};
use crate::cbor::array_head;
use crate::header::{AspectEntry, DeleteKey, Header, retention_value};
use crate::Error;
use osis_base::format::MAX_BLOB;
use osis_crypto::padme;
use osis_schema::Retention;
use std::collections::BTreeMap;

/// AEAD tag bytes after the padded plaintext.
const TAG_LEN: usize = 16;
/// Fixed prefix bytes before the commitments (spec/wire.md §5).
const PREFIX_FIXED: usize = 26;

/// One blob of a commit: the deltas of one (readable subset, retention class), or a size split
/// of one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Projection<K> {
    /// The caller's reader-set key of the class.
    pub readers: K,
    pub retention: Retention,
    /// Prefix expiry.
    pub expires: Option<u64>,
    /// Header delete keys the class calls for; the prefix commits to them under the blob's salt
    /// ([`crate::Prefix::from_keys`]).
    pub keys: Vec<DeleteKey>,
    /// `(ai, di)` of the deltas held.
    pub parts: Vec<(usize, usize)>,
    /// The commit blob plaintext (unpadded).
    pub plaintext: Vec<u8>,
}

/// Whole blob size for a plaintext length and commitment count.
fn blob_len(plain: usize, commitments: usize) -> usize {
    PREFIX_FIXED.saturating_add(33usize.saturating_mul(commitments)).saturating_add(padme(plain.saturating_add(1))).saturating_add(TAG_LEN)
}

fn head_len(n: usize) -> usize {
    let mut v = Vec::new();
    array_head(n, &mut v);
    v.len()
}

/// Encoded length of one part.
fn part_len(p: &Part) -> usize {
    let mut v = Vec::new();
    array_head(3, &mut v);
    osis_base::cbor::encode_into(&crate::cbor::uidx(p.ai), &mut v);
    osis_base::cbor::encode_into(&crate::cbor::uidx(p.di), &mut v);
    v.len().saturating_add(p.delta.len())
}

/// Plaintext bytes outside the parts list: outer head, header, signature.
fn fixed_len(c: &CommitBlob) -> usize {
    1usize.saturating_add(c.header.encode().len()).saturating_add(osis_base::encode(&c.signature.to_value()).len())
}

/// The prefix inputs any blob of `h` holding `parts` must carry: the expiry and the delete keys
/// of their one retention class (spec/wire.md §4, spec/sync.md §3). Parts of different classes
/// (retention, expiry or key set) in one blob are bad input. Zero parts: none.
pub fn prefix_inputs(h: &Header, parts: &[(usize, usize)]) -> Result<(Option<u64>, Vec<DeleteKey>), Error> {
    let mut class: Option<&AspectEntry> = None;
    for (ai, _) in parts {
        let a = h.aspects.get(*ai).ok_or(Error::Malformed("part aspect index out of range"))?;
        match class {
            None => class = Some(a),
            Some(c) if (c.retention, c.expires, &c.keys) != (a.retention, a.expires, &a.keys) => {
                return Err(Error::Invalid("one blob holding deltas of several retention classes"));
            }
            Some(_) => {}
        }
    }
    let Some(c) = class else { return Ok((None, Vec::new())) };
    let keys = c.keys.iter().map(|i| h.keys.get(*i).copied().ok_or(Error::Malformed("delete key index out of range"))).collect::<Result<Vec<_>, _>>()?;
    Ok((c.expires, keys))
}

/// Every delta fits a blob of `max` bytes alone (spec/commits.md §1; paging keeps a canonical
/// delta far below `MAX_BLOB`, so only a caller's mistake fails, such as a value left unchunked).
pub(crate) fn check_fits(c: &CommitBlob, max: usize) -> Result<(), Error> {
    let fixed = fixed_len(c).saturating_add(head_len(1));
    for p in &c.parts {
        let (_, toks) = prefix_inputs(&c.header, &[(p.ai, p.di)])?;
        if blob_len(fixed.saturating_add(part_len(p)), toks.len()) > max {
            return Err(Error::Build("one delta does not fit a blob"));
        }
    }
    Ok(())
}

/// Projects a commit into blobs: one per distinct (readable subset, retention class) of its
/// deltas, the class being retention, expiry and delete key set; a class above `MAX_BLOB` splits
/// greedily in aspect-list order. `readers(ai)` is the reader-set key of aspect `ai`'s thing.
/// Ordered by class key, then split order.
pub fn project<K: Ord + Clone>(c: &CommitBlob, readers: impl Fn(usize) -> K) -> Result<Vec<Projection<K>>, Error> {
    project_resolved(c, &c.header, readers)
}

/// [`project`] of a commit whose header lists go by link, classed by `resolved` (its header
/// with the lists read, spec/commits.md §1); the blobs carry the header as signed.
pub fn project_resolved<K: Ord + Clone>(c: &CommitBlob, resolved: &Header, readers: impl Fn(usize) -> K) -> Result<Vec<Projection<K>>, Error> {
    type Class<K> = (K, Vec<u8>, Option<u64>, Vec<usize>);
    let mut classes: BTreeMap<Class<K>, Vec<&Part>> = BTreeMap::new();
    for p in &c.parts {
        let a = resolved.aspects.get(p.ai).ok_or(Error::Malformed("part aspect index out of range"))?;
        let key = (readers(p.ai), osis_base::encode(&retention_value(&a.retention)), a.expires, a.keys.clone());
        classes.entry(key).or_default().push(p);
    }
    let header = c.header.encode();
    let fixed = fixed_len(c);
    let mut out = Vec::new();
    for ((k, _, expires, _), parts) in classes {
        let ai = parts.first().map_or(0, |p| p.ai);
        let retention = resolved.aspects.get(ai).map(|a| a.retention).unwrap_or_default();
        let (_, keys) = prefix_inputs(resolved, &[(ai, 0)])?;
        let fits = |n: usize, body: usize| blob_len(fixed.saturating_add(head_len(n)).saturating_add(body), keys.len()) <= MAX_BLOB;
        let mut groups: Vec<Vec<&Part>> = Vec::new();
        let mut cur: Vec<&Part> = Vec::new();
        let mut body = 0usize;
        for p in parts {
            let l = part_len(p);
            if !cur.is_empty() && !fits(cur.len() + 1, body.saturating_add(l)) {
                groups.push(std::mem::take(&mut cur));
                body = 0;
            }
            if !fits(1, l) {
                return Err(Error::Build("one delta does not fit a blob"));
            }
            cur.push(p);
            body = body.saturating_add(l);
        }
        if !cur.is_empty() {
            groups.push(cur);
        }
        for g in groups {
            out.push(Projection {
                readers: k.clone(),
                retention,
                expires,
                keys: keys.clone(),
                parts: g.iter().map(|p| (p.ai, p.di)).collect(),
                plaintext: encode_parts(&header, &c.signature, g.into_iter()),
            });
        }
    }
    Ok(out)
}

/// Whether delta set `a` is a strict subset of `b` (both sorted).
pub fn strict_subset(a: &[(usize, usize)], b: &[(usize, usize)]) -> bool {
    a.len() < b.len() && a.iter().all(|x| b.binary_search(x).is_ok())
}

/// Purge rewrite: the same header and signature without the deltas `drop` names (header-only
/// when none remain). Frame it with [`prefix_inputs`] of the remaining parts.
pub fn rewrite(c: &CommitBlob, drop: impl Fn(usize, usize) -> bool) -> CommitBlob {
    CommitBlob { header: c.header.clone(), signature: c.signature, parts: c.parts.iter().filter(|p| !drop(p.ai, p.di)).cloned().collect() }
}
