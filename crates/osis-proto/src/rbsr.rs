//! Range-based set reconciliation over blob IDs (spec/wire.md §11.3): additive fingerprints,
//! 16-way splits, ID lists at 32, difference lists at 1024. Sets are sorted, deduplicated slices.

use crate::Error;
use crate::msg::{MAX_RECONCILE_RANGES, Mode, Range};
use osis_core::BlobId;
use std::cmp::Ordering;
use std::collections::BTreeSet;

/// Most IDs in a mode 1 list.
pub const LIST_MAX: usize = 32;
/// Most IDs a responder holds in a range it answers by mode 2.
pub const DIFF_MAX: usize = 1024;
/// Subranges per split.
pub const SPLIT: usize = 16;

/// A range bound: at most 32 bytes, compared as if right-padded with zeros. As an upper bound
/// the empty bound is the end of the ID space; as a lower bound it is zero.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Bound(Vec<u8>);

impl Bound {
    pub fn new(bytes: Vec<u8>) -> Option<Bound> {
        (bytes.len() <= 32).then_some(Bound(bytes))
    }
    /// The empty bound (zero as lower, end as upper).
    pub fn empty() -> Bound {
        Bound(Vec::new())
    }
    pub fn of(id: &BlobId) -> Bound {
        Bound(id.0.to_vec())
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn is_end(&self) -> bool {
        self.0.is_empty()
    }
    fn padded(&self) -> [u8; 32] {
        let mut p = [0u8; 32];
        for (d, s) in p.iter_mut().zip(&self.0) {
            *d = *s;
        }
        p
    }
}

/// Order of two bounds as zero-padded strings.
pub fn cmp_bounds(a: &Bound, b: &Bound) -> Ordering {
    a.padded().cmp(&b.padded())
}

/// Whether `lower < upper` as range bounds.
pub fn lower_below_upper(lower: &Bound, upper: &Bound) -> bool {
    upper.is_end() || cmp_bounds(lower, upper) == Ordering::Less
}

/// `lower <= id < upper`.
pub fn contains(lower: &Bound, upper: &Bound, id: &BlobId) -> bool {
    lower.padded() <= id.0 && (upper.is_end() || id.0 < upper.padded())
}

/// The IDs of a sorted set inside `[lower, upper)`.
pub fn slice<'a>(set: &'a [BlobId], lower: &Bound, upper: &Bound) -> &'a [BlobId] {
    let lo = lower.padded();
    let start = set.partition_point(|i| i.0 < lo);
    let end = if upper.is_end() {
        set.len()
    } else {
        let hi = upper.padded();
        set.partition_point(|i| i.0 < hi)
    };
    set.get(start..end.max(start)).unwrap_or(&[])
}

/// First 16 bytes of BLAKE3(`le256(sum mod 2^256) || le64(count)`), IDs read little-endian.
pub fn fingerprint(ids: &[BlobId]) -> [u8; 16] {
    let mut sum = [0u64; 4];
    for id in ids {
        let mut carry = 0u64;
        for (limb, chunk) in sum.iter_mut().zip(id.0.as_chunks::<8>().0) {
            let (s1, c1) = limb.overflowing_add(u64::from_le_bytes(*chunk));
            let (s2, c2) = s1.overflowing_add(carry);
            *limb = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
    }
    let mut input = Vec::with_capacity(40);
    for limb in sum {
        input.extend_from_slice(&limb.to_le_bytes());
    }
    input.extend_from_slice(&(ids.len() as u64).to_le_bytes());
    let h = osis_core::hash::hash(&input);
    let mut fp = [0u8; 16];
    fp.copy_from_slice(h.get(..16).unwrap_or(&[0; 16]));
    fp
}

/// The ranges answering a mismatched fingerprint, or splitting an over-full mode 1 range: one
/// mode 1 range when `own` holds at most 32, else 16 subranges of near-equal own counts (bounds:
/// the first own ID of each subrange), each mode 0, or mode 1 where it holds at most 32.
fn answer_or_split(own: &[BlobId], lower: &Bound, upper: &Bound, out: &mut Vec<Range>) {
    if own.len() <= LIST_MAX {
        out.push(Range { lower: lower.clone(), upper: upper.clone(), mode: Mode::Ids(own.to_vec()) });
        return;
    }
    split(own, lower, upper, out);
}

fn split(own: &[BlobId], lower: &Bound, upper: &Bound, out: &mut Vec<Range>) {
    let n = own.len();
    let mut lo = lower.clone();
    for i in 0..SPLIT {
        let (start, end) = (i * n / SPLIT, (i + 1) * n / SPLIT);
        let part = own.get(start..end).unwrap_or(&[]);
        let hi = if i + 1 == SPLIT { upper.clone() } else { own.get(end).map_or_else(|| upper.clone(), Bound::of) };
        let mode = if part.len() <= LIST_MAX { Mode::Ids(part.to_vec()) } else { Mode::Fingerprint(fingerprint(part)) };
        out.push(Range { lower: lo, upper: hi.clone(), mode });
        lo = hi;
    }
}

/// IDs of `a` not in `b` (both sorted).
fn minus(a: &[BlobId], b: &[BlobId]) -> Vec<BlobId> {
    a.iter().filter(|x| b.binary_search(x).is_err()).copied().collect()
}

/// The responder's answer to one Reconcile message (spec/wire.md §11.3). Mode 2 is never sent
/// to a responder.
pub fn respond(own: &[BlobId], ranges: &[Range]) -> Result<Vec<Range>, Error> {
    let mut out = Vec::new();
    for r in ranges {
        let mine = slice(own, &r.lower, &r.upper);
        match &r.mode {
            Mode::Fingerprint(fp) => {
                if fingerprint(mine) != *fp {
                    answer_or_split(mine, &r.lower, &r.upper, &mut out);
                }
            }
            Mode::Ids(theirs) => {
                if mine.len() <= DIFF_MAX {
                    out.push(Range { lower: r.lower.clone(), upper: r.upper.clone(), mode: Mode::Diff { theirs: minus(mine, theirs), lacking: minus(theirs, mine) } });
                } else {
                    split(mine, &r.lower, &r.upper, &mut out);
                }
            }
            Mode::Diff { .. } => return Err(Error::Malformed("mode 2 in a request")),
        }
    }
    Ok(out)
}

/// The requester's side: ranges still to send, and both differences found so far.
#[derive(Debug, Default)]
pub struct Reconciler {
    queue: Vec<Range>,
    /// IDs the responder holds that we lack.
    pub need: BTreeSet<BlobId>,
    /// IDs we hold that the responder lacks.
    pub have: BTreeSet<BlobId>,
}

impl Reconciler {
    /// Opens with one range over the whole space: mode 1 with our IDs if at most 32, else mode 0.
    pub fn new(own: &[BlobId]) -> Reconciler {
        let (lo, hi) = (Bound::empty(), Bound::empty());
        let mode = if own.len() <= LIST_MAX { Mode::Ids(own.to_vec()) } else { Mode::Fingerprint(fingerprint(own)) };
        Reconciler { queue: vec![Range { lower: lo, upper: hi, mode }], ..Default::default() }
    }

    /// The next Reconcile batch (at most 256 ranges, sorted), `None` when nothing is queued.
    pub fn next_batch(&mut self) -> Option<Vec<Range>> {
        if self.queue.is_empty() {
            return None;
        }
        self.queue.sort_by(|a, b| cmp_bounds(&a.lower, &b.lower));
        let n = self.queue.len().min(MAX_RECONCILE_RANGES);
        Some(self.queue.drain(..n).collect())
    }

    /// Whether ranges remain to be sent.
    pub fn has_queued(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Takes a ReconcileReply.
    pub fn on_reply(&mut self, own: &[BlobId], ranges: &[Range]) {
        for r in ranges {
            let mine = slice(own, &r.lower, &r.upper);
            match &r.mode {
                Mode::Fingerprint(fp) => {
                    if fingerprint(mine) != *fp {
                        answer_or_split(mine, &r.lower, &r.upper, &mut self.queue);
                    }
                }
                Mode::Ids(theirs) => {
                    self.need.extend(minus(theirs, mine));
                    self.have.extend(minus(mine, theirs));
                }
                Mode::Diff { theirs, lacking } => {
                    self.need.extend(theirs.iter().filter(|i| mine.binary_search(i).is_err()));
                    self.have.extend(lacking.iter().filter(|i| mine.binary_search(i).is_ok()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
