//! Range-based set reconciliation over blob IDs (spec/wire.md §11.3): additive fingerprints,
//! 16-way splits, ID lists at 32 (8 under a dense difference), difference lists at 1024. Sets are sorted, deduplicated slices.

use crate::Error;
use crate::msg::{MAX_RECONCILE_RANGES, Mode, Range};
use osis_core::BlobId;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

/// Most IDs in a mode 1 list.
pub const LIST_MAX: usize = 32;
/// Most IDs a responder holds in a range it answers by mode 2.
pub const DIFF_MAX: usize = 1024;
/// Subranges per split.
pub const SPLIT: usize = 16;
/// Most IDs in a subrange sent as mode 1 when the difference is dense.
pub const DENSE_LIST: usize = 8;

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
fn answer_or_split(own: &[BlobId], lower: &Bound, upper: &Bound, dense: bool, out: &mut Vec<Range>) {
    if own.len() <= LIST_MAX {
        out.push(Range { lower: lower.clone(), upper: upper.clone(), mode: Mode::Ids(own.to_vec()) });
        return;
    }
    split(own, lower, upper, dense, out);
}

/// Whether the difference looks dense: at least a split's worth of fingerprint ranges in one
/// message, most of them mismatched. Then nearly every small subrange would differ too and its
/// ID list would carry nearly the whole set, so subranges go as fingerprints down to
/// `DENSE_LIST` IDs (one more round, bytes about 16 fingerprints per difference instead of O(n)).
fn dense(mismatched: &[Option<bool>]) -> bool {
    let fps = mismatched.iter().flatten().count();
    let bad = mismatched.iter().flatten().filter(|m| **m).count();
    fps >= SPLIT && 2 * bad > fps
}

/// For each range: `Some(mismatched)` for a fingerprint range, `None` otherwise.
fn mismatches<'a>(own: &[BlobId], ranges: impl IntoIterator<Item = &'a Range>) -> Vec<Option<bool>> {
    ranges
        .into_iter()
        .map(|r| match &r.mode {
            Mode::Fingerprint(fp) => Some(fingerprint(slice(own, &r.lower, &r.upper)) != *fp),
            _ => None,
        })
        .collect()
}

fn split(own: &[BlobId], lower: &Bound, upper: &Bound, dense: bool, out: &mut Vec<Range>) {
    let list_max = if dense { DENSE_LIST } else { LIST_MAX };
    let n = own.len();
    let mut lo = lower.clone();
    for i in 0..SPLIT {
        let (start, end) = (i * n / SPLIT, (i + 1) * n / SPLIT);
        let part = own.get(start..end).unwrap_or(&[]);
        let hi = if i + 1 == SPLIT { upper.clone() } else { own.get(end).map_or_else(|| upper.clone(), Bound::of) };
        let mode = if part.len() <= list_max { Mode::Ids(part.to_vec()) } else { Mode::Fingerprint(fingerprint(part)) };
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
    let mism = mismatches(own, ranges);
    let dense = dense(&mism);
    for (r, bad) in ranges.iter().zip(mism) {
        let mine = slice(own, &r.lower, &r.upper);
        match &r.mode {
            Mode::Fingerprint(_) => {
                if bad == Some(true) {
                    answer_or_split(mine, &r.lower, &r.upper, dense, &mut out);
                }
            }
            Mode::Ids(theirs) => {
                if mine.len() <= DIFF_MAX {
                    out.push(Range { lower: r.lower.clone(), upper: r.upper.clone(), mode: Mode::Diff { theirs: minus(mine, theirs), lacking: minus(theirs, mine) } });
                } else {
                    split(mine, &r.lower, &r.upper, dense, &mut out);
                }
            }
            Mode::Diff { .. } => return Err(Error::Malformed("mode 2 in a request")),
        }
    }
    Ok(out)
}

/// The requester's side: ranges still to send, ranges asked per outstanding batch, and both
/// differences found so far. Reply ranges outside what a batch asked are dropped.
#[derive(Debug, Default)]
pub struct Reconciler {
    queue: Vec<Range>,
    /// Per batch token: the ranges sent, and whether each carried our ID list (mode 1).
    asked: BTreeMap<u64, Vec<(Bound, Bound, bool)>>,
    next: u64,
    /// IDs the responder holds that we lack.
    pub need: BTreeSet<BlobId>,
    /// IDs we hold that the responder lacks.
    pub have: BTreeSet<BlobId>,
}

/// Whether `[lower, upper)` lies inside `[lo, hi)`.
fn within(lo: &Bound, hi: &Bound, lower: &Bound, upper: &Bound) -> bool {
    cmp_bounds(lo, lower) != Ordering::Greater && (hi.is_end() || (!upper.is_end() && cmp_bounds(upper, hi) != Ordering::Greater))
}

impl Reconciler {
    /// Opens with one range over the whole space: mode 1 with our IDs if at most 32, else mode 0.
    pub fn new(own: &[BlobId]) -> Reconciler {
        let (lo, hi) = (Bound::empty(), Bound::empty());
        let mode = if own.len() <= LIST_MAX { Mode::Ids(own.to_vec()) } else { Mode::Fingerprint(fingerprint(own)) };
        Reconciler { queue: vec![Range { lower: lo, upper: hi, mode }], ..Default::default() }
    }

    /// The next Reconcile batch (at most 256 ranges, sorted) with its token for `on_reply`;
    /// `None` when nothing is queued.
    pub fn next_batch(&mut self) -> Option<(u64, Vec<Range>)> {
        if self.queue.is_empty() {
            return None;
        }
        self.queue.sort_by(|a, b| cmp_bounds(&a.lower, &b.lower));
        let n = self.queue.len().min(MAX_RECONCILE_RANGES);
        let batch: Vec<Range> = self.queue.drain(..n).collect();
        self.next += 1;
        self.asked.insert(self.next, batch.iter().map(|r| (r.lower.clone(), r.upper.clone(), matches!(r.mode, Mode::Ids(_)))).collect());
        Some((self.next, batch))
    }

    /// Whether ranges remain to be sent.
    pub fn has_queued(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Nothing queued and no batch unanswered.
    pub fn is_done(&self) -> bool {
        self.queue.is_empty() && self.asked.is_empty()
    }

    /// Takes the ReconcileReply to batch `token`; a range not inside an asked one, or a mode 2
    /// range not answering one of our mode 1 ranges exactly, is dropped. Returns whether the
    /// token was outstanding.
    pub fn on_reply(&mut self, token: u64, own: &[BlobId], ranges: &[Range]) -> bool {
        let Some(asked) = self.asked.remove(&token) else { return false };
        let ranges: Vec<&Range> = ranges
            .iter()
            .filter(|r| {
                asked.iter().any(|(lo, hi, ids)| match r.mode {
                    Mode::Diff { .. } => *ids && within(lo, hi, &r.lower, &r.upper) && within(&r.lower, &r.upper, lo, hi),
                    _ => within(lo, hi, &r.lower, &r.upper),
                })
            })
            .collect();
        let mism = mismatches(own, ranges.iter().copied());
        let dense = dense(&mism);
        for (r, bad) in ranges.into_iter().zip(mism) {
            let mine = slice(own, &r.lower, &r.upper);
            match &r.mode {
                Mode::Fingerprint(_) => {
                    if bad == Some(true) {
                        answer_or_split(mine, &r.lower, &r.upper, dense, &mut self.queue);
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
        true
    }
}

#[cfg(test)]
mod tests;
