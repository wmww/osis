//! Golomb-Rice coded beacon filters (spec/wire.md §11.2 Beacons): an ascending multiset of `f`-bit
//! values over a range `[lo, hi)`, each gap as a unary quotient and `P` remainder bits. Decoding
//! costs at most one comparison per value, each value at least `P + 1` bits: linear in the bytes.

use crate::Error;
use crate::limits::BEACON_P;

/// The width of a whole filter of `n` entries: `ceil(log2 n) + P` bits, `P` for an empty one.
pub fn filter_width(n: usize) -> u8 {
    let log = if n <= 1 { 0 } else { usize::BITS - (n - 1).leading_zeros() };
    (log + BEACON_P) as u8
}

/// The first `f` bits of `beacon`, as an integer below `2^f`. `f` at most 64.
pub fn beacon_value(beacon: &[u8; 32], f: u8) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(beacon.get(..8).unwrap_or(&[0; 8]));
    u64::from_be_bytes(b) >> (64 - u32::from(f.clamp(1, 64)))
}

struct Writer {
    out: Vec<u8>,
    acc: u32,
    bits: u32,
}

impl Writer {
    fn put(&mut self, v: u32, n: u32) {
        for i in (0..n).rev() {
            self.acc = (self.acc << 1) | ((v >> i) & 1);
            self.bits += 1;
            if self.bits == 8 {
                self.out.push(self.acc as u8);
                self.acc = 0;
                self.bits = 0;
            }
        }
    }
}

/// Encodes ascending `values` of a range starting at `lo`.
pub fn encode_gcs(values: &[u64], lo: u64) -> Vec<u8> {
    let mut w = Writer { out: Vec::with_capacity(values.len() * 5 / 4 + 1), acc: 0, bits: 0 };
    let mut prev = lo;
    for v in values {
        let gap = v - prev;
        prev = *v;
        for _ in 0..(gap >> BEACON_P) {
            w.put(1, 1);
        }
        w.put(0, 1);
        w.put((gap & ((1 << BEACON_P) - 1)) as u32, BEACON_P);
    }
    if w.bits > 0 {
        let pad = 8 - w.bits;
        w.put(0, pad);
    }
    w.out
}

/// One page of a filter (spec/wire.md §11.2 Beacons): its range and coded values.
#[derive(Debug, PartialEq, Eq)]
pub struct Page {
    pub lo: u64,
    pub hi: u64,
    pub gcs: Vec<u8>,
    pub more: bool,
}

/// Splits ascending `values` of an `f`-bit space into pages of about `max_bytes` each, over
/// consecutive ranges from 0 to `2^f`. Equal values stay on one page: a page's `hi` is above each
/// of its values, the next page starts at it.
pub fn pages(values: &[u64], f: u8, max_bytes: usize) -> Vec<Page> {
    let end = 1u64.checked_shl(u32::from(f)).unwrap_or(u64::MAX);
    let mut out = Vec::new();
    let (mut start, mut lo) = (0usize, 0u64);
    loop {
        let (mut stop, mut bits, mut prev) = (start, 0usize, lo);
        for v in values.iter().skip(start) {
            let splits_equal = stop > start && *v == prev;
            if bits / 8 >= max_bytes && stop > start && !splits_equal {
                break;
            }
            bits += 1 + BEACON_P as usize + usize::try_from((*v - prev) >> BEACON_P).unwrap_or(usize::MAX);
            prev = *v;
            stop += 1;
        }
        let last = stop == values.len();
        let hi = if last { end } else { values.get(stop).copied().unwrap_or(end) };
        out.push(Page { lo, hi, gcs: encode_gcs(values.get(start..stop).unwrap_or(&[]), lo), more: !last });
        if last {
            return out;
        }
        (start, lo) = (stop, hi);
    }
}

/// The values of a page over `[lo, hi)`, ascending, each below `hi`, read one at a time: a
/// value past `hi`, a gap running off the end, or bytes left over that are more than fewer than
/// 8 zero padding bits, is an error (and ends the iteration).
struct Values<'a> {
    gcs: &'a [u8],
    pos: usize,
    prev: u64,
    hi: u64,
    done: bool,
}

impl Values<'_> {
    fn fail(&mut self, what: &'static str) -> Option<Result<u64, Error>> {
        self.done = true;
        Some(Err(Error::Malformed(what)))
    }

    fn bit(&self, i: usize) -> u8 {
        (self.gcs.get(i / 8).copied().unwrap_or(0) >> (7 - (i % 8))) & 1
    }
}

impl Iterator for Values<'_> {
    type Item = Result<u64, Error>;
    fn next(&mut self) -> Option<Result<u64, Error>> {
        if self.done {
            return None;
        }
        let total = self.gcs.len() * 8;
        if total - self.pos <= BEACON_P as usize {
            self.done = true;
            let padded = total - self.pos < 8 && (self.pos..total).all(|p| self.bit(p) == 0);
            return (!padded).then_some(Err(Error::Malformed("filter padding")));
        }
        let mut q = 0u64;
        while self.pos < total && self.bit(self.pos) == 1 {
            q += 1;
            self.pos += 1;
        }
        if total - self.pos < 1 + BEACON_P as usize {
            return self.fail("filter gap");
        }
        self.pos += 1;
        let mut r = 0u64;
        for _ in 0..BEACON_P {
            r = (r << 1) | u64::from(self.bit(self.pos));
            self.pos += 1;
        }
        let Some(v) = q.checked_mul(1 << BEACON_P).and_then(|x| x.checked_add(r)).and_then(|gap| self.prev.checked_add(gap)) else { return self.fail("filter gap") };
        if v >= self.hi {
            return self.fail("filter value outside its range");
        }
        self.prev = v;
        Some(Ok(v))
    }
}

fn values(gcs: &[u8], lo: u64, hi: u64) -> Values<'_> {
    Values { gcs, pos: 0, prev: lo, hi, done: false }
}

/// Decodes the values of a page over `[lo, hi)` (spec/wire.md §11.2 Beacons).
pub fn decode_gcs(gcs: &[u8], lo: u64, hi: u64) -> Result<Vec<u64>, Error> {
    values(gcs, lo, hi).collect()
}

/// Checks a page as `decode_gcs` does and counts its values, allocating nothing: what a message
/// decoder runs on a peer's page.
pub fn count_gcs(gcs: &[u8], lo: u64, hi: u64) -> Result<u64, Error> {
    values(gcs, lo, hi).try_fold(0u64, |n, v| v.map(|_| n + 1))
}

/// Entries between two index points of a `Run`: a performance switch (any value is correct): a
/// lookup decodes at most this many entries, the index costs 16 B per this many. 1: an index
/// point per entry (16 B each, more than the 8 B of a plain array); infinity: a scan per lookup.
const STRIDE: u64 = 64;

/// One ascending run of a peer's filter, Golomb-Rice coded as on the wire from 0 (spec/wire.md
/// §11.2 Beacons): about `P + 2` bits an entry, with an index point every `STRIDE` entries. Built
/// a value at a time as pages arrive, so a filter never sits decoded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Run {
    bits: Vec<u8>,
    len: usize,
    n: u64,
    last: u64,
    /// Per `STRIDE` entries: the entry's value and the bit just past it.
    index: Vec<(u64, usize)>,
}

impl Run {
    fn put(&mut self, v: u32, n: u32) {
        for i in (0..n).rev() {
            if self.len.is_multiple_of(8) {
                self.bits.push(0);
            }
            if (v >> i) & 1 == 1
                && let Some(b) = self.bits.last_mut()
            {
                *b |= 0x80 >> (self.len % 8);
            }
            self.len += 1;
        }
    }

    fn bit(&self, i: usize) -> u64 {
        u64::from((self.bits.get(i / 8).copied().unwrap_or(0) >> (7 - (i % 8))) & 1)
    }

    /// Appends `v`, at least the last value.
    pub fn push(&mut self, v: u64) {
        let gap = v.saturating_sub(self.last);
        for _ in 0..(gap >> BEACON_P) {
            self.put(1, 1);
        }
        self.put(0, 1);
        self.put((gap & ((1 << BEACON_P) - 1)) as u32, BEACON_P);
        self.last = v;
        if self.n.is_multiple_of(STRIDE) {
            self.index.push((v, self.len));
        }
        self.n += 1;
    }

    /// The values from index point `k` on, that point's value first.
    fn from(&self, k: usize) -> impl Iterator<Item = u64> + '_ {
        let (first, mut pos) = self.index.get(k).copied().unwrap_or((0, self.len));
        let mut prev = first;
        let rest = std::iter::from_fn(move || {
            if pos >= self.len {
                return None;
            }
            let mut q = 0u64;
            while self.bit(pos) == 1 {
                q += 1;
                pos += 1;
            }
            pos += 1;
            let mut r = 0u64;
            for _ in 0..BEACON_P {
                r = (r << 1) | self.bit(pos);
                pos += 1;
            }
            prev += (q << BEACON_P) | r;
            Some(prev)
        });
        (k < self.index.len()).then_some(first).into_iter().chain(rest)
    }

    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.from(0)
    }

    fn contains(&self, v: u64) -> bool {
        let k = self.index.partition_point(|(x, _)| *x <= v);
        k > 0 && self.from(k - 1).take(STRIDE as usize).take_while(|x| *x <= v).any(|x| x == v)
    }

    /// Heap bytes held.
    pub fn bytes(&self) -> usize {
        self.bits.capacity() + self.index.capacity() * size_of::<(u64, usize)>()
    }

    /// Entries.
    pub fn len(&self) -> u64 {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// The run's values coded from 0, as one page of `[0, 2^f)` codes them (`encode_gcs`).
    pub fn gcs(&self) -> &[u8] {
        &self.bits
    }

    /// Appends the values of a page over `[lo, hi)` (`decode_gcs`'s checks), each at least the
    /// last value: pages of one generation come in ascending ranges.
    pub fn extend_from_gcs(&mut self, gcs: &[u8], lo: u64, hi: u64) -> Result<(), Error> {
        if self.n > 0 && lo < self.last {
            return Err(Error::Malformed("filter page below the run"));
        }
        for v in values(gcs, lo, hi) {
            self.push(v?);
        }
        Ok(())
    }
}

/// A peer's filter as a node holds it: ascending multisets of entries kept as their Golomb-Rice
/// coding, so it holds about what the peer sent (notes/decode-bounds.md), not 8 B an entry.
/// Additions come as runs; a run at least as long as the one before is merged into it, so a
/// filter of n entries is at most log2(n) + 1 runs and each entry is coded again at most log2(n)
/// times.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Beacons {
    runs: Vec<Run>,
}

impl Beacons {
    /// Adds `run`.
    pub fn add(&mut self, mut run: Run) {
        while run.n > 0 && self.runs.last().is_some_and(|r| r.n <= run.n) {
            let Some(prev) = self.runs.pop() else { break };
            let mut merged = Run::default();
            {
                let (mut a, mut b) = (prev.iter().peekable(), run.iter().peekable());
                while let Some(v) = match (a.peek(), b.peek()) {
                    (Some(x), Some(y)) if x <= y => a.next(),
                    (_, Some(_)) => b.next(),
                    (Some(_), None) => a.next(),
                    (None, None) => None,
                } {
                    merged.push(v);
                }
            }
            run = merged;
        }
        if run.n > 0 {
            run.bits.shrink_to_fit();
            run.index.shrink_to_fit();
            self.runs.push(run);
        }
    }

    /// Runs held (tests: at most log2(entries) + 1).
    pub fn runs(&self) -> usize {
        self.runs.len()
    }

    pub fn contains(&self, v: u64) -> bool {
        self.runs.iter().any(|r| r.contains(v))
    }

    /// Entries held.
    pub fn len(&self) -> u64 {
        self.runs.iter().map(|r| r.n).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Heap bytes held.
    pub fn bytes(&self) -> usize {
        self.runs.iter().map(Run::bytes).sum::<usize>() + self.runs.capacity() * size_of::<Run>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/wire.md §11.2 Beacons: encodes and decodes every shape, duplicates included
    #[test]
    fn gcs_round_trips_with_duplicates_spec_wire_11_2() {
        for values in [vec![], vec![5u64], vec![0, 0, 1, 1000, 1000, 1001], (0..500u64).map(|x| x * 257).collect()] {
            let hi = 1 << 20;
            assert_eq!(decode_gcs(&encode_gcs(&values, 0), 0, hi).unwrap(), values);
        }
        let v = vec![100u64, 300];
        assert_eq!(decode_gcs(&encode_gcs(&v, 50), 50, 500).unwrap(), v, "from a page's own lower bound");
    }

    // spec/wire.md §11.2 Beacons: a page is refused for a value past its range and for trailing bytes
    #[test]
    fn gcs_rejects_out_of_range_and_trailing_bytes_spec_wire_11_2() {
        assert!(decode_gcs(&encode_gcs(&[5, 900], 0), 0, 500).is_err());
        let mut b = encode_gcs(&[1, 2], 0);
        b.push(0xff);
        assert!(decode_gcs(&b, 0, 500).is_err(), "a gap that runs off the end");
    }

    // spec/wire.md §11.2 Beacons: a split keeps every page's values inside its range, an equal pair
    // that falls at a boundary included (a filter is a multiset), and the pages decode back whole
    #[test]
    fn pages_cover_the_space_and_keep_equal_values_together_spec_wire_11_2() {
        let f = 20u8;
        let mut values: Vec<u64> = (0..4000u64).map(|x| x * 251).collect();
        for at in [333usize, 334, 1000, 2600] {
            values[at] = values[at - 1];
        }
        values.sort_unstable();
        for max in [1usize, 16, 100, 1 << 20] {
            let ps = pages(&values, f, max);
            let mut got = Vec::new();
            let mut lo = 0;
            for (i, p) in ps.iter().enumerate() {
                assert_eq!(p.lo, lo);
                assert!(p.lo < p.hi);
                assert_eq!(p.more, i + 1 < ps.len());
                got.extend(decode_gcs(&p.gcs, p.lo, p.hi).unwrap());
                lo = p.hi;
            }
            assert_eq!(lo, 1 << f);
            assert_eq!(got, values, "max {max}");
        }
        assert_eq!(pages(&[], f, 16), vec![Page { lo: 0, hi: 1 << f, gcs: vec![], more: false }]);
    }

    // spec/wire.md §11.2 Beacons: a page's padding is fewer than 8 zero bits; the count agrees
    #[test]
    fn gcs_padding_and_count_spec_wire_11_2() {
        let b = encode_gcs(&[1, 2, 3], 0);
        assert_eq!(count_gcs(&b, 0, 500), Ok(3));
        let mut one = b.clone();
        *one.last_mut().unwrap() |= 1;
        assert!(count_gcs(&one, 0, 500).is_err(), "a padding bit set");
        assert!(count_gcs(&[0], 0, 500).is_err(), "8 bits of padding");
        assert_eq!(count_gcs(&[], 0, 500), Ok(0));
    }

    fn run(values: &[u64]) -> Run {
        let mut r = Run::default();
        r.extend_from_gcs(&encode_gcs(values, 0), 0, u64::MAX).unwrap();
        r
    }

    // notes/decode-bounds.md: a peer's filter held as its coding answers as the multiset of its
    // entries, whole and through many additions (duplicates, index boundaries, empty runs), in at
    // most log2(n) + 1 runs and about what its coding took on the wire
    #[test]
    fn beacons_answer_as_their_entries_in_their_coded_size() {
        let f = 21u32;
        let mut k = 0u64;
        let mut draw = |n: usize| {
            let mut v: Vec<u64> = (0..n)
                .map(|_| {
                    k += 1;
                    beacon_value(&osis_base::hash::hash(&k.to_le_bytes()), f as u8)
                })
                .collect();
            v.sort_unstable();
            v
        };
        let whole = draw(1 << 13);
        let mut b = Beacons::default();
        let r = run(&whole);
        assert_eq!(r.gcs(), encode_gcs(&whole, 0).as_slice(), "a run is the wire coding");
        b.add(r);
        let mut all = whole.clone();
        for n in [0, 1, 3, 64, 65, 1000, 1, 1, 3000, 129] {
            let add = draw(n);
            all.extend(&add);
            b.add(run(&add));
        }
        all.sort_unstable();
        assert_eq!(b.len(), all.len() as u64);
        assert!(b.runs() <= (all.len() as f64).log2() as usize + 1, "{} runs", b.runs());
        let set: std::collections::BTreeSet<u64> = all.iter().copied().collect();
        for v in all.iter().copied().chain(draw(5000)).chain([0, (1 << f) - 1]) {
            assert_eq!(b.contains(v), set.contains(&v), "{v}");
        }
        let coded = encode_gcs(&all, 0).len();
        assert!(b.bytes() <= coded * 3 / 2, "{} held for {coded} coded", b.bytes());
        assert!(b.bytes() * 4 < all.len() * 8, "far below 8 B an entry");
    }

    // spec/wire.md §11.2 Beacons: the width of a whole filter
    #[test]
    fn filter_width_is_ceil_log2_plus_p() {
        assert_eq!(filter_width(0), BEACON_P as u8);
        assert_eq!(filter_width(1), BEACON_P as u8);
        assert_eq!(filter_width(2), BEACON_P as u8 + 1);
        assert_eq!(filter_width(1025), BEACON_P as u8 + 11);
    }
}
