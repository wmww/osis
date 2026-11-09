//! Golomb-Rice coded beacon filters (spec/wire.md §11.2 Beacons): an ascending multiset of `f`-bit
//! values over a range `[lo, hi)`, each gap as a unary quotient and `P` remainder bits. Decoding
//! costs at most one comparison per value, each value at least `P + 1` bits: linear in the bytes.

use crate::Error;

/// Rice parameter and false-positive width (issues/net-shared-set.md Picked values).
pub const BEACON_P: u32 = 8;

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

/// Decodes the values of a page over `[lo, hi)`: ascending, each below `hi`. An error for bytes
/// left over that are more than zero padding of one byte, or a value outside the range.
pub fn decode_gcs(gcs: &[u8], lo: u64, hi: u64) -> Result<Vec<u64>, Error> {
    let mut out = Vec::new();
    let mut prev = lo;
    let total = gcs.len() * 8;
    let read = |i: usize| (gcs.get(i / 8).copied().unwrap_or(0) >> (7 - (i % 8))) & 1;
    let mut pos = 0usize;
    while total - pos > BEACON_P as usize {
        let mut q = 0u64;
        while pos < total && read(pos) == 1 {
            q += 1;
            pos += 1;
        }
        if pos >= total {
            return Err(Error::Malformed("filter gap"));
        }
        pos += 1;
        if total - pos < BEACON_P as usize {
            return Err(Error::Malformed("filter gap"));
        }
        let mut r = 0u64;
        for _ in 0..BEACON_P {
            r = (r << 1) | u64::from(read(pos));
            pos += 1;
        }
        let gap = q.checked_mul(1 << BEACON_P).and_then(|x| x.checked_add(r)).ok_or(Error::Malformed("filter gap"))?;
        let v = prev.checked_add(gap).ok_or(Error::Malformed("filter gap"))?;
        if v >= hi {
            return Err(Error::Malformed("filter value outside its range"));
        }
        out.push(v);
        prev = v;
    }
    if total - pos >= 8 || (pos..total).any(|p| read(p) == 1) {
        return Err(Error::Malformed("filter padding"));
    }
    Ok(out)
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

    // issues/net-shared-set.md Beacons: the width of a whole filter
    #[test]
    fn filter_width_is_ceil_log2_plus_p() {
        assert_eq!(filter_width(0), BEACON_P as u8);
        assert_eq!(filter_width(1), BEACON_P as u8);
        assert_eq!(filter_width(2), BEACON_P as u8 + 1);
        assert_eq!(filter_width(1025), BEACON_P as u8 + 11);
    }
}
