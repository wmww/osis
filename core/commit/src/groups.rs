//! Prefix inputs of a commit blob (the commitment groups and expiry, spec/wire.md §5), the
//! purge rewrite and the whole-commit size check (spec/commits.md §5; spec/sync.md §3).

use crate::blob::{CommitBlob, Section, part_len};
use crate::header::{DeleteKey, Header};
use crate::Error;
use osis_base::cbor::head_len;
use osis_base::format::{COMMITMENT_LEN, MAX_DRIFT_MS, PREFIX_FIXED_LEN};

/// The commitment groups of a blob of `h` whose sections list aspects `ais` (every section's,
/// opened or not): one group per distinct delete-key set among them, each in header key order,
/// groups in order of their first aspect (spec/wire.md §5). A `nobody` aspect's set is empty,
/// its own group. Zero aspects (a header-only blob): none. The order given does not matter.
pub fn prefix_groups(h: &Header, ais: impl IntoIterator<Item = usize>) -> Result<Vec<Vec<DeleteKey>>, Error> {
    let mut groups: Vec<Vec<DeleteKey>> = Vec::new();
    let mut sets: Vec<&Vec<usize>> = Vec::new();
    let ais: std::collections::BTreeSet<usize> = ais.into_iter().collect();
    for ai in ais {
        let a = h.aspects.get(ai).ok_or(Error::Malformed("part aspect index out of range"))?;
        if sets.contains(&&a.keys) {
            continue;
        }
        let keys = a.keys.iter().map(|i| h.keys.get(*i).copied().ok_or(Error::Malformed("delete key index out of range"))).collect::<Result<Vec<_>, _>>()?;
        sets.push(&a.keys);
        groups.push(keys);
    }
    Ok(groups)
}

/// The prefix expiry of a blob of `h`: the commit's `expires`; for a relay-only commit (which
/// has none) `ts + MAX_DRIFT`, the end of its replay window (spec/wire.md §5, spec/sync.md §9).
pub fn blob_expiry(h: &Header) -> Option<u64> {
    match h.ephemeral {
        Some(crate::EphClass::Relay) => Some(h.ts.wall_ms().0.saturating_add(MAX_DRIFT_MS)),
        _ => h.expires,
    }
}

/// The build error of a commit that does not fit one blob.
pub const COMMIT_PAST_BLOB: &str = "the commit does not fit a blob";

/// An upper bound on the framed size of `c` as one blob (spec/sync.md §3: no size split):
/// a section per thing with the deepest derivation chain (its list and ciphertext heads at their
/// widest), a commitment group per distinct key set, an index per aspect, every delta's bytes.
pub fn blob_bound(c: &CommitBlob) -> usize {
    let h = &c.header;
    let things = h.aspects.iter().map(|a| a.tid).collect::<std::collections::BTreeSet<_>>().len().max(1);
    let groups = prefix_groups(h, 0..h.aspects.len()).map_or(h.aspects.len(), |g| g.len());
    let fixed = 1usize.saturating_add(h.encode().len()).saturating_add(c.sigs.encoded_len()).saturating_add(head_len(things as u64));
    let section = Section { ais: Vec::new(), chain: vec![osis_base::Tid::from_bytes([0; 15]); osis_base::format::MAX_CHAIN_DEPTH], wrap: vec![0; osis_crypto::SECTION_WRAP_LEN], ciphertext: vec![0; 16 + 9] }.len();
    let heads = h.aspects.len().saturating_add(things).saturating_mul(head_len(h.aspects.len() as u64)).saturating_add(things.saturating_mul(8));
    let parts: usize = c.parts.iter().map(part_len).fold(0, usize::saturating_add);
    let prefix = PREFIX_FIXED_LEN.saturating_add(groups.saturating_mul(1 + 3 * COMMITMENT_LEN));
    osis_crypto::blob_len(prefix, fixed.saturating_add(parts).saturating_add(things.saturating_mul(section)).saturating_add(heads))
}

/// The whole commit fits a blob of `max` bytes (spec/commits.md §1: paging keeps deltas far
/// below `MAX_BLOB`; a commit whose paged roots still pass it is refused at the writer).
pub(crate) fn check_fits(c: &CommitBlob, max: usize) -> Result<(), Error> {
    if blob_bound(c) > max {
        return Err(Error::Build(COMMIT_PAST_BLOB));
    }
    Ok(())
}

/// Whether part set `a` is a strict subset of `b` (aspect indices, both sorted).
pub fn strict_subset(a: &[usize], b: &[usize]) -> bool {
    a.len() < b.len() && a.iter().all(|x| b.binary_search(x).is_ok())
}

/// Purge rewrite: the same header and signature without the deltas `drop` names (header-only
/// when none remain). Its prefix groups are those of its remaining aspects (`prefix_groups`).
pub fn rewrite(c: &CommitBlob, drop: impl Fn(usize) -> bool) -> CommitBlob {
    CommitBlob { header: c.header.clone(), sigs: c.sigs.clone(), parts: c.parts.iter().filter(|p| !drop(p.ai)).cloned().collect() }
}
