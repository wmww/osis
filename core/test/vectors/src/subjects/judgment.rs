//! `judgment/` (spec/permissions.md §5-§6, spec/commits.md §5): generated in memory and replayed by
//! osis-engine (`tests/it/judgment.rs`), which runs this shape check too: every
//! case has its inputs, its entries (the header's `setup`, then its own) parse and its order names
//! entries and things.

use crate::file::VecFile;
use crate::unhex;
use osis_crypto::WRAP_LEN;

/// One entry of a case's `entries`: its wrap and its blob's bytes.
pub type Entry = ([u8; WRAP_LEN], Vec<u8>);

/// Parses entry bytes (README.md, `judgment/`): per entry its wrap, the blob's length (4 bytes,
/// big-endian) and the blob.
pub fn entries(mut b: &[u8]) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let (wrap, rest) = b.split_first_chunk::<WRAP_LEN>().ok_or("truncated wrap")?;
        let (len, rest) = rest.split_first_chunk::<4>().ok_or("truncated length")?;
        let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| "length")?;
        let (blob, rest) = rest.split_at_checked(len).ok_or("truncated blob")?;
        out.push((*wrap, blob.to_vec()));
        b = rest;
    }
    Ok(out)
}

pub fn check(f: &VecFile) -> Result<(), String> {
    let setup = unhex(f.header.req("setup")?)?;
    let mut counts: Vec<(String, usize)> = Vec::new();
    for c in f.live() {
        let name = c.req("case")?;
        for k in ["read-secret", "now", "order"] {
            c.req(k)?;
        }
        let e = c.req("entries")?;
        let n = match e.strip_prefix("as in ") {
            Some(other) => counts.iter().find(|(x, _)| x == other).map(|x| x.1).ok_or_else(|| format!("{name}: no earlier case {other}"))?,
            None => entries(&[setup.clone(), unhex(e)?].concat()).map_err(|e| format!("{name}: {e}"))?.len(),
        };
        counts.push((name.to_string(), n));
        for t in c.req("order")?.split(',') {
            let i = t.strip_prefix('d').unwrap_or(t);
            if let Some(ms) = t.strip_prefix('+') {
                ms.parse::<u64>().map_err(|_| format!("{name}: bad order step {t}"))?;
            } else if let Some(x) = t.strip_prefix('s') {
                x.parse::<osis_base::Tid>().map_err(|_| format!("{name}: bad order step {t}"))?;
            } else if i.parse::<usize>().ok().is_none_or(|i| i >= n) {
                return Err(format!("{name}: order step {t} names no entry"));
            }
        }
    }
    Ok(())
}
