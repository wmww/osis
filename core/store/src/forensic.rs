//! The forensic attack (tests only): everything an attacker holding the device recovers. It is
//! the project's definition of "forensically clean" (spec/requirements.md, Deletion: a node that
//! deleted honestly and is compromised later yields nothing; notes/testing.md, Forensic attack).
//!
//! The attacker holds what the device yields now (the keys of the current store tree, and
//! secrets the node's code computes from it, `Evidence::secrets`), every row and blob the
//! backend was ever given (`MemoryBackend::history`, `blob_history`: storage never erases), and
//! knows how blobs and wraps open (`Ciphers`). Until nothing new turns up it:
//! - reads every row and blob as it lies (the clear rows `r`, `p`, `j`; a blob stored in clear);
//! - opens every row with every store key, taking the keys an opened tree node lists;
//! - takes every random-looking 32 bytes of anything it recovered as a candidate key, and tries
//!   each on every blob (link keys, node-sync's blob keys, anything else);
//! - reads table pages as entries (overflow values joined from their units) and, for each entry
//!   whose key holds a blob's ID, tries the start of its value as that blob's wrap (store wraps,
//!   node-sync entries) under every candidate key as a label read secret, opening the blob with
//!   what unwraps.
//!
//! What it recovers is that set; how it finds it is cheaper than every try in full, and exact:
//! a row the store sealed is tried with the one key that opens it (`Evidence::sealed`), if held;
//! a candidate is prepared once (`osis_crypto::Trial`) and rules itself out of a blob or a wrap
//! by one keystream byte before the AEAD pass decides.

use crate::KeyValue;
use crate::btree::forensic_leaf;
use crate::pager::{forensic_clear_row, forensic_node_keys, forensic_open, forensic_unit_slot};
use osis_base::BlobId;
use osis_crypto::{Trial, WRAP_LEN};
use std::collections::{BTreeMap, HashMap, HashSet};

/// What the attacker holds.
#[derive(Default)]
pub struct Evidence {
    /// Every key the current store tree yields (`Store::forensic_keys`).
    pub store_keys: Vec<[u8; 32]>,
    /// Secrets the node's own code computes from the device now (derived label read secrets).
    pub secrets: Vec<[u8; 32]>,
    /// Every row ever written (`MemoryBackend::history`).
    pub rows: Vec<KeyValue>,
    /// Every blob ever put or freed (`MemoryBackend::blob_history`).
    pub blobs: Vec<(BlobId, Option<Vec<u8>>)>,
    /// Not evidence: the key each row value was sealed under, by its AEAD tag
    /// (`MemoryBackend::sealed`). A ciphertext opens under the key that sealed it and no other
    /// (but with the chance of a Poly1305 forgery), so a row found here is tried with that key
    /// alone, if the attacker holds it; a row not found here, with every key.
    pub sealed: HashMap<[u8; 16], [u8; 32]>,
}

impl Evidence {
    /// The store keys given and everything `backend` recorded (`record_history`).
    pub fn of(store_keys: Vec<[u8; 32]>, backend: &crate::MemoryBackend) -> Evidence {
        Evidence { store_keys, secrets: Vec::new(), rows: backend.history(), blobs: backend.blob_history(), sealed: backend.sealed() }
    }
}

/// Opens a blob under a candidate key.
pub type OpenBlob = fn(&[u8], &[u8; 32]) -> Option<Vec<u8>>;

/// The sections of an opened commit blob plaintext, but those listed open already, that any
/// of the candidates opens, as a read secret of their wrap or as their key: (section index,
/// plaintext), one per section. Empty for any other plaintext.
pub type OpenSections = fn(&[u8], &[Trial], &HashSet<usize>) -> Vec<(usize, Vec<u8>)>;

/// How blobs and sections open: the layers above the store define them (osis-label's frame,
/// osis-commit's sections). A blob is a clear prefix and a ciphertext as
/// `osis_crypto::encrypt_blob` seals it; a wrap is `osis_crypto::wrap`'s.
pub struct Ciphers {
    /// A blob's clear prefix length; `None`: not a blob these open.
    pub prefix: fn(&[u8]) -> Option<usize>,
    pub open: OpenBlob,
    pub sections: OpenSections,
}

/// Where a recovered plaintext came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// A row opened with a store key (the row's key).
    Row(Vec<u8>),
    /// A row's value as stored.
    RawRow(Vec<u8>),
    /// A blob opened with a key the attack found; `wrapped`: the key came from a wrap.
    Blob { id: BlobId, wrapped: bool },
    /// A blob as stored.
    RawBlob(BlobId),
}

#[derive(Clone, Debug)]
pub struct Recovered {
    pub from: Source,
    pub plain: Vec<u8>,
}

/// Fewest distinct byte values a random 32-byte key has but for a chance of about 2^-55
/// (expected about 30); skips text and padding, which cannot be keys.
const KEY_MIN_DISTINCT: usize = 16;

/// The random-looking 32-byte windows of `plain`, in order (the distinct byte values counted as
/// the window slides).
fn random_windows(plain: &[u8]) -> impl Iterator<Item = [u8; 32]> + '_ {
    let mut count = [0u32; 256];
    let mut distinct = 0;
    plain.iter().enumerate().filter_map(move |(i, b)| {
        let mut step = |b: u8, add: bool| {
            if let Some(c) = count.get_mut(usize::from(b)) {
                if add {
                    distinct += usize::from(*c == 0);
                    *c += 1;
                } else {
                    *c -= 1;
                    distinct -= usize::from(*c == 0);
                }
            }
        };
        step(*b, true);
        if let Some(old) = i.checked_sub(32).and_then(|j| plain.get(j)) {
            step(*old, false);
        }
        let w = plain.get(i.checked_sub(31)?..=i)?;
        (distinct >= KEY_MIN_DISTINCT).then(|| <[u8; 32]>::try_from(w).ok()).flatten()
    })
}

/// A candidate's hash: its 8-byte words folded (no defence against chosen keys needed).
#[derive(Default)]
struct Fold(u64);

impl std::hash::Hasher for Fold {
    fn write(&mut self, b: &[u8]) {
        for w in b.as_chunks::<8>().0 {
            self.0 = (self.0.rotate_left(29) ^ u64::from_le_bytes(*w)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
    }
    fn finish(&self) -> u64 {
        self.0
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// `keys` prepared as trials (`Trial::new`), on every core.
fn prepare(keys: &[[u8; 32]]) -> Vec<Trial> {
    let n = if keys.len() < 1024 { 1 } else { std::thread::available_parallelism().map_or(1, |n| n.get()) };
    std::thread::scope(|sc| {
        let hs: Vec<_> = keys.chunks(keys.len().div_ceil(n).max(1)).map(|c| sc.spawn(move || c.iter().map(Trial::new).collect::<Vec<_>>())).collect();
        hs.into_iter().flat_map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e))).collect()
    })
}

/// Everything the attacker recovers from `ev` (see the module doc); without `ciphers` blobs
/// are read only as stored.
pub fn attack(ev: &Evidence, ciphers: Option<&Ciphers>) -> Vec<Recovered> {
    let mut out: Vec<Recovered> = Vec::new();
    for (row, value) in &ev.rows {
        out.push(Recovered { from: Source::RawRow(row.clone()), plain: value.clone() });
    }
    let mut blobs: Vec<(BlobId, Vec<u8>)> = Vec::new();
    for (id, b) in &ev.blobs {
        if let Some(b) = b
            && !blobs.iter().any(|(x, _)| x == id)
        {
            out.push(Recovered { from: Source::RawBlob(*id), plain: b.clone() });
            blobs.push((*id, b.clone()));
        }
    }
    // Rows: every row with every store key, to a fixpoint (tree nodes list more keys).
    let mut keys = ev.store_keys.clone();
    let mut known: HashSet<[u8; 32]> = keys.iter().copied().collect();
    let mut opened: Vec<Option<Vec<u8>>> = vec![None; ev.rows.len()];
    let mut tried = 0;
    while tried < keys.len() {
        let batch = keys.get(tried..).unwrap_or_default().to_vec();
        let held: HashSet<[u8; 32]> = batch.iter().copied().collect();
        tried = keys.len();
        for ((row, value), slot) in ev.rows.iter().zip(opened.iter_mut()) {
            if slot.is_some() {
                continue;
            }
            let tag = value.len().checked_sub(16).and_then(|n| value.get(n..)).and_then(|t| <[u8; 16]>::try_from(t).ok());
            let found = match tag.and_then(|t| ev.sealed.get(&t)) {
                Some(k) => held.contains(k).then(|| forensic_open(row, value, k)).flatten(),
                None => batch.iter().find_map(|k| forensic_open(row, value, k)),
            };
            if let Some(plain) = found {
                for nk in forensic_node_keys(row, &plain) {
                    if known.insert(nk) {
                        keys.push(nk);
                    }
                }
                *slot = Some(plain);
            }
        }
    }
    let mut units: BTreeMap<u64, Vec<&[u8]>> = BTreeMap::new();
    for ((row, value), plain) in ev.rows.iter().zip(&opened) {
        if let Some(p) = plain {
            out.push(Recovered { from: Source::Row(row.clone()), plain: p.clone() });
            if let Some(slot) = forensic_unit_slot(row) {
                units.entry(slot).or_default().push(p);
            }
        } else if forensic_clear_row(row) {
            out.push(Recovered { from: Source::Row(row.clone()), plain: value.clone() });
        }
    }
    let Some(c) = ciphers else { return out };
    // Entries keyed by a blob ID: (blob, value), every version of an overflow value.
    let mut keyed: Vec<(usize, Vec<u8>)> = Vec::new();
    for p in opened.iter().flatten() {
        for (k, v) in forensic_leaf(p) {
            let Some(b) = blobs.iter().position(|(id, _)| contains(&k, &id.0)) else { continue };
            match v {
                Ok(v) => keyed.push((b, v)),
                Err(slot) => keyed.extend(units.get(&slot).into_iter().flatten().map(|v| (b, v.to_vec()))),
            }
        }
    }
    let mut wraps: Vec<Vec<Vec<u8>>> = vec![Vec::new(); blobs.len()];
    let mut seen_wraps: HashSet<(usize, &[u8])> = HashSet::new();
    for (b, v) in &keyed {
        if let Some(w) = v.get(..WRAP_LEN)
            && seen_wraps.insert((*b, w))
            && let Some(ws) = wraps.get_mut(*b)
        {
            ws.push(w.to_vec());
        }
    }
    // Blobs: every candidate as a key and, through every wrap, as a read secret.
    let mut cands: Vec<[u8; 32]> = ev.secrets.clone();
    let mut seen: HashSet<[u8; 32], std::hash::BuildHasherDefault<Fold>> = cands.iter().copied().collect();
    let mut harvest = |plain: &[u8], cands: &mut Vec<[u8; 32]>| {
        for k in random_windows(plain) {
            if seen.insert(k) {
                cands.push(k);
            }
        }
    };
    for r in &out {
        if !matches!(r.from, Source::RawRow(_) | Source::RawBlob(_)) {
            harvest(&r.plain, &mut cands);
        }
    }
    if blobs.is_empty() {
        return out;
    }
    let mut open_blobs = vec![false; blobs.len()];
    // opened commit blobs: their plaintexts, with the sections opened so far
    let mut envelopes: Vec<(usize, Vec<u8>, HashSet<usize>)> = Vec::new();
    // the candidates prepared once each (`Trial`: a keystream, a wrap key)
    let mut trials: Vec<Trial> = Vec::new();
    let mut done = 0;
    while done < cands.len() {
        trials.extend(prepare(cands.get(trials.len()..).unwrap_or_default()));
        let batch = trials.get(done..).unwrap_or_default();
        done = cands.len();
        // sections of blobs opened before: every candidate as a read secret or section key
        for (i, plain, opened) in &mut envelopes {
            for (si, p) in (c.sections)(plain, batch, opened) {
                if opened.insert(si)
                    && let Some((id, _)) = blobs.get(*i)
                {
                    harvest(&p, &mut cands);
                    out.push(Recovered { from: Source::Blob { id: *id, wrapped: true }, plain: p });
                }
            }
        }
        // every candidate as the blob's key, then through every wrap of it as a read secret
        let try_blob = |i: usize| -> Option<(usize, Vec<u8>, bool)> {
            let (id, blob) = blobs.get(i)?;
            let ct = (c.prefix)(blob).and_then(|n| blob.get(n..));
            if let Some(ct) = ct
                && let Some(p) = batch.iter().filter(|t| t.may_open_blob(ct)).find_map(|t| (c.open)(blob, t.key().expose()))
            {
                return Some((i, p, false));
            }
            let ws = wraps.get(i).filter(|w| !w.is_empty())?;
            batch.iter().find_map(|t| t.unwraps(id, ws).iter().find_map(|k| (c.open)(blob, k.expose()))).map(|p| (i, p, true))
        };
        let try_blob = &try_blob;
        // tens of thousands of candidates per blob: one thread per blob keeps a test's wall short
        let found: Vec<(usize, Vec<u8>, bool)> = std::thread::scope(|sc| {
            let todo = (0..blobs.len()).filter(|i| open_blobs.get(*i) != Some(&true));
            let hs: Vec<_> = todo.map(|i| sc.spawn(move || try_blob(i))).collect();
            hs.into_iter().filter_map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e))).collect()
        });
        for (i, p, wrapped) in found {
            if let (Some(o), Some((id, _))) = (open_blobs.get_mut(i), blobs.get(i)) {
                *o = true;
                harvest(&p, &mut cands);
                // its sections under every candidate so far (a read secret seen before this blob's key)
                trials.extend(prepare(cands.get(trials.len()..).unwrap_or_default()));
                let mut opened = HashSet::new();
                for (si, sp) in (c.sections)(&p, &trials, &HashSet::new()) {
                    if opened.insert(si) {
                        harvest(&sp, &mut cands);
                        out.push(Recovered { from: Source::Blob { id: *id, wrapped: true }, plain: sp });
                    }
                }
                envelopes.push((i, p.clone(), opened));
                out.push(Recovered { from: Source::Blob { id: *id, wrapped }, plain: p });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec: none (forensic test support): the sliding count finds exactly the windows of at
    // least `KEY_MIN_DISTINCT` distinct byte values, in order
    #[test]
    fn random_windows_are_the_counted_ones() {
        let distinct = |w: &[u8]| w.iter().collect::<HashSet<_>>().len();
        let mut x = 7u64;
        let mut plain = Vec::new();
        for i in 0..3000u64 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            // runs of text-like, zero and random bytes, so windows cross the threshold both ways
            plain.push(match (i / 50) % 3 {
                0 => b'a' + (x >> 60) as u8,
                1 => 0,
                _ => (x >> 56) as u8,
            });
        }
        for p in [&plain[..], &plain[..31], &plain[..32], &[]] {
            let want: Vec<[u8; 32]> = p.windows(32).filter(|w| distinct(w) >= KEY_MIN_DISTINCT).map(|w| w.try_into().unwrap()).collect();
            assert_eq!(random_windows(p).collect::<Vec<_>>(), want);
        }
        assert!(random_windows(&plain).count() > 100);
    }
}
