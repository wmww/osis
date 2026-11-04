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

use crate::KeyValue;
use crate::btree::forensic_leaf;
use crate::pager::{forensic_clear_row, forensic_node_keys, forensic_open, forensic_unit_slot};
use osis_base::BlobId;
use std::collections::{BTreeMap, HashSet};

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
}

impl Evidence {
    /// The store keys given and everything `backend` recorded (`record_history`).
    pub fn of(store_keys: Vec<[u8; 32]>, backend: &crate::MemoryBackend) -> Evidence {
        Evidence { store_keys, secrets: Vec::new(), rows: backend.history(), blobs: backend.blob_history() }
    }
}

/// Opens a blob under a candidate key.
pub type OpenBlob = fn(&[u8], &[u8; 32]) -> Option<Vec<u8>>;
/// The blob key a wrap of the blob yields under a candidate read secret.
pub type Unwrap = fn(&[u8; 32], &BlobId, &[u8]) -> Option<[u8; 32]>;

/// The sections of an opened commit blob plaintext that any of the candidates opens, as a
/// read secret of their wrap or as their key: (section index, plaintext), one per section.
/// Empty for any other plaintext.
pub type OpenSections = fn(&[u8], &[[u8; 32]]) -> Vec<(usize, Vec<u8>)>;

/// How blobs, wraps and sections open: the layers above the store define them (osis-label's
/// frame and wrap, osis-commit's sections).
pub struct Ciphers {
    pub open: OpenBlob,
    pub unwrap: Unwrap,
    pub wrap_len: usize,
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

fn random_looking(w: &[u8]) -> bool {
    let mut seen = [false; 256];
    let mut n = 0;
    for b in w {
        if let Some(s) = seen.get_mut(usize::from(*b))
            && !*s
        {
            *s = true;
            n += 1;
        }
    }
    n >= KEY_MIN_DISTINCT
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
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
        tried = keys.len();
        for ((row, value), slot) in ev.rows.iter().zip(opened.iter_mut()) {
            if slot.is_some() {
                continue;
            }
            if let Some(plain) = batch.iter().find_map(|k| forensic_open(row, value, k)) {
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
        if let Some(w) = v.get(..c.wrap_len)
            && seen_wraps.insert((*b, w))
            && let Some(ws) = wraps.get_mut(*b)
        {
            ws.push(w.to_vec());
        }
    }
    // Blobs: every candidate as a key and, through every wrap, as a read secret.
    let mut cands: Vec<[u8; 32]> = ev.secrets.clone();
    let mut seen: HashSet<[u8; 32]> = cands.iter().copied().collect();
    let mut harvest = |plain: &[u8], cands: &mut Vec<[u8; 32]>| {
        for w in plain.windows(32) {
            if let Ok(k) = <[u8; 32]>::try_from(w)
                && random_looking(w)
                && seen.insert(k)
            {
                cands.push(k);
            }
        }
    };
    for r in &out {
        if !matches!(r.from, Source::RawRow(_) | Source::RawBlob(_)) {
            harvest(&r.plain, &mut cands);
        }
    }
    let mut open_blobs = vec![false; blobs.len()];
    // opened commit blobs: their plaintexts, with the sections opened so far
    let mut envelopes: Vec<(usize, Vec<u8>, HashSet<usize>)> = Vec::new();
    let mut done = 0;
    while done < cands.len() {
        let batch = cands.get(done..).unwrap_or_default().to_vec();
        done = cands.len();
        // sections of blobs opened before: every candidate as a read secret or section key
        for (i, plain, opened) in &mut envelopes {
            let found: Vec<(usize, Vec<u8>)> = (c.sections)(plain, &batch).into_iter().filter(|(si, _)| !opened.contains(si)).collect();
            for (si, p) in found {
                if opened.insert(si)
                    && let Some((id, _)) = blobs.get(*i)
                {
                    harvest(&p, &mut cands);
                    out.push(Recovered { from: Source::Blob { id: *id, wrapped: true }, plain: p });
                }
            }
        }
        // tens of thousands of candidates per blob: one thread per blob keeps a test's wall short
        let try_blob = |i: usize| -> Option<(usize, Vec<u8>, bool)> {
            let (id, blob) = blobs.get(i)?;
            if let Some(p) = batch.iter().find_map(|k| (c.open)(blob, k)) {
                return Some((i, p, false));
            }
            let wrapped = wraps.get(i).into_iter().flatten().find_map(|w| batch.iter().find_map(|s| (c.unwrap)(s, id, w)));
            wrapped.and_then(|k| (c.open)(blob, &k)).map(|p| (i, p, true))
        };
        let try_blob = &try_blob;
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
                let mut opened = HashSet::new();
                for (si, sp) in (c.sections)(&p, &cands) {
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
