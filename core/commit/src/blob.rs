//! Commit blob plaintext `[Header, signature, [Section*]]` and its
//! opened form, the commit's held parts (spec/wire.md §4).
//!
//! Confidentiality invariants (spec/wire.md §4, spec/sync-judgement.md §1):
//! - a section holds the parts of one reader, sealed under a fresh random section key
//!   that encrypts this one plaintext (nonce zero, used once) and nothing else ever: a rewrite
//!   seals the section again under a new key;
//! - the section key is wrapped under `kdf("section", read secret)` of that actor with a random
//!   nonce carried in the wrap (`osis_crypto::wrap_section`), so two wraps of one commit's
//!   section under one read secret never share a nonce;
//! - both AEADs take the commit ID as AD, so a section opens only inside its own commit;
//! - a reader that cannot open a section learns its `ai` list, its thing's derivation chain and its
//!   size, nothing else, and copies it verbatim into a fresh encryption (`seal_commit`'s
//!   `extra`).

use crate::cbor::{item, strictly_ascending};
use crate::header::{Header, LIMITS};
use crate::path::{Paths, ThingPath};
use crate::Error;
use osis_base::cbor::{Item, MAJOR_ARRAY, MAJOR_UINT, encode_into, head, put_array, put_bytes, put_uint};
use osis_base::{CommitId, Tid};
use osis_crypto::{CryptoRngCore, Domain, SECTION_WRAP_LEN, Secret32, Signature, SigningSecret};
use std::borrow::Borrow;
use std::collections::BTreeMap;

/// One delta of a commit blob: its aspect's index and canonical delta (or snapshot) bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub ai: usize,
    pub delta: Vec<u8>,
}

/// A commit as a node holds it: the header, its signatures, the parts it opened and, where it
/// states the split form, the path keys its opened encryptions carried (its stored form,
/// `[Header, signature, [Part*]]`, then `[PathKey+]` where it holds
/// one; a sealed fire's payload too, spec/wire.md §9, and a header-only copy of a commit stating
/// one path is the commit blob plaintext without sections).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitBlob {
    pub header: Header,
    pub sigs: Sigs,
    /// Sorted by `ai`, distinct.
    pub parts: Vec<Part>,
    /// Where the header states the split form: the path key of each thing (by its place among
    /// those written, `Header::things`) an opened encryption carried, each the key its entry
    /// commits to, so one per entry wherever it came from; empty where the path is in the clear.
    pub keys: BTreeMap<usize, [u8; 32]>,
}

/// A commit's signature (spec/wire.md §4): the signer's key's, over the commit ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sigs {
    pub signature: Signature,
}

impl Sigs {
    /// The signature of commit `id` by `key`.
    pub fn signed(id: &CommitId, key: &SigningSecret) -> Sigs {
        Sigs { signature: key.sign(Domain::Commit, &id.0) }
    }

    /// Bytes of the signature in a blob.
    pub fn encoded_len(&self) -> usize {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out.len()
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_into(&self.signature.to_value(), out);
    }

    fn read(sv: Item) -> Result<Sigs, Error> {
        Ok(Sigs { signature: Signature::from_value(&sv.to_value()?)? })
    }
}

impl CommitBlob {
    pub fn id(&self) -> CommitId {
        self.header.id()
    }

    /// The part on aspect `ai`, if held (a search: `parts` is sorted).
    pub fn part(&self, ai: usize) -> Option<&Part> {
        self.parts.binary_search_by_key(&ai, |p| p.ai).ok().and_then(|i| self.parts.get(i))
    }

    /// The path it states for thing `t`, where known here: the header's in the clear, else `t`'s entry opened under its held path key.
    pub fn path(&self, t: &Tid) -> Option<ThingPath> {
        match &self.header.path {
            Paths::One(p) => self.header.aspects.iter().any(|a| a.tid == *t).then(|| ThingPath::Known(p.clone())),
            Paths::Split(_) => {
                let i = self.header.things().iter().position(|x| x == t)?;
                self.header.open_path(i, self.keys.get(&i)?)
            }
        }
    }

    /// The things (by place) whose parts it holds, once the aspect list is resolved.
    fn held_things(&self) -> BTreeMap<usize, ()> {
        let h = &self.header;
        let things = h.things();
        self.parts.iter().filter_map(|p| h.aspects.get(p.ai).and_then(|a| things.iter().position(|t| *t == a.tid))).map(|i| (i, ())).collect()
    }

    /// Once the aspect list is resolved, drops every part of a split commit whose thing's path key
    /// it does not hold or whose entry opens to a bad path (`ThingPath::Bad`): such parts hold
    /// nothing, at every reader of the thing alike (spec/wire.md §4 `Split`).
    pub fn settle_paths(&mut self) {
        if !self.header.is_split() || !self.header.is_resolved() {
            return;
        }
        let things = self.header.things();
        let ok: Vec<bool> = (0..things.len()).map(|i| self.keys.get(&i).is_some_and(|k| matches!(self.header.open_path(i, k), Some(ThingPath::Known(_))))).collect();
        let h = &self.header;
        self.parts.retain(|p| h.aspects.get(p.ai).and_then(|a| things.iter().position(|t| *t == a.tid)).is_some_and(|i| ok.get(i) == Some(&true)));
    }

    /// Checks `keys` against the header: none where the path is in the clear; else each in range
    /// and the key its entry commits to (spec/wire.md §4); once the aspect list is resolved, every
    /// held part's thing with its key and a path that is not bad (`settle_paths` makes it so).
    pub fn check_paths(&self) -> Result<(), Error> {
        let h = &self.header;
        let entries = match &h.path {
            Paths::One(_) => return if self.keys.is_empty() { Ok(()) } else { Err(Error::Malformed("a path key beside a path in the clear")) },
            Paths::Split(s) => &s.entries,
        };
        for (i, k) in &self.keys {
            let Some(e) = entries.get(*i) else { return Err(Error::Malformed("a path key out of range")) };
            if crate::path::Split::open(k, e).is_none() {
                return Err(Error::Malformed("a path key its entry does not commit to"));
            }
        }
        if h.is_resolved() && self.held_things().keys().any(|i| !matches!(self.keys.get(i).and_then(|k| h.open_path(*i, k)), Some(ThingPath::Known(_)))) {
            return Err(Error::Malformed("a part without its thing's path"));
        }
        Ok(())
    }

    /// Canonical bytes of the opened form (unpadded).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        head(&mut out, MAJOR_ARRAY, if self.keys.is_empty() { 3 } else { 4 });
        self.header.encode_into(&mut out);
        self.sigs.encode_into(&mut out);
        encode_parts(&self.parts, &mut out);
        if !self.keys.is_empty() {
            encode_keys(self.keys.iter().map(|(i, k)| (*i, k)), &mut out);
        }
        out
    }

    /// Decodes the opened form. Linked header lists stay unresolved; part indices are checked
    /// against the header by [`crate::verify_part`], paths by `check_paths` once resolved.
    pub fn decode(b: &[u8]) -> Result<CommitBlob, Error> {
        let items: Vec<Item> = item::list(Item::parse(b, &LIMITS)?)?.iter().collect();
        let (Some([hv, sv, pv]), tv) = (items.get(..3).and_then(|x| <[Item; 3]>::try_from(x).ok()), items.get(3)) else { return Err(Error::Malformed("commit blob arity")) };
        if items.len() > 4 {
            return Err(Error::Malformed("commit blob arity"));
        }
        let header = Header::read(hv, false)?;
        let sigs = Sigs::read(sv)?;
        let parts = decode_parts(pv)?;
        let keys = tv.map(|t| decode_keys(*t, false)).transpose()?.unwrap_or_default();
        let blob = CommitBlob { header, sigs, parts, keys };
        if blob.encode() != b {
            return Err(Error::Malformed("commit blob not canonical"));
        }
        blob.check_paths()?;
        Ok(blob)
    }

    /// `decode` of a commit this node stored, checked when it arrived and written canonical by
    /// `encode`: decode-only (no canonical re-encode), its delete keys not decompressed again (a
    /// third of what re-reading an aspect's bodies cost) and each part's delta kept as its stored
    /// bytes, never decoded here. Only for bytes this node wrote from a blob `decode` accepted
    /// (stored and pending rows; a parked row of raw bytes fails here on its version, and what
    /// applies it decodes it with `decode`); never for bytes from a peer.
    pub fn decode_stored(b: &[u8]) -> Result<CommitBlob, Error> {
        let mut r = osis_base::cbor::Reader::new(b);
        let n = r.array()?;
        if !(3..=4).contains(&n) {
            return Err(Error::Malformed("commit blob arity"));
        }
        let mut next = || -> Result<Item, Error> { Ok(Item::parse(r.item()?, &LIMITS)?) };
        let header = Header::read(next()?, true)?;
        let sigs = Sigs::read(next()?)?;
        let mut parts = Vec::new();
        for _ in 0..r.array()? {
            if r.array()? != 2 {
                return Err(Error::Malformed("part arity"));
            }
            let ai = usize::try_from(r.uint()?).map_err(|_| Error::Malformed("index too large"))?;
            if r.peek_major() != Some(MAJOR_ARRAY) {
                return Err(Error::Malformed("part delta"));
            }
            parts.push(Part { ai, delta: r.item()?.to_vec() });
        }
        let keys = if n == 4 { decode_keys(Item::parse(r.item()?, &LIMITS)?, false)? } else { BTreeMap::new() };
        r.end()?;
        if !strictly_ascending(&parts, |p| p.ai) {
            return Err(Error::Malformed("parts not sorted and distinct"));
        }
        Ok(CommitBlob { header, sigs, parts, keys })
    }

    /// Aspects whose delta this blob does not hold (purged, or in a section not opened).
    pub fn missing(&self) -> Vec<usize> {
        (0..self.header.aspects.len()).filter(|ai| self.part(*ai).is_none()).collect()
    }
}

/// `[Part*]` (a part `[ai, delta]`) by concatenation: delta bytes are already canonical items.
fn encode_parts(parts: &[impl Borrow<Part>], out: &mut Vec<u8>) {
    head(out, MAJOR_ARRAY, parts.len() as u64);
    for p in parts {
        let p = p.borrow();
        head(out, MAJOR_ARRAY, 2);
        head(out, MAJOR_UINT, p.ai as u64);
        out.extend_from_slice(&p.delta);
    }
}

/// A section's plaintext, opened (spec/wire.md §4 `Contents`): its parts and, in a split commit,
/// the path keys it carries by thing place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contents {
    pub parts: Vec<Part>,
    pub keys: BTreeMap<usize, [u8; 32]>,
}

/// A section's plaintext `Contents` (spec/wire.md §4): `[Part*]`, or in a split commit
/// `[[Part*], [PathKey*]]`.
fn encode_contents(parts: &[impl Borrow<Part>], keys: Option<&BTreeMap<usize, [u8; 32]>>, out: &mut Vec<u8>) {
    if let Some(k) = keys {
        put_array(out, 2);
        encode_parts(parts, out);
        encode_keys(k.iter().map(|(i, k)| (*i, k)), out);
    } else {
        encode_parts(parts, out);
    }
}

/// `[PathKey*]`, `PathKey := [index, bytes]`, ascending by index.
fn encode_keys<'a>(keys: impl ExactSizeIterator<Item = (usize, &'a [u8; 32])>, out: &mut Vec<u8>) {
    put_array(out, keys.len());
    for (i, k) in keys {
        put_array(out, 2);
        put_uint(out, i as u64);
        put_bytes(out, k);
    }
}

/// `[PathKey*]`, ascending by index, distinct; at least one where `empty_ok` is false.
fn decode_keys(v: Item, empty_ok: bool) -> Result<BTreeMap<usize, [u8; 32]>, Error> {
    let mut out = BTreeMap::new();
    let mut last = None;
    for x in item::list(v)? {
        let Some([i, k]) = item::list(x)?.tuple() else { return Err(Error::Malformed("path key arity")) };
        let i = item::idx(i)?;
        if last.is_some_and(|l| l >= i) {
            return Err(Error::Malformed("path keys not ascending by index"));
        }
        last = Some(i);
        out.insert(i, item::bytes(k)?);
    }
    if out.is_empty() && !empty_ok {
        return Err(Error::Malformed("an empty path key list"));
    }
    Ok(out)
}

/// Encoded length of one part.
pub(crate) fn part_len(p: &Part) -> usize {
    use osis_base::cbor::head_len;
    (head_len(2) + head_len(p.ai as u64)).saturating_add(p.delta.len())
}

/// The parts of a `[Part*]` value: sorted by `ai`, distinct.
fn decode_parts(pv: Item) -> Result<Vec<Part>, Error> {
    let mut parts = Vec::new();
    for p in item::list(pv)? {
        let Some([ai, d]) = item::list(p)?.tuple() else { return Err(Error::Malformed("part arity")) };
        if d.as_list().is_none() {
            return Err(Error::Malformed("part delta"));
        }
        parts.push(Part { ai: item::idx(ai)?, delta: d.bytes().to_vec() });
    }
    if !strictly_ascending(&parts, |p| p.ai) {
        return Err(Error::Malformed("parts not sorted and distinct"));
    }
    Ok(parts)
}

/// One section of a commit blob `[[ai+], [chain*], wrap, ciphertext]` (spec/wire.md §4): the
/// aspect indices of its parts (ascending, distinct, each with a part inside), the derivation chain
/// of their thing up to the actor its read secret derives from (a reader derives the secret
/// through it without the thing's record), the section key wrapped under that read secret,
/// the parts sealed under that key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub ais: Vec<usize>,
    pub chain: Vec<Tid>,
    pub wrap: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Section {
    /// Hash of the section's encoding: what a node that cannot open it compares of it
    /// (spec/sync-compaction.md §1 Duplicates).
    pub fn digest(&self) -> [u8; 32] {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.put(&mut out);
        osis_base::hash::hash(&out)
    }

    /// Encoded length.
    pub fn encoded_len(&self) -> usize {
        use osis_base::cbor::head_len;
        let ais = head_len(self.ais.len() as u64) + self.ais.iter().map(|a| head_len(*a as u64)).sum::<usize>();
        let chain = head_len(self.chain.len() as u64) + self.chain.len() * (1 + osis_base::format::TID_LEN);
        head_len(4) + ais + chain + head_len(self.wrap.len() as u64) + self.wrap.len() + head_len(self.ciphertext.len() as u64) + self.ciphertext.len()
    }

    fn put(&self, out: &mut Vec<u8>) {
        put_array(out, 4);
        put_array(out, self.ais.len());
        self.ais.iter().for_each(|a| put_uint(out, *a as u64));
        put_array(out, self.chain.len());
        self.chain.iter().for_each(|t| put_bytes(out, t.as_bytes()));
        put_bytes(out, &self.wrap);
        put_bytes(out, &self.ciphertext);
    }

    fn read(v: Item) -> Result<Section, Error> {
        let Some([ais, chain, wrap, ct]) = item::list(v)?.tuple() else { return Err(Error::Malformed("section arity")) };
        let ais = item::list(ais)?.iter().map(item::idx).collect::<Result<Vec<_>, _>>()?;
        // no aspect: a header-only copy's section of a split commit (`Envelope::decode`)
        if !strictly_ascending(&ais, |a| *a) {
            return Err(Error::Malformed("section aspects not ascending and distinct"));
        }
        let chain = item::list(chain)?.iter().map(item::tid).collect::<Result<Vec<_>, _>>()?;
        if chain.len() > osis_base::format::MAX_CHAIN_DEPTH {
            return Err(Error::Malformed("section chain too deep"));
        }
        let mut seen = std::collections::BTreeSet::new();
        if !chain.iter().all(|o| seen.insert(*o)) {
            return Err(Error::Malformed("section chain repeats a thing"));
        }
        let wrap = wrap.as_bytes().ok_or(Error::Malformed("section wrap"))?.to_vec();
        if wrap.len() != SECTION_WRAP_LEN {
            return Err(Error::Malformed("section wrap length"));
        }
        let ciphertext = ct.as_bytes().ok_or(Error::Malformed("section ciphertext"))?.to_vec();
        Ok(Section { ais, chain, wrap, ciphertext })
    }

    /// Whether the key of keystream `zero` (under nonce zero) may be this section's key, judged
    /// by its first plaintext bytes alone (`Contents`: `[Part*]` of as many parts as it lists, or
    /// in a split commit a 2-array of that and the path keys; `encode_contents`), NOT
    /// authenticated: forensic tests only, to rule a candidate out before `open`'s pass over the
    /// whole ciphertext. Never false for the section's own key.
    #[doc(hidden)]
    pub fn may_open_with(&self, zero: &osis_crypto::aead::Keystream, split: bool) -> bool {
        let mut want = Vec::new();
        if split {
            put_array(&mut want, 2);
        }
        put_array(&mut want, self.ais.len());
        want.iter().enumerate().all(|(i, b)| zero.plain_byte(&self.ciphertext, i) == Some(*b))
    }

    /// Opens this section with one of `secrets` (newest first): its `Contents` (path keys only
    /// where `split`), the parts exactly on the aspects listed. `None`: no secret opens the wrap. A
    /// section whose wrap some secret opens to a key opening nothing, or that opens to parts
    /// disagreeing with its list, is bad input.
    ///
    /// Every secret is tried until one's key opens the ciphertext: XChaCha20-Poly1305 commits to
    /// no key, so a writer can make one wrap open under two secrets to two keys, and a reader
    /// taking the first that unwraps would read less for holding more. The commit ID (both AEADs'
    /// AD) fixes the contents (parts by delta hash, path keys by commitment), so a key opening the
    /// ciphertext to them is the only key opening it: a writer keeping a free block for a second
    /// key has junk on both, bad at every reader alike. What a reader takes is a function of the
    /// secrets it holds, never of their order (spec/crypto.md §5 Section).
    pub fn open(&self, commit: &CommitId, split: bool, secrets: &[Secret32]) -> Result<Option<Contents>, Error> {
        let mut opened = None;
        for s in secrets {
            let Ok(key) = osis_crypto::unwrap_section(s, commit, &self.wrap) else { continue };
            opened = Some(osis_crypto::open_section(commit, &key, &self.ciphertext));
            if opened.as_ref().is_some_and(|r| r.is_ok()) {
                break;
            }
        }
        let Some(pt) = opened else { return Ok(None) };
        let pt = pt?;
        let v = Item::parse(&pt, &LIMITS)?;
        let (parts, keys) = if split {
            let Some([pv, kv]) = item::list(v)?.tuple() else { return Err(Error::Malformed("section contents arity")) };
            (decode_parts(pv)?, decode_keys(kv, true)?)
        } else {
            (decode_parts(v)?, BTreeMap::new())
        };
        if !parts.iter().map(|p| p.ai).eq(self.ais.iter().copied()) {
            return Err(Error::Malformed("section parts disagree with its aspect list"));
        }
        let mut canon = Vec::new();
        encode_contents(&parts, split.then_some(&keys), &mut canon);
        if canon != pt {
            return Err(Error::Malformed("section not canonical"));
        }
        Ok(Some(Contents { parts, keys }))
    }

    /// Seals `parts` (sorted), with the path keys `keys` where the commit states the split form,
    /// under the thing's read secret `secret`, listing its derivation chain `chain`.
    pub fn seal(commit: &CommitId, parts: &[impl Borrow<Part>], keys: Option<&BTreeMap<usize, [u8; 32]>>, chain: Vec<Tid>, secret: &Secret32, rng: &mut dyn CryptoRngCore) -> Result<Section, Error> {
        let mut pt = Vec::new();
        encode_contents(parts, keys, &mut pt);
        let (key, ciphertext) = osis_crypto::seal_section(commit, &pt, rng)?;
        let wrap = osis_crypto::wrap_section(secret, commit, &key, rng)?.to_vec();
        let ais: Vec<usize> = parts.iter().map(|p| p.borrow().ai).collect();
        Ok(Section { ais, chain, wrap, ciphertext })
    }
}

/// A commit blob's plaintext as the wire carries it: header, signature, sections sorted by
/// their first aspect index, no aspect in two sections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub header: Header,
    pub sigs: Sigs,
    pub sections: Vec<Section>,
}

impl Envelope {
    pub fn id(&self) -> CommitId {
        self.header.id()
    }

    /// Canonical plaintext bytes (unpadded).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        head(&mut out, MAJOR_ARRAY, 3);
        self.header.encode_into(&mut out);
        self.sigs.encode_into(&mut out);
        put_array(&mut out, self.sections.len());
        self.sections.iter().for_each(|s| s.put(&mut out));
        out
    }

    /// Decodes a commit blob plaintext. Linked header lists stay unresolved; aspect indices
    /// are checked against the header once resolved (`prefix_groups`).
    pub fn decode(b: &[u8]) -> Result<Envelope, Error> {
        let Some([hv, sv, ss]) = item::list(Item::parse(b, &LIMITS)?)?.tuple() else { return Err(Error::Malformed("commit blob arity")) };
        let header = Header::read(hv, false)?;
        let sigs = Sigs::read(sv)?;
        let sections = item::list(ss)?.iter().map(Section::read).collect::<Result<Vec<_>, _>>()?;
        if !strictly_ascending(&sections, |s| s.ais.first().copied()) {
            return Err(Error::Malformed("sections not sorted by first aspect"));
        }
        let mut seen = std::collections::BTreeSet::new();
        if sections.iter().flat_map(|s| s.ais.iter()).any(|a| !seen.insert(*a)) {
            return Err(Error::Malformed("an aspect in two sections"));
        }
        // a section of no part carries path keys alone: a header-only copy of a split commit
        if !header.is_split() && sections.iter().any(|s| s.ais.is_empty()) {
            return Err(Error::Malformed("section aspects not ascending and distinct"));
        }
        let e = Envelope { header, sigs, sections };
        if e.encode() != b {
            return Err(Error::Malformed("commit blob not canonical"));
        }
        Ok(e)
    }

    /// Every aspect index any section lists, ascending.
    pub fn ais(&self) -> Vec<usize> {
        self.sections.iter().flat_map(|s| s.ais.iter().copied()).collect()
    }

    /// Opens every section `secrets` has a read secret for (asked per section): the commit with
    /// the parts opened, and the sections left sealed. In a split commit a section carrying a path
    /// key its entry does not commit to holds nothing (spec/wire.md §4): it is no key of that
    /// entry, so every section a reader takes carries the one key each entry accepts; the parts
    /// of a thing whose path key no opened section carries, or whose entry opens to a bad path,
    /// are dropped once the aspect list is resolved (`CommitBlob::settle_paths`).
    pub fn open(&self, mut secrets: impl FnMut(&Section) -> Vec<Secret32>) -> Result<Opened, Error> {
        let id = self.id();
        let h = &self.header;
        let split = h.is_split();
        let mut parts = Vec::new();
        let mut keys = BTreeMap::new();
        let mut sealed = Vec::new();
        for s in &self.sections {
            let Some(c) = s.open(&id, split, &secrets(s))? else {
                sealed.push(s.clone());
                continue;
            };
            let entries = match &h.path {
                Paths::Split(sp) => sp.entries.as_slice(),
                Paths::One(_) => &[],
            };
            if c.keys.iter().any(|(i, k)| entries.get(*i).is_none_or(|e| crate::path::Split::open(k, e).is_none())) || (split && !keys_exact(h, &s.ais, &c.keys)) {
                continue;
            }
            parts.extend(c.parts);
            keys.extend(c.keys);
        }
        parts.sort_by_key(|p| p.ai);
        let mut commit = CommitBlob { header: h.clone(), sigs: self.sigs.clone(), parts, keys };
        commit.settle_paths();
        commit.check_paths()?;
        Ok(Opened { commit, sealed })
    }
}

/// Whether a split commit's section on aspects `ais` carries the path keys of exactly the things
/// its parts are on, or, holding no part, of things the commit destroys only (spec/wire.md §4
/// `Contents`: one encoding; a key beyond them is bad input). Read once the aspect list is
/// resolved: before, a section's things are unknown and its keys are checked against their
/// entries alone.
fn keys_exact(h: &Header, ais: &[usize], keys: &BTreeMap<usize, [u8; 32]>) -> bool {
    if !h.is_resolved() {
        return true;
    }
    let things = h.things();
    let place = |t: &Tid| things.iter().position(|x| x == t);
    if ais.is_empty() {
        let destroyed: std::collections::BTreeSet<usize> = h.destroyed().filter_map(place).collect();
        return !keys.is_empty() && keys.keys().all(|i| destroyed.contains(i));
    }
    let of_parts: std::collections::BTreeSet<usize> = ais.iter().filter_map(|ai| h.aspects.get(*ai)).filter_map(|a| place(&a.tid)).collect();
    keys.keys().copied().eq(of_parts)
}

/// What opening an envelope gives: the commit with its opened parts, and the sections no held
/// secret opened (copied verbatim into a fresh encryption).
#[derive(Clone, Debug)]
pub struct Opened {
    pub commit: CommitBlob,
    pub sealed: Vec<Section>,
}

/// Seals a commit's parts into sections, one per value of `section_of(ai)`, each wrapped under the
/// read secret `secret_of(key, parts)` gives with the thing's derivation chain (that secret at the
/// epoch the writer uses, spec/crypto.md §5); in a split commit each section carries the path key
/// of every thing whose parts it holds (`resolved`, `c`'s header with its lists resolved, says
/// the thing of each part). A section whose secret is not held (`None`) is left out, its parts
/// travelling in other copies; `extra` sections are copied verbatim, except one listing an aspect
/// a sealed part is on.
pub fn seal_commit<K: Ord + Clone>(c: &CommitBlob, resolved: &Header, section_of: impl Fn(usize) -> K, mut secret_of: impl FnMut(&K, &[usize]) -> Option<(Secret32, Vec<Tid>)>, extra: &[Section], rng: &mut dyn CryptoRngCore) -> Result<Envelope, Error> {
    let id = c.id();
    let things = if c.header.is_split() { resolved.things() } else { Vec::new() };
    let mut by: BTreeMap<K, Vec<&Part>> = BTreeMap::new();
    for p in &c.parts {
        by.entry(section_of(p.ai)).or_default().push(p);
    }
    let mut sections = Vec::with_capacity(by.len() + extra.len());
    let mut own: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for (k, ps) in by {
        let ais: Vec<usize> = ps.iter().map(|p| p.ai).collect();
        let keys = c.header.is_split().then(|| path_keys_of(c, resolved, &things, &ais)).transpose()?;
        let Some((secret, chain)) = secret_of(&k, &ais) else { continue };
        own.extend(ais.iter().copied());
        sections.push(Section::seal(&id, &ps, keys.as_ref(), chain, &secret, rng)?);
    }
    let mut seen = own.clone();
    for s in extra {
        if s.ais.iter().any(|a| own.contains(a)) {
            continue;
        }
        if s.ais.iter().any(|a| !seen.insert(*a)) {
            return Err(Error::Malformed("an aspect in two sections"));
        }
        sections.push(s.clone());
    }
    sections.sort_by_key(|s| s.ais.first().copied());
    Ok(Envelope { header: c.header.clone(), sigs: c.sigs.clone(), sections })
}

/// The path keys of the things the parts on `ais` are on, every one held.
fn path_keys_of(c: &CommitBlob, resolved: &Header, things: &[Tid], ais: &[usize]) -> Result<BTreeMap<usize, [u8; 32]>, Error> {
    ais.iter()
        .map(|ai| {
            let i = resolved.aspects.get(*ai).and_then(|a| things.iter().position(|t| *t == a.tid)).ok_or(Error::Malformed("part aspect index out of range"))?;
            Ok((i, *c.keys.get(&i).ok_or(Error::Malformed("a part without its thing's path key"))?))
        })
        .collect()
}

/// A header-only copy of `c` (spec/wire.md §4): no section, or, where `c` states the split form and
/// destroys things (`Header::destroyed`), one section of no part carrying their held path keys,
/// under `secret` (a copy's blob key), so the destroyed things' judges open their paths.
pub fn seal_header_only(c: &CommitBlob, resolved: &Header, secret: &Secret32, rng: &mut dyn CryptoRngCore) -> Result<Envelope, Error> {
    let things = resolved.things();
    let keys: BTreeMap<usize, [u8; 32]> = resolved.destroyed().filter_map(|t| things.iter().position(|x| x == t)).filter_map(|i| Some((i, *c.keys.get(&i)?))).collect();
    let sections = if c.header.is_split() && !keys.is_empty() { vec![Section::seal(&c.id(), &[] as &[Part], Some(&keys), Vec::new(), secret, rng)?] } else { Vec::new() };
    Ok(Envelope { header: c.header.clone(), sigs: c.sigs.clone(), sections })
}
