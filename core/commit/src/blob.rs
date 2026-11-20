//! Commit blob plaintext `[Header, signature, Opt(inner), [signature*], [Section*]]` and its
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
use crate::path::{Acting, Path, Paths, Salted};
use crate::Error;
use osis_base::cbor::{Item, MAJOR_ARRAY, MAJOR_UINT, encode_into, head, put_array, put_bytes, put_uint};
use osis_base::{CommitId, Tid, Value};
use osis_crypto::{CryptoRngCore, Domain, INNER_LEN, SECTION_WRAP_LEN, Secret32, Signature, SigningSecret};
use std::borrow::Borrow;
use std::collections::BTreeMap;

/// One delta of a commit blob: its aspect's index and canonical delta (or snapshot) bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub ai: usize,
    pub delta: Vec<u8>,
}

/// A commit as a node holds it: the header, its signatures, the parts it opened and, where it
/// states hashed paths, the path of each thing whose section it opened (its stored form,
/// `[Header, signature, Opt(inner), [signature*], [Part*]]`, then `[[index, Salted]+]` where it
/// holds one; a sealed fire's payload too, spec/wire.md §9, and a header-only copy is the
/// commit blob plaintext without sections).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitBlob {
    pub header: Header,
    pub sigs: Sigs,
    /// Sorted by `ai`, distinct.
    pub parts: Vec<Part>,
    /// Where the header's paths are hashed: each opened thing's `Salted` by the index of the hash
    /// it matches (the thing's place among those written, `Header::things`); empty where the path
    /// is in the clear.
    pub salted: BTreeMap<usize, Salted>,
}

/// A commit's signatures (spec/wire.md §4): the signer's; an account's commit's sealed inner
/// signature, and a rotation's sealed again under each other epoch it opens with (`more`); a
/// merge's signatures at the forks its rotation names, in that order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sigs {
    pub signature: Signature,
    pub inner: Option<[u8; INNER_LEN]>,
    /// A rotation's inner signature sealed again (spec/crypto.md §3): a plain rotation's under
    /// the epoch it mints; a merge certificate's under each tip it names, in that order, then the
    /// merge epoch. Carried after `inner` in its byte string.
    pub more: Vec<[u8; INNER_LEN]>,
    pub merge: Vec<Signature>,
}

impl Sigs {
    /// The signatures of commit `id` by `key`, its inner (and `more`) and merge signatures bound
    /// in.
    pub fn signed(id: &CommitId, key: &SigningSecret, inner: Option<[u8; INNER_LEN]>, more: Vec<[u8; INNER_LEN]>, merge: Vec<Signature>) -> Sigs {
        let mut sigs = Sigs { signature: Signature([0; 64]), inner, more, merge };
        sigs.signature = key.sign(Domain::Commit, &sigs.digest(id));
        sigs
    }

    /// What the signer's signature signs (spec/crypto.md §2): the commit ID, and for an account's
    /// commit also the inner (each seal) and merge signatures, which the commit ID cannot cover
    /// (each signs that ID), so a relay swaps none.
    pub fn digest(&self, id: &CommitId) -> [u8; 32] {
        let Some(inner) = &self.inner else { return id.0 };
        let mut b = Vec::with_capacity(32 + INNER_LEN * (1 + self.more.len()) + 64 * self.merge.len());
        b.extend_from_slice(&id.0);
        b.extend_from_slice(inner);
        for m in &self.more {
            b.extend_from_slice(m);
        }
        for s in &self.merge {
            b.extend_from_slice(&s.0);
        }
        osis_base::hash::hash(&b)
    }

    /// Bytes of the three in a blob.
    pub fn encoded_len(&self) -> usize {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out.len()
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_into(&self.signature.to_value(), out);
        let inner = self.inner.map(|i| Value::Bytes(i.iter().chain(self.more.iter().flatten()).copied().collect()));
        encode_into(&Value::opt(inner), out);
        encode_into(&Value::List(self.merge.iter().map(Signature::to_value).collect()), out);
    }

    fn read(sv: Item, iv: Item, mv: Item) -> Result<Sigs, Error> {
        let signature = Signature::from_value(&sv.to_value()?)?;
        let seals: Vec<[u8; INNER_LEN]> = match item::opt(iv)? {
            None => Vec::new(),
            Some(b) => {
                let b = b.as_bytes().filter(|b| !b.is_empty() && b.len() % INNER_LEN == 0).ok_or(Error::Malformed("inner signatures"))?;
                b.chunks(INNER_LEN).map(|c| c.try_into().map_err(|_| Error::Malformed("inner signatures"))).collect::<Result<_, _>>()?
            }
        };
        let (inner, more) = match seals.split_first() {
            Some((i, rest)) => (Some(*i), rest.to_vec()),
            None => (None, Vec::new()),
        };
        let merge = item::list(mv)?.iter().map(|s| Ok(Signature::from_value(&s.to_value()?)?)).collect::<Result<Vec<_>, Error>>()?;
        Ok(Sigs { signature, inner, more, merge })
    }

    /// The signatures of a stored blob (`CommitBlob::decode_stored`'s input), from its bytes past
    /// the array head and the header item: an open reads them with the header bytes, decoding
    /// neither the header nor the parts.
    pub fn read_stored(b: &[u8]) -> Result<Sigs, Error> {
        let mut r = osis_base::cbor::Reader::new(b);
        let mut next = || -> Result<Item, Error> { Ok(Item::parse(r.item()?, &LIMITS)?) };
        Sigs::read(next()?, next()?, next()?)
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

    /// The path it states for thing `t`, where known here: the header's in the clear, else the
    /// opened section's.
    pub fn path(&self, t: &Tid) -> Option<&Path> {
        match &self.header.path {
            Paths::One(p) => self.header.aspects.iter().any(|a| a.tid == *t).then_some(p),
            Paths::Hashed(_) => self.salted_of(t).map(|s| &s.path),
        }
    }

    /// Thing `t`'s `Salted`, where its paths are hashed and a section of `t` opened here.
    pub fn salted_of(&self, t: &Tid) -> Option<&Salted> {
        self.salted.get(&self.header.things().iter().position(|x| x == t)?)
    }

    // Interim (notes/a1-spec/README.md step 3): the walk judges each thing along its own path.
    /// What the walk reads it as acting on, per thing it writes (`Acting`): one thing for all
    /// where its path is in the clear, else each thing's own path's, for the things whose
    /// `Salted` is known here.
    pub fn acting(&self) -> Acting {
        let s = self.header.signer;
        match &self.header.path {
            Paths::One(p) => Acting::All(p.acting(s)),
            Paths::Hashed(_) => {
                let things = self.header.things();
                Acting::Each(self.salted.iter().filter_map(|(i, x)| Some((*things.get(*i)?, x.path.acting(s)))).collect())
            }
        }
    }

    /// Checks `salted` against the header: each entry hashing to the hash at its index and a
    /// path it may state (spec/wire.md §4); once the aspect list is resolved, every held part's
    /// thing among them. Each thing is judged along its own path, so the paths of different
    /// things are not compared.
    pub fn check_paths(&self) -> Result<(), Error> {
        let h = &self.header;
        let hashes = match &h.path {
            Paths::One(_) => return if self.salted.is_empty() { Ok(()) } else { Err(Error::Malformed("salted path beside a path in the clear")) },
            Paths::Hashed(hs) => hs,
        };
        for (i, s) in &self.salted {
            if hashes.get(*i) != Some(&s.hash()) || !h.path_allowed(&s.path) {
                return Err(Error::Malformed("salted path not matching its thing's hash"));
            }
        }
        if h.is_resolved() {
            let things = h.things();
            if self.parts.iter().any(|p| h.aspects.get(p.ai).and_then(|a| things.iter().position(|t| *t == a.tid)).is_none_or(|i| !self.salted.contains_key(&i))) {
                return Err(Error::Malformed("a part without its thing's path"));
            }
        }
        Ok(())
    }

    /// Canonical bytes of the opened form (unpadded).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        head(&mut out, MAJOR_ARRAY, if self.salted.is_empty() { 5 } else { 6 });
        self.header.encode_into(&mut out);
        self.sigs.encode_into(&mut out);
        encode_parts(&self.parts, &mut out);
        if !self.salted.is_empty() {
            encode_salted(&self.salted, &mut out);
        }
        out
    }

    /// Decodes the opened form. Linked header lists stay unresolved; part indices are checked
    /// against the header by [`crate::verify_part`], paths by `check_paths` once resolved.
    pub fn decode(b: &[u8]) -> Result<CommitBlob, Error> {
        let items: Vec<Item> = item::list(Item::parse(b, &LIMITS)?)?.iter().collect();
        let (Some([hv, sv, iv, mv, pv]), tv) = (items.get(..5).and_then(|x| <[Item; 5]>::try_from(x).ok()), items.get(5)) else { return Err(Error::Malformed("commit blob arity")) };
        if items.len() > 6 {
            return Err(Error::Malformed("commit blob arity"));
        }
        let header = Header::read(hv, false)?;
        let sigs = Sigs::read(sv, iv, mv)?;
        let parts = decode_parts(pv)?;
        let salted = tv.map(|t| decode_salted(*t, &header.signer)).transpose()?.unwrap_or_default();
        let blob = CommitBlob { header, sigs, parts, salted };
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
        if !(5..=6).contains(&n) {
            return Err(Error::Malformed("commit blob arity"));
        }
        let mut next = || -> Result<Item, Error> { Ok(Item::parse(r.item()?, &LIMITS)?) };
        let header = Header::read(next()?, true)?;
        let sigs = Sigs::read(next()?, next()?, next()?)?;
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
        let salted = if n == 6 { decode_salted(Item::parse(r.item()?, &LIMITS)?, &header.signer)? } else { BTreeMap::new() };
        r.end()?;
        if !strictly_ascending(&parts, |p| p.ai) {
            return Err(Error::Malformed("parts not sorted and distinct"));
        }
        Ok(CommitBlob { header, sigs, parts, salted })
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

/// A section's plaintext, opened (spec/wire.md §4 `Contents`): its thing's `Salted` where the
/// commit's paths are hashed, and its parts.
pub type Contents = (Option<Salted>, Vec<Part>);

/// A section's plaintext `Contents := [Opt(Salted), [Part*]]` (spec/wire.md §4).
fn encode_contents(salted: Option<&Salted>, parts: &[impl Borrow<Part>], out: &mut Vec<u8>) {
    put_array(out, 2);
    put_array(out, usize::from(salted.is_some()));
    if let Some(s) = salted {
        s.put(out);
    }
    encode_parts(parts, out);
}

/// `[[index, Salted]*]`, ascending by index.
fn encode_salted(salted: &BTreeMap<usize, Salted>, out: &mut Vec<u8>) {
    put_array(out, salted.len());
    for (i, s) in salted {
        put_array(out, 2);
        put_uint(out, *i as u64);
        s.put(out);
    }
}

fn decode_salted(v: Item, signer: &Tid) -> Result<BTreeMap<usize, Salted>, Error> {
    let mut out = BTreeMap::new();
    let mut last = None;
    for x in item::list(v)? {
        let Some([i, s]) = item::list(x)?.tuple() else { return Err(Error::Malformed("salted path entry arity")) };
        let i = item::idx(i)?;
        if last.is_some_and(|l| l >= i) {
            return Err(Error::Malformed("salted paths not ascending by index"));
        }
        last = Some(i);
        out.insert(i, Salted::read(s, signer)?);
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
        if ais.is_empty() || !strictly_ascending(&ais, |a| *a) {
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
    /// by its first plaintext bytes alone (`Contents`, a 2-array whose first item is an option;
    /// `encode_contents`), NOT authenticated: forensic tests only, to rule a candidate out before
    /// `open_section`'s pass over the whole ciphertext. Never false for the section's own key.
    #[doc(hidden)]
    pub fn may_open_with(&self, zero: &osis_crypto::aead::Keystream) -> bool {
        let at = |i| zero.plain_byte(&self.ciphertext, i);
        at(0) == Some(MAJOR_ARRAY << 5 | 2) && matches!(at(1), Some(b) if b == MAJOR_ARRAY << 5 || b == MAJOR_ARRAY << 5 | 1)
    }

    /// Opens this section with one of `secrets` (newest first): its `Contents`, the thing's
    /// `Salted` where present and the parts, which must be exactly on the aspects listed. `None`:
    /// no secret opens the wrap. A section that opens to parts disagreeing with its list is bad
    /// input.
    pub fn open(&self, commit: &CommitId, signer: &Tid, secrets: &[Secret32]) -> Result<Option<Contents>, Error> {
        let Some(key) = secrets.iter().find_map(|s| osis_crypto::unwrap_section(s, commit, &self.wrap).ok()) else { return Ok(None) };
        let pt = osis_crypto::open_section(commit, &key, &self.ciphertext)?;
        let Some([sv, pv]) = item::list(Item::parse(&pt, &LIMITS)?)?.tuple() else { return Err(Error::Malformed("section contents arity")) };
        let salted = item::opt(sv)?.map(|v| Salted::read(v, signer)).transpose()?;
        let parts = decode_parts(pv)?;
        if !parts.iter().map(|p| p.ai).eq(self.ais.iter().copied()) {
            return Err(Error::Malformed("section parts disagree with its aspect list"));
        }
        let mut canon = Vec::new();
        encode_contents(salted.as_ref(), &parts, &mut canon);
        if canon != pt {
            return Err(Error::Malformed("section not canonical"));
        }
        Ok(Some((salted, parts)))
    }

    /// Seals `parts` (sorted), with their thing's `salted` path where the commit's paths are
    /// hashed, under the thing's read secret `secret`, listing its derivation chain
    /// `chain`.
    pub fn seal(commit: &CommitId, salted: Option<&Salted>, parts: &[impl Borrow<Part>], chain: Vec<Tid>, secret: &Secret32, rng: &mut dyn CryptoRngCore) -> Result<Section, Error> {
        let mut pt = Vec::new();
        encode_contents(salted, parts, &mut pt);
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
        head(&mut out, MAJOR_ARRAY, 5);
        self.header.encode_into(&mut out);
        self.sigs.encode_into(&mut out);
        put_array(&mut out, self.sections.len());
        self.sections.iter().for_each(|s| s.put(&mut out));
        out
    }

    /// Decodes a commit blob plaintext. Linked header lists stay unresolved; aspect indices
    /// are checked against the header once resolved (`prefix_groups`).
    pub fn decode(b: &[u8]) -> Result<Envelope, Error> {
        let Some([hv, sv, iv, mv, ss]) = item::list(Item::parse(b, &LIMITS)?)?.tuple() else { return Err(Error::Malformed("commit blob arity")) };
        let header = Header::read(hv, false)?;
        let sigs = Sigs::read(sv, iv, mv)?;
        let sections = item::list(ss)?.iter().map(Section::read).collect::<Result<Vec<_>, _>>()?;
        if !strictly_ascending(&sections, |s| s.ais.first().copied()) {
            return Err(Error::Malformed("sections not sorted by first aspect"));
        }
        let mut seen = std::collections::BTreeSet::new();
        if sections.iter().flat_map(|s| s.ais.iter()).any(|a| !seen.insert(*a)) {
            return Err(Error::Malformed("an aspect in two sections"));
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
    /// the parts opened, and the sections left sealed. A section whose `Salted` is absent where
    /// the commit's paths are hashed, present where its path is in the clear, not hashing to its
    /// thing's entry, or beside parts of several things there, holds no part of the commit
    /// (spec/wire.md §4): its parts are dropped, as
    /// bytes not matching their delta hash. Where the aspect list is not resolved, a `Salted`
    /// matching any entry stands, its thing checked once it resolves (`CommitBlob::check_paths`).
    pub fn open(&self, mut secrets: impl FnMut(&Section) -> Vec<Secret32>) -> Result<Opened, Error> {
        let id = self.id();
        let h = &self.header;
        let things = h.things();
        let mut parts = Vec::new();
        let mut salted = BTreeMap::new();
        let mut sealed = Vec::new();
        for s in &self.sections {
            let Some((path, ps)) = s.open(&id, &h.signer, &secrets(s))? else {
                sealed.push(s.clone());
                continue;
            };
            let fits = match (&h.path, path) {
                (Paths::One(_), None) => true,
                (Paths::Hashed(hs), Some(p)) => {
                    // where paths are hashed a section holds one thing's parts: its place among
                    // those written, where the aspects say it
                    let mut at = s.ais.iter().map(|ai| h.aspects.get(*ai).and_then(|a| things.iter().position(|t| *t == a.tid)));
                    let first = at.next().flatten();
                    if h.is_resolved() && (first.is_none() || at.any(|i| i != first)) {
                        continue;
                    }
                    let i = hs.iter().position(|x| *x == p.hash()).filter(|i| first.is_none_or(|f| f == *i));
                    let ok = i.is_some() && h.path_allowed(&p.path);
                    if ok && let Some(i) = i {
                        salted.insert(i, p);
                    }
                    ok
                }
                _ => false,
            };
            if fits {
                parts.extend(ps);
            }
        }
        parts.sort_by_key(|p| p.ai);
        let commit = CommitBlob { header: h.clone(), sigs: self.sigs.clone(), parts, salted };
        commit.check_paths()?;
        Ok(Opened { commit, sealed })
    }
}

/// What opening an envelope gives: the commit with its opened parts, and the sections no held
/// secret opened (copied verbatim into a fresh encryption).
#[derive(Clone, Debug)]
pub struct Opened {
    pub commit: CommitBlob,
    pub sealed: Vec<Section>,
}

/// Seals a commit's parts into sections, one per value of `section_of(ai)` and, where its paths
/// are hashed, per thing (each section then carries its thing's `Salted`; `resolved`, `c`'s
/// header with its lists resolved, says the thing of each part), each wrapped under the read
/// secret `secret_of(key, parts)` gives with the thing's derivation chain (that secret at the
/// epoch the writer uses, spec/crypto.md §5); a section whose secret is not held (`None`) is left
/// out, its parts travelling in other copies; `extra` sections are copied verbatim, except one
/// listing an aspect a sealed part is on.
pub fn seal_commit<K: Ord + Clone>(c: &CommitBlob, resolved: &Header, section_of: impl Fn(usize) -> K, mut secret_of: impl FnMut(&K, &[usize]) -> Option<(Secret32, Vec<Tid>)>, extra: &[Section], rng: &mut dyn CryptoRngCore) -> Result<Envelope, Error> {
    let id = c.id();
    let hashed = matches!(c.header.path, Paths::Hashed(_));
    let things = if hashed { resolved.things() } else { Vec::new() };
    let mut by: BTreeMap<(K, Option<usize>), Vec<&Part>> = BTreeMap::new();
    for p in &c.parts {
        let thing = if hashed {
            Some(resolved.aspects.get(p.ai).and_then(|a| things.iter().position(|t| *t == a.tid)).ok_or(Error::Malformed("part aspect index out of range"))?)
        } else {
            None
        };
        by.entry((section_of(p.ai), thing)).or_default().push(p);
    }
    let mut sections = Vec::with_capacity(by.len() + extra.len());
    let mut own: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for ((k, thing), ps) in by {
        let ais: Vec<usize> = ps.iter().map(|p| p.ai).collect();
        let salted = thing.map(|i| c.salted.get(&i).ok_or(Error::Malformed("a part without its thing's path"))).transpose()?;
        let Some((secret, chain)) = secret_of(&k, &ais) else { continue };
        own.extend(ais.iter().copied());
        sections.push(Section::seal(&id, salted, &ps, chain, &secret, rng)?);
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
