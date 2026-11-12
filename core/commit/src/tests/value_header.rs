//! The `Value`-tree header and blob codec the direct one replaced (test oracle): the header built
//! as a value tree and serialized; blobs decoded to a tree, read from it, then re-encoded to
//! check their canonical form. `direct_*` tests hold the direct codec to it.

use crate::cbor::{ak, as_bytes, as_list, as_tid, as_uint, strictly_ascending, tid, uint};
use crate::header::{LIMITS, purge_value};
use crate::*;
use osis_base::cbor::{encode_into, put_array, put_uint};
use osis_base::{CommitId, SIGNING_KEY_ED25519, Ts, Value};
use osis_crypto::{KemPublicKey, Signature, VerifyingKey};

fn uidx(n: usize) -> Value {
    uint(n as u64)
}

fn as_idx(v: &Value) -> Result<usize, Error> {
    usize::try_from(as_uint(v)?).map_err(|_| Error::Malformed("index too large"))
}

fn as_opt(v: &Value) -> Result<Option<&Value>, Error> {
    v.as_opt().ok_or(Error::Malformed("expected an option"))
}

fn form_value(f: &Form) -> Value {
    match f {
        Form::Commit => uint(0),
        Form::Session(n) => Value::List(vec![uint(1), Value::bytes(n)]),
    }
}

fn form_from_value(v: &Value) -> Result<Form, Error> {
    if let Value::List(l) = v {
        return match l.as_slice() {
            [k, n] if as_uint(k)? == 1 => Ok(Form::Session(as_bytes(n)?)),
            _ => Err(Error::Malformed("dot form")),
        };
    }
    match as_uint(v)? {
        0 => Ok(Form::Commit),
        _ => Err(Error::Malformed("dot form")),
    }
}

fn rotation_value(r: &RotationHeader) -> Value {
    let ids = |v: &[CommitId]| Value::List(v.iter().map(|c| Value::bytes(&c.0)).collect());
    Value::List(vec![Value::Enum(SIGNING_KEY_ED25519, Some(Box::new(Value::bytes(&r.signing_key.to_bytes())))), r.kem_key.to_value(), ids(&r.supersedes), ids(&r.names), Value::bytes(&r.list_root)])
}

fn rotation_from_value(v: &Value) -> Result<RotationHeader, Error> {
    let [sk, kem, sup, names, root] = as_list(v)? else { return Err(Error::Malformed("rotation arity")) };
    let signing_key = match sk {
        Value::Enum(SIGNING_KEY_ED25519, Some(b)) => match b.as_ref() {
            Value::Bytes(k) => VerifyingKey::from_slice(k).map_err(|_| Error::Malformed("rotation signing key"))?,
            _ => return Err(Error::Malformed("rotation signing key")),
        },
        _ => return Err(Error::Malformed("rotation signing key")),
    };
    let kem_key = KemPublicKey::from_value(kem).map_err(|_| Error::Malformed("rotation kem key"))?;
    let ids = |v: &Value| -> Result<Vec<CommitId>, Error> { as_list(v)?.iter().map(|c| as_bytes(c).map(CommitId)).collect() };
    Ok(RotationHeader { signing_key, kem_key, supersedes: ids(sup)?, names: ids(names)?, list_root: as_bytes(root)? })
}

fn aspect_value(a: &AspectEntry) -> Value {
    Value::List(vec![
        tid(&a.tid),
        ak(&a.ak),
        uint(a.lo),
        uint(a.hi),
        uint(a.retention.by as u64),
        Value::List(a.keys.iter().map(|i| uidx(*i)).collect()),
        Value::bytes(&a.hash),
        Value::List(a.replaces.iter().map(|c| Value::bytes(&c.0)).collect()),
    ])
}

fn key_value(t: &DeleteKey) -> Value {
    Value::List(vec![uint(u64::from(t.level)), Value::bytes(&t.key)])
}

fn chunk_value(c: &ChunkEntry) -> Value {
    Value::List(vec![Value::bytes(&c.blob.0), uidx(c.ai), Value::List(c.keys.iter().map(|i| uidx(*i)).collect()), Value::bytes(&c.blind)])
}

/// The list's (or frontier's) value as it would sit inline; `None` for an absent frontier.
pub(crate) fn list_value(h: &Header, f: ListField) -> Option<Value> {
    Some(match f {
        ListField::Aspects => Value::List(h.aspects.iter().map(aspect_value).collect()),
        ListField::Chunks => Value::List(h.chunks.iter().map(chunk_value).collect()),
        ListField::Purge => Value::List(h.purge.iter().map(purge_value).collect()),
        ListField::Keys => Value::List(h.keys.iter().map(key_value).collect()),
        ListField::Frontier => return h.frontier.clone(),
    })
}

fn position(h: &Header, f: ListField) -> Value {
    match (f, h.links.get(f)) {
        (ListField::Frontier, Some(l)) => Value::opt(Some(Value::link(*l))),
        (ListField::Frontier, None) => Value::opt(h.frontier.clone()),
        (_, Some(l)) => Value::link(*l),
        (_, None) => list_value(h, f).unwrap_or(Value::List(Vec::new())),
    }
}

pub(crate) fn to_value(h: &Header) -> Value {
    Value::List(vec![
        uint(h.version),
        tid(&h.author),
        tid(&h.actor),
        uint(h.kind.id()),
        uint(h.ts.to_u64()),
        form_value(&h.form),
        Value::opt(h.expires.map(uint)),
        position(h, ListField::Aspects),
        position(h, ListField::Chunks),
        position(h, ListField::Purge),
        Value::opt(h.undoes.map(|c| Value::bytes(&c.0))),
        Value::bytes(&h.blind),
        position(h, ListField::Keys),
        position(h, ListField::Frontier),
        Value::opt(h.ephemeral.map(|c| uint(c as u64))),
        Value::opt(h.epoch.map(|c| Value::bytes(&c.0))),
        Value::opt(h.rotation.as_ref().map(rotation_value)),
    ])
}

pub(crate) fn encode(h: &Header) -> Vec<u8> {
    osis_base::encode(&to_value(h))
}

fn take_position(h: &mut Header, f: ListField, v: &Value, stored: bool) -> Result<(), Error> {
    let inner = if f == ListField::Frontier {
        match as_opt(v)? {
            None => return Ok(()),
            Some(x) => x,
        }
    } else {
        v
    };
    if let Value::Link(l) = inner {
        h.links.set(f, Some(**l));
        return Ok(());
    }
    let bytes = osis_base::encode(inner);
    if !stored && bytes.len() > osis_base::format::CHUNK_THRESHOLD {
        return Err(Error::Malformed("inline list above CHUNK_THRESHOLD"));
    }
    if f == ListField::Frontier {
        h.frontier = Some(inner.clone());
        return Ok(());
    }
    h.read_list(f, &bytes, !stored)
}

pub(crate) fn from_value(v: &Value, stored: bool) -> Result<Header, Error> {
    let items = as_list(v)?;
    let version = as_uint(items.first().ok_or(Error::Malformed("empty header"))?)?;
    if version > osis_base::format::FORMAT_VERSION {
        return Err(Error::UnknownVersion(version));
    }
    if version != osis_base::format::FORMAT_VERSION {
        return Err(Error::Malformed("format version"));
    }
    let [_, author, actor, kind, ts, form, expires, aspects, chunks, purge, undoes, blind, keys, frontier, ephemeral, epoch, rotation] = items else {
        return Err(Error::Malformed("header arity"));
    };
    let as_ts = |v: &Value| -> Result<Ts, Error> { Ts::from_u64(as_uint(v)?).ok_or(Error::Malformed("ts out of range")) };
    let mut h = Header {
        version,
        author: as_tid(author)?,
        actor: as_tid(actor)?,
        kind: Kind::from_id(as_uint(kind)?).ok_or(Error::Malformed("kind"))?,
        ts: as_ts(ts)?,
        form: form_from_value(form)?,
        expires: as_opt(expires)?.map(as_uint).transpose()?,
        aspects: Vec::new(),
        chunks: Vec::new(),
        purge: Vec::new(),
        undoes: as_opt(undoes)?.map(|c| as_bytes(c).map(CommitId)).transpose()?,
        blind: as_bytes(blind)?,
        keys: Vec::new(),
        frontier: None,
        links: Links::default(),
        ephemeral: as_opt(ephemeral)?.map(|c| EphClass::from_id(as_uint(c)?).ok_or(Error::Malformed("ephemeral marker"))).transpose()?,
        epoch: as_opt(epoch)?.map(|c| as_bytes(c).map(CommitId)).transpose()?,
        rotation: as_opt(rotation)?.map(rotation_from_value).transpose()?,
    };
    take_position(&mut h, ListField::Aspects, aspects, stored)?;
    take_position(&mut h, ListField::Chunks, chunks, stored)?;
    take_position(&mut h, ListField::Purge, purge, stored)?;
    take_position(&mut h, ListField::Keys, keys, stored)?;
    take_position(&mut h, ListField::Frontier, frontier, stored)?;
    Ok(h)
}

pub(crate) fn decode(b: &[u8]) -> Result<Header, Error> {
    let v = osis_base::decode(b, &LIMITS)?;
    let h = from_value(&v, false)?;
    if encode(&h) != b {
        return Err(Error::Malformed("not canonical"));
    }
    Ok(h)
}

fn sigs_from_values(sv: &Value, iv: &Value, mv: &Value) -> Result<Sigs, Error> {
    let signature = Signature::from_value(sv)?;
    let inner = as_opt(iv)?.map(as_bytes::<{ osis_crypto::INNER_LEN }>).transpose()?;
    let merge = as_list(mv)?.iter().map(Signature::from_value).collect::<Result<Vec<_>, _>>()?;
    Ok(Sigs { signature, inner, merge })
}

fn sigs_values(s: &Sigs) -> [Value; 3] {
    [s.signature.to_value(), Value::opt(s.inner.map(|i| Value::bytes(&i))), Value::List(s.merge.iter().map(Signature::to_value).collect())]
}

/// `CommitBlob::decode` as it was.
pub(crate) fn decode_blob(b: &[u8]) -> Result<CommitBlob, Error> {
    let v = osis_base::decode(b, &LIMITS)?;
    let [hv, sv, iv, mv, pv] = as_list(&v)? else { return Err(Error::Malformed("commit blob arity")) };
    let header = from_value(hv, false)?;
    let sigs = sigs_from_values(sv, iv, mv)?;
    let mut parts = Vec::new();
    for p in as_list(pv)? {
        let [ai, d] = as_list(p)? else { return Err(Error::Malformed("part arity")) };
        if !matches!(d, Value::List(_)) {
            return Err(Error::Malformed("part delta"));
        }
        parts.push(Part { ai: as_idx(ai)?, delta: osis_base::encode(d) });
    }
    if !strictly_ascending(&parts, |p| p.ai) {
        return Err(Error::Malformed("parts not sorted and distinct"));
    }
    let blob = CommitBlob { header, sigs, parts };
    if blob_bytes(&blob.header, &blob.sigs, |out| {
        put_array(out, blob.parts.len());
        for p in &blob.parts {
            put_array(out, 2);
            put_uint(out, p.ai as u64);
            out.extend_from_slice(&p.delta);
        }
    }) != b
    {
        return Err(Error::Malformed("commit blob not canonical"));
    }
    Ok(blob)
}

/// `[Header, signature, Opt(inner), [signature*], rest]` with the old header encoding.
fn blob_bytes(h: &Header, s: &Sigs, rest: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut out = Vec::new();
    put_array(&mut out, 5);
    out.extend_from_slice(&encode(h));
    for v in sigs_values(s) {
        encode_into(&v, &mut out);
    }
    rest(&mut out);
    out
}

fn section_from_value(v: &Value) -> Result<Section, Error> {
    let [ais, chain, wrap, ct] = as_list(v)? else { return Err(Error::Malformed("section arity")) };
    let ais = as_list(ais)?.iter().map(as_idx).collect::<Result<Vec<_>, _>>()?;
    if ais.is_empty() || !strictly_ascending(&ais, |a| *a) {
        return Err(Error::Malformed("section aspects not ascending and distinct"));
    }
    let chain = as_list(chain)?.iter().map(as_tid).collect::<Result<Vec<_>, _>>()?;
    if chain.len() > osis_base::format::MAX_CHAIN_DEPTH {
        return Err(Error::Malformed("section chain too deep"));
    }
    let mut seen = std::collections::BTreeSet::new();
    if !chain.iter().all(|o| seen.insert(*o)) {
        return Err(Error::Malformed("section chain repeats a thing"));
    }
    let wrap = wrap.as_bytes().ok_or(Error::Malformed("section wrap"))?.to_vec();
    if wrap.len() != osis_crypto::SECTION_WRAP_LEN {
        return Err(Error::Malformed("section wrap length"));
    }
    let ciphertext = ct.as_bytes().ok_or(Error::Malformed("section ciphertext"))?.to_vec();
    Ok(Section { ais, chain, wrap, ciphertext })
}

fn section_value(s: &Section) -> Value {
    Value::List(vec![Value::List(s.ais.iter().map(|a| uidx(*a)).collect()), Value::List(s.chain.iter().map(tid).collect()), Value::bytes(&s.wrap), Value::bytes(&s.ciphertext)])
}

/// `Envelope::decode` as it was.
pub(crate) fn decode_envelope(b: &[u8]) -> Result<Envelope, Error> {
    let v = osis_base::decode(b, &LIMITS)?;
    let [hv, sv, iv, mv, ss] = as_list(&v)? else { return Err(Error::Malformed("commit blob arity")) };
    let header = from_value(hv, false)?;
    let sigs = sigs_from_values(sv, iv, mv)?;
    let sections = as_list(ss)?.iter().map(section_from_value).collect::<Result<Vec<_>, _>>()?;
    if !strictly_ascending(&sections, |s| s.ais.first().copied()) {
        return Err(Error::Malformed("sections not sorted by first aspect"));
    }
    let mut seen = std::collections::BTreeSet::new();
    if sections.iter().flat_map(|s| s.ais.iter()).any(|a| !seen.insert(*a)) {
        return Err(Error::Malformed("an aspect in two sections"));
    }
    if blob_bytes(&header, &sigs, |out| encode_into(&Value::List(sections.iter().map(section_value).collect()), out)) != b {
        return Err(Error::Malformed("commit blob not canonical"));
    }
    Ok(Envelope { header, sigs, sections })
}
