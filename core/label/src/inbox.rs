//! Inbox blobs (spec/wire.md §9, spec/crypto.md §5, spec/sync-inbox.md §2). The role commit
//! travels as its `CommitBlobPlaintext` value; osis-commit parses it (the only coupling to the
//! commit layout, kept here).

use crate::cbor::{get_bytes, get_key, get_opt, get_tid, tid};
use crate::blob::Prefix;
use crate::step::OBJECT_LIMITS;
use crate::Error;
use osis_base::cbor::{decode, encode};
use osis_base::format::INBOX_LIFETIME_MS;
use osis_base::format::MAX_URL_BYTES;
use osis_base::{CreationRecord, SyncId, Tid, Value, WallMs};
use osis_crypto::{CryptoRngCore, KemPublicKey, KemSecret, Signature, VerifyingKey, open_inbox, seal_inbox};

/// At most this many URLs in an inbox blob's dial hint (spec/wire.md §9 position 4).
pub const MAX_DIAL_URLS: usize = 16;

/// A thing the commit names: its own sync ID, if it has one (never a group's holding it), and
/// for a thing with secrets of its own its current admin and write delete keys
/// (spec/crypto.md §7), which the grantee lists until it holds the thing's `keys.0`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxThing {
    pub tid: Tid,
    pub sync_id: Option<SyncId>,
    pub delete_keys: Option<(VerifyingKey, VerifyingKey)>,
}

/// The sending node's dialable key and URLs: a dial hint (spec/wire.md §9 position 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialHint {
    pub dialable: [u8; 32],
    pub urls: Vec<String>,
}

/// `InboxPayload := [CommitBlobPlaintext, [[tid, Opt(sync_id), Opt([admin_pk, write_pk])]*],
/// [CommitBlobPlaintext*], [creation*], Opt([dialable, [url*]]), [[sync_id, sig]*]]`
/// (spec/wire.md §9), things sorted by tid, distinct, records ascending by tid, distinct,
/// removal signatures ascending by sync ID, distinct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxPayload {
    /// The role commit's `CommitBlobPlaintext` value (header, signature, parts about the
    /// recipient).
    pub commit: Value,
    pub things: Vec<InboxThing>,
    /// The author's chain certificates for the commit's carried parts (spec/permissions.md §4), as
    /// `CommitBlobPlaintext` values each projected to its chain deltas, so the recipient verifies
    /// the commit without reading any label of the things it names (spec/wire.md §9).
    pub chain: Vec<Value>,
    /// The raw creation records of that chain (spec/permissions.md §4): a record proves itself by
    /// its hash.
    pub records: Vec<CreationRecord>,
    pub dial: Option<DialHint>,
    /// Removal signatures per sync ID of `things` the commit ends the recipient's grant on, each
    /// with the sync epoch number it is signed at (`sign_removal`).
    pub removals: Vec<(SyncId, u64, Signature)>,
}

impl InboxPayload {
    pub fn to_value(&self) -> Value {
        let mut things = Vec::with_capacity(self.things.len());
        for t in &self.things {
            things.push(Value::List(vec![
                tid(&t.tid),
                Value::List(t.sync_id.iter().map(|s| Value::bytes(&s.0)).collect()),
                Value::List(t.delete_keys.iter().map(|(a, w)| Value::List(vec![Value::bytes(&a.to_bytes()), Value::bytes(&w.to_bytes())])).collect()),
            ]));
        }
        let dial = self.dial.iter().map(|d| Value::List(vec![Value::bytes(&d.dialable), Value::List(d.urls.iter().map(|u| Value::Str(u.clone())).collect())])).collect();
        let mut removals: Vec<&(SyncId, u64, Signature)> = self.removals.iter().collect();
        removals.sort_by_key(|(s, _, _)| *s);
        removals.dedup_by_key(|(s, _, _)| *s);
        let removals = removals.into_iter().map(|(s, e, sig)| Value::List(vec![Value::bytes(&s.0), Value::Int(*e as i64), sig.to_value()])).collect();
        Value::List(vec![self.commit.clone(), Value::List(things), Value::List(self.chain.clone()), records_value(&self.records), Value::List(dial), Value::List(removals)])
    }

    /// The commit's plaintext, its decoded form freed first so that decoding the plaintext again
    /// does not hold two decoded copies of a stranger's blob; and the rest.
    pub fn split(self) -> (Vec<u8>, InboxRest) {
        (encode(&self.commit), InboxRest { things: self.things, chain: self.chain, records: self.records, dial: self.dial, removals: self.removals })
    }

    /// Takes `v` apart without copying: it is a blob from anyone (`open_inbox_blob`).
    pub fn from_value(v: Value) -> Result<InboxPayload, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("inbox payload")) };
        let Ok::<[Value; 6], _>([commit @ Value::List(_), Value::List(things), Value::List(chain), Value::List(records), dial, Value::List(removals)]) = items.try_into() else { return Err(Error::Malformed("inbox payload")) };
        if !chain.iter().all(|c| matches!(c, Value::List(_))) {
            return Err(Error::Malformed("inbox chain"));
        }
        let records = records_from(&records)?;
        let mut out: Vec<InboxThing> = Vec::with_capacity(things.len());
        for t in &things {
            let Value::List(f) = t else { return Err(Error::Malformed("inbox thing")) };
            let [tid, label, keys] = f.as_slice() else { return Err(Error::Malformed("inbox thing")) };
            let sync_id = get_opt(label, "inbox sync ID")?.map(|v| get_bytes(v, "inbox sync ID").map(SyncId)).transpose()?;
            let key = |v: &Value| get_key(v, "inbox delete key");
            let delete_keys = match get_opt(keys, "inbox delete keys")? {
                None => None,
                Some(Value::List(ks)) => match ks.as_slice() {
                    [a, w] => Some((key(a)?, key(w)?)),
                    _ => return Err(Error::Malformed("inbox delete keys")),
                },
                Some(_) => return Err(Error::Malformed("inbox delete keys")),
            };
            let tid = get_tid(tid, "inbox tid")?;
            if out.last().is_some_and(|p| p.tid >= tid) {
                return Err(Error::Malformed("inbox things not sorted by tid"));
            }
            out.push(InboxThing { tid, sync_id, delete_keys });
        }
        let dial = match get_opt(&dial, "inbox dial hint")? {
            None => None,
            Some(Value::List(d)) => {
                let [k, Value::List(urls)] = d.as_slice() else { return Err(Error::Malformed("inbox dial hint")) };
                if urls.len() > MAX_DIAL_URLS {
                    return Err(Error::Malformed("inbox dial hint"));
                }
                let urls = urls
                    .iter()
                    .map(|u| match u {
                        Value::Str(u) if u.len() <= MAX_URL_BYTES => Ok(u.clone()),
                        _ => Err(Error::Malformed("inbox dial url")),
                    })
                    .collect::<Result<_, _>>()?;
                Some(DialHint { dialable: get_bytes(k, "inbox dialable")?, urls })
            }
            Some(_) => return Err(Error::Malformed("inbox dial hint")),
        };
        let mut rs: Vec<(SyncId, u64, Signature)> = Vec::with_capacity(removals.len());
        for r in &removals {
            let Value::List(r) = r else { return Err(Error::Malformed("inbox removal")) };
            let [s, e, sig] = r.as_slice() else { return Err(Error::Malformed("inbox removal")) };
            let s = SyncId(get_bytes(s, "inbox removal sync ID")?);
            if rs.last().is_some_and(|(p, _, _)| *p >= s) {
                return Err(Error::Malformed("inbox removals not sorted by sync ID"));
            }
            rs.push((s, crate::cbor::get_uint(e, "inbox removal epoch")?, Signature::from_value(sig).map_err(|_| Error::Malformed("inbox removal signature"))?));
        }
        Ok(InboxPayload { commit, things: out, chain, records, dial, removals: rs })
    }
}

/// An inbox payload but its commit (`InboxPayload::split`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InboxRest {
    pub things: Vec<InboxThing>,
    pub chain: Vec<Value>,
    pub records: Vec<CreationRecord>,
    pub dial: Option<DialHint>,
    pub removals: Vec<(SyncId, u64, Signature)>,
}

/// `StrandedNotice := ["stranded", sync_id, holder, [CommitBlobPlaintext*], [creation*]]`
/// (spec/wire.md §9): holder `holder` is stranded on label `label` (spec/permissions.md §4), with
/// the holder's current `keys.0` commits and their authors' chains (`HolderKeys`). It carries no
/// role commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrandedNotice {
    pub label: SyncId,
    pub holder: Tid,
    pub keys: HolderKeys,
}

/// A stranded report's holder keys (spec/wire.md §9): the holder's current `keys.0` commits, each
/// projected to that delta, with their authors' chain certificates for them, as
/// `CommitBlobPlaintext` values projected to their chain deltas, and the raw creation records of
/// that chain, ascending by tid, distinct. A reader of the label's actor that is gone from the
/// holder seals it at its keyset and deposits under its inbox from these alone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HolderKeys {
    pub commits: Vec<Value>,
    pub records: Vec<CreationRecord>,
}

impl HolderKeys {
    pub fn to_values(&self) -> [Value; 2] {
        [Value::List(self.commits.clone()), records_value(&self.records)]
    }

    pub fn from_values(commits: &Value, records: &Value) -> Result<HolderKeys, Error> {
        let (Value::List(commits), Value::List(records)) = (commits, records) else { return Err(Error::Malformed("holder keys")) };
        if !commits.iter().all(|c| matches!(c, Value::List(_))) {
            return Err(Error::Malformed("holder keys commits"));
        }
        Ok(HolderKeys { commits: commits.clone(), records: records_from(records)? })
    }
}

/// Creation records ascending by tid, distinct.
fn records_value(records: &[CreationRecord]) -> Value {
    let mut records: Vec<&CreationRecord> = records.iter().collect();
    records.sort_by_key(|r| r.tid());
    records.dedup_by_key(|r| r.tid());
    Value::List(records.into_iter().map(CreationRecord::to_value).collect())
}

/// Creation records, which must be ascending by tid and distinct.
fn records_from(records: &[Value]) -> Result<Vec<CreationRecord>, Error> {
    let records = records.iter().map(|r| CreationRecord::from_value(r).ok_or(Error::Malformed("creation record"))).collect::<Result<Vec<_>, _>>()?;
    if !records.windows(2).all(|w| matches!(w, [x, y] if x.tid() < y.tid())) {
        return Err(Error::Malformed("creation records not sorted by tid"));
    }
    Ok(records)
}

impl StrandedNotice {
    pub fn to_value(&self) -> Value {
        let [commits, records] = self.keys.to_values();
        Value::List(vec![Value::Str("stranded".into()), Value::bytes(&self.label.0), tid(&self.holder), commits, records])
    }

    pub fn from_value(v: &Value) -> Result<StrandedNotice, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("stranded notice")) };
        let [Value::Str(k), label, holder, commits, records] = items.as_slice() else { return Err(Error::Malformed("stranded notice")) };
        if k != "stranded" {
            return Err(Error::Malformed("stranded notice"));
        }
        Ok(StrandedNotice { label: SyncId(get_bytes(label, "stranded label")?), holder: get_tid(holder, "stranded holder")?, keys: HolderKeys::from_values(commits, records)? })
    }
}

/// What an inbox blob carries: a role commit with what it names, or a stranded notice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inbox {
    Payload(InboxPayload),
    Stranded(StrandedNotice),
}

impl Inbox {
    pub fn from_value(v: Value) -> Result<Inbox, Error> {
        match &v {
            Value::List(items) if matches!(items.first(), Some(Value::Str(_))) => StrandedNotice::from_value(&v).map(Inbox::Stranded),
            _ => InboxPayload::from_value(v).map(Inbox::Payload),
        }
    }
}

/// Seals a stranded notice to `recipient`'s newest read keyset KEM key, as `seal_inbox_blob`.
pub fn seal_stranded_notice(recipient: &Tid, kem: &KemPublicKey, notice: &StrandedNotice, now: WallMs, rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
    seal(recipient, kem, &notice.to_value(), now, rng)
}

/// Seals an inbox blob to `recipient`'s newest read keyset KEM key: prefix with expiry `now`
/// (the sender's wall ms) + `INBOX_LIFETIME`, no commitments. Its entry's wrap is a
/// filler (`osis_crypto::filler_wrap`).
pub fn seal_inbox_blob(recipient: &Tid, kem: &KemPublicKey, payload: &InboxPayload, now: WallMs, rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
    seal(recipient, kem, &payload.to_value(), now, rng)
}

fn seal(recipient: &Tid, kem: &KemPublicKey, v: &Value, now: WallMs, rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
    let prefix = Prefix::new(Prefix::random_salt(rng), Some(now.saturating_add(INBOX_LIFETIME_MS)), vec![])?;
    seal_inbox(&prefix.to_bytes(), recipient, kem, &encode(v), rng).map_err(|e| match e {
        osis_crypto::Error::TooLarge => Error::TooLarge("inbox blob above MAX_BLOB"),
        e => Error::Crypto(e),
    })
}

/// Opens an inbox blob addressed to `recipient` with its read KEM secret: a role commit's
/// payload (a stranded notice is an error here, `open_inbox_item`).
pub fn open_inbox_blob(blob: &[u8], recipient: &Tid, kem: &KemSecret) -> Result<(Prefix, InboxPayload), Error> {
    match open_inbox_item(blob, recipient, kem)? {
        (p, Inbox::Payload(x)) => Ok((p, x)),
        (_, Inbox::Stranded(_)) => Err(Error::Malformed("inbox payload")),
    }
}

/// Opens an inbox blob addressed to `recipient` with its read KEM secret, whatever it carries.
pub fn open_inbox_item(blob: &[u8], recipient: &Tid, kem: &KemSecret) -> Result<(Prefix, Inbox), Error> {
    crate::blob::check_size(blob)?;
    let prefix = Prefix::parse(blob)?;
    let pt = open_inbox(blob, prefix.len(), recipient, kem)?;
    Ok((prefix, Inbox::from_value(decode(&pt, &OBJECT_LIMITS)?)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_crypto::{SeededRng, Secret32};

    fn dk(b: u8) -> VerifyingKey {
        osis_crypto::DeleteSecret::derive(&Secret32::from_bytes([b; 32])).verifying_key()
    }

    fn payload() -> InboxPayload {
        InboxPayload {
            chain: vec![Value::List(vec![Value::List(vec![]), Value::Int(1), Value::List(vec![])])],
            records: vec![CreationRecord::Thing { admin: Tid::from_bytes([4; 15]), nonce: [4; 32], link: None }],
            commit: Value::List(vec![Value::List(vec![]), Value::Int(0), Value::List(vec![])]),
            things: vec![
                InboxThing { tid: Tid::from_bytes([1; 15]), sync_id: Some(SyncId([2; 16])), delete_keys: None },
                InboxThing { tid: Tid::from_bytes([3; 15]), sync_id: None, delete_keys: Some((dk(1), dk(2))) },
            ],
            dial: Some(DialHint { dialable: [6; 32], urls: vec!["quic://s".into()] }),
            removals: vec![(SyncId([2; 16]), 3, Signature::from_slice(&[7; 64]).unwrap())],
        }
    }

    // spec/wire.md §9, spec/crypto.md §5: inbox blob seals to the recipient's KEM key with AD
    // (recipient, "inbox", prefix); expiry INBOX_LIFETIME after now; no commitments.
    #[test]
    fn round_trip() {
        let mut rng = SeededRng::from_u64(0);
        let kem = KemSecret::derive(&Secret32::from_bytes([9; 32]));
        let r = Tid::from_bytes([5; 15]);
        let b = seal_inbox_blob(&r, kem.public(), &payload(), WallMs(1000), &mut rng).unwrap();
        let (p, got) = open_inbox_blob(&b, &r, &kem).unwrap();
        assert_eq!(got, payload());
        assert_eq!(p.expiry(), Some(WallMs(1000 + INBOX_LIFETIME_MS)));
        assert_eq!(p.commitments().count(), 0);
        assert!(open_inbox_blob(&b, &Tid::from_bytes([6; 15]), &kem).is_err());
        let other = KemSecret::derive(&Secret32::from_bytes([8; 32]));
        assert!(open_inbox_blob(&b, &r, &other).is_err());
    }

    // spec/wire.md §9 (stranded notice): a stranded notice seals and opens as an inbox blob,
    // never as a role commit's payload.
    #[test]
    fn stranded_notice_round_trip() {
        let mut rng = SeededRng::from_u64(0);
        let kem = KemSecret::derive(&Secret32::from_bytes([9; 32]));
        let r = Tid::from_bytes([5; 15]);
        let p = payload();
        let n = StrandedNotice { label: SyncId([3; 16]), holder: Tid::from_bytes([7; 15]), keys: HolderKeys { commits: p.chain, records: p.records } };
        let b = seal_stranded_notice(&r, kem.public(), &n, WallMs(1000), &mut rng).unwrap();
        let (p, got) = open_inbox_item(&b, &r, &kem).unwrap();
        assert_eq!(got, Inbox::Stranded(n));
        assert_eq!(p.expiry(), Some(WallMs(1000 + INBOX_LIFETIME_MS)));
        assert!(open_inbox_blob(&b, &r, &kem).is_err());
        let b = seal_inbox_blob(&r, kem.public(), &payload(), WallMs(1000), &mut rng).unwrap();
        assert_eq!(open_inbox_item(&b, &r, &kem).unwrap().1, Inbox::Payload(payload()));
    }

    // spec/wire.md §9: things sorted by tid and distinct; layout positions.
    #[test]
    fn rejections() {
        let mut p = payload();
        p.things.reverse();
        assert!(InboxPayload::from_value(p.to_value()).is_err());
        let mut p = payload();
        p.things[1].tid = p.things[0].tid;
        assert!(InboxPayload::from_value(p.to_value()).is_err());
        assert!(InboxPayload::from_value(Value::List(vec![Value::Int(0), Value::List(vec![])])).is_err());
        assert_eq!(InboxPayload::from_value(payload().to_value()).unwrap(), payload());
        let mut p = payload();
        p.dial = Some(DialHint { dialable: [6; 32], urls: vec!["quic://s".into(); MAX_DIAL_URLS + 1] });
        assert!(InboxPayload::from_value(p.to_value()).is_err());
    }
}
