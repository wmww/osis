//! Inbox blobs (spec/wire.md §9, spec/crypto.md §5, spec/sync.md §3). The role commit
//! travels as its `CommitBlobPlaintext` value; osis-commit parses it (the only coupling to the
//! commit layout, kept here).

use crate::addr::{Address, address_from_value};
use crate::cbor::{get_bytes, get_key, get_opt, get_tid, get_uint, tid, uint};
use crate::blob::Prefix;
use crate::step::OBJECT_LIMITS;
use crate::Error;
use osis_base::cbor::{decode, encode};
use osis_base::format::INBOX_LIFETIME_MS;
use osis_base::{LabelId, Tid, Value, WallMs};
use osis_crypto::{CryptoRngCore, KemPublicKey, KemSecret, VerifyingKey, open_inbox, seal_inbox};
use osis_schema::Codec;

/// A label of the thing's own: its ID, index (its role keys derive from it, spec/sync.md §2) and
/// host addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxLabel {
    pub id: LabelId,
    pub index: u64,
    pub hosts: Vec<Address>,
}

/// A thing the commit names: its own label, if it has one (a label of a group holding it opens
/// under that group's secrets, not this thing's), and for a thing with secrets of its own its
/// current admin and write delete keys (spec/crypto.md §7), which the grantee lists until it
/// holds the thing's `keys.0`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxThing {
    pub tid: Tid,
    pub label: Option<InboxLabel>,
    pub delete_keys: Option<(VerifyingKey, VerifyingKey)>,
}

/// `InboxPayload := [CommitBlobPlaintext, [[tid, Opt([label_id, index, [address*]]),
/// Opt([admin_pk, write_pk])]*]]`, things sorted by tid, distinct.
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
}

impl InboxPayload {
    pub fn to_value(&self) -> Result<Value, Error> {
        let mut things = Vec::with_capacity(self.things.len());
        for t in &self.things {
            let label = match &t.label {
                Some(l) => vec![Value::List(vec![Value::bytes(&l.id.0), uint(l.index)?, Value::List(l.hosts.iter().map(Codec::to_value).collect())])],
                None => Vec::new(),
            };
            things.push(Value::List(vec![
                tid(&t.tid),
                Value::List(label),
                Value::List(t.delete_keys.iter().map(|(a, w)| Value::List(vec![Value::bytes(&a.to_bytes()), Value::bytes(&w.to_bytes())])).collect()),
            ]));
        }
        Ok(Value::List(vec![self.commit.clone(), Value::List(things), Value::List(self.chain.clone())]))
    }

    /// The commit's plaintext, its decoded form freed first so that decoding the plaintext again
    /// does not hold two decoded copies of a stranger's blob; and the rest.
    pub fn split(self) -> (Vec<u8>, Vec<InboxThing>, Vec<Value>) {
        (encode(&self.commit), self.things, self.chain)
    }

    /// Takes `v` apart without copying: it is a blob from anyone (`open_inbox_blob`).
    pub fn from_value(v: Value) -> Result<InboxPayload, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("inbox payload")) };
        let Ok::<[Value; 3], _>([commit @ Value::List(_), Value::List(things), Value::List(chain)]) = items.try_into() else { return Err(Error::Malformed("inbox payload")) };
        if !chain.iter().all(|c| matches!(c, Value::List(_))) {
            return Err(Error::Malformed("inbox chain"));
        }
        let mut out: Vec<InboxThing> = Vec::with_capacity(things.len());
        for t in &things {
            let Value::List(f) = t else { return Err(Error::Malformed("inbox thing")) };
            let [tid, label, keys] = f.as_slice() else { return Err(Error::Malformed("inbox thing")) };
            let label = match get_opt(label, "inbox label")? {
                None => None,
                Some(Value::List(l)) => {
                    let [id, index, Value::List(hosts)] = l.as_slice() else { return Err(Error::Malformed("inbox label")) };
                    let hosts = hosts.iter().map(address_from_value).collect::<Result<_, _>>()?;
                    Some(InboxLabel { id: LabelId(get_bytes(id, "inbox label")?), index: get_uint(index, "inbox label index")?, hosts })
                }
                Some(_) => return Err(Error::Malformed("inbox label")),
            };
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
            out.push(InboxThing { tid, label, delete_keys });
        }
        Ok(InboxPayload { commit, things: out, chain })
    }
}

/// Seals an inbox blob to `recipient`'s newest read keyset KEM key: prefix with expiry `now`
/// (the sender's corrected wall ms) + `INBOX_LIFETIME`, no commitments. Its entry's wrap is a
/// filler (`osis_crypto::filler_wrap`).
pub fn seal_inbox_blob(recipient: &Tid, kem: &KemPublicKey, payload: &InboxPayload, now: WallMs, rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
    let prefix = Prefix::new(Prefix::random_salt(rng), Some(now.saturating_add(INBOX_LIFETIME_MS)), vec![])?;
    seal_inbox(&prefix.to_bytes(), recipient, kem, &encode(&payload.to_value()?), rng).map_err(|e| match e {
        osis_crypto::Error::TooLarge => Error::TooLarge("inbox blob above MAX_BLOB"),
        e => Error::Crypto(e),
    })
}

/// Opens an inbox blob addressed to `recipient` with its read KEM secret.
pub fn open_inbox_blob(blob: &[u8], recipient: &Tid, kem: &KemSecret) -> Result<(Prefix, InboxPayload), Error> {
    crate::blob::check_size(blob)?;
    let prefix = Prefix::parse(blob)?;
    let pt = open_inbox(blob, prefix.len(), recipient, kem)?;
    Ok((prefix, InboxPayload::from_value(decode(&pt, &OBJECT_LIMITS)?)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_crypto::{SeededRng, Secret32};

    fn dk(b: u8) -> VerifyingKey {
        osis_crypto::DeleteSecret::derive(&Secret32::from_bytes([b; 32])).verifying_key()
    }

    fn payload() -> InboxPayload {
        let a = Address { url: "quic://s".into(), key: [1; 32] };
        InboxPayload {
            chain: vec![Value::List(vec![Value::List(vec![]), Value::Int(1), Value::List(vec![])])],
            commit: Value::List(vec![Value::List(vec![]), Value::Int(0), Value::List(vec![])]),
            things: vec![
                InboxThing { tid: Tid::from_bytes([1; 15]), label: Some(InboxLabel { id: LabelId([2; 16]), index: 0, hosts: vec![a.clone()] }), delete_keys: None },
                InboxThing { tid: Tid::from_bytes([3; 15]), label: None, delete_keys: Some((dk(1), dk(2))) },
            ],
        }
    }

    // spec/wire.md §9, spec/crypto.md §5: inbox blob seals to the recipient's KEM key with AD
    // (recipient, "inbox", prefix); expiry INBOX_LIFETIME after now; no commitments.
    #[test]
    fn round_trip() {
        let mut rng = SeededRng::from_u64(1);
        let kem = KemSecret::derive(&Secret32::from_bytes([9; 32]));
        let r = Tid::from_bytes([5; 15]);
        let b = seal_inbox_blob(&r, kem.public(), &payload(), WallMs(1000), &mut rng).unwrap();
        let (p, got) = open_inbox_blob(&b, &r, &kem).unwrap();
        assert_eq!(got, payload());
        assert_eq!(p.expiry(), Some(WallMs(1000 + INBOX_LIFETIME_MS)));
        assert!(p.commitments().is_empty());
        assert!(open_inbox_blob(&b, &Tid::from_bytes([6; 15]), &kem).is_err());
        let other = KemSecret::derive(&Secret32::from_bytes([8; 32]));
        assert!(open_inbox_blob(&b, &r, &other).is_err());
    }

    // spec/wire.md §9: things sorted by tid and distinct; layout positions.
    #[test]
    fn rejections() {
        let mut p = payload();
        p.things.reverse();
        assert!(InboxPayload::from_value(p.to_value().unwrap()).is_err());
        let mut p = payload();
        p.things[1].tid = p.things[0].tid;
        assert!(InboxPayload::from_value(p.to_value().unwrap()).is_err());
        assert!(InboxPayload::from_value(Value::List(vec![Value::Int(0), Value::List(vec![])])).is_err());
        assert_eq!(InboxPayload::from_value(payload().to_value().unwrap()).unwrap(), payload());
    }
}
