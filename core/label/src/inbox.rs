//! Inbox blobs (spec/wire.md §9, spec/crypto.md §5, spec/sync.md §3). The membership commit
//! travels as its `CommitBlobPlaintext` value; osis-commit parses it (the only coupling to the
//! commit layout, kept here).

use crate::addr::{Address, address_from_value};
use crate::auth::get_bytes;
use crate::blob::Prefix;
use crate::step::OBJECT_LIMITS;
use crate::Error;
use osis_base::cbor::{decode, encode};
use osis_base::format::INBOX_LIFETIME_MS;
use osis_base::{LabelId, Tid, Value, WallMs};
use osis_crypto::{CryptoRngCore, KemPublicKey, KemSecret, VerifyingKey, open_inbox, seal_inbox};
use osis_schema::Codec;

/// A thing the commit names: its label ID and server addresses, and for a thing with secrets
/// of its own its current admin and write delete keys (spec/crypto.md §7), which the grantee
/// lists until it holds the thing's `/keys`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxThing {
    pub tid: Tid,
    pub label: LabelId,
    pub servers: Vec<Address>,
    pub delete_keys: Option<(VerifyingKey, VerifyingKey)>,
}

/// `InboxPayload := [CommitBlobPlaintext, [[tid, label_id, [address*], Opt([admin_pk,
/// write_pk])]*]]`, things sorted by tid, distinct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxPayload {
    /// The membership commit's `CommitBlobPlaintext` value (header, signature, parts about the
    /// recipient).
    pub commit: Value,
    pub things: Vec<InboxThing>,
}

impl InboxPayload {
    pub fn to_value(&self) -> Value {
        let things = self.things.iter().map(|t| {
            Value::List(vec![
                Value::Bytes(t.tid.as_bytes().to_vec()),
                Value::Bytes(t.label.0.to_vec()),
                Value::List(t.servers.iter().map(Codec::to_value).collect()),
                Value::List(t.delete_keys.iter().map(|(a, w)| Value::List(vec![Value::Bytes(a.to_bytes().to_vec()), Value::Bytes(w.to_bytes().to_vec())])).collect()),
            ])
        });
        Value::List(vec![self.commit.clone(), Value::List(things.collect())])
    }

    pub fn from_value(v: &Value) -> Result<InboxPayload, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("inbox payload")) };
        let [commit @ Value::List(_), Value::List(things)] = items.as_slice() else { return Err(Error::Malformed("inbox payload")) };
        let mut out: Vec<InboxThing> = Vec::with_capacity(things.len());
        for t in things {
            let Value::List(f) = t else { return Err(Error::Malformed("inbox thing")) };
            let [tid, label, Value::List(servers), keys] = f.as_slice() else { return Err(Error::Malformed("inbox thing")) };
            let key = |v: &Value| VerifyingKey::from_bytes(&get_bytes(v, "inbox delete key")?).map_err(|_| Error::Malformed("inbox delete key"));
            let delete_keys = match crate::auth::get_opt(keys, "inbox delete keys")? {
                None => None,
                Some(Value::List(ks)) => match ks.as_slice() {
                    [a, w] => Some((key(a)?, key(w)?)),
                    _ => return Err(Error::Malformed("inbox delete keys")),
                },
                Some(_) => return Err(Error::Malformed("inbox delete keys")),
            };
            let tid = Tid::from_bytes(get_bytes(tid, "inbox tid")?);
            if out.last().is_some_and(|p| p.tid >= tid) {
                return Err(Error::Malformed("inbox things not sorted by tid"));
            }
            let servers = servers.iter().map(address_from_value).collect::<Result<_, _>>()?;
            out.push(InboxThing { tid, label: LabelId(get_bytes(label, "inbox label")?), servers, delete_keys });
        }
        Ok(InboxPayload { commit: commit.clone(), things: out })
    }
}

/// Seals an inbox blob to `recipient`'s newest read keyset KEM key: prefix with expiry `now`
/// (the sender's corrected wall ms) + `INBOX_LIFETIME`, no commitments. Its entry's wrap is a
/// filler (`osis_crypto::filler_wrap`).
pub fn seal_inbox_blob(recipient: &Tid, kem: &KemPublicKey, payload: &InboxPayload, now: WallMs, rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
    let prefix = Prefix::new(Prefix::random_salt(rng), Some(now.saturating_add(INBOX_LIFETIME_MS)), vec![])?;
    seal_inbox(&prefix.to_bytes(), recipient, kem, &encode(&payload.to_value()), rng).map_err(|e| match e {
        osis_crypto::Error::TooLarge => Error::TooLarge("inbox blob above MAX_BLOB"),
        e => Error::Crypto(e),
    })
}

/// Opens an inbox blob addressed to `recipient` with its read KEM secret.
pub fn open_inbox_blob(blob: &[u8], recipient: &Tid, kem: &KemSecret) -> Result<(Prefix, InboxPayload), Error> {
    crate::blob::check_size(blob)?;
    let prefix = Prefix::parse(blob)?;
    let pt = open_inbox(blob, prefix.len(), recipient, kem)?;
    Ok((prefix, InboxPayload::from_value(&decode(&pt, &OBJECT_LIMITS)?)?))
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
            commit: Value::List(vec![Value::List(vec![]), Value::Int(0), Value::List(vec![])]),
            things: vec![
                InboxThing { tid: Tid::from_bytes([1; 15]), label: LabelId([2; 16]), servers: vec![a.clone()], delete_keys: None },
                InboxThing { tid: Tid::from_bytes([3; 15]), label: LabelId([4; 16]), servers: vec![], delete_keys: Some((dk(1), dk(2))) },
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
        assert!(InboxPayload::from_value(&p.to_value()).is_err());
        let mut p = payload();
        p.things[1].tid = p.things[0].tid;
        assert!(InboxPayload::from_value(&p.to_value()).is_err());
        assert!(InboxPayload::from_value(&Value::List(vec![Value::Int(0), Value::List(vec![])])).is_err());
        assert_eq!(InboxPayload::from_value(&payload().to_value()).unwrap(), payload());
    }
}
