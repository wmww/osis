//! Signal envelopes (spec/wire.md §9, spec/sync.md §9): a blob with no expiry and no
//! commitments, at most 64 KiB, wrapped under the label; plaintext `[SignalBody, signature]`
//! signed by the sender node under `"osis v1 signal"`. Publish authorization: `auth::PublishAuth`.

use crate::auth::{get_bytes, get_opt, get_uint, opt, uint};
use crate::blob::{Prefix, frame, open};
use crate::step::OBJECT_LIMITS;
use crate::Error;
use osis_base::cbor::{decode, encode};
use osis_base::format::MAX_VALUE_DEPTH;
use osis_base::{Ak, SchemaId, Tid, Ts, Value};
use osis_crypto::{CryptoRngCore, Domain, Secret32, Signature, SigningSecret, VerifyingKey};

/// Largest signal envelope (spec/wire.md §13).
pub const MAX_SIGNAL: usize = 64 * 1024;

/// `SignalBody := [node, actor, ts, tid, kind, target, schema, value]`.
#[derive(Clone, Debug, PartialEq)]
pub struct SignalBody {
    /// Sender node.
    pub node: Tid,
    pub actor: Tid,
    pub ts: Ts,
    /// Target thing.
    pub tid: Tid,
    /// The signal kind, an AK.
    pub kind: Ak,
    /// Target node, if targeted.
    pub target: Option<Tid>,
    pub schema: Option<(SchemaId, u64)>,
    pub value: Value,
}

fn tid(t: &Tid) -> Value {
    Value::Bytes(t.as_bytes().to_vec())
}

fn get_tid(v: &Value, what: &'static str) -> Result<Tid, Error> {
    Ok(Tid::from_bytes(get_bytes(v, what)?))
}

impl SignalBody {
    pub fn to_value(&self) -> Result<Value, Error> {
        let schema = self.schema.map(|(id, rev)| Ok::<_, Error>(Value::List(vec![Value::Bytes(id.0.to_vec()), uint(rev)?]))).transpose()?;
        Ok(Value::List(vec![
            tid(&self.node),
            tid(&self.actor),
            uint(self.ts.to_u64())?,
            tid(&self.tid),
            Value::Str(self.kind.as_str().to_string()),
            opt(self.target.as_ref().map(tid)),
            opt(schema),
            self.value.clone(),
        ]))
    }

    pub fn from_value(v: &Value) -> Result<SignalBody, Error> {
        let Value::List(items) = v else { return Err(Error::Malformed("signal body")) };
        let [node, actor, ts, t, Value::Str(kind), target, schema, value] = items.as_slice() else {
            return Err(Error::Malformed("signal body"));
        };
        if value.depth() > MAX_VALUE_DEPTH {
            return Err(Error::Malformed("signal value too deep"));
        }
        let schema = match get_opt(schema, "signal schema")? {
            Some(Value::List(s)) => match s.as_slice() {
                [id, rev] => Some((SchemaId(get_bytes(id, "signal schema id")?), get_uint(rev, "signal schema revision")?)),
                _ => return Err(Error::Malformed("signal schema")),
            },
            Some(_) => return Err(Error::Malformed("signal schema")),
            None => None,
        };
        Ok(SignalBody {
            node: get_tid(node, "signal node")?,
            actor: get_tid(actor, "signal actor")?,
            ts: Ts::from_u64(get_uint(ts, "signal ts")?).ok_or(Error::Malformed("signal ts"))?,
            tid: get_tid(t, "signal tid")?,
            kind: Ak::new(kind.clone()).map_err(|_| Error::Malformed("signal kind"))?,
            target: get_opt(target, "signal target")?.map(|t| get_tid(t, "signal target")).transpose()?,
            schema,
            value: value.clone(),
        })
    }

    /// BLAKE3 of the canonical body.
    pub fn digest(&self) -> Result<[u8; 32], Error> {
        Ok(osis_base::hash::hash(&encode(&self.to_value()?)))
    }

    pub fn verify(&self, node_key: &VerifyingKey, sig: &Signature) -> Result<(), Error> {
        node_key.verify(Domain::Signal, &self.digest()?, sig).map_err(|_| Error::Verify("signal signature"))
    }
}

/// Signs the body with the sender node's key and encrypts the envelope; returns the blob key and
/// the blob. `TooLarge` above 64 KiB.
pub fn seal_signal(body: &SignalBody, node_key: &SigningSecret, rng: &mut dyn CryptoRngCore) -> Result<(Secret32, Vec<u8>), Error> {
    let sig = node_key.sign(Domain::Signal, &body.digest()?);
    let pt = encode(&Value::List(vec![body.to_value()?, sig.to_value()]));
    let prefix = Prefix::new(Prefix::random_salt(rng), None, vec![])?;
    let (key, blob) = frame(&prefix, &pt, rng)?;
    if blob.len() > MAX_SIGNAL {
        return Err(Error::TooLarge("signal envelope above 64 KiB"));
    }
    Ok((key, blob))
}

/// Decrypts an envelope; the caller verifies the signature under the sender node's key
/// (`SignalBody::verify`) and its chain.
pub fn open_signal(blob: &[u8], key: &Secret32) -> Result<(SignalBody, Signature), Error> {
    if blob.len() > MAX_SIGNAL {
        return Err(Error::Malformed("signal envelope above 64 KiB"));
    }
    let (prefix, pt) = open(blob, key)?;
    if prefix.expiry().is_some() || !prefix.commitments().is_empty() {
        return Err(Error::Malformed("signal envelope with expiry or commitments"));
    }
    let Value::List(items) = decode(&pt, &OBJECT_LIMITS)? else { return Err(Error::Malformed("signal plaintext")) };
    let [body, sig] = items.as_slice() else { return Err(Error::Malformed("signal plaintext")) };
    Ok((SignalBody::from_value(body)?, Signature::from_value(sig)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_crypto::SeededRng;

    pub(crate) fn body() -> SignalBody {
        SignalBody {
            node: Tid::from_bytes([1; 15]),
            actor: Tid::from_bytes([2; 15]),
            ts: Ts::from_u64(1 << 20).unwrap(),
            tid: Tid::from_bytes([3; 15]),
            kind: Ak::new("/chat/typing").unwrap(),
            target: Some(Tid::from_bytes([4; 15])),
            schema: Some((SchemaId([5; 16]), 2)),
            value: Value::Str("hi".into()),
        }
    }

    // spec/wire.md §9: envelope round trip; signature by the sender node over the body; no
    // expiry, no commitments; 64 KiB cap.
    #[test]
    fn round_trip() {
        let mut rng = SeededRng::from_u64(1);
        let node = SigningSecret::from_seed(&Secret32::from_bytes([1; 32]));
        let (k, blob) = seal_signal(&body(), &node, &mut rng).unwrap();
        let (b, sig) = open_signal(&blob, &k).unwrap();
        assert_eq!(b, body());
        b.verify(&node.verifying_key(), &sig).unwrap();
        let other = SigningSecret::from_seed(&Secret32::from_bytes([2; 32]));
        assert!(b.verify(&other.verifying_key(), &sig).is_err());
        let mut big = body();
        big.value = Value::Bytes(vec![0; MAX_SIGNAL]);
        assert!(matches!(seal_signal(&big, &node, &mut rng), Err(Error::TooLarge(_))));
        let mut plain = body();
        plain.target = None;
        plain.schema = None;
        assert_eq!(SignalBody::from_value(&plain.to_value().unwrap()).unwrap(), plain);
        // An envelope with an expiry is not a signal envelope.
        let p = Prefix::new([0; 16], Some(osis_base::WallMs(9)), vec![]).unwrap();
        let pt = encode(&Value::List(vec![body().to_value().unwrap(), sig.to_value()]));
        let (k2, b2) = frame(&p, &pt, &mut rng).unwrap();
        assert!(open_signal(&b2, &k2).is_err());
    }

    // spec/wire.md §9, §13: body rejections: bad kind, wrong positions, bad schema option.
    #[test]
    fn rejections() {
        let Value::List(items) = body().to_value().unwrap() else { panic!() };
        let mut bad = items.clone();
        bad[4] = Value::Str(String::new());
        assert!(SignalBody::from_value(&Value::List(bad)).is_err());
        let mut bad = items.clone();
        bad[6] = Value::List(vec![Value::Int(1)]);
        assert!(SignalBody::from_value(&Value::List(bad)).is_err());
        let mut bad = items;
        bad.pop();
        assert!(SignalBody::from_value(&Value::List(bad)).is_err());
    }
}
