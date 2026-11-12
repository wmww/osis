//! The direct header and blob codec (bytes written and read in place) against the `Value`-tree
//! codec it replaced (`value_header`): the same header bytes, and for headers, commit blobs and
//! envelopes, valid and mutated (bytewise or by one value node), the same decode result or the
//! same error.

use crate::tests::prop::header;
use crate::tests::value_header as old;
use crate::*;
use osis_base::{CommitId, Tid, Value};
use osis_crypto::{Secret32, Signature};
use proptest::prelude::*;

fn show<T: std::fmt::Debug>(r: Result<T, Error>) -> Result<String, String> {
    r.map(|x| format!("{x:?}")).map_err(|e| e.to_string())
}

/// Every node of a value tree, pre-order.
fn count(v: &Value) -> usize {
    1 + match v {
        Value::List(l) => l.iter().map(count).sum(),
        Value::Map(m) => m.iter().map(|(k, x)| count(k) + count(x)).sum(),
        Value::Enum(_, Some(p)) => count(p),
        _ => 0,
    }
}

/// Changes the `k`-th node (pre-order) of `v` by `op`: an int nudged or zeroed, a list item
/// dropped or repeated, bytes shortened or lengthened, a node turned into another kind.
fn mutate_at(v: &mut Value, k: &mut usize, op: u8) -> bool {
    if *k == 0 {
        *v = match (op % 6, &*v) {
            (0, Value::Int(i)) => Value::Int(i.wrapping_add(1)),
            (1, Value::Int(_)) => Value::Int(0),
            (0, Value::List(l)) if !l.is_empty() => Value::List(l[1..].to_vec()),
            (1, Value::List(l)) if !l.is_empty() => Value::List([l.as_slice(), &l[..1]].concat()),
            (0 | 1, Value::Bytes(b)) => Value::Bytes(if op.is_multiple_of(2) { b[..b.len() / 2].to_vec() } else { [b.as_slice(), &[0]].concat() }),
            (2, _) => Value::Int(-1),
            (3, _) => Value::List(Vec::new()),
            (4, _) => Value::Bytes(vec![1; 15]),
            _ => Value::Str("x.0".into()),
        };
        return true;
    }
    *k -= 1;
    match v {
        Value::List(l) => l.iter_mut().any(|x| mutate_at(x, k, op)),
        Value::Enum(_, Some(p)) => mutate_at(p, k, op),
        _ => false,
    }
}

/// A mutant of `b`: one value node changed (`seed` picks it), or one byte edit.
fn mutant(b: &[u8], seed: u64) -> Vec<u8> {
    let op = (seed >> 8) as u8;
    if seed.is_multiple_of(2)
        && let Ok(mut v) = osis_base::decode(b, &osis_base::Limits::DEFAULT)
    {
        let mut k = (seed >> 16) as usize % count(&v);
        mutate_at(&mut v, &mut k, op);
        return osis_base::encode(&v);
    }
    let mut b = b.to_vec();
    let at = (seed >> 16) as usize % (b.len() + 1);
    match op % 4 {
        0 if at < b.len() => b[at] ^= (op | 1).rotate_left(3),
        1 => b.insert(at, op),
        2 if at < b.len() => drop(b.remove(at)),
        _ => b.truncate(at),
    }
    b
}

/// Header, commit blob and envelope decoders of both codecs agree on `b`.
fn decodes_alike(b: &[u8]) -> Result<(), TestCaseError> {
    prop_assert_eq!(show(Header::decode(b)), show(old::decode(b)), "header {:02x?}", b);
    Ok(())
}

fn blobs_alike(b: &[u8]) -> Result<(), TestCaseError> {
    prop_assert_eq!(show(CommitBlob::decode(b)), show(old::decode_blob(b)), "blob {:02x?}", b);
    prop_assert_eq!(show(Envelope::decode(b)), show(old::decode_envelope(b)), "envelope {:02x?}", b);
    Ok(())
}

fn sigs(n: u8, merge: usize) -> Sigs {
    Sigs { signature: Signature([n; 64]), inner: n.is_multiple_of(2).then_some([n; osis_crypto::INNER_LEN]), merge: (0..merge).map(|i| Signature([i as u8; 64])).collect() }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Headers (a rotation on some), commit blobs and envelopes: the direct codec writes the old
    /// bytes, and decodes them and 40 mutants of each as the old one did.
    #[test]
    fn direct_header_codec_matches_value_codec(mut h in header(), rot in any::<bool>(), n in any::<u8>(), seed in any::<u64>()) {
        if rot {
            let keys = osis_crypto::AccountEpochKeys::from_seed(&Secret32::from_bytes([n; 32]));
            h.rotation = Some(RotationHeader { signing_key: keys.signing.verifying_key(), kem_key: keys.kem.public().clone(), supersedes: vec![FIRST_EPOCH, CommitId([n; 32])], names: vec![CommitId([n; 32])], list_root: [n; 32] });
        }
        let b = h.encode();
        prop_assert_eq!(&b, &old::encode(&h));
        prop_assert_eq!(show(Header::decode_stored(&b)), show(old::from_value(&osis_base::decode(&b, &osis_base::Limits::DEFAULT).unwrap(), true)));
        let delta = osis_base::encode(&Value::List(vec![Value::Int(i64::from(n)), Value::bytes(&[n; 3])]));
        let blob = CommitBlob { header: h.clone(), sigs: sigs(n, usize::from(n % 3)), parts: vec![Part::new(0, delta.clone()), Part::new(2, delta)] };
        let section = Section { ais: vec![0, 1], chain: vec![Tid::from_bytes([n; 15])], wrap: vec![n; osis_crypto::SECTION_WRAP_LEN], ciphertext: vec![n; usize::from(n)] };
        let env = Envelope { header: h, sigs: sigs(n, 1), sections: vec![section] };
        let ins = [b, blob.encode(), env.encode()];
        for (i, x) in ins.iter().enumerate() {
            decodes_alike(x)?;
            blobs_alike(x)?;
            for k in 0..40u64 {
                let m = mutant(x, seed.wrapping_add(k.wrapping_mul(0x9e37_79b9_7f4a_7c15)).wrapping_add(i as u64));
                decodes_alike(&m)?;
                blobs_alike(&m)?;
            }
        }
        prop_assert!(CommitBlob::decode(&ins[1]).is_ok() && Envelope::decode(&ins[2]).is_ok());
    }
}
