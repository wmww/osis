//! `blob/`: clear prefixes and blobs (spec/wire.md §5, §6, spec/crypto.md §5, §7). Generated.
//! `prefix.vec`: prefix fields → bytes, and rejections. `blobs.vec`: chunk, tree-node and page
//! blobs from fixed keys and salts, with link content hashes; a bad-padding rejection.

use super::{FixedRng, case, generated_header, s32};
use crate::file::{Record, VecFile};
use crate::hex;
use osis_core::{Link, Value, WallMs, encode};
use osis_crypto::{SUITE_1, aead, link_hash, link_tree_hash, pad};
use osis_label::{Error, Prefix, frame, open, tree::node_plaintext};

const SPEC: &str = "spec/wire.md §5";

fn c(level: u8, b: u8) -> [u8; 17] {
    let mut x = [b; 17];
    x[0] = level;
    x
}

fn commitments(p: &Prefix) -> String {
    p.commitments().iter().map(|c| hex(c)).collect::<Vec<_>>().join(",")
}

fn prefix_case(name: &str, p: &Prefix) -> Record {
    case(name, SPEC)
        .with("salt", hex(p.salt()))
        .with("expiry", p.expiry().map_or("none".to_string(), |t| t.0.to_string()))
        .with("commitments", commitments(p))
        .with("prefix", hex(&p.to_bytes()))
}

fn reject(name: &str, bytes: &[u8], rule: &str) -> Record {
    let got = Prefix::parse(bytes);
    let want = match rule {
        "framing" => Error::UnknownFraming(bytes[0]),
        "prefix-order" => Error::Malformed("commitments not strictly ascending"),
        "prefix-level" => Error::Malformed("commitment level"),
        "prefix-count" => Error::Malformed("more than MAX_COMMITMENTS"),
        "prefix-short" => Error::Malformed("short prefix"),
        _ => panic!("unknown rule {rule}"),
    };
    assert_eq!(got, Err(want), "{name}");
    let key = if rule == "framing" { "parked" } else { "reject" };
    case(name, SPEC).with("prefix", hex(bytes)).with(key, rule)
}

pub fn prefixes() -> VecFile {
    let salt = [0x21; 16];
    let mut cases = vec![prefix_case("no commitments, no expiry", &Prefix::new(salt, None, vec![]).unwrap())];
    cases.push(prefix_case("one commitment, expiry", &Prefix::new(salt, Some(WallMs(1_700_000_000_000)), vec![c(2, 0x22)]).unwrap()));
    // Commitments derived from (level, token hash) pairs under the prefix salt.
    let tokens = [(1u8, [0x23u8; 16]), (2, [0x24; 16]), (3, [0x25; 16])];
    let p = Prefix::for_tokens(salt, None, &tokens).unwrap();
    let pairs: Vec<String> = tokens.iter().map(|(l, h)| format!("{l}:{}", hex(h))).collect();
    cases.push(prefix_case("three commitments from token hashes", &p).with("tokens", pairs.join(",")));
    let many: Vec<[u8; 17]> = (0..16).map(|i| c(1 + i % 3, i)).collect();
    cases.push(prefix_case("sixteen commitments", &Prefix::new(salt, Some(WallMs(1)), many).unwrap()));

    let base = Prefix::new(salt, None, vec![c(1, 1), c(1, 2)]).unwrap().to_bytes();
    let mut b = base.clone();
    b[26..43].copy_from_slice(&c(1, 2));
    b[43..60].copy_from_slice(&c(1, 1));
    cases.push(reject("commitments unsorted", &b, "prefix-order"));
    let mut b = base.clone();
    b[43..60].copy_from_slice(&c(1, 1));
    cases.push(reject("commitments duplicate", &b, "prefix-order"));
    let mut b = base.clone();
    b[26] = 0;
    cases.push(reject("commitment level 0", &b, "prefix-level"));
    let mut b = base.clone();
    b[43] = 4;
    cases.push(reject("commitment level 4", &b, "prefix-level"));
    let mut b = Prefix::new(salt, None, vec![]).unwrap().to_bytes();
    b[25] = 17;
    for i in 0..17u8 {
        b.extend(c(1, i));
    }
    cases.push(reject("seventeen commitments", &b, "prefix-count"));
    cases.push(reject("truncated", &base[..50], "prefix-short"));
    let mut b = base;
    b[0] = 2;
    cases.push(reject("unknown framing version", &b, "framing"));
    VecFile { header: generated_header("blob", SPEC), cases }
}

fn blob_case(name: &str, spec: &str, prefix: &Prefix, plaintext: &[u8], key: [u8; 32], hash: [u8; 32]) -> (Record, Link) {
    let (k, blob) = frame(prefix, plaintext, &mut FixedRng::new(&[&key])).unwrap();
    assert_eq!(open(&blob, &k).unwrap().1, plaintext);
    let id = osis_label::blob_id(&blob);
    let r = case(name, spec)
        .with("prefix", hex(&prefix.to_bytes()))
        .with("plaintext", hex(plaintext))
        .with("padded", hex(&pad(plaintext)))
        .with("blob-key", hex(&key))
        .with("blob", hex(&blob))
        .with("blob-id", hex(&id.0))
        .with("link-hash", hex(&hash));
    (r, Link { hash, blob: id, suite: SUITE_1, key })
}

pub fn blobs() -> VecFile {
    let dedup = s32(0x07);
    let mut cases = Vec::new();
    // Chunk: prefix with the chunk token of an `admin` delta (level 1, secret 0x26).
    let salt = [0x27; 16];
    let secret = s32(0x26);
    let (p, hashes) = Prefix::for_chunk(salt, Some(WallMs(1_800_000_000_000)), &[(1, &secret)]).unwrap();
    let chunk = b"osis chunk bytes".to_vec();
    let (r, l1) = blob_case("chunk blob", "spec/wire.md §6", &p, &chunk, [0x28; 32], link_hash(&dedup, &chunk));
    cases.push(
        r.with("dedup", hex(dedup.expose()))
            .with("token-secret", hex(secret.expose()))
            .with("token-level", "1")
            .with("chunk-token-hash", hex(&hashes[0])),
    );
    // Tree node over that chunk, with its length.
    let node = node_plaintext(1, &[(l1, chunk.len() as u64)]).unwrap();
    let (r, _) = blob_case("tree node blob", "spec/wire.md §6", &p, &node, [0x29; 32], link_tree_hash(&dedup, 1, &[l1.hash]));
    cases.push(r.with("dedup", hex(dedup.expose())));
    // Page: the canonical array of its elements.
    let page = encode(&Value::List(vec![Value::Int(1), Value::Str("two".into())]));
    let p0 = Prefix::new(salt, None, vec![]).unwrap();
    let (r, _) = blob_case("page blob", "spec/wire.md §6", &p0, &page, [0x2a; 32], link_hash(&dedup, &page));
    cases.push(r.with("dedup", hex(dedup.expose())));
    cases.push(case("commit blob", SPEC).with("pending", "osis-commit (CommitBlobPlaintext)"));
    // Bad padding: a valid AEAD over a plaintext without the 0x80 marker.
    let key = [0x2b; 32];
    let pb = p0.to_bytes();
    let mut blob = pb.clone();
    blob.extend(aead::seal(&key, &aead::ZERO_NONCE, &pb, &[1, 0, 0, 0]).unwrap());
    assert_eq!(open(&blob, &osis_crypto::Secret32::from_bytes(key)).map(|_| ()), Err(Error::Crypto(osis_crypto::Error::BadPadding)));
    cases.push(case("bad padding", SPEC).with("blob-key", hex(&key)).with("blob", hex(&blob)).with("reject", "padding"));
    VecFile { header: generated_header("blob", SPEC), cases }
}
