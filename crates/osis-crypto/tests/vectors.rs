//! Known-answer vectors for every derivation, box, wrap, token and signature of spec/crypto.md
//! (layouts spec/wire.md §3, §5, §7, §8, §9, §11.2), frozen in `vectors/crypto/*.json` (format: vectors/crypto/README.md). Tier 1 checks the
//! committed files byte for byte; `OSIS_WRITE_VECTORS=1` rewrites them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_core::{BlobId, Classified, LabelId, Role, Tid};
use osis_crypto::kdf::{self, kdf, kdf_xof};
use osis_crypto::*;
use std::path::PathBuf;

/// Rng that hands out fixed bytes in order, so vectors list the randomness they consume.
struct FixedRng(Vec<u8>);

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert!(self.0.len() >= dest.len(), "FixedRng exhausted");
        let rest = self.0.split_off(dest.len());
        dest.copy_from_slice(&self.0);
        self.0 = rest;
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for FixedRng {}

fn fixed(parts: &[&[u8]]) -> FixedRng {
    FixedRng(parts.concat())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn s32(b: u8) -> Secret32 {
    Secret32::from_bytes([b; 32])
}

/// One JSON object with ordered fields; values are pre-encoded JSON.
#[derive(Default)]
struct Obj(Vec<(String, String)>);

impl Obj {
    fn new(name: &str) -> Obj {
        let mut o = Obj::default();
        o.str("name", name);
        o
    }
    fn str(&mut self, k: &str, v: &str) -> &mut Obj {
        self.0.push((k.into(), format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))));
        self
    }
    fn hex(&mut self, k: &str, v: &[u8]) -> &mut Obj {
        let h = hex(v);
        self.str(k, &h)
    }
    fn num(&mut self, k: &str, v: u64) -> &mut Obj {
        self.0.push((k.into(), v.to_string()));
        self
    }
    fn error(&mut self, e: Error) -> &mut Obj {
        self.str("expect", "error").str("error_class", &format!("{:?}", e.class()))
    }
    fn render(&self, indent: &str) -> String {
        let fields: Vec<String> = self.0.iter().map(|(k, v)| format!("{indent}  \"{k}\": {v}")).collect();
        format!("{{\n{}\n{indent}}}", fields.join(",\n"))
    }
}

fn file(spec: &str, comment: &str, cases: Vec<Obj>) -> String {
    let cs: Vec<String> = cases.iter().map(|c| format!("    {}", c.render("    "))).collect();
    format!(
        "{{\n  \"spec\": \"{spec}\",\n  \"comment\": \"{comment}\",\n  \"cases\": [\n{}\n  ]\n}}\n",
        cs.join(",\n")
    )
}

fn kdf_vectors() -> String {
    let secret = [0x11u8; 32];
    let input = b"osis test input";
    let mut cases = Vec::new();
    for p in kdf::PURPOSES {
        let mut o = Obj::new(p);
        o.str("purpose", p).hex("secret", &secret).hex("input", input).hex("out", &kdf(p, &secret, input));
        cases.push(o);
    }
    let mut xof = [0u8; 96];
    kdf_xof(kdf::KEM, &secret, b"", &mut xof);
    let mut o = Obj::new("kem xof 96");
    o.str("purpose", kdf::KEM).hex("secret", &secret).hex("input", b"").hex("out", &xof);
    cases.push(o);
    let mut o = Obj::new("dedup");
    o.str("derive_key", kdf::DEDUP).hex("material", &secret).hex("out", dedup_secret(&secret).expose());
    cases.push(o);
    file("spec/crypto.md §1, §3, §6, §7; spec/sync.md §2", "kdf(purpose, secret, input) = keyed_hash(derive_key('osis v1 ' + purpose, secret), input); out is 32 bytes unless named xof", cases)
}

fn keys_vectors() -> String {
    let seed = s32(0x05);
    let k = KeyActorKeys::from_seed(&seed);
    let label = LabelId([0x0a; 16]);
    let step = X25519Secret::from_secret(&s32(0x06));
    let mut cases = Vec::new();
    let mut o = Obj::new("key actor from seed");
    o.hex("seed", seed.expose())
        .hex("ed25519_public", &k.signing.verifying_key().to_bytes())
        .hex("signing_key_value", &osis_core::encode(&k.signing.verifying_key().to_value()))
        .hex("kem_public", k.kem.public().as_bytes())
        .hex("x25519_public", &k.kem.public().x25519())
        .hex("creation_nonce", &creation_nonce(&seed));
    for r in [Role::Read, Role::Write, Role::Admin] {
        o.hex(&format!("role_secret_{r:?}").to_lowercase(), key_actor_role_secret(&seed, r).expose());
    }
    cases.push(o);
    let tid = Tid::from_bytes([0x01; 15]);
    let mut o = Obj::new("plain thing secrets");
    o.hex("owner_secret", seed.expose()).hex("tid", tid.as_bytes());
    for r in [Role::Read, Role::Write, Role::Admin] {
        o.hex(&format!("thing_secret_{r:?}").to_lowercase(), thing_role_secret(&seed, r, &tid).expose());
    }
    o.hex("read_kem_public", role_kem(&thing_role_secret(&seed, Role::Read, &tid)).public().as_bytes());
    cases.push(o);
    let mut o = Obj::new("claim key and static entry");
    let claim = claim_key(&step, &k.kem.public().x25519(), &label, &step.public()).unwrap();
    o.hex("member_seed", seed.expose())
        .hex("step_private", s32(0x06).expose())
        .hex("step_key", &step.public())
        .hex("label_id", &label.0)
        .hex("claim_public", &claim.verifying_key().to_bytes())
        .hex("static_entry", &static_entry(&label, &k.signing.verifying_key()));
    cases.push(o);
    for i in [0u64, 1] {
        let mut o = Obj::new(&format!("label keys index {i}"));
        o.hex("secret", seed.expose()).num("index", i);
        for (n, r) in [("sync", LabelRole::Sync), ("write", LabelRole::Write), ("delete", LabelRole::Delete)] {
            o.hex(&format!("{n}_public"), &label_role_key(r, &seed, i).verifying_key().to_bytes());
        }
        let genesis_delete = label_role_key(LabelRole::Delete, &seed, i).verifying_key();
        let id = label_id(&genesis_delete);
        o.hex("label_id_from_delete", &id.0).hex("deposit_seed", seed.expose()).hex("deposit_public", &deposit_key(&seed, &id).verifying_key().to_bytes());
        cases.push(o);
    }
    let mut o = Obj::new("content hashes");
    let d = s32(0x07);
    let (a, b) = (link_hash(&d, b"chunk a"), link_hash(&d, b"chunk b"));
    o.hex("dedup", d.expose())
        .hex("delta_hash_of_delta", &delta_hash(&d, b"delta"))
        .hex("link_hash_chunk_a", &a)
        .hex("link_hash_chunk_b", &b)
        .hex("link_tree_hash_level1_ab", &link_tree_hash(&d, 1, &[a, b]))
        .hex("lan_tag_at_ms_1234567890123", &lan_tag(&d, 1_234_567_890_123));
    cases.push(o);
    file("spec/crypto.md §3, §6; spec/sync.md §2, §10; spec/wire.md §3, §6, §8", "all Ed25519 keys are RFC 8032 keys from the stated seeds; byte strings are ASCII where they read as text", cases)
}

fn box_vectors() -> String {
    let recipient = KemSecret::derive(&s32(0x05));
    let (eph, m) = ([0x0cu8; 32], [0x0du8; 32]);
    let actor = Tid::from_bytes([0x01; 15]);
    let member = Tid::from_bytes([0x02; 15]);
    let e = |n: u64| Epoch::new(n, [n as u8; 16]).unwrap();
    let mut cases = Vec::new();

    let sealed = seal_with(recipient.public(), b"ad", b"payload", &Secret32::from_bytes(eph), &m).unwrap();
    let mut o = Obj::new("hybrid sealed box");
    o.hex("recipient_kem_seed", s32(0x05).expose())
        .hex("recipient_public", recipient.public().as_bytes())
        .hex("ephemeral_x25519_private", &eph)
        .hex("mlkem_encaps_randomness", &m)
        .hex("ad", b"ad")
        .hex("payload", b"payload")
        .hex("sealed", &sealed)
        .hex("sealed_value", &osis_core::encode(&sealed_to_value(&sealed)));
    cases.push(o);
    let mut t = sealed.clone();
    *t.last_mut().unwrap() ^= 1;
    let mut o = Obj::new("hybrid sealed box tampered");
    o.hex("ad", b"ad").hex("sealed", &t).error(open_sealed(&recipient, b"ad", &t).unwrap_err());
    cases.push(o);
    let mut o = Obj::new("hybrid sealed box wrong ad");
    o.hex("ad", b"ae").hex("sealed", &sealed).error(open_sealed(&recipient, b"ae", &sealed).unwrap_err());
    cases.push(o);

    // Sealed /secrets box to an actor member: one item.
    let form = BoxForm::Sealed { keyset: Some(e(3)), suite: 1 };
    let ad = secrets_box_ad(&actor, &member, Role::Write, &e(4), form);
    let item = BoxItem { role: Role::Write, epoch: e(4), secret: s32(0x09) };
    let b = seal_box(recipient.public(), &ad, std::slice::from_ref(&item), &mut fixed(&[&eph, &m])).unwrap();
    assert_eq!(open_box(&recipient, &ad, form, &b).unwrap(), vec![item]);
    let mut o = Obj::new("secrets box sealed form, actor member");
    o.hex("actor", actor.as_bytes()).hex("member", member.as_bytes()).num("role", 1).num("n", 4).hex("nonce", &[4; 16]);
    o.str("form", "sealed, keyset [3, 03*16], suite 1").hex("ad", &ad).hex("ephemeral_x25519_private", &eph).hex("mlkem_encaps_randomness", &m);
    o.str("payload", "[[1, 4, 04*16, 09*32]]").hex("sealed", &b);
    cases.push(o);

    // Sealed /secrets box to a key-actor member: no keyset, every written role.
    let form = BoxForm::Sealed { keyset: None, suite: 1 };
    let ad = secrets_box_ad(&actor, &member, Role::Write, &e(4), form);
    let items = [BoxItem { role: Role::Read, epoch: e(2), secret: s32(0x08) }, BoxItem { role: Role::Write, epoch: e(4), secret: s32(0x09) }];
    let b = seal_box(recipient.public(), &ad, &items, &mut fixed(&[&eph, &m])).unwrap();
    let mut o = Obj::new("secrets box sealed form, key-actor member");
    o.hex("ad", &ad).hex("ephemeral_x25519_private", &eph).hex("mlkem_encaps_randomness", &m);
    o.str("payload", "[[0, 2, 02*16, 08*32], [1, 4, 04*16, 09*32]]").hex("sealed", &b);
    cases.push(o);

    // Symmetric form.
    let form = BoxForm::Symmetric { epoch_s: e(7) };
    let ad = secrets_box_ad(&actor, &member, Role::Read, &e(1), form);
    let w = wrap_symmetric_box(&s32(0x0b), &ad, &s32(0x09));
    let mut o = Obj::new("secrets box symmetric form");
    o.hex("actor", actor.as_bytes()).hex("member", member.as_bytes()).num("role", 0).num("n", 1).hex("nonce", &[1; 16]);
    o.str("form", "symmetric, epoch of s [7, 07*16]").hex("ad", &ad).hex("s", s32(0x0b).expose()).hex("secret", s32(0x09).expose()).hex("wrap", &w);
    cases.push(o);
    let mut o = Obj::new("secrets box symmetric form wrong s");
    o.hex("ad", &ad).hex("s", s32(0x0c).expose()).hex("wrap", &w).error(open_symmetric_box(&s32(0x0c), &ad, &w).unwrap_err());
    cases.push(o);

    // Entry box.
    let label = LabelId([0x0a; 16]);
    let step_key = X25519Secret::from_secret(&s32(0x06)).public();
    let form = BoxForm::Sealed { keyset: None, suite: 1 };
    let ad = entry_box_ad(&label, &step_key, form);
    let item = BoxItem { role: Role::Read, epoch: e(2), secret: s32(0x08) };
    let b = seal_box(recipient.public(), &ad, &[item], &mut fixed(&[&eph, &m])).unwrap();
    let mut o = Obj::new("entry box");
    o.hex("label_id", &label.0).hex("step_key", &step_key).str("form", "sealed, no keyset, suite 1").hex("ad", &ad);
    o.hex("ephemeral_x25519_private", &eph).hex("mlkem_encaps_randomness", &m).str("payload", "[[0, 2, 02*16, 08*32]]").hex("sealed", &b);
    cases.push(o);

    // History box.
    let earlier = [(e(1), s32(0x21)), (e(2), s32(0x22))];
    let h = seal_history(&s32(0x09), &actor, Role::Read, &e(3), &earlier).unwrap();
    let mut o = Obj::new("history box");
    o.hex("secret", s32(0x09).expose()).hex("actor", actor.as_bytes()).num("role", 0).num("n", 3).hex("nonce", &[3; 16]);
    o.str("plaintext", "[[1, 01*16, 21*32], [2, 02*16, 22*32]]").hex("box", &h);
    cases.push(o);
    let mut o = Obj::new("history box wrong role");
    o.num("role", 1).hex("box", &h).error(open_history(&s32(0x09), &actor, Role::Write, &e(3), &h).unwrap_err());
    cases.push(o);
    file("spec/crypto.md §1, §4; spec/wire.md §7", "byte patterns written xx*n are n repetitions of byte xx; rng order: ephemeral X25519 private key, then ML-KEM randomness", cases)
}

fn blob_vectors() -> String {
    let mut cases = Vec::new();
    let mut prefix = vec![1u8];
    prefix.extend([0x01; 16]);
    prefix.extend(0u64.to_le_bytes());
    prefix.push(0);
    let key = [0x10u8; 32];
    let (k, blob) = encrypt_blob(&prefix, b"osis", &mut fixed(&[&key])).unwrap();
    assert_eq!(k.expose(), &key);
    let id = blob_id(&blob);
    let mut o = Obj::new("blob, prefix without commitments");
    o.hex("prefix", &prefix).hex("plaintext", b"osis").hex("blob_key", &key).hex("blob", &blob).hex("blob_id", &id.0);
    cases.push(o);
    let mut t = blob.clone();
    t[1] ^= 1;
    let mut o = Obj::new("blob, prefix tampered");
    o.num("prefix_len", prefix.len() as u64).hex("blob_key", &key).hex("blob", &t).error(decrypt_blob(&t, prefix.len(), &k).unwrap_err());
    cases.push(o);
    let mut o = Obj::new("wrap");
    let (rs, bk, bid) = (s32(0x0f), s32(0x10), BlobId([0x0e; 32]));
    o.hex("read_secret", rs.expose()).hex("blob_id", &bid.0).hex("blob_key", bk.expose()).hex("wrap", &wrap(&rs, &bid, &bk));
    cases.push(o);
    let mut o = Obj::new("wrap of the blob above");
    o.hex("read_secret", rs.expose()).hex("blob_id", &id.0).hex("blob_key", &key).hex("wrap", &wrap(&rs, &id, &k));
    cases.push(o);
    let recipient = KemSecret::derive(&s32(0x05));
    let r = Tid::from_bytes([0x03; 15]);
    let (eph, m) = ([0x0cu8; 32], [0x0du8; 32]);
    let ib = seal_inbox(&prefix, &r, recipient.public(), b"membership commit", &mut fixed(&[&eph, &m])).unwrap();
    let mut o = Obj::new("inbox blob");
    o.hex("prefix", &prefix).hex("recipient", r.as_bytes()).hex("recipient_kem_seed", s32(0x05).expose());
    o.hex("ephemeral_x25519_private", &eph).hex("mlkem_encaps_randomness", &m).hex("payload", b"membership commit").hex("blob", &ib);
    cases.push(o);
    for (l, p) in [(1usize, 1usize), (9, 10), (1000, 1024), (131073, 135168), (1000000, 1015808)] {
        assert_eq!(padme(l), p);
        let mut o = Obj::new(&format!("padme {l}"));
        o.num("l", l as u64).num("padme", p as u64);
        cases.push(o);
    }
    for (name, bytes) in [("unpad no marker", vec![0u8, 0, 0, 0]), ("unpad nonzero after marker", vec![0x80, 0, 0, 1]), ("unpad not padme length", vec![1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0])] {
        let mut o = Obj::new(name);
        o.hex("padded", &bytes).error(unpad(&bytes).unwrap_err());
        cases.push(o);
    }
    file("spec/crypto.md §5; spec/wire.md §5, §9", "prefix: framing version 1, salt 01*16, no expiry, no commitments; rng supplies the blob key", cases)
}

fn token_and_sign_vectors() -> String {
    let mut cases = Vec::new();
    let salt = [0x12u8; 16];
    let prefix_salt = [0x13u8; 16];
    for (level, secret) in [(1u8, 0x14u8), (2, 0x15), (3, 0x16)] {
        let t = delete_token(&s32(secret), &salt);
        let th = token_hash(t.expose());
        let c = commitment(level, &th, &prefix_salt).unwrap();
        let mut o = Obj::new(&format!("delete token level {level}"));
        o.hex("secret", s32(secret).expose()).hex("salt", &salt).hex("token", t.expose()).hex("token_hash", &th).hex("prefix_salt", &prefix_salt).hex("commitment", &c);
        cases.push(o);
    }
    let sk = SigningSecret::from_seed(&s32(0x08));
    let digest = [0x17u8; 32];
    for d in Domain::ALL {
        let mut o = Obj::new(&format!("signature {}", d.as_str()));
        o.str("domain", d.as_str()).hex("seed", s32(0x08).expose()).hex("public", &sk.verifying_key().to_bytes()).hex("digest", &digest).hex("signature", &sk.sign(d, &digest).0);
        cases.push(o);
    }
    let (l, c, s) = (LabelId([0x0a; 16]), [0x18u8; 32], [0x19u8; 32]);
    let mut o = Obj::new("open signature");
    o.hex("seed", s32(0x08).expose()).hex("label_id", &l.0).hex("challenge", &c).hex("static_key", &s).hex("digest", &open_digest(&l, &c, &s)).hex("signature", &sign_open(&sk, &l, &c, &s).0);
    cases.push(o);
    file("spec/crypto.md §2, §7; spec/wire.md §11.2", "signatures are Ed25519 over domain || digest; RFC 8032 key from seed", cases)
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/crypto")
}

// spec/crypto.md (all sections), spec/wire.md §5, §7: the committed vectors match this build.
#[test]
fn vectors_frozen() {
    let files = [
        ("kdf.json", kdf_vectors()),
        ("keys.json", keys_vectors()),
        ("box.json", box_vectors()),
        ("blob.json", blob_vectors()),
        ("token_sign.json", token_and_sign_vectors()),
    ];
    let write = std::env::var("OSIS_WRITE_VECTORS").is_ok_and(|v| v == "1");
    for (name, content) in files {
        let path = dir().join(name);
        if write {
            std::fs::create_dir_all(dir()).unwrap();
            std::fs::write(&path, &content).unwrap();
        } else {
            let held = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {name}; run with OSIS_WRITE_VECTORS=1"));
            assert!(held == content, "{name} differs from this build's output");
        }
    }
}
