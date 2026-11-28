//! `kdf` (spec/crypto.md §1) and every domain string the spec uses: kdf purposes, BLAKE3
//! derive_key contexts and hash prefixes. Signature domains: `Domain`.

use crate::Secret32;
use osis_base::Role;
use zeroize::{Zeroize, Zeroizing};

/// `kdf(purpose, secret, input) = keyed_hash(derive_key("osis v1 " + purpose, secret), input)`.
/// Callers deriving a public value (a hash, a nonce) copy it out of the `Secret32`.
pub fn kdf(purpose: &str, secret: &[u8], input: &[u8]) -> Secret32 {
    Secret32::from_bytes(blake3::keyed_hash(&kdf_key(purpose, secret), input).into())
}

/// The first 16 bytes of `kdf`: the public tags and blinds the spec cuts to 16 bytes.
pub(crate) fn kdf16(purpose: &str, secret: &[u8], input: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&kdf(purpose, secret, input).expose()[..16]);
    out
}

/// The XOF form of `kdf`, filling `out` (spec/crypto.md §1: where more than 32 bytes are needed).
pub fn kdf_xof(purpose: &str, secret: &[u8], input: &[u8], out: &mut [u8]) {
    let mut h = blake3::Hasher::new_keyed(&kdf_key(purpose, secret));
    h.update(input);
    let mut reader = h.finalize_xof();
    reader.fill(out);
    reader.zeroize();
    h.zeroize();
}

fn kdf_key(purpose: &str, secret: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = blake3::Hasher::new_derive_key(&format!("{PREFIX}{purpose}"));
    h.update(secret);
    let k = Zeroizing::new(h.finalize().into());
    h.zeroize();
    k
}

/// Prefix of every derive_key context.
pub const PREFIX: &str = "osis v1 ";

// kdf purposes (without `PREFIX`).
/// Dependent thing role secrets from the mint admin's (spec/crypto.md §3); `thing_purpose` picks one.
pub const THING_SYNC: &str = "thing sync";
pub const THING_READ: &str = "thing read";
pub const THING_WRITE: &str = "thing write";
pub const THING_ADMIN: &str = "thing admin";
/// A link key's role secrets from its seed (spec/crypto.md §3); `role_purpose` picks one.
pub const ROLE_SYNC: &str = "role sync";
pub const ROLE_READ: &str = "role read";
pub const ROLE_WRITE: &str = "role write";
pub const ROLE_ADMIN: &str = "role admin";
/// A signing key from its seed (spec/crypto.md §3).
pub const SIGN: &str = "sign";
/// KEM key pair from a seed or role secret.
pub const KEM: &str = "kem";
/// Link key creation nonce from the seed (spec/wire.md §3).
pub const CREATION_NONCE: &str = "creation nonce";
/// Symmetric box key (spec/wire.md §7).
pub const BOX: &str = "box";
/// History box key.
pub const HISTORY: &str = "history";
/// Epoch nonce from its roles secret (spec/crypto.md §4).
pub const EPOCH: &str = "epoch";
/// A read epoch's roles secret from its secret (spec/crypto.md §4, Roles secrets).
pub const ROLES: &str = "roles";
/// Wrap key from a sync ID read secret (spec/crypto.md §5).
pub const WRAP: &str = "wrap";
/// Section key from a thing's read or roles secret or a copy's blob key (spec/crypto.md §5).
pub const SECTION: &str = "section";
/// Keyed content hashes (spec/crypto.md §6).
pub const DELTA: &str = "delta";
pub const LINK: &str = "link";
pub const LINK_TREE: &str = "link tree";
/// A delete key's blinding factor and blinded signing nonce (spec/crypto.md §7).
pub const DELETE_BLIND: &str = "delete blind";
pub const DELETE_NONCE: &str = "delete nonce";
/// A linked blob's blind, from its blob key (spec/crypto.md §7).
pub const LINK_BLIND: &str = "link blind";
/// A linked blob's commitments' blind, from its link blind and its thing (spec/crypto.md §7).
pub const THING_BLIND: &str = "thing blind";
/// Sync ID role keys (spec/sync-ids.md §2).
pub const SYNC_KEY: &str = "sync key";
pub const SYNC_WRITE: &str = "sync write";
pub const SYNC_DELETE: &str = "sync delete";
pub const SYNC_DEPOSIT: &str = "sync deposit";
/// A holder's claim key (spec/wire.md §8).
pub const CLAIM_KEY: &str = "claim key";
/// A sync epoch's step secret, and the public's claim key (spec/wire.md §8).
pub const STEP_KEY: &str = "step key";
pub const PUBLIC_CLAIM_KEY: &str = "public claim key";
/// A thing's genesis seed from its mint admin's, and its genesis step's key
/// (spec/crypto.md §3 Genesis seed, spec/wire.md §8).
pub const SYNC_GENESIS: &str = "sync genesis";
pub const GENESIS_STEP: &str = "genesis step";
/// The pair key of a record, or of a connection with none (`pair_key`).
pub const PAIR_KEY: &str = "pair key";
/// A beacon's key over its match value and sync ID (spec/sync-opens.md §5).
pub const BEACON: &str = "beacon";
/// A Hit over a beacon, its sender's side and the connection (`beacon_hit`).
pub const BEACON_HIT: &str = "beacon hit";
/// The tag answering a Hit (`beacon_reply`).
pub const BEACON_REPLY: &str = "beacon reply";
/// The proof credential of a sync key, from its seed (`sync_proof`).
pub const SYNC_PROOF: &str = "sync proof";
/// A thing's path key in a split commit, from its independent's read roles secret (spec/crypto.md §5).
pub const PATH: &str = "path";
/// A split entry's commitment to its path key (spec/crypto.md §5 Path entry).
pub const PATH_COMMIT: &str = "path commit";
/// A claim page's blob key, from its commit blob's key and its own salt (spec/wire.md §5 Claim pages).
pub const CLAIM_PAGE: &str = "claim page";

/// Every kdf purpose, for distinctness checks and vectors.
pub const PURPOSES: [&str; 40] = [
    THING_SYNC, THING_READ, THING_WRITE, THING_ADMIN, ROLE_SYNC, ROLE_READ, ROLE_WRITE, ROLE_ADMIN, SIGN, KEM, CREATION_NONCE, BOX, HISTORY, EPOCH, ROLES, WRAP, SECTION,
    DELTA, LINK, LINK_TREE, DELETE_BLIND, DELETE_NONCE, LINK_BLIND, THING_BLIND, SYNC_KEY, SYNC_WRITE, SYNC_DELETE, SYNC_DEPOSIT, CLAIM_KEY, STEP_KEY, PUBLIC_CLAIM_KEY, SYNC_GENESIS, GENESIS_STEP,
    BEACON, BEACON_HIT, BEACON_REPLY, SYNC_PROOF, PATH, PATH_COMMIT, CLAIM_PAGE,
];

// Full derive_key contexts used directly (not through `kdf`).
/// Dedup secret from the creation nonce (spec/crypto.md §3).
pub const DEDUP: &str = "osis v1 dedup";
/// Hybrid KEM combiner (spec/crypto.md §1).
pub const HYBRID_KEM: &str = "osis v1 hybrid kem";

// Unkeyed hash prefixes.
/// Sync ID = BLAKE3(SYNC_ID || genesis delete key)[..16] (spec/wire.md §8).
pub const SYNC_ID: &str = "osis v1 sync id";

pub fn thing_purpose(role: Role) -> &'static str {
    match role {
        Role::Sync => THING_SYNC,
        Role::Read => THING_READ,
        Role::Write => THING_WRITE,
        Role::Admin => THING_ADMIN,
    }
}

pub fn role_purpose(role: Role) -> &'static str {
    match role {
        Role::Sync => ROLE_SYNC,
        Role::Read => ROLE_READ,
        Role::Write => ROLE_WRITE,
        Role::Admin => ROLE_ADMIN,
    }
}

/// The pair key from two nodes' nonces (spec/sync-opens.md §3), or from a connection's
/// challenges where no record is kept (spec/sync-opens.md §3).
pub fn pair_key(a: &[u8; 32], b: &[u8; 32]) -> Secret32 {
    kdf(PAIR_KEY, a, b)
}

/// The tag a dialer sends for a record it holds with pair key `r` on this connection
/// (`dialer` and `listener` its Hello challenges, `key` the static key it dialed): only a holder
/// of r computes it, and a tag sent to one listener is no tag at another.
pub fn resume_tag(r: &[u8; 32], key: &[u8; 32], dialer: &[u8; 32], listener: &[u8; 32]) -> [u8; 32] {
    resume_hash(r, b"resume", key, dialer, listener)
}

/// The listener's answer to a tag it matched: shows it holds r, and differs from the tag it
/// answers, so echoing the dialer's own value proves nothing.
pub fn resumed_tag(r: &[u8; 32], key: &[u8; 32], dialer: &[u8; 32], listener: &[u8; 32]) -> [u8; 32] {
    resume_hash(r, b"resumed", key, dialer, listener)
}

/// A beacon: `BLAKE3(key = kdf("beacon", match, L), r)` (spec/sync-opens.md §5): the
/// value both sides compute for one credential, so a filter entry is its first bits.
pub fn beacon(match_value: &[u8; 32], sync_id: &[u8; 16], r: &[u8; 32]) -> [u8; 32] {
    *blake3::keyed_hash(kdf(BEACON, match_value, sync_id).expose(), r).as_bytes()
}

/// The match value of a proof of a sync secret (spec/sync-opens.md §4, admissible):
/// `kdf("sync proof", seed, "")`, `seed` the sync key's (`sync_id::role_key_seed`). Invariant:
/// only a holder of that sync secret computes it, so its beacon, Hit and tag prove the secret as
/// a read secret's do, and a node holding only L's public keys finds no proof in a filter (model
/// `ON_proofpub`).
pub fn sync_proof(seed: &Secret32) -> [u8; 32] {
    *kdf(SYNC_PROOF, seed.expose(), b"").expose()
}

/// Which side a Hit or a tag is sent by and the connection it binds: `(by_listener, listener key,
/// dialer challenge, listener challenge)`.
pub type Side<'a> = (bool, &'a [u8; 32], &'a [u8; 32], &'a [u8; 32]);

/// `kdf(purpose, match || L, side || listener key || challenges || beacon)`: a Hit or its reply.
fn bound(purpose: &str, match_value: &[u8; 32], sync_id: &[u8; 16], side: Side<'_>, beacon: &[u8; 32]) -> [u8; 32] {
    let (by_listener, key, dialer, listener) = side;
    let input = [&[u8::from(by_listener)], &key[..], &dialer[..], &listener[..], &beacon[..]].concat();
    *kdf(purpose, &[&match_value[..], &sync_id[..]].concat(), &input).expose()
}

/// A Hit (spec/wire.md §11.2): a beacon as one side shows it on one connection. A beacon is the same
/// value on both sides, so a Hit carries its sender's side, the listener's key and both challenges:
/// a peer that reflects one to its sender, or carries it to another connection, shows nothing.
pub fn beacon_hit(match_value: &[u8; 32], sync_id: &[u8; 16], beacon: &[u8; 32], side: Side<'_>) -> [u8; 32] {
    bound(BEACON_HIT, match_value, sync_id, side, beacon)
}

/// The tag answering a Hit, by the replier's side: computable only with the credential.
pub fn beacon_reply(match_value: &[u8; 32], sync_id: &[u8; 16], beacon: &[u8; 32], side: Side<'_>) -> [u8; 32] {
    bound(BEACON_REPLY, match_value, sync_id, side, beacon)
}

/// A connection's place among the connections of one record (spec/sync-opens.md §3, pair key): the
/// smaller is kept. Both ends compute it from what the connection showed, so they agree whatever
/// order the connections' answers arrived in.
pub fn connection_order(r: &[u8; 32], dialer: &[u8; 32], listener: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(r);
    h.update(dialer);
    h.update(listener);
    *h.finalize().as_bytes()
}

/// The digest of a record's shared set (spec/sync-opens.md §3, agreement): the xor over its members of
/// `BLAKE3(key = r, sync_id)`. Equal sets give equal digests, whatever their size.
pub fn members_digest<'a>(r: &[u8; 32], members: impl IntoIterator<Item = &'a [u8; 16]>) -> [u8; 32] {
    let mut d = [0u8; 32];
    for l in members {
        for (x, y) in d.iter_mut().zip(blake3::keyed_hash(r, l).as_bytes()) {
            *x ^= y;
        }
    }
    d
}

fn resume_hash(r: &[u8; 32], word: &[u8], key: &[u8; 32], dialer: &[u8; 32], listener: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(r);
    h.update(word);
    h.update(key);
    h.update(dialer);
    h.update(listener);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Domain;
    use std::collections::BTreeSet;

    // spec/crypto.md §1, §2: every context, prefix and signature domain is distinct.
    #[test]
    fn strings_distinct() {
        let mut all: Vec<String> = PURPOSES.iter().map(|p| format!("{PREFIX}{p}")).collect();
        all.extend([DEDUP, HYBRID_KEM, SYNC_ID, "osis v1 gear table"].map(String::from));
        all.extend(Domain::ALL.iter().map(|d| d.as_str().to_string()));
        let set: BTreeSet<&String> = all.iter().collect();
        assert_eq!(set.len(), all.len());
        assert_eq!(all.len(), PURPOSES.len() + 4 + Domain::ALL.len());
    }

    // spec/crypto.md §1: kdf = keyed_hash(derive_key("osis v1 " + purpose, secret), input).
    #[test]
    fn kdf_definition() {
        let secret = [0x11; 32];
        let k = blake3::derive_key("osis v1 wrap", &secret);
        assert_eq!(kdf(WRAP, &secret, b"in").expose(), blake3::keyed_hash(&k, b"in").as_bytes());
        let mut out = [0u8; 96];
        kdf_xof(KEM, &secret, b"", &mut out);
        assert_eq!(out[..32], kdf(KEM, &secret, b"").expose()[..]);
        assert_ne!(kdf(LINK, &secret, b"x"), kdf(LINK_TREE, &secret, b"x"));
    }
}
