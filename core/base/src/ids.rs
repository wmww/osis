//! Tids, AKs, links, node addresses and fixed-size ids (spec/data-model.md §1, §2, §6, §7, §9;
//! spec/sync-ids.md §2; spec/sync-transport.md §1).

use crate::cbor::encode;
use crate::format::{MAX_AK_BYTES, TID_LEN, TID_TEXT_LEN};
use crate::value::Value;
use crate::{ErrorClass, hash};
use std::fmt;

/// A thing's identity: 120 bits, minted offline when it is created. `Display` and `parse` give its
/// text form.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tid([u8; TID_LEN]);

impl Tid {
    /// The zero tid: the public (spec/permissions.md §1), a holder that is no thing, standing for
    /// every party. No creation record hashes to it, so nothing signs as it, holds a role on it or
    /// lists it on a path.
    pub const PUBLIC: Tid = Tid([0; TID_LEN]);

    /// Whether this names the public.
    pub fn is_public(&self) -> bool {
        *self == Tid::PUBLIC
    }

    /// From its 15 bytes. Any bytes are a valid reference, perhaps to nothing.
    pub const fn from_bytes(b: [u8; TID_LEN]) -> Tid {
        Tid(b)
    }
    pub const fn as_bytes(&self) -> &[u8; TID_LEN] {
        &self.0
    }
    /// `osis://` plus the text form.
    pub fn to_uri(&self) -> String {
        format!("osis://{self}")
    }
    /// Parses the 20-character text form, with or without `osis://`.
    pub fn parse(s: &str) -> Result<Tid, TidParseError> {
        let s = s.strip_prefix("osis://").unwrap_or(s);
        if s.len() != TID_TEXT_LEN {
            return Err(TidParseError);
        }
        let out: [u8; TID_LEN] = crate::base64url::decode(s).and_then(|b| b.try_into().ok()).ok_or(TidParseError)?;
        Ok(Tid(out))
    }
}

/// Unpadded base64url; 15 bytes give exactly 20 characters.
impl fmt::Display for Tid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::base64url::encode(&self.0))
    }
}

impl fmt::Debug for Tid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tid({self})")
    }
}

impl std::str::FromStr for Tid {
    type Err = TidParseError;
    fn from_str(s: &str) -> Result<Tid, TidParseError> {
        Tid::parse(s)
    }
}

/// A public signing key (spec/permissions.md §1 Signing key): a value with no tid, aspect or
/// roster. It holds grants on the things it signs as; nothing is sealed to it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignKey(pub [u8; 32]);

impl SignKey {
    /// The `signing_key` value (spec/wire.md §3): `1617([1, h'...'])`, the ed25519 case.
    pub fn to_value(&self) -> Value {
        Value::Enum(SIGNING_KEY_ED25519, Some(Box::new(Value::Bytes(self.0.to_vec()))))
    }
    /// Reads a `signing_key` value of the ed25519 case, 32 bytes; `None` for anything else.
    pub fn from_value(v: &Value) -> Option<SignKey> {
        match v {
            Value::Enum(SIGNING_KEY_ED25519, Some(p)) => match p.as_ref() {
                Value::Bytes(b) => b.as_slice().try_into().ok().map(SignKey),
                _ => None,
            },
            _ => None,
        }
    }
}

impl fmt::Debug for SignKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignKey({})", crate::base64url::encode(&self.0[..9]))
    }
}

/// The holder of a grant (spec/permissions.md §1): a thing (`roles.0`), or a signing key
/// (`signers.0`, a key grant). Keys order after things.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Holder {
    Thing(Tid),
    Key(SignKey),
}

impl Holder {
    /// The thing it is, where it is no key.
    pub fn thing(&self) -> Option<Tid> {
        match self {
            Holder::Thing(t) => Some(*t),
            Holder::Key(_) => None,
        }
    }
}

impl From<Tid> for Holder {
    fn from(t: Tid) -> Holder {
        Holder::Thing(t)
    }
}

/// Text that is no tid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TidParseError;
crate::impl_error!(TidParseError, "invalid tid text form");
impl crate::Classified for TidParseError {
    fn class(&self) -> ErrorClass {
        ErrorClass::BadInput
    }
}

/// A thing's creation record (spec/wire.md §3): the `creation` struct of the core schema. How
/// the thing came to exist is the one fact fixed in it (spec/permissions.md §1): minted with a
/// mint admin, or with a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreationRecord {
    /// Its mint admin or its key.
    pub minter: Minter,
    /// 32 bytes: random, a link key's from its seed (spec/crypto.md §3).
    pub nonce: [u8; 32],
    /// Beside a mint admin: it is a link's thing K, made for this target; beside a key: it is
    /// a link key, holding a grant on this K (spec/permissions.md §7).
    pub link: Option<Tid>,
    /// Beside a mint admin only: the wall ms the thing ends at, whatever any minting of it says
    /// (spec/commits.md §5 Destruction).
    pub expires: Option<u64>,
}

/// What a thing was minted with (spec/permissions.md §1): its mint admin, holding its record
/// edge (admin) from the start, or a key, the record's key, holding admin from the start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Minter {
    Admin(Tid),
    Key(SignKey),
}

// spec/wire.md §3: `creation = struct { admin 0: weak, key 1: signing_key, nonce 2: blob, link 3: weak, expires 5: timestamp }`.
const REC_ADMIN: i64 = 0;
const REC_KEY: i64 = 1;
const REC_NONCE: i64 = 2;
const REC_LINK: i64 = 3;
const REC_EXPIRES: i64 = 5;
/// `signing_key` case ed25519 (spec/wire.md §3).
pub const SIGNING_KEY_ED25519: u64 = 1;

impl CreationRecord {
    /// A thing minted with admin `admin`.
    pub fn with_admin(admin: Tid, nonce: [u8; 32]) -> CreationRecord {
        CreationRecord { minter: Minter::Admin(admin), nonce, link: None, expires: None }
    }
    /// A thing minted with `key`.
    pub fn with_key(key: SignKey, nonce: [u8; 32]) -> CreationRecord {
        CreationRecord { minter: Minter::Key(key), nonce, link: None, expires: None }
    }
    /// The record's value; its canonical encoding is what the tid hashes.
    pub fn to_value(&self) -> Value {
        let mut m = crate::ValueMap::new();
        match self.minter {
            Minter::Admin(admin) => m.insert(Value::Int(REC_ADMIN), Value::Weak(admin)),
            Minter::Key(key) => m.insert(Value::Int(REC_KEY), key.to_value()),
        };
        m.insert(Value::Int(REC_NONCE), Value::Bytes(self.nonce.to_vec()));
        if let Some(t) = self.link {
            m.insert(Value::Int(REC_LINK), Value::Weak(t));
        }
        if let Some(t) = self.expires {
            m.insert(Value::Int(REC_EXPIRES), Value::Int(i64::try_from(t).unwrap_or(i64::MAX)));
        }
        Value::Map(m)
    }
    /// Reads a record: exactly one of admin and key, a 32-byte nonce, `link` a weak, `expires`
    /// only beside admin, no other field, key an ed25519 `signing_key` of 32 bytes. `None` is bad
    /// input (an unknown key case included: callers that must park it check the enum case
    /// themselves).
    pub fn from_value(v: &Value) -> Option<CreationRecord> {
        let Value::Map(m) = v else { return None };
        let nonce: [u8; 32] = match m.get(&Value::Int(REC_NONCE)) {
            Some(Value::Bytes(b)) => b.as_slice().try_into().ok()?,
            _ => return None,
        };
        let minter = match (m.get(&Value::Int(REC_ADMIN)), m.get(&Value::Int(REC_KEY))) {
            (Some(Value::Weak(admin)), None) => Minter::Admin(*admin),
            (None, Some(k)) => Minter::Key(SignKey::from_value(k)?),
            _ => return None,
        };
        let link = match m.get(&Value::Int(REC_LINK)) {
            None => None,
            Some(Value::Weak(t)) => Some(*t),
            _ => return None,
        };
        let expires = match m.get(&Value::Int(REC_EXPIRES)) {
            None => None,
            Some(Value::Int(t)) if *t >= 0 && matches!(minter, Minter::Admin(_)) => Some(t.unsigned_abs()),
            _ => return None,
        };
        (m.len() == 2 + usize::from(link.is_some()) + usize::from(expires.is_some())).then_some(CreationRecord { minter, nonce, link, expires })
    }
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
    /// The thing's tid: the first 15 bytes of BLAKE3 of the record's encoding (spec/wire.md §3).
    pub fn tid(&self) -> Tid {
        let h = hash::hash(&encode(&self.to_value()));
        let mut b = [0u8; TID_LEN];
        for (d, s) in b.iter_mut().zip(h) {
            *d = s;
        }
        Tid(b)
    }
    /// Whether this is a link's thing K (spec/permissions.md §7).
    pub fn is_link(&self) -> bool {
        self.link_target().is_some()
    }
    /// The wall ms the thing ends at, whatever any minting of it says; `None`: it never expires
    /// (spec/commits.md §5 Destruction). Every minting's commit carries it as its `expires`.
    pub fn expires(&self) -> Option<u64> {
        self.expires
    }
    /// The target a link's thing K was made for, as its creator says (spec/permissions.md §7).
    pub fn link_target(&self) -> Option<Tid> {
        self.mint_admin().and(self.link)
    }
    /// The K a link key holds a grant on (spec/permissions.md §7).
    pub fn link_key_of(&self) -> Option<Tid> {
        self.key().and(self.link)
    }
    /// The mint admin (spec/permissions.md §1): the next thing up the record chain, whose
    /// secrets a dependent thing derives from (none for a thing minted with a key).
    pub fn mint_admin(&self) -> Option<Tid> {
        match self.minter {
            Minter::Admin(a) => Some(a),
            Minter::Key(_) => None,
        }
    }
    /// The key the record holds (spec/permissions.md §1 Key grant), where it names no mint admin.
    pub fn key(&self) -> Option<SignKey> {
        match self.minter {
            Minter::Admin(_) => None,
            Minter::Key(k) => Some(k),
        }
    }
    /// The holder of the record's admin edge from the start: its mint admin (the record edge) or
    /// its key (the record's key).
    pub fn holder(&self) -> Holder {
        match self.minter {
            Minter::Admin(a) => Holder::Thing(a),
            Minter::Key(k) => Holder::Key(k),
        }
    }
}

/// The markers of an AK (spec/data-model.md §2), each independent of the others.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Markers {
    /// `+`: its writes are held in memory, never in durable commits.
    pub ephemeral: bool,
    /// `^`: writing it needs admin.
    pub admin_only: bool,
    /// `~` in place of the `.`: it has no current value; it is only written.
    pub signal: bool,
    /// `@` before the `~` (never beside `+` or `^`): an external signal.
    pub external: bool,
}

/// An aspect key: name segments `[a-z_][a-z0-9_]*` joined by `:`, after an optional leading
/// `:<tid>` segment; then the markers `+` (ephemeral) and `^` (admin-only); then `.` (an aspect)
/// or `~` (a signal), or `@~` alone (an external signal), and the version: `name.0`,
/// `contact:names.0`, `:<tid>:foo:bar+^.1`, `x+~0`, `grant@~0`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Ak(String);

/// Byte offsets and fields of a valid AK.
#[derive(Clone, Copy)]
struct Parsed {
    /// Start of the name segments: 0, or after the tid segment.
    names: usize,
    /// End of the name segments (the markers start here).
    end: usize,
    version: u64,
    markers: Markers,
}

const fn name_start(c: u8) -> bool {
    c.is_ascii_lowercase() || c == b'_'
}

/// The grammar of [`Ak`]; `const` so key constants are checked at build time ([`Ak::check`]).
const fn parse(s: &[u8]) -> Option<Parsed> {
    if s.len() > MAX_AK_BYTES {
        return None;
    }
    let mut rest = s;
    let mut names = 0;
    if let [b':', tail @ ..] = rest {
        let mut t = tail;
        let mut n = 0;
        while n < TID_TEXT_LEN {
            match t {
                [c, r @ ..] if c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_' => t = r,
                _ => return None,
            }
            n += 1;
        }
        let [b':', r @ ..] = t else { return None };
        rest = r;
        names = TID_TEXT_LEN + 2;
    }
    loop {
        match rest {
            [c, r @ ..] if name_start(*c) => rest = r,
            _ => return None,
        }
        while let [c, r @ ..] = rest {
            if !(name_start(*c) || c.is_ascii_digit()) {
                break;
            }
            rest = r;
        }
        match rest {
            [b':', r @ ..] => rest = r,
            _ => break,
        }
    }
    let end = s.len() - rest.len();
    let external = matches!(rest, [b'@', b'~', ..]);
    if external {
        rest = match rest {
            [_, r @ ..] => r,
            _ => rest,
        };
    }
    let mut ephemeral = false;
    if let [b'+', r @ ..] = rest
        && !external
    {
        ephemeral = true;
        rest = r;
    }
    let mut admin_only = false;
    if let [b'^', r @ ..] = rest
        && !external
    {
        admin_only = true;
        rest = r;
    }
    let signal = match rest {
        [b'.', r @ ..] if !external => {
            rest = r;
            false
        }
        [b'~', r @ ..] => {
            rest = r;
            true
        }
        _ => return None,
    };
    // the version: decimal, no leading zero, to the end
    let mut version: u64 = 0;
    let mut digits = 0;
    while let [c, r @ ..] = rest {
        if !c.is_ascii_digit() || (digits == 1 && version == 0) {
            return None;
        }
        version = match version.checked_mul(10) {
            Some(v) => match v.checked_add((*c - b'0') as u64) {
                Some(v) => v,
                None => return None,
            },
            None => return None,
        };
        digits += 1;
        rest = r;
    }
    if digits == 0 {
        return None;
    }
    Some(Parsed { names, end, version, markers: Markers { ephemeral, admin_only, signal, external } })
}

impl Ak {
    pub fn new(s: impl Into<String>) -> Result<Ak, AkError> {
        let s = s.into();
        match parse(s.as_bytes()) {
            Some(_) => Ok(Ak(s)),
            None => Err(AkError),
        }
    }
    #[doc(hidden)]
    /// `s` if it is a valid AK, a signal (`~`) exactly when `signal`, else a panic: at build
    /// time in a `const` (key constants).
    pub const fn check(s: &'static str, signal: bool) -> &'static str {
        let p = parse(s.as_bytes());
        assert!(p.is_some(), "invalid aspect key");
        assert!(matches!(p, Some(p) if p.markers.signal == signal), "a `~` key is a signal key, any other a value key");
        s
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    fn parsed(&self) -> Parsed {
        // only `MIN` fails to parse: it reads as no segments, version 0, no markers
        parse(self.0.as_bytes()).unwrap_or(Parsed { names: 0, end: 0, version: 0, markers: Markers::default() })
    }
    /// The name segments (the tid segment is [`Ak::tid`]).
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        let p = self.parsed();
        self.0.get(p.names..p.end).unwrap_or("").split(':').filter(|s| !s.is_empty())
    }
    /// The key up to its markers: tid and name segments (`a:b+^.1` is `a:b`).
    pub fn unmarked(&self) -> &str {
        self.0.get(..self.parsed().end).unwrap_or("")
    }
    /// The aspect version, the digits ending the key.
    pub fn version(&self) -> u64 {
        self.parsed().version
    }
    /// The leading tid segment, if any.
    pub fn tid(&self) -> Option<Tid> {
        if self.parsed().names == 0 {
            return None;
        }
        self.0.get(1..=TID_TEXT_LEN).and_then(|t| Tid::parse(t).ok())
    }
    /// The `+` marker: its writes are held in memory, never in durable commits.
    pub fn ephemeral(&self) -> bool {
        self.parsed().markers.ephemeral
    }
    /// The `^` marker: writing it needs admin.
    pub fn admin_only(&self) -> bool {
        self.parsed().markers.admin_only
    }
    /// The `~` marker (in place of the `.`): it has no current value; it is only written.
    pub fn signal(&self) -> bool {
        self.parsed().markers.signal
    }
    /// The `@` marker (before `~`): an external signal, which anyone holding the thing's public key
    /// record may fire (spec/data-model.md §2, spec/sync-inbox.md §2).
    pub fn external(&self) -> bool {
        self.parsed().markers.external
    }
    #[doc(hidden)]
    /// The markers of a valid AK's text, read from its tail (`+`, `^`, `@` and `~` occur nowhere
    /// else in one). For keys held as text (`RawKey::ak`).
    pub fn markers_of(s: &str) -> Markers {
        let b = s.as_bytes();
        let mut i = b.len();
        while i > 0 && b.get(i - 1).is_some_and(u8::is_ascii_digit) {
            i -= 1;
        }
        let signal = b.get(i.wrapping_sub(1)) == Some(&b'~');
        let i = i.saturating_sub(1);
        if signal && b.get(i.wrapping_sub(1)) == Some(&b'@') {
            return Markers { ephemeral: false, admin_only: false, signal, external: true };
        }
        let admin_only = b.get(i.wrapping_sub(1)) == Some(&b'^');
        let i = i.saturating_sub(usize::from(admin_only));
        let ephemeral = b.get(i.wrapping_sub(1)) == Some(&b'+');
        Markers { ephemeral, admin_only, signal, external: false }
    }
    /// Whether this key is a later version of `other`: the same tid and name segments, a higher
    /// version, any markers.
    pub fn successor_of(&self, other: &Ak) -> bool {
        let (p, q) = (self.parsed(), other.parsed());
        self.0.get(..p.end) == other.0.get(..q.end) && p.version > q.version
    }
    /// Sorts before every key, valid none: the start of a range over one thing's aspects.
    #[doc(hidden)]
    pub const MIN: Ak = Ak(String::new());
}

impl fmt::Display for Ak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Text that is no aspect key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkError;
crate::impl_error!(AkError, "invalid aspect key");
impl crate::Classified for AkError {
    fn class(&self) -> ErrorClass {
        ErrorClass::BadInput
    }
}

macro_rules! byte_id {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; $len]);
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "("))?;
                for b in self.0.iter().take(8) {
                    write!(f, "{b:02x}")?;
                }
                write!(f, "..)")
            }
        }
    };
}

byte_id!(
    /// BLAKE3 of a whole blob (spec/crypto.md §5).
    BlobId, 32
);
byte_id!(
    /// BLAKE3 of a commit header (spec/commits.md §1).
    CommitId, 32
);
byte_id!(
    /// A sync ID: the first 16 bytes of BLAKE3 over its genesis step's delete key (spec/wire.md §8).
    SyncId, 16
);

/// Link to a chunk, tree node or page (spec/data-model.md §5-§6, spec/crypto.md §6): what reads
/// the blob (content hash, blob ID, suite and key) and what deletes it (the prefix salt and the
/// delete keys its commitments bear, the writer's claim). `Debug` hides the blob key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Link {
    /// Keyed content hash of the canonical value the subtree encodes.
    pub hash: [u8; 32],
    pub blob: BlobId,
    pub suite: u8,
    pub key: [u8; 32],
    /// The blob's prefix salt.
    pub salt: [u8; 16],
    pub del: Del,
}

impl fmt::Debug for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Link({:?}, suite {}, key .., del {:?})", self.blob, self.suite, self.del)
    }
}

/// The delete keys a linked blob's one commitment group bears, at most one per level 1 to 3
/// (spec/crypto.md §7), as its writer claims them: `[DeleteKey*]` by level ascending.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Del([Option<[u8; 32]>; 3]);

impl Del {
    /// No keys (a `nobody` delta's blob, a header list of a header without a level-2 key).
    pub const NONE: Del = Del([None; 3]);

    /// From `(level, key)` pairs in any order; `None` for a level outside 1 to 3 or a level twice.
    pub fn from_keys(keys: impl IntoIterator<Item = (u8, [u8; 32])>) -> Option<Del> {
        let mut d = Del::NONE;
        for (level, key) in keys {
            let slot = d.0.get_mut(usize::from(level).checked_sub(1)?)?;
            if slot.replace(key).is_some() {
                return None;
            }
        }
        Some(d)
    }

    /// `(level, key)` by level ascending.
    pub fn iter(&self) -> impl Iterator<Item = (u8, [u8; 32])> + '_ {
        (1u8..).zip(self.0.iter()).filter_map(|(l, k)| k.map(|k| (l, k)))
    }

    pub fn len(&self) -> usize {
        self.0.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for Del {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let levels: Vec<u8> = self.iter().map(|(l, _)| l).collect();
        write!(f, "Del{levels:?}")
    }
}

/// Who may purge a write: admins always may; by default only they may.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum PurgeBy {
    /// Its thing's admins.
    #[default]
    Admin = 1,
    /// Whom it is by, or an admin.
    AuthorOrAdmin = 2,
    /// Anyone who may write its thing.
    Writer = 3,
}

impl PurgeBy {
    /// Every set, smallest first.
    pub const ALL: [PurgeBy; 3] = [PurgeBy::Admin, PurgeBy::AuthorOrAdmin, PurgeBy::Writer];
    /// Its name in a schema: `admin`, `author_or_admin`, `writer`.
    pub fn name(self) -> &'static str {
        match self {
            PurgeBy::Admin => "admin",
            PurgeBy::AuthorOrAdmin => "author_or_admin",
            PurgeBy::Writer => "writer",
        }
    }
    #[doc(hidden)]
    pub fn from_id(id: u64) -> Option<PurgeBy> {
        PurgeBy::ALL.into_iter().find(|p| *p as u64 == id)
    }
    /// The set holds the author.
    pub fn author(self) -> bool {
        matches!(self, PurgeBy::AuthorOrAdmin | PurgeBy::Writer)
    }
    /// The set holds every writer.
    pub fn writer(self) -> bool {
        self == PurgeBy::Writer
    }
}

/// A role, ordered sync < read < write < admin. `Sync` holds and serves a thing's sync IDs and
/// reads nothing of it (spec/permissions.md §1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Role {
    Sync,
    Read,
    Write,
    Admin,
}

impl Role {
    /// Every role, lowest first.
    pub const ALL: [Role; 4] = [Role::Sync, Role::Read, Role::Write, Role::Admin];
    /// The role's value in a structure and its byte in the nonce rule (spec/wire.md §1).
    pub fn id(self) -> u8 {
        match self {
            Role::Read => 0,
            Role::Write => 1,
            Role::Admin => 2,
            Role::Sync => 3,
        }
    }
    pub fn from_id(id: u64) -> Option<Role> {
        Role::ALL.into_iter().find(|r| u64::from(r.id()) == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/data-model.md §1: text form is 20 chars of unpadded base64url, `osis://` optional.
    #[test]
    fn tid_text_round_trip() {
        let t = Tid::from_bytes(*b"\x00\x10\x83\x10Q\x87 \x92\x8b0\xd3\x8f\x41\x14\x93");
        let s = t.to_string();
        assert_eq!(s.len(), 20);
        assert_eq!(s, "ABCDEFGHIJKLMNOPQRST");
        assert_eq!(Tid::parse(&s), Ok(t));
        assert_eq!(Tid::parse(&t.to_uri()), Ok(t));
        let all = Tid::from_bytes([0xff; 15]);
        assert_eq!(all.to_string(), "____________________");
        assert_eq!(Tid::parse("____________________"), Ok(all));
    }

    // spec/data-model.md §1: anything but 20 base64url chars is rejected.
    #[test]
    fn tid_parse_rejects() {
        for s in ["", "ABCDEFGHIJKLMNOPQRS", "ABCDEFGHIJKLMNOPQRSTU", "ABCDEFGHIJKLMNOPQRS=", "ABCDEFGHIJKLMNOPQRS+", "osis:/ABCDEFGHIJKLMNOPQRST"] {
            assert_eq!(Tid::parse(s), Err(TidParseError), "{s}");
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        crate::hex::decode(s).unwrap()
    }

    // spec/wire.md §3: frozen layout of the record forms; tid = first 15 bytes of BLAKE3 of
    // exactly these bytes.
    #[test]
    fn creation_record_bytes() {
        let r = CreationRecord::with_admin(Tid::from_bytes([7; 15]), [1; 32]);
        let rb = hex(&format!("a2 00 d90655 4f{} 02 5820{}", "07".repeat(15), "01".repeat(32)));
        let l = CreationRecord { link: Some(Tid::from_bytes([8; 15])), ..r.clone() };
        assert_ne!(l.tid(), r.tid(), "the link's target is in the tid");
        assert!(l.is_link() && !r.is_link());
        assert_eq!(l.link_target(), Some(Tid::from_bytes([8; 15])));
        assert_eq!(CreationRecord::from_value(&l.to_value()), Some(l.clone()));
        // `link` only a weak
        let with = |f: &dyn Fn(&mut crate::ValueMap)| {
            let Value::Map(mut m) = l.to_value() else { panic!() };
            f(&mut m);
            CreationRecord::from_value(&Value::Map(m))
        };
        assert!(with(&|m| { m.insert(Value::Int(REC_LINK), Value::Bool(true)); }).is_none());
        let k = CreationRecord::with_key(crate::SignKey([9; 32]), [1; 32]);
        // beside a key, `link` makes a link key, naming its K
        let lk = with(&|m| { m.remove(&Value::Int(REC_ADMIN)); m.insert(Value::Int(REC_KEY), crate::SignKey([9; 32]).to_value()); }).unwrap();
        assert_eq!((lk.link_key_of(), lk.link_target(), lk.is_link()), (Some(Tid::from_bytes([8; 15])), None, false));
        assert_eq!(lk, CreationRecord { link: Some(Tid::from_bytes([8; 15])), ..k.clone() });
        // `expires`: field 5, a uint beside admin only, in the tid
        let e = CreationRecord { expires: Some(5), ..r.clone() };
        assert_ne!(e.tid(), r.tid(), "the expiry is in the tid");
        assert_eq!((e.expires(), r.expires(), k.expires()), (Some(5), None, None));
        assert_eq!(CreationRecord::from_value(&e.to_value()), Some(e.clone()));
        let eb = hex(&format!("a3 00 d90655 4f{} 02 5820{} 05 05", "07".repeat(15), "01".repeat(32)));
        assert_eq!(encode(&e.to_value()), eb);
        let field = |base: &CreationRecord, v: Value| {
            let Value::Map(mut m) = base.to_value() else { panic!() };
            m.insert(Value::Int(REC_EXPIRES), v);
            CreationRecord::from_value(&Value::Map(m))
        };
        assert!(field(&k, Value::Int(5)).is_none(), "expires beside key");
        assert!(field(&r, Value::Int(-1)).is_none(), "negative expires");
        assert!(field(&r, Value::Bool(true)).is_none(), "expires no uint");
        let kb = hex(&format!("a2 01 d90651 82 01 5820{} 02 5820{}", "09".repeat(32), "01".repeat(32)));
        for (rec, bytes) in [(r, rb), (k, kb)] {
            assert_eq!(encode(&rec.to_value()), bytes);
            assert_eq!(rec.tid().as_bytes()[..], blake3::hash(&bytes).as_bytes()[..15]);
            assert_eq!(CreationRecord::from_value(&rec.to_value()), Some(rec));
        }
    }

    // spec/wire.md §3: exactly one of admin and key, a 32-byte nonce, ed25519 keys of 32 bytes,
    // no other field.
    #[test]
    fn creation_record_rejects() {
        let admin = Tid::from_bytes([7; 15]);
        let r = CreationRecord::with_admin(admin, [1; 32]);
        assert_ne!(r.tid(), CreationRecord::with_admin(admin, [2; 32]).tid());
        assert_eq!(CreationRecord::from_value(&Value::Int(0)), None);
        let Value::Map(m) = r.to_value() else { unreachable!() };
        let key = |alg, len| Value::Enum(alg, Some(Box::new(Value::Bytes(vec![9; len]))));
        let with = |f: &dyn Fn(&mut crate::ValueMap)| {
            let mut m = m.clone();
            f(&mut m);
            CreationRecord::from_value(&Value::Map(m))
        };
        assert_eq!(with(&|m| { m.insert(Value::Int(1), key(1, 32)); }), None); // both
        assert_eq!(with(&|m| { m.remove(&Value::Int(0)); }), None); // neither
        assert_eq!(with(&|m| { m.insert(Value::Int(2), Value::Bytes(vec![1; 31])); }), None);
        assert_eq!(with(&|m| { m.insert(Value::Int(3), Value::Int(0)); }), None);
        for (alg, len) in [(1, 31), (1, 33), (0, 32), (2, 32)] {
            assert_eq!(with(&|m| { m.remove(&Value::Int(0)); m.insert(Value::Int(1), key(alg, len)); }), None, "{alg} {len}");
        }
        assert!(with(&|m| { m.remove(&Value::Int(0)); m.insert(Value::Int(1), key(1, 32)); }).is_some());
        assert_eq!(with(&|m| { m.insert(Value::Int(3), Value::Bool(true)); }), None);
        assert_eq!(with(&|m| { m.insert(Value::Int(4), Value::Int(0)); }), None);
    }

    // spec/data-model.md §2: the AK grammar and its accessors.
    #[test]
    fn ak_rules() {
        let a = Ak::new("note:body.0").unwrap();
        assert_eq!(a.segments().collect::<Vec<_>>(), ["note", "body"]);
        let m = |ephemeral, admin_only, signal| Markers { ephemeral, admin_only, signal, external: false };
        let markers = |a: &Ak| m(a.ephemeral(), a.admin_only(), a.signal());
        assert_eq!((a.version(), a.tid(), markers(&a)), (0, None, m(false, false, false)));
        let t = Tid::from_bytes([7; 15]);
        let b = Ak::new(format!(":{t}:a_1:b+^.12")).unwrap();
        assert_eq!(b.segments().collect::<Vec<_>>(), ["a_1", "b"]);
        assert_eq!((b.version(), b.tid(), markers(&b)), (12, Some(t), m(true, true, false)));
        assert_eq!(Ak::new("roles.0").unwrap().segments().count(), 1);
        // every marker combination, each marker independent
        for e in [false, true] {
            for ad in [false, true] {
                for sg in [false, true] {
                    let k = format!("x{}{}{}3", if e { "+" } else { "" }, if ad { "^" } else { "" }, if sg { "~" } else { "." });
                    let a = Ak::new(k.as_str()).unwrap();
                    assert_eq!((markers(&a), a.version()), (m(e, ad, sg), 3), "{k}");
                    assert_eq!(a.segments().collect::<Vec<_>>(), ["x"], "{k}");
                    assert_eq!(Ak::markers_of(&k), m(e, ad, sg), "{k}");
                }
            }
        }
        assert_eq!(Ak::markers_of(":AAAAAAAAAAAAAAAAAAAA:a+^~12"), m(true, true, true));
        // `@` only as `@~`, never beside `+` or `^`
        let external = Markers { signal: true, external: true, ..Markers::default() };
        let k = Ak::new("grant@~0").unwrap();
        assert!(k.external() && k.signal() && !k.ephemeral() && !k.admin_only() && k.segments().eq(["grant"]));
        assert_eq!((Ak::markers_of("grant@~0"), Ak::markers_of("x~0").external), (external, false));
        for bad in ["x@.0", "x+@~0", "x^@~0", "x@+~0", "x@^~0", "x@~", "x@0", "@~0", "x@@~0"] {
            assert_eq!(Ak::new(bad), Err(AkError), "{bad}");
        }
        assert!(Ak::new("note:body.1").unwrap().successor_of(&a));
        assert!(Ak::new("note:body+.1").unwrap().successor_of(&a));
        assert!(Ak::new("note:body+~1").unwrap().successor_of(&a));
        assert!(!Ak::new("note:body+.0").unwrap().successor_of(&a));
        assert!(!a.successor_of(&a) && !Ak::new("note:bod.1").unwrap().successor_of(&a) && !Ak::new(format!(":{t}:note:body.1")).unwrap().successor_of(&a));
        let max = format!("x.{}", u64::MAX);
        assert_eq!(Ak::new(max).unwrap().version(), u64::MAX);
        for bad in [
            "", "x", "x.", "x~", "x+", "x+~", ".0", "~0", "/x.0", "x.00", "x.01", "x~01", "x.-1", "X.0", "1x.0", "x:.0", ":x.0", "x::y.0", "x-y.0", "x^+.0", "x++.0",
            "x^^.0", "x.~0", "x~.0", "x+^", "x.0^", "x.0~", "x.0*", "x*0", "x.^", "x.0^0", "x+.0+", "x.0 ", "x.0.0", "x.18446744073709551616", "x:Y.0",
            ":AAAAAAAAAAAAAAAAAAAA.0", ":AAAAAAAAAAAAAAAAAAA:x.0", ":AAAAAAAAAAAAAAAAAAA=:x.0",
        ] {
            assert_eq!(Ak::new(bad), Err(AkError), "{bad}");
        }
        assert!(Ak::new(":AAAAAAAAAAAAAAAAAAAA:x.0").is_ok());
        assert!(Ak::new(format!("{}.0", "a".repeat(MAX_AK_BYTES - 2))).is_ok());
        assert!(Ak::new(format!("{}.0", "a".repeat(MAX_AK_BYTES - 1))).is_err());
        assert_eq!(Ak::MIN.segments().count(), 0);
    }

    // A key constant is checked at build time: `Ak::check` is a `const fn` panicking on a
    // non-AK or a key of the other kind, and every `Aspect::new`/`Signal::new` constant evaluates it.
    const CHECKED: &str = Ak::check("note:body+^.0", false);
    const CHECKED_SIGNAL: &str = Ak::check("note:ping+~0", true);
    #[test]
    #[should_panic(expected = "invalid aspect key")]
    fn ak_check_rejects() {
        assert_eq!((CHECKED, CHECKED_SIGNAL), ("note:body+^.0", "note:ping+~0"));
        let _ = Ak::check(std::hint::black_box("/note/body"), false);
    }

    #[test]
    #[should_panic(expected = "signal key")]
    fn ak_check_rejects_kind() {
        let _ = Ak::check(std::hint::black_box("note:ping~0"), false);
    }

    #[test]
    fn link_debug_hides_key() {
        let l = Link { hash: [1; 32], blob: BlobId([2; 32]), suite: 1, key: [0xab; 32], salt: [0; 16], del: Del::NONE };
        assert!(!format!("{l:?}").contains("abab"));
    }

    // spec/data-model.md §5: Del holds at most one key per level 1 to 3.
    #[test]
    fn del_levels() {
        let d = Del::from_keys([(3, [3; 32]), (1, [1; 32])]).unwrap();
        assert_eq!(d.iter().collect::<Vec<_>>(), vec![(1, [1; 32]), (3, [3; 32])]);
        assert_eq!(d.len(), 2);
        assert_eq!(Del::from_keys([(1, [1; 32]), (1, [2; 32])]), None);
        assert_eq!(Del::from_keys([(0, [1; 32])]), None);
        assert_eq!(Del::from_keys([(4, [1; 32])]), None);
        assert!(Del::NONE.is_empty());
    }
}

/// Where to dial a node (spec/sync-transport.md §1, spec/data-model.md §9 `address`): a transport
/// URL and the 32-byte key the node must authenticate with. One type from the transport to the
/// data model: osis-schema gives it its `Codec`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    pub url: String,
    pub key: [u8; 32],
}

/// Scheme of P2P addresses (spec/sync-transport.md §3): a node dialed by its dialable key at the
/// socket addresses and through the relays the URL lists (`peer://` then items separated by
/// single spaces). The key is `Address::key`.
pub const PEER_SCHEME: &str = "peer";

/// The `peer://` URL listing `items` (spec/sync-transport.md §3).
pub fn peer_url(items: &[String]) -> String {
    format!("{PEER_SCHEME}://{}", items.join(" "))
}
