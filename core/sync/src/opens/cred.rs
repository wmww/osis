//! Credentials of a sync ID and the values a connection computes from them (spec/sync-opens.md
//! §4-§5, spec/wire.md §11.2): match values, beacons, Hits, tags and open signatures, each bound
//! to its sender's side and one connection.

use crate::types::Credential;
use osis_base::SyncId;
use osis_crypto::kdf::{beacon, beacon_hit, beacon_reply};
use osis_crypto::{sign_open, static_entry, verify_open};
use osis_crypto::{Epoch, Secret32, Signature, SigningSecret, VerifyingKey};
use osis_label::StepId;

/// One connection as opens binds to it (spec/wire.md §11.1-§11.2): this side's role, both Hello
/// challenges and the listener's static key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bind {
    /// This side dialed.
    pub dialer: bool,
    pub own_challenge: [u8; 32],
    pub peer_challenge: [u8; 32],
    /// The listener's static key (spec/wire.md §11.1 Static key).
    pub listener_key: [u8; 32],
    /// The route rank, the same at both ends (spec/sync-transport.md §1).
    pub rank: u8,
}

impl Bind {
    fn challenges(&self) -> (&[u8; 32], &[u8; 32]) {
        if self.dialer { (&self.own_challenge, &self.peer_challenge) } else { (&self.peer_challenge, &self.own_challenge) }
    }

    /// The side tuple of a Hit or tag sent by this side (`own`) or the peer.
    fn side(&self, own: bool) -> osis_crypto::kdf::Side<'_> {
        let (d, l) = self.challenges();
        let by_listener = if own { !self.dialer } else { self.dialer };
        (by_listener, &self.listener_key, d, l)
    }

    /// A Hit on `beacon` as this side sends it.
    pub fn hit(&self, m: &[u8; 32], s: &SyncId, b: &[u8; 32]) -> [u8; 32] {
        beacon_hit(m, &s.0, b, self.side(true))
    }

    /// A Hit on `beacon` as the peer sends it: what a Hit received must equal.
    pub fn peer_hit(&self, m: &[u8; 32], s: &SyncId, b: &[u8; 32]) -> [u8; 32] {
        beacon_hit(m, &s.0, b, self.side(false))
    }

    /// The tag this side answers a Hit with.
    pub fn tag(&self, m: &[u8; 32], s: &SyncId, b: &[u8; 32]) -> [u8; 32] {
        beacon_reply(m, &s.0, b, self.side(true))
    }

    /// The tag the peer must answer this side's Hit with.
    pub fn peer_tag(&self, m: &[u8; 32], s: &SyncId, b: &[u8; 32]) -> [u8; 32] {
        beacon_reply(m, &s.0, b, self.side(false))
    }

    /// An open signature by this side: over its side, S, the peer's challenge, the listener's key.
    pub fn sign(&self, key: &SigningSecret, s: &SyncId) -> Signature {
        sign_open(key, !self.dialer, s, &self.peer_challenge, &self.listener_key)
    }

    /// This connection's place among the connections of the record keyed `r` (spec/sync-opens.md
    /// §1 One connection per pair): its route rank, then `BLAKE3(key = r, dialer challenge ||
    /// listener challenge)`; the smaller stays. Both ends compute the same.
    pub fn pair_order(&self, r: &[u8; 32]) -> (u8, [u8; 32]) {
        let (d, l) = self.challenges();
        (self.rank, osis_crypto::kdf::connection_order(r, d, l))
    }

    /// Whether `sig` is the peer's open signature by `key` on this connection.
    pub fn peer_signed(&self, key: &[u8; 32], s: &SyncId, sig: &Signature) -> bool {
        VerifyingKey::from_bytes(key).is_ok_and(|k| verify_open(&k, self.dialer, s, &self.own_challenge, &self.listener_key, sig).is_ok())
    }
}

/// A beacon of a match value (spec/sync-opens.md §5): `BLAKE3(key = kdf("beacon", match, S), r)`.
pub fn beacon_of(m: &[u8; 32], s: &SyncId, r: &[u8; 32]) -> [u8; 32] {
    beacon(m, &s.0, r)
}

/// A credential this node shows in its filter (spec/sync-opens.md §4 Admissible), by its match value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shown {
    Read(Epoch, [u8; 32]),
    Proof([u8; 32]),
    SyncKey([u8; 32]),
    Claim([u8; 32]),
    Static([u8; 32]),
    Deposit([u8; 32]),
}

impl Shown {
    /// The match value (spec/sync-opens.md §5 Beacon).
    pub fn matched(&self) -> &[u8; 32] {
        match self {
            Shown::Read(_, m) | Shown::Proof(m) | Shown::SyncKey(m) | Shown::Claim(m) | Shown::Static(m) | Shown::Deposit(m) => m,
        }
    }

    pub fn credential(&self) -> Credential {
        match self {
            Shown::Read(e, _) => Credential::ReadSecret(*e),
            Shown::Proof(_) => Credential::SyncProof,
            Shown::SyncKey(_) => Credential::SyncKey,
            Shown::Claim(_) => Credential::Claim,
            Shown::Static(e) => Credential::Static(*e),
            Shown::Deposit(_) => Credential::Deposit,
        }
    }
}

/// A credential this node tests against a peer's filter, with what it proves itself by.
#[derive(Clone, Debug)]
pub enum Tested {
    Read(Epoch, Secret32),
    Proof([u8; 32]),
    /// A sync key (`step`'s, none at a node keeping S unread with no head) and its secret: the
    /// Hit carries an open signature by it.
    SyncKey { step: Option<StepId>, key: SigningSecret },
    /// A claim of `step`'s claim set; `sync` that step's sync key, which signs the answer.
    Claim { step: StepId, key: SigningSecret, sync: [u8; 32] },
    /// A key actor's static entry this node acts for, with that actor's signing key.
    Static { step: Option<StepId>, key: SigningSecret },
}

impl Tested {
    /// The match value (spec/sync-opens.md §5 Beacon).
    pub fn matched(&self, s: &SyncId) -> [u8; 32] {
        match self {
            Tested::Read(_, k) => *k.expose(),
            Tested::Proof(p) => *p,
            Tested::SyncKey { key, .. } | Tested::Claim { key, .. } => key.verifying_key().to_bytes(),
            Tested::Static { key, .. } => static_entry(s, &key.verifying_key()),
        }
    }

    pub fn credential(&self, s: &SyncId) -> Credential {
        match self {
            Tested::Read(e, _) => Credential::ReadSecret(*e),
            Tested::Proof(_) => Credential::SyncProof,
            Tested::SyncKey { .. } => Credential::SyncKey,
            Tested::Claim { .. } => Credential::Claim,
            Tested::Static { key, .. } => Credential::Static(static_entry(s, &key.verifying_key())),
        }
    }

    /// The step a walk credential belongs to (spec/sync-ids.md §6 Walk).
    pub fn step(&self) -> Option<StepId> {
        match self {
            Tested::Claim { step, .. } => Some(*step),
            Tested::SyncKey { step, .. } | Tested::Static { step, .. } => *step,
            _ => None,
        }
    }

    /// The answer must carry a tag keyed by a secret (read secret, sync proof); otherwise an open
    /// signature by the replier's step's sync key.
    pub fn secret(&self) -> bool {
        matches!(self, Tested::Read(..) | Tested::Proof(_))
    }
}

/// The source class of a member (spec/sync-opens.md §4 source): reading the spec's list, a
/// member is a store source (the peer keeps S unread) when opened by a sync key, a claim or a
/// static entry this side tested (only a node keeping S unread shows these at its head with a
/// claim set), or by a sync proof the peer tested (only a node keeping S unread tests one); every
/// other open is a reader source.
pub fn source_class(by: &Credential, tested_here: bool) -> crate::types::SourceClass {
    use crate::types::SourceClass::{Reader, Store};
    match by {
        Credential::SyncKey | Credential::Claim | Credential::Static(_) if tested_here => Store,
        Credential::SyncProof if !tested_here => Store,
        _ => Reader,
    }
}
