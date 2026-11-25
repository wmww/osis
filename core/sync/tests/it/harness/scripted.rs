//! Opens between scripted peers (notes/sync-test-harness.md, hostile peers are scripted nodes):
//! honest sides run the product's `Opens` over a table of what they hold (`Table`, the
//! `opens::holds::Holds` seam) and a recording connection (`Pipe`, the `opens::Wire` seam); a
//! hostile side is a test script that reads what an honest side sent and sends any message it can
//! build with real keys and real crypto (`Adv`). Until the session and the engine's sync facade
//! are built, this is where opens' rules run end to end.

use osis_base::{SyncId, Tid};
use osis_crypto::kdf::{beacon, sync_proof};
use osis_crypto::{Epoch, RoleKey, NodeRng, Secret32, SeededRng, SigningSecret, role_key, role_key_seed, static_entry};
use osis_engine::sync::{J, ProvenThing};
use osis_blob::StepId;
use osis_proto::{BehindItem, Code, DepositItem, Flow, Grant, Id, Msg, SharedItem};
use osis_sync::opens::cred::{Bind, Shown, Tested};
use osis_sync::opens::holds::{Creds, Holds};
use osis_sync::opens::{Ctx, Moved, Opens, Reported, Wire};
use osis_sync::session::{Incoming, Proven};
use osis_store::{MemoryBackend, MemoryRoot};
use osis_sync::Store;
use osis_sync::types::{ConnId, Credential, Cursor, Holding, Position, RecordId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// One sync ID's keys at one step: what its sync secret derives.
#[derive(Clone)]
pub struct StepKeys {
    pub id: StepId,
    pub epoch: Epoch,
    pub sync: SigningSecret,
    pub proof: [u8; 32],
}

impl StepKeys {
    /// Step `n` of a sync ID, its sync secret drawn from `seed` and `n`.
    pub fn new(seed: u8, n: u8) -> StepKeys {
        let secret = Secret32::from_bytes([seed ^ 0x5a, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let s = role_key_seed(RoleKey::Sync, &secret);
        StepKeys { id: StepId([seed.wrapping_add(n); 32]), epoch: epoch(n), sync: role_key(RoleKey::Sync, &secret), proof: sync_proof(&s) }
    }

    pub fn pk(&self) -> [u8; 32] {
        self.sync.verifying_key().to_bytes()
    }
}

pub fn epoch(n: u8) -> Epoch {
    Epoch::new(u64::from(n), [n; 32]).unwrap()
}

/// A read secret at epoch `n`.
pub fn read_secret(seed: u8, n: u8) -> (Epoch, Secret32) {
    (epoch(n), Secret32::from_bytes([seed, n, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]))
}

/// A link key's signing key.
pub fn link_key(n: u8) -> SigningSecret {
    SigningSecret::from_seed(&Secret32::from_bytes([n; 32]))
}

/// What a node reading S at `step` holds: its read secret, the static entries its roster lists,
/// the link keys it acts for, and the walk's sync keys of the steps it holds (newest first).
pub fn reader(s: &SyncId, read: &(Epoch, Secret32), step: &StepKeys, older: &[StepKeys], roster_links: &[&SigningSecret], own_links: &[&SigningSecret]) -> Creds {
    let mut c = Creds { holding: Some(Holding::Read), ..Creds::default() };
    c.shows.push((Shown::Read(read.0, *read.1.expose()), Some(read.0)));
    c.shows.push((Shown::Proof(step.proof), Some(step.epoch)));
    c.shows.extend(roster_links.iter().map(|k| (Shown::Static(static_entry(s, &k.verifying_key())), None)));
    c.tests.push((Tested::Read(read.0, read.1.clone()), Some(read.0)));
    c.tests.extend(own_links.iter().map(|k| (Tested::Static { step: None, key: (*k).clone() }, None)));
    for st in std::iter::once(step).chain(older) {
        c.tests.push((Tested::SyncKey { step: Some(st.id), key: st.sync.clone() }, Some(st.epoch)));
    }
    c.step = Some((step.sync.clone(), Some(step.epoch)));
    c
}

/// What a node keeping S unread at head `head` holds: the product's own (`Creds::kept_unread`),
/// with no claim set.
pub fn store(head: &StepKeys) -> Creds {
    // with no claim set, which sync ID it is says nothing
    Creds::kept_unread(&SyncId([0; 16]), &osis_sync::unread::UnreadCredentials { step: Some(head.id), keys: vec![(head.sync.clone(), Secret32::from_bytes(head.proof))], deposit: Some(SigningSecret::from_seed(&Secret32::from_bytes(head.proof)).verifying_key()), claims: None })
}

/// What a node keeping S unread holds before any step is registered there, granted the sync
/// secrets of `steps` (newest first): the product's own, with no head.
pub fn store_no_head(steps: &[&StepKeys]) -> Creds {
    let keys = steps.iter().map(|st| (st.sync.clone(), Secret32::from_bytes(st.proof))).collect();
    Creds::kept_unread(&SyncId([0; 16]), &osis_sync::unread::UnreadCredentials { step: None, keys, deposit: None, claims: None })
}

/// What a link holder holds: its own static entry to test, no secret of S.
pub fn link_holder(link: &SigningSecret) -> Creds {
    let mut c = Creds { holding: Some(Holding::Read), ..Creds::default() };
    c.tests.push((Tested::Static { step: None, key: link.clone() }, None));
    c
}

/// An honest side's view of what it holds (the `Holds` seam), set by the test.
pub struct Table {
    pub rng: SeededRng,
    pub creds: BTreeMap<SyncId, Arc<Creds>>,
    due: BTreeSet<SyncId>,
    /// J per (S, proven actor); `Unknown` otherwise.
    pub j: BTreeMap<(SyncId, Tid), J>,
    /// Epochs covering every departure, per S.
    pub covering: BTreeSet<(SyncId, Epoch)>,
    pub until: Position,
    /// Whether a departure's rotation is logged (`Holds::departure_until`: `until`, else none).
    pub departure_logged: bool,
    /// What `take_grant` gives: the head's sync key, per S.
    pub grants: BTreeMap<SyncId, [u8; 32]>,
    pub gives_grant: bool,
    /// The sync IDs whose grant was taken (its secrets learned).
    pub taken: BTreeSet<SyncId>,
    /// The recorded path per S: what a source's steps verify under.
    pub recorded: BTreeMap<SyncId, Vec<osis_blob::Step>>,
    /// The members whose J is followed (`Holds::standing`), with the actors their peer names.
    pub followed: BTreeMap<(RecordId, SyncId), Vec<Tid>>,
    standing_due: BTreeSet<(RecordId, SyncId)>,
    /// Actors that may be no one (spec/sync-opens.md §3 who it may be: a revoked key, a removed
    /// node): a peer naming only these is no one.
    no_one: BTreeSet<Tid>,
}

impl Table {
    pub fn new(seed: u64) -> Table {
        Table { rng: SeededRng::from_u64(seed), creds: BTreeMap::new(), due: BTreeSet::new(), j: BTreeMap::new(), covering: BTreeSet::new(), until: 100, departure_logged: true, grants: BTreeMap::new(), gives_grant: false, taken: BTreeSet::new(), recorded: BTreeMap::new(), followed: BTreeMap::new(), standing_due: BTreeSet::new(), no_one: BTreeSet::new() }
    }

    /// S's credentials are now `c` (none: S left the sync set).
    pub fn set(&mut self, s: SyncId, c: Option<Creds>) {
        match c {
            Some(c) => self.creds.insert(s, Arc::new(c)),
            None => self.creds.remove(&s),
        };
        self.due.insert(s);
    }

    /// Every sync ID held comes due again (a restart: the memos start over).
    pub fn redue(&mut self) {
        self.due.extend(self.creds.keys().copied());
    }

    /// J of `actor` for S is now `j`: each member of S whose peer names `actor` comes due
    /// (spec/sync-opens.md §6), as the engine's memo follows the rosters.
    pub fn judge_as(&mut self, s: SyncId, actor: Tid, j: J) {
        self.j.insert((s, actor), j);
        let due = self.followed.iter().filter(|((_, x), a)| *x == s && a.contains(&actor)).map(|(k, _)| *k);
        self.standing_due.extend(due);
    }
}

impl Table {
    /// `actor` may be no one now: each member whose peer names it comes due.
    pub fn no_one(&mut self, actor: Tid) {
        self.no_one.insert(actor);
        let due = self.followed.iter().filter(|(_, a)| a.contains(&actor)).map(|(k, _)| *k);
        self.standing_due.extend(due);
    }
}

impl Holds for Table {
    fn rng(&mut self) -> &mut dyn NodeRng {
        &mut self.rng
    }
    fn due(&mut self) -> Vec<SyncId> {
        std::mem::take(&mut self.due).into_iter().collect()
    }
    fn creds(&mut self, s: &SyncId) -> Option<Arc<Creds>> {
        self.creds.get(s).cloned()
    }
    fn named(&mut self, proven: &Proven) -> osis_store::Named {
        proven.named.clone()
    }
    /// Each thing a claim names (signed as, or on its path), proven at admin: the table judges it.
    fn counts(&mut self, named: &osis_store::Named, _copies: &osis_blob::Certificates) -> Vec<ProvenThing> {
        let things: BTreeSet<Tid> = named.claims.iter().flat_map(|c| std::iter::once(c.thing).chain(c.path.iter().copied())).collect();
        things.into_iter().map(|thing| ProvenThing { thing, role: Some(osis_base::Role::Admin) }).collect()
    }
    fn judge(&mut self, s: &SyncId, proven: &[ProvenThing]) -> J {
        let js: Vec<J> = proven.iter().filter_map(|p| self.j.get(&(*s, p.thing)).copied()).collect();
        [J::Reader, J::SyncHolder, J::Departed].into_iter().find(|j| js.contains(j)).unwrap_or(J::Unknown)
    }
    fn standing(&mut self, rec: RecordId, s: &SyncId, named: &osis_store::Named, _copies: &osis_blob::Certificates) -> Option<J> {
        let proven = self.counts(named, &osis_blob::Certificates::default());
        let j = self.judge(s, &proven);
        let actors: Vec<Tid> = proven.iter().map(|p| p.thing).collect();
        let no_one = !actors.is_empty() && actors.iter().all(|a| self.no_one.contains(a));
        self.followed.insert((rec, *s), actors);
        (!no_one).then_some(j)
    }
    fn standing_due(&mut self) -> Vec<(RecordId, SyncId)> {
        std::mem::take(&mut self.standing_due).into_iter().collect()
    }
    fn unfollow(&mut self, rec: RecordId, s: &SyncId) {
        self.followed.remove(&(rec, *s));
    }
    fn covers_departures(&mut self, s: &SyncId, epoch: &Epoch) -> bool {
        self.covering.contains(&(*s, *epoch))
    }
    fn until(&mut self, _s: &SyncId, _by: &Credential) -> Position {
        self.until
    }
    fn departure_until(&mut self, _s: &SyncId, _by: &Credential) -> Option<Position> {
        self.departure_logged.then_some(self.until)
    }
    fn cursor_at(&mut self, pos: Position) -> Option<Cursor> {
        Some(pos.to_be_bytes().to_vec())
    }
    fn grant(&mut self, s: &SyncId, _entry: &[u8; 32]) -> Option<Grant> {
        // a path of one step (its bytes are never verified here: `take_grant` is the table's)
        let k = link_key(1).verifying_key();
        let keys = osis_blob::StepKeys { sync: k, write: k, delete: k, deposit: k };
        let step = osis_blob::Step { sync_id: *s, prev: None, keys, step_key: [0; 32], claims_hash: [0; 32], sig: osis_crypto::Signature([0; 64]) };
        self.gives_grant.then(|| Grant { entry_box: None, steps: vec![step] })
    }
    fn take_grant(&mut self, s: &SyncId, _entry: &[u8; 32], _grant: &Grant, signed: &dyn Fn(&[u8; 32]) -> bool) -> bool {
        let ok = self.grants.get(s).is_some_and(signed);
        if ok {
            self.taken.insert(*s);
        }
        ok
    }
    fn behind(&mut self, _item: &BehindItem) -> SharedItem {
        SharedItem::code(Code::DECLINED)
    }
    fn behind_unsigned(&mut self, _s: &SyncId) -> SharedItem {
        SharedItem::code(Code::DECLINED)
    }
    fn deposit(&mut self, _src: osis_sync::store::Source, _item: &DepositItem) -> Code {
        Code::DECLINED
    }
    fn verify_steps(&mut self, s: &SyncId, known: &[osis_blob::Step], steps: &[osis_blob::Step]) -> Vec<osis_blob::Step> {
        let recorded = self.recorded.get(s).cloned().unwrap_or_default();
        let mut out = osis_sync::opens::holds::known_steps(s, recorded.iter().chain(known), steps);
        out.retain(|st| !recorded.iter().any(|r| r.id() == st.id()));
        out
    }
    fn step_creds(&mut self, s: &SyncId, step: &osis_blob::Step) -> Vec<(Tested, Option<Epoch>)> {
        let pk = step.keys.sync.to_bytes();
        let held = self.creds.get(s).and_then(|c| c.tests.iter().find_map(|(t, e)| match t {
            Tested::SyncKey { key, .. } if key.verifying_key().to_bytes() == pk => Some((key.clone(), *e)),
            _ => None,
        }));
        held.map(|(key, e)| (Tested::SyncKey { step: Some(step.id()), key }, e)).into_iter().collect()
    }
}

/// An honest side's connections: what it sent, per connection, in order.
#[derive(Default)]
pub struct Pipe {
    pub binds: BTreeMap<ConnId, (Bind, Proven)>,
    pub sent: Vec<(ConnId, Msg)>,
    pub closed: Vec<(ConnId, &'static str)>,
    next: u32,
}

impl Wire for Pipe {
    fn bind(&self, c: ConnId) -> Option<(Bind, Proven)> {
        self.binds.get(&c).cloned()
    }
    fn request(&mut self, c: ConnId, mut m: Msg) -> Id {
        let id = if m.kind() == 40 {
            osis_proto::limits::NO_RECORD_ID
        } else {
            self.next += 1;
            self.next | osis_proto::limits::TOP_BIT
        };
        m.set_id(id);
        self.sent.push((c, m));
        id
    }
    fn answer(&mut self, c: ConnId, to: Id, mut m: Msg) {
        m.set_id(to);
        self.sent.push((c, m));
    }
    fn push(&mut self, c: ConnId, m: Msg) {
        self.sent.push((c, m));
    }
    fn close(&mut self, c: ConnId, why: &'static str) {
        self.closed.push((c, why));
    }
}

/// An honest side: the product's opens over its table and connections.
pub struct Side {
    pub opens: Opens,
    /// Where its records live (`Opens::flush` at the end of each step).
    pub store: Store,
    pub device: (MemoryBackend, MemoryRoot),
    pub table: Table,
    pub pipe: Pipe,
    pub moved: Vec<Moved>,
    pub mono: osis_base::Mono,
}

impl Side {
    pub fn new(seed: u64) -> Side {
        let (backend, root) = (MemoryBackend::new(), MemoryRoot::new());
        let store = Store::open(Box::new(backend.clone()), Box::new(root.clone()), Box::new(SeededRng::from_u64(seed))).unwrap();
        Side { opens: Opens::default(), store, device: (backend, root), table: Table::new(seed), pipe: Pipe::default(), moved: Vec::new(), mono: osis_base::Mono(1_000) }
    }

    /// Settles (the driver's settle round for opens).
    pub fn settle(&mut self) {
        let mut ctx = Ctx { holds: &mut self.table, wire: &mut self.pipe, store: &mut self.store, mono: self.mono };
        self.opens.tick(&mut ctx, &mut self.moved);
        self.flush();
    }

    /// The end of the node's step: opens writes its records (and evicts past its budget).
    pub fn flush(&mut self) -> Vec<osis_sync::types::RecordId> {
        self.opens.flush(&mut self.store).unwrap()
    }

    /// A restart: the store reopened over its device, opens started from it, every connection
    /// gone.
    pub fn restart(&mut self) {
        self.store = Store::open(Box::new(self.device.0.clone()), Box::new(self.device.1.clone()), Box::new(SeededRng::from_u64(99))).unwrap();
        self.opens = Opens::default();
        self.pipe = Pipe::default();
        self.moved.clear();
        self.table.redue();
        self.table.followed.clear();
        self.settle();
    }

    /// Takes one message and settles, then loses power before the step's end: opens' records of
    /// that step are not written (what the store took in the step stays), nothing it sent goes,
    /// and it restarts.
    pub fn crash_taking(&mut self, conn: ConnId, m: Incoming) {
        let mut ctx = Ctx { holds: &mut self.table, wire: &mut self.pipe, store: &mut self.store, mono: self.mono };
        self.opens.message(&mut ctx, conn, m, &mut self.moved);
        self.opens.tick(&mut ctx, &mut self.moved);
        self.restart();
    }

    /// Takes one message, then settles.
    pub fn take(&mut self, conn: ConnId, m: Incoming) {
        let mut ctx = Ctx { holds: &mut self.table, wire: &mut self.pipe, store: &mut self.store, mono: self.mono };
        self.opens.message(&mut ctx, conn, m, &mut self.moved);
        self.settle();
    }

    /// The peer reported position `pos` for S (streams' word).
    pub fn reported(&mut self, conn: ConnId, s: SyncId, pos: Position) {
        let mut ctx = Ctx { holds: &mut self.table, wire: &mut self.pipe, store: &mut self.store, mono: self.mono };
        self.opens.reported(&mut ctx, Reported::Member(conn, s, Some((pos, pos.to_be_bytes().to_vec()))), &mut self.moved);
        self.settle();
    }

    /// Member S follows the peer's stream (its join merged, or the first Pull did not name it).
    pub fn merged(&mut self, conn: ConnId, s: SyncId) {
        let mut ctx = Ctx { holds: &mut self.table, wire: &mut self.pipe, store: &mut self.store, mono: self.mono };
        self.opens.reported(&mut ctx, Reported::Merged(conn, s), &mut self.moved);
        self.settle();
    }

    /// The peer's stream stands at `pos` (an Applied): every member at the stream stands there.
    pub fn reported_stream(&mut self, conn: ConnId, pos: Position) {
        let mut ctx = Ctx { holds: &mut self.table, wire: &mut self.pipe, store: &mut self.store, mono: self.mono };
        self.opens.reported(&mut ctx, Reported::Stream(conn, pos, pos.to_be_bytes().to_vec()), &mut self.moved);
        self.settle();
    }

    pub fn closed(&mut self, conn: ConnId) {
        self.opens.closed(conn, &mut self.moved);
        self.flush();
    }

    /// What it sent since the last call.
    pub fn sent(&mut self) -> Vec<(ConnId, Msg)> {
        std::mem::take(&mut self.pipe.sent)
    }

    pub fn open(&self, conn: ConnId, s: &SyncId) -> bool {
        self.opens.members(conn).contains_key(s)
    }
}

/// How a received message reaches opens, by its flow (spec/wire.md §11.1), through its wire
/// bytes: one the wire refuses (a shape the spec forbids) fails the test.
pub fn incoming(m: Msg) -> Incoming {
    let m = Msg::decode(&m.encode()).unwrap_or_else(|e| panic!("{m:?} does not decode: {e:?}"));
    match m.flow() {
        Flow::Request => Incoming::Request(m.id(), m),
        Flow::Reply => Incoming::Reply(osis_sync::session::To::Opens, m.id(), m),
        Flow::Push => Incoming::Push(m),
    }
}

/// Node `n`'s node thing's creation record.
fn account_record(n: u8) -> osis_base::CreationRecord {
    osis_base::CreationRecord::with_key(osis_base::SignKey([n; 32]), [n; 32])
}

/// Node `n`, proved.
pub fn account(n: u8) -> Proven {
    Proven { named: named(n), ..Proven::default() }
}

/// What a record of a peer proving `account(n)` names: node `n`'s claim, no path.
pub fn named(n: u8) -> osis_store::Named {
    osis_store::Named { claims: vec![osis_store::Claim { thing: tid(n), key: [n; 32], path: Vec::new() }] }
}

/// Node `n`'s tid.
pub fn tid(n: u8) -> Tid {
    account_record(n).tid()
}

/// One connection between two honest sides: `a` dialed `b`. Each gets the other's proofs.
pub struct Pair {
    pub a: Side,
    pub b: Side,
    pub ca: ConnId,
    pub cb: ConnId,
    /// Messages delivered (a storm guard).
    pub delivered: u64,
    /// Every message delivered: whether `a` sent it, and the message.
    pub log: Vec<(bool, Msg)>,
}

pub const KEY_B: [u8; 32] = [0x4b; 32];

/// The binds of a connection `a` dialed, a direct one (rank 1): `a`'s and `b`'s.
pub fn binds(ch_a: [u8; 32], ch_b: [u8; 32], key_b: [u8; 32]) -> (Bind, Bind) {
    binds_at(ch_a, ch_b, key_b, 1)
}

/// The binds of a connection `a` dialed at route rank `rank`.
pub fn binds_at(ch_a: [u8; 32], ch_b: [u8; 32], key_b: [u8; 32], rank: u8) -> (Bind, Bind) {
    (Bind { dialer: true, own_challenge: ch_a, peer_challenge: ch_b, listener_key: key_b, rank }, Bind { dialer: false, own_challenge: ch_b, peer_challenge: ch_a, listener_key: key_b, rank })
}

impl Pair {
    /// `a` dials `b` on connection `n`; `pa` is what `a` proved to `b`, `pb` what `b` proved to `a`.
    pub fn new(a: Side, b: Side, pa: Proven, pb: Proven) -> Pair {
        let mut p = Pair { a, b, ca: ConnId(1), cb: ConnId(ConnId::ACCEPTED | 1), delivered: 0, log: Vec::new() };
        p.connect(1, pa, pb);
        p
    }

    /// A new connection `n`, `a` dialing `b` (the earlier one closed).
    pub fn connect(&mut self, n: u64, pa: Proven, pb: Proven) {
        self.ca = ConnId(n);
        self.cb = ConnId(ConnId::ACCEPTED | n);
        let (ba, bb) = binds([0xa1 ^ n as u8; 32], [0xb2 ^ n as u8; 32], KEY_B);
        self.a.pipe.binds.insert(self.ca, (ba, pb));
        self.b.pipe.binds.insert(self.cb, (bb, pa));
        self.b.take(self.cb, Incoming::Proved);
        self.a.take(self.ca, Incoming::Proved);
    }

    /// Delivers every message both ways until none flows.
    pub fn run(&mut self) {
        loop {
            let (fa, fb) = (self.a.sent(), self.b.sent());
            if fa.is_empty() && fb.is_empty() {
                return;
            }
            for (c, m) in fa {
                if c == self.ca {
                    self.delivered += 1;
                    self.log.push((true, m.clone()));
                    self.b.take(self.cb, incoming(m));
                }
            }
            for (c, m) in fb {
                if c == self.cb {
                    self.delivered += 1;
                    self.log.push((false, m.clone()));
                    self.a.take(self.ca, incoming(m));
                }
            }
            assert!(self.delivered < 2_000, "opens storm");
        }
    }

    /// Both settle (a change of what they hold), then messages flow.
    pub fn settle(&mut self) {
        self.a.settle();
        self.b.settle();
        self.run();
    }

    pub fn close(&mut self) {
        self.a.closed(self.ca);
        self.b.closed(self.cb);
        self.a.sent();
        self.b.sent();
    }
}

/// The hostile side of one connection to an honest side: it sees what the honest side sent and
/// sends what it builds. `bind` is its own view of the connection.
pub struct Adv {
    pub bind: Bind,
    /// The honest side's connection.
    pub peer: ConnId,
    next: u32,
}

impl Adv {
    /// Adv dialed by honest `h` (`h` dialed), or dialing it; `ch_adv` its Hello challenge (it
    /// may copy the honest side's).
    pub fn connect(h: &mut Side, h_dialed: bool, ch_h: [u8; 32], ch_adv: [u8; 32], adv_proves: Proven) -> Adv {
        let key = [0x77; 32];
        let (hb, ab) = if h_dialed {
            let (x, y) = binds(ch_h, ch_adv, key);
            (x, y)
        } else {
            let (x, y) = binds(ch_adv, ch_h, key);
            (y, x)
        };
        let peer = if h_dialed { ConnId(9) } else { ConnId(ConnId::ACCEPTED | 9) };
        h.pipe.binds.insert(peer, (hb, adv_proves));
        h.take(peer, Incoming::Proved);
        Adv { bind: ab, peer, next: 0 }
    }

    pub fn id(&mut self) -> Id {
        self.next += 1;
        self.next | osis_proto::limits::TOP_BIT
    }

    /// Sends `m` to the honest side.
    pub fn send(&mut self, h: &mut Side, m: Msg) {
        h.take(self.peer, incoming(m));
    }

    /// Adv's Hit on match value `m` of S, as it would compute it (with the honest side's pair key
    /// unknown to it unless it holds the record: `r`).
    pub fn hit(&self, m: &[u8; 32], s: &SyncId, r: &[u8; 32]) -> [u8; 32] {
        self.bind.hit(m, s, &beacon(m, &s.0, r))
    }
}

/// The pair key of a connection that keeps no record (spec/sync-opens.md §3).
pub fn unkept_r(b: &Bind) -> [u8; 32] {
    let (d, l) = if b.dialer { (b.own_challenge, b.peer_challenge) } else { (b.peer_challenge, b.own_challenge) };
    *osis_crypto::kdf::pair_key(&d, &l).expose()
}

/// The Shared answering request `id` among `sent`.
pub fn shared(sent: &[(ConnId, Msg)], id: Id) -> Option<Vec<SharedItem>> {
    sent.iter().find_map(|(_, m)| match m {
        Msg::Shared { id: i, items } if *i == id => Some(items.clone()),
        _ => None,
    })
}

/// Every message of a kind among `sent`.
pub fn of_kind(sent: &[(ConnId, Msg)], kind: u64) -> Vec<Msg> {
    sent.iter().filter(|(_, m)| m.kind() == kind).map(|(_, m)| m.clone()).collect()
}

impl Adv {
    /// Adv dials honest `h` and keeps no record (NoRecord): the set runs under the connection's
    /// own pair key, which Adv computes too. What `h` sent so far is returned.
    pub fn dials(h: &mut Side, proves: Proven, ch_adv: [u8; 32]) -> (Adv, Vec<(ConnId, Msg)>) {
        let mut a = Adv::connect(h, false, [0xc3; 32], ch_adv, proves);
        let id = osis_proto::limits::NO_RECORD_ID;
        a.send(h, Msg::NoRecord { id });
        let sent = h.sent();
        (a, sent)
    }

    /// The pair key of this connection (it keeps no record).
    pub fn r(&self) -> [u8; 32] {
        unkept_r(&self.bind)
    }

    /// Sends a whole filter showing match values `ms` of S.
    pub fn filter(&mut self, h: &mut Side, ms: &[[u8; 32]], s: &SyncId) {
        let r = self.r();
        let bs: Vec<[u8; 32]> = ms.iter().map(|m| beacon(m, &s.0, &r)).collect();
        let f = osis_proto::filter::filter_width(bs.len());
        let mut v: Vec<u64> = bs.iter().map(|b| osis_proto::filter::beacon_value(b, f)).collect();
        v.sort_unstable();
        let gcs = osis_proto::filter::encode_gcs(&v, 0);
        let id = self.id();
        self.send(h, Msg::Beacons { id, generation: 1, base: None, f, lo: 0, hi: 1 << f, gcs, more: false });
    }

    /// Sends an Offer of `items`; the honest side's answers.
    pub fn offer(&mut self, h: &mut Side, items: Vec<osis_proto::OfferItem>) -> Vec<SharedItem> {
        let id = self.id();
        self.send(h, Msg::Offer { id, items });
        let sent = h.sent();
        shared(&sent, id).expect("an Offer is answered")
    }

    /// Adv's Hit on match value `m` of S on this connection.
    pub fn hit_on(&self, m: &[u8; 32], s: &SyncId) -> [u8; 32] {
        self.hit(m, s, &self.r())
    }

    /// The tag Adv answers a Hit on `m` with (computable by anyone holding `m`).
    pub fn tag_on(&self, m: &[u8; 32], s: &SyncId) -> [u8; 32] {
        self.bind.tag(m, s, &beacon(m, &s.0, &self.r()))
    }
}

/// The values of every Beacons page among `sent`, with the last page's width.
pub fn filter_values(sent: &[(ConnId, Msg)]) -> (Vec<u64>, u8, Option<u64>) {
    let mut out = (Vec::new(), 0, None);
    for (_, m) in sent {
        if let Msg::Beacons { f, lo, hi, gcs, base, .. } = m {
            out.0.extend(osis_proto::filter::decode_gcs(gcs, *lo, *hi).unwrap());
            out.1 = *f;
            out.2 = *base;
        }
    }
    out
}
