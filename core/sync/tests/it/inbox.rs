//! Inbox, deposits, steps and Register (osis_sync::inbox): each rule's decision over plain values
//! (`act_of`, `adds_delta`, `to_clear`, `plan`), and Deposit items out (`Offers`) over a real
//! store and a `Net` that records what is sent. One test per rule of spec/sync-inbox.md §2-§4 and
//! spec/sync-ids.md §6 Steps and Register it implements. The module in a node over the engine
//! (a sealed fire offered and taken) is tests/it/keep.rs.

use osis_base::format::INBOX_LIFETIME_MS;
use osis_base::memo::{Stamped, StampedSet};
use osis_base::{BlobId, SyncId, Tid, WallMs};
use osis_crypto::{Epoch, RoleKey, Secret32, SeededRng, SigningSecret, deposit_key, role_key};
use osis_engine::sync::{Holding, Path, SyncSet};
use osis_blob::{ClaimSet, Class, Parent, Prefix, Step, StepId, StepKeys};
use osis_proto::{Code, Msg, OfferItem, SharedItem};
use osis_store::{MemoryBackend, MemoryRoot};
use osis_sync::Result;
use osis_sync::inbox::{Judge, Net, Offers, Plan, Progress, Judged, Promotion, Target, adds_delta, plan};
use osis_sync::opens::{Member, Moved};
use osis_sync::session::RequestId;
use osis_sync::store::Source;
use osis_sync::types::{ConnId, Credential, Entry, SourceClass};
use osis_sync::Store;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const T0: u64 = 1_000_000;
const THING: Tid = Tid::from_bytes([0x51; 15]);

fn tid(i: u32) -> Tid {
    let mut b = [3u8; 15];
    b[..4].copy_from_slice(&i.to_le_bytes());
    Tid::from_bytes(b)
}

fn sync_id(i: u32) -> SyncId {
    let mut b = [1u8; 16];
    b[..4].copy_from_slice(&i.to_le_bytes());
    SyncId(b)
}

/// A sealed fire on `THING` offered where `to` is proven.
fn fire(to: Tid) -> Target {
    Target::Fire { thing: THING, to: Arc::new(std::collections::BTreeSet::from([to])) }
}

fn conn(i: u64) -> ConnId {
    ConnId(i)
}

fn deposit_seed(n: u8) -> Secret32 {
    Secret32::from_bytes([0xd0 ^ n; 32])
}

/// A blob of `n` payload bytes with prefix expiry `expiry` (`tag` makes it distinct).
fn blob(tag: u64, n: usize, expiry: Option<u64>) -> (BlobId, Vec<u8>) {
    let mut rng = SeededRng::from_u64(tag ^ 0x5eed);
    let p = Prefix::new(Prefix::random_salt(&mut rng), expiry.map(WallMs), vec![]).unwrap();
    let (_, bytes) = osis_blob::frame(&p, &vec![tag as u8; n], &mut rng).unwrap();
    (osis_blob::blob_id(&bytes), bytes)
}

/// Peers as inbox sees them, and what it sent.
#[derive(Default)]
struct FakeNet {
    actors: BTreeMap<ConnId, Vec<Tid>>,
    members: Stamped<(ConnId, SyncId), Member>,
    present: StampedSet<(ConnId, SyncId, BlobId)>,
    generation: BTreeMap<ConnId, u64>,
    /// (connection, S, deposit key) its peer's filter shows.
    shown: BTreeSet<(ConnId, SyncId, [u8; 32])>,
    /// The kept record each connection holds (else the connection is its own source).
    rec: BTreeMap<ConnId, osis_sync::types::RecordId>,
    /// Connections whose digests agreed.
    agreed: StampedSet<ConnId>,
    next: RequestId,
    requests: Vec<(ConnId, RequestId, Msg)>,
    answers: Vec<(ConnId, RequestId, Msg)>,
}

impl Net for FakeNet {
    fn named(&self, conn: ConnId) -> osis_store::Named {
        // key actors: each counts whatever this node holds
        osis_store::Named { key_actors: self.actors.get(&conn).cloned().unwrap_or_default(), ..Default::default() }
    }
    fn member(&self, conn: ConnId, s: &SyncId) -> Option<Member> {
        self.members.get(&(conn, *s)).cloned()
    }
    fn member_at(&self, src: Source, s: &SyncId) -> Option<Member> {
        let Source::Conn(c) = src else { return None };
        self.member(c, s)
    }
    fn conn_of(&self, src: Source) -> Option<ConnId> {
        match src {
            Source::Conn(c) => Some(c),
            Source::Record(r) => self.rec.iter().find(|(_, x)| **x == r).map(|(c, _)| *c),
        }
    }
    fn agreed_on(&self, src: Source) -> Option<ConnId> {
        self.conn_of(src).filter(|c| self.agreed.contains(c))
    }
    fn members(&self, _: ConnId) -> Vec<(SyncId, SourceClass)> {
        Vec::new()
    }
    fn head(&self, _src: Source, _s: &SyncId) -> Option<StepId> {
        None
    }
    fn present(&self, src: Source, s: &SyncId, b: &BlobId) -> bool {
        let Source::Conn(c) = src else { return false };
        self.present.contains(&(c, *s, *b))
    }
    fn shown(&self, _s: &SyncId, _b: &BlobId) -> bool {
        false
    }
    fn filter_generation(&self, conn: ConnId) -> u64 {
        self.generation.get(&conn).copied().unwrap_or(0)
    }
    fn shows_deposit_key(&self, conn: ConnId, s: &SyncId, key: &[u8; 32]) -> bool {
        self.shown.contains(&(conn, *s, *key))
    }
    fn source(&self, conn: ConnId) -> Source {
        self.rec.get(&conn).map_or(Source::Conn(conn), |r| Source::Record(*r))
    }
    fn request(&mut self, conn: ConnId, m: Msg) -> Option<RequestId> {
        self.next += 1;
        self.requests.push((conn, self.next, m));
        Some(self.next)
    }
    fn answer(&mut self, conn: ConnId, id: RequestId, m: Msg) {
        self.answers.push((conn, id, m));
    }
}

/// Deposit items out over a real store: each S's deposit key from `keys` (its seed number, a
/// stamped value as the engine's reads are); the actors no longer counted (`opens::counted`)
/// in `uncounted`, stamped likewise.
struct T {
    net: FakeNet,
    store: Store,
    offers: Offers,
    keys: Stamped<SyncId, u8>,
    uncounted: StampedSet<Tid>,
    now: u64,
}

struct FakeJudge<'a> {
    keys: &'a Stamped<SyncId, u8>,
    uncounted: &'a StampedSet<Tid>,
}

impl Judge for FakeJudge<'_> {
    fn deposit_key(&mut self, s: &SyncId, _: Option<Tid>) -> Result<Option<SigningSecret>> {
        Ok(self.keys.get(s).map(|n| deposit_key(&deposit_seed(*n), s)))
    }
    fn counted(&mut self, named: &osis_store::Named) -> Vec<Tid> {
        named.key_actors.iter().filter(|a| !self.uncounted.contains(a)).copied().collect()
    }
}

impl T {
    fn new() -> T {
        let store = Store::open(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), Box::new(SeededRng::from_u64(7))).unwrap();
        T { net: FakeNet::default(), store, offers: Offers::default(), keys: Stamped::default(), uncounted: StampedSet::default(), now: T0 }
    }

    fn settle(&mut self) {
        let mut judge = FakeJudge { keys: &self.keys, uncounted: &self.uncounted };
        for _ in 0..100 {
            if !self.offers.settle(osis_base::Mono(self.now), &self.store, &mut self.net, &mut judge).unwrap() {
                return;
            }
        }
        panic!("offers settle did not end");
    }

    fn advance(&mut self, ms: u64) {
        self.now += ms;
        self.settle();
    }

    fn hold(&mut self, ids: &[(SyncId, Holding)]) {
        self.store.set_sync_set(&SyncSet { ids: ids.iter().map(|(s, h)| (*s, ([THING].into(), *h))).collect(), ..SyncSet::default() }).unwrap();
    }

    /// `c` proved `actors`, its digests agreed at once.
    fn connect(&mut self, c: ConnId, actors: &[Tid]) {
        self.net.agreed.insert(c);
        self.net.actors.insert(c, actors.to_vec());
        self.offers.connected(c, &self.net);
        self.settle();
    }

    /// `c` takes kept record `r`, its digests not agreed yet.
    fn take(&mut self, c: ConnId, r: osis_sync::types::RecordId) {
        self.net.rec.insert(c, r);
        self.offers.connected(c, &self.net);
        self.offers.record_moved(c);
        self.settle();
    }

    fn agree(&mut self, c: ConnId) {
        self.net.agreed.insert(c);
        self.settle();
    }

    /// `c` ends, its record let go.
    fn close(&mut self, c: ConnId) {
        self.offers.closed(c);
        self.net.rec.remove(&c);
        if self.net.agreed.contains(&c) {
            self.net.agreed.remove(&c);
        }
        self.settle();
    }

    fn join(&mut self, c: ConnId, s: SyncId, class: SourceClass) {
        self.net.members.insert((c, s), Member { class, own: SourceClass::Reader, by: Credential::SyncKey, until: None, departed: false });
        let _ = Moved::Joined(c, s, osis_sync::opens::Rejoin::Held);
        self.offers.joined(c, &s, &self.net);
        self.settle();
    }

    fn reply(&mut self, c: ConnId, id: RequestId, m: Msg) {
        self.offers.answered(osis_base::Mono(self.now), c, id, &m);
        self.settle();
    }

    /// An own deposit of `tag` under S, offered to `target`.
    fn deposit(&mut self, s: SyncId, tag: u64, target: Target) -> BlobId {
        if !self.keys.contains_key(&s) {
            self.keys.insert(s, s.0[0]);
        }
        let (b, bytes) = blob(tag, 64, Some(T0 + INBOX_LIFETIME_MS));
        match target {
            // a sealed fire: held outside the store
            Target::Fire { .. } => self.offers.add_fire(s, b, Arc::new(bytes), [5; 57], target),
            Target::Stores => {
                let e = Entry { blob: b, wrap: [5; 57], stamp: None, deposited: true, own: true, role: false, class: Class::Durable, expires: Some(WallMs(T0 + INBOX_LIFETIME_MS)) };
                assert_eq!(self.store.log(&s, e, Some(bytes), None).unwrap(), Code::OK);
                self.offers.add(s, b, target);
            }
        }
        self.settle();
        b
    }

    /// The Deposit items sent so far: (connection, request, sync ID, blob).
    fn deposits_sent(&self) -> Vec<(ConnId, RequestId, SyncId, BlobId)> {
        self.net
            .requests
            .iter()
            .filter_map(|(c, id, m)| match m {
                Msg::Offer { items, .. } => match items.as_slice() {
                    [OfferItem::Deposit(d)] => Some((*c, *id, d.sync_id, osis_blob::blob_id(&d.blob))),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    fn shared(code: Code) -> Msg {
        Msg::Shared { id: 0, items: vec![SharedItem::code(code)] }
    }
}

// spec/sync-inbox.md §3 (sending): a sealed fire is offered as a Deposit item signed by
// the inbox's deposit key to a peer that may hold the inbox (the recipient proven there), never
// to an unrelated peer.
#[test]
fn sealed_fire_offered_to_recipient_spec_sync_inbox_3() {
    let mut t = T::new();
    t.connect(conn(1), &[tid(9)]);
    t.connect(conn(2), &[tid(0)]);
    let s = sync_id(100);
    let b = t.deposit(s, 1, fire(tid(0)));
    assert_eq!(t.deposits_sent().iter().map(|x| (x.0, x.3)).collect::<Vec<_>>(), vec![(conn(2), b)], "only to the recipient's node");
    let Msg::Offer { items, .. } = &t.net.requests[0].2 else { panic!() };
    let [OfferItem::Deposit(d)] = items.as_slice() else { panic!() };
    let head = deposit_key(&deposit_seed(s.0[0]), &s).verifying_key();
    assert!(osis_blob::verify_deposit(&head, &d.sync_id, &b, &d.wrap, &d.sig).is_ok());
}

// spec/sync-inbox.md §3 (sending), spec/sync-opens.md §3 (A record names what its last session's proofs counted for): the
// recipient proven on a connection counts only while its proof counts now: once it stops (its
// account removed the proving node, its key's epoch closed), nothing more is offered there for
// it, also what was ready or backed off; counted again, its offers go there again.
#[test]
fn sealed_fire_offered_only_while_the_recipient_counts_spec_sync_inbox_3() {
    let mut t = T::new();
    t.connect(conn(2), &[tid(0)]);
    let s = sync_id(100);
    let first = t.deposit(s, 1, fire(tid(0)));
    let (c, id, ..) = t.deposits_sent()[0];
    t.reply(c, id, T::shared(Code::RATE_LIMITED));
    t.uncounted.insert(tid(0));
    t.deposit(s, 2, fire(tid(0)));
    t.advance(osis_sync::inbox::backoff_ms(0));
    assert_eq!(t.deposits_sent().len(), 1, "no offer for a recipient no longer counted there: {:?}", t.deposits_sent());
    t.uncounted.remove(&tid(0));
    t.settle();
    let sent = t.deposits_sent();
    assert_eq!(sent.len(), 2, "counted again: offered again");
    t.reply(c, sent[1].1, T::shared(Code::OK));
    let blobs: BTreeSet<BlobId> = t.deposits_sent().iter().map(|x| x.3).collect();
    assert!(blobs.len() == 2 && blobs.contains(&first), "both offers went: {blobs:?}");
}

// spec/sync-inbox.md §3 (Sending; Refused for now: sent again after a back-off until taken or
// moot): a back-off whose wake came while the peer could not take the offer (its recipient counted no more there) waits for nothing: S joining
// that connection, or its filter showing S's deposit key, offers it there again.
#[test]
fn a_back_off_over_while_untakeable_waits_for_nothing_spec_sync_inbox_3() {
    for by_filter in [false, true] {
        let mut t = T::new();
        t.connect(conn(2), &[tid(0)]);
        let s = sync_id(100);
        t.deposit(s, 1, fire(tid(0)));
        let (c, id, ..) = t.deposits_sent()[0];
        t.reply(c, id, T::shared(Code::RATE_LIMITED));
        t.uncounted.insert(tid(0));
        t.advance(osis_sync::inbox::backoff_ms(0));
        assert_eq!(t.deposits_sent().len(), 1, "not offered while the recipient counts no more");
        if by_filter {
            let key = deposit_key(&deposit_seed(s.0[0]), &s).verifying_key().to_bytes();
            t.net.shown.insert((conn(2), s, key));
            t.net.generation.insert(conn(2), 1);
            t.settle();
        } else {
            t.join(conn(2), s, SourceClass::Reader);
        }
        assert_eq!(t.deposits_sent().len(), 2, "offered again (by filter: {by_filter})");
    }
}

// spec/sync-inbox.md §3 (sending): a sealed fire also goes to a peer whose filter shows the
// inbox's deposit key (a node keeping it unread shows it to every connection,
// spec/sync-opens.md §5 Filter), once that filter arrives; never to one showing another key.
#[test]
fn sealed_fire_offered_where_filter_shows_deposit_key_spec_sync_inbox_3() {
    let mut t = T::new();
    t.connect(conn(1), &[tid(9)]);
    t.connect(conn(2), &[tid(8)]);
    let s = sync_id(100);
    t.deposit(s, 1, fire(tid(0)));
    assert!(t.deposits_sent().is_empty(), "no peer may hold the inbox");
    let key = deposit_key(&deposit_seed(s.0[0]), &s).verifying_key().to_bytes();
    t.net.shown.insert((conn(1), s, key));
    t.net.shown.insert((conn(2), s, [7; 32]));
    t.settle();
    assert!(t.deposits_sent().is_empty(), "nothing before the filter that shows it arrives");
    t.net.generation.insert(conn(1), 1);
    t.net.generation.insert(conn(2), 1);
    t.settle();
    assert_eq!(t.deposits_sent().iter().map(|x| x.0).collect::<Vec<_>>(), vec![conn(1)]);
}

// spec/sync-inbox.md §3 (sending): one unanswered Deposit item per connection; the next goes when
// it is answered.
#[test]
fn one_deposit_item_unanswered_per_connection_spec_sync_inbox_3() {
    let mut t = T::new();
    for i in 0..3 {
        t.deposit(sync_id(100), i, fire(tid(0)));
    }
    t.connect(conn(2), &[tid(0)]);
    assert_eq!(t.deposits_sent().len(), 1);
    let (c, id, ..) = t.deposits_sent()[0];
    t.reply(c, id, T::shared(Code::OK));
    assert_eq!(t.deposits_sent().len(), 2);
}

// spec/sync-inbox.md §3 (refused for now): 4, 5 or 12 is no answer: the item is offered again
// after a back-off, never at once; one taken at that peer ends the back-off of the others of
// its sync ID there.
#[test]
fn refused_for_now_backs_off_spec_sync_inbox_3() {
    let mut t = T::new();
    for i in 0..2 {
        t.deposit(sync_id(100), i, fire(tid(0)));
    }
    t.connect(conn(2), &[tid(0)]);
    let (c, id, s, first) = t.deposits_sent()[0];
    t.reply(c, id, T::shared(Code::DEPOSIT_BUDGET_FULL));
    let (_, id2, _, second) = t.deposits_sent()[1];
    assert!(second != first);
    t.reply(c, id2, T::shared(Code::RATE_LIMITED));
    assert_eq!(t.deposits_sent().len(), 2, "both backed off");
    t.advance(osis_sync::inbox::backoff_ms(0));
    let again = t.deposits_sent();
    assert_eq!(again.len(), 3, "the first again after its back-off");
    assert_eq!((again[2].2, again[2].3), (s, first));
    t.reply(c, again[2].1, T::shared(Code::OK));
    let last = t.deposits_sent();
    assert_eq!(last.len(), 4, "taken: the other's back-off ended at once");
    assert_eq!(last[3].3, second);
}

// spec/sync-inbox.md §3 (14): a refused item is sent again where signing again changes the
// signature (the deposit key moved), else not on that connection until the receiver's next
// filter arrives.
#[test]
fn refused_waits_for_filter_or_new_key_spec_sync_inbox_3() {
    let mut t = T::new();
    t.deposit(sync_id(100), 1, fire(tid(0)));
    t.connect(conn(2), &[tid(0)]);
    let (c, id, ..) = t.deposits_sent()[0];
    t.reply(c, id, T::shared(Code::DECLINED));
    t.advance(60 * 60 * 1000);
    assert_eq!(t.deposits_sent().len(), 1, "not again on that connection");
    t.net.generation.insert(c, 1);
    t.settle();
    let sent = t.deposits_sent();
    assert_eq!(sent.len(), 2, "again at the next filter");
    t.reply(c, sent[1].1, T::shared(Code::DECLINED));
    t.keys.insert(sync_id(100), 42);
    t.settle();
    assert_eq!(t.deposits_sent().len(), 3, "again at once under a new deposit key");
}

// spec/sync-inbox.md §3 (sending): an own deposit under a sync ID this node reads goes to each
// source keeping S unread until it answers, never to a reader (readers pull it); scenario
// eph-revert-reads: a body only a reader holds, deposited by it, reaches a node keeping S unread.
#[test]
fn own_deposit_offered_to_store_sources_only_spec_sync_inbox_3() {
    let mut t = T::new();
    let s = sync_id(1);
    t.hold(&[(s, Holding::Read)]);
    t.connect(conn(1), &[]);
    t.connect(conn(2), &[]);
    t.join(conn(1), s, SourceClass::Reader);
    t.join(conn(2), s, SourceClass::Store);
    let b = t.deposit(s, 1, Target::Stores);
    let sent = t.deposits_sent();
    assert_eq!(sent.iter().map(|x| (x.0, x.3)).collect::<Vec<_>>(), vec![(conn(2), b)]);
    t.reply(conn(2), sent[0].1, T::shared(Code::OK));
    assert_eq!(t.deposits_sent().len(), 1, "answered: done there");
}

/// A blob as a promoter judges it: the parts it opened and checked, its other sections by
/// their bytes (one byte each, as a digest).
fn opened(parts: &[usize], sealed: &[u8]) -> Judged {
    Judged { parts: parts.iter().copied().collect(), sealed: sealed.iter().map(|b| [*b; 32]).collect() }
}

// spec/sync-inbox.md §4 (by its bytes alone): a writer that cannot open B's section holds a
// stamped forgery of the commit (its checked part 0, junk where B's section goes); the genuine
// deposit holds the same checked part and B's section by bytes it does not hold stamped, so it is
// no duplicate and is promoted beside the forgery; one byte-identical to a stamped entry's is not.
#[test]
fn genuine_deposit_promoted_beside_stamped_forgery_spec_sync_inbox_4() {
    let need: BTreeSet<usize> = [0, 1].into();
    let forgery = opened(&[0], &[9]);
    assert!(adds_delta(&need, &opened(&[0], &[1]), std::slice::from_ref(&forgery)), "the genuine deposit");
    assert!(!adds_delta(&need, &opened(&[0], &[9]), std::slice::from_ref(&forgery)), "byte-identical to the stamped one");
    assert!(!adds_delta(&need, &opened(&[0], &[]), std::slice::from_ref(&forgery)), "nothing unopened: a copy of part 0");
    // a stamped entry holding no needed part (a certificate copy) takes no bytes-only slot
    let copy = opened(&[5], &[]);
    assert!(adds_delta(&need, &opened(&[0], &[1]), &[forgery.clone(), copy]), "a certificate copy beside the forgery shuts nothing out");
}

// spec/sync-hostile.md §2 (promotes one more deposit of the commit by its bytes alone): a forger depositing N variants of a commit
// (each with other junk) gets at most one promoted beside the stamped entries while one stands;
// the rest stay deposits. A writer that opens B judges the genuine deposit by its part 1, which
// no stamped variant holds, and promotes it: the slot starves it only until such a writer acts.
#[test]
fn forger_variants_hold_one_slot_until_an_opener_promotes_spec_sync_hostile_2() {
    let need: BTreeSet<usize> = [0, 1].into();
    // as a writer that cannot open B judges them: the forgery stamped first, one variant
    // promoted, every later one (the genuine deposit too) waits
    let mut stamped = vec![opened(&[0], &[100])];
    let mut promoted = 0;
    for v in 101..=110u8 {
        if adds_delta(&need, &opened(&[0], &[v]), &stamped) {
            stamped.push(opened(&[0], &[v]));
            promoted += 1;
        }
    }
    assert_eq!(promoted, 1, "one bytes-only promotion while it stands");
    assert!(!adds_delta(&need, &opened(&[0], &[1]), &stamped), "the genuine deposit waits");
    // a writer of S that opens B: the forged sections do not open under B's secrets (junk), the
    // genuine one opens and checks
    let at_opener = [opened(&[0], &[100]), opened(&[0], &[101])];
    assert!(adds_delta(&need, &opened(&[0, 1], &[]), &at_opener), "the genuine deposit adds part 1");
}

// spec/sync-inbox.md §4 (promotion): one stamped copy per delta, however many encryptions are
// deposited: a deposit adds a delta only by a part S must hold that no stamped entry of the
// commit holds.
#[test]
fn one_stamped_copy_per_delta_spec_sync_inbox_4() {
    let need: BTreeSet<usize> = [0, 1].into();
    let stamped = [opened(&[0], &[])];
    assert!(!adds_delta(&need, &opened(&[0], &[]), &stamped), "a second copy of part 0");
    assert!(!adds_delta(&need, &opened(&[0, 2], &[]), &stamped), "part 2 is no part S must hold");
    assert!(adds_delta(&need, &opened(&[0, 1], &[]), &stamped), "part 1 not held stamped");
    assert!(adds_delta(&need, &opened(&[0], &[]), &[]), "the first copy");
}

/// Steps of one sync ID: genesis and children, as an admin issues them.
struct Steps {
    steps: Vec<(Step, ClaimSet)>,
}

impl Steps {
    fn new(n: usize) -> Steps {
        let admin = Secret32::from_bytes([0xab; 32]);
        let id = osis_blob::genesis_sync_id(&admin);
        let d = role_key(RoleKey::Delete, &admin);
        let mut steps: Vec<(Step, ClaimSet)> = Vec::new();
        for i in 0..n {
            let (sync, write) = (Secret32::from_bytes([i as u8; 32]), Secret32::from_bytes([i as u8 + 0x40; 32]));
            let keys = StepKeys::derive(&sync, &write, &admin, &deposit_seed(0), &id);
            let read = Epoch::derive(&THING, osis_base::Role::Read, i as u64, &write).unwrap();
            let se = Epoch::derive(&THING, osis_base::Role::Sync, i as u64, &sync).unwrap();
            let parent = match steps.last() {
                None => Parent::Genesis(&d),
                Some((p, _)) => Parent::Child { step: p, delete: &d },
            };
            let mut rng = SeededRng::from_u64(i as u64);
            steps.push(osis_blob::register(parent, keys, &[], (&THING, read, &write), (se, &sync), &mut rng).unwrap());
        }
        Steps { steps }
    }
    fn path(&self) -> Arc<Path> {
        Arc::new(Path { steps: self.steps.iter().map(|(s, c)| (s.clone(), Some(c.clone()))).collect() })
    }
    fn id(&self, i: usize) -> StepId {
        self.steps[i].0.id()
    }
}

/// The plan at a source standing at step `at`, given what it holds.
fn plan_at(st: &Steps, at: Option<StepId>, p: Progress, held: &[StepId]) -> Plan {
    plan(at, &st.path(), &p, &mut |x: &StepId| Ok(held.contains(x))).unwrap()
}

fn sends(p: &Plan) -> Option<StepId> {
    match p {
        Plan::Send(s, _) => Some(s.id()),
        _ => None,
    }
}

// spec/sync-ids.md §6 (steps): a reader registers at a source keeping S unread the recorded steps
// after the source's step, in order, each once the source's stream showed the role commits it
// depends on; at the head, nothing.
#[test]
fn registers_steps_after_source_step_spec_sync_ids_6() {
    let st = Steps::new(3);
    let all = [st.id(0), st.id(1), st.id(2)];
    assert_eq!(plan_at(&st, Some(st.id(0)), Progress::default(), &[]), Plan::Wait, "the role commits are not there yet");
    assert_eq!(sends(&plan_at(&st, Some(st.id(0)), Progress::default(), &all)), Some(st.id(1)));
    let after = Progress { at: Some(st.id(1)), ..Progress::default() };
    assert_eq!(sends(&plan_at(&st, Some(st.id(0)), after, &all)), Some(st.id(2)), "registered there: the next");
    assert_eq!(plan_at(&st, Some(st.id(2)), Progress::default(), &all), Plan::Nothing, "at the head");
    assert_eq!(plan_at(&st, Some(StepId([7; 32])), Progress::default(), &all), Plan::Nothing, "a source on a step not recorded");
}

// spec/sync-ids.md §6 (walk: moving it, from genesis while the source's step is not known): a
// source whose stream named no head gets the genesis step at once, whatever it holds; refused
// there, nothing until its head event; once registered there, the next.
#[test]
fn a_source_holding_no_step_gets_genesis_first_spec_sync_ids_6() {
    let st = Steps::new(3);
    assert_eq!(sends(&plan_at(&st, None, Progress::default(), &[])), Some(st.id(0)), "genesis, at once");
    assert_eq!(plan_at(&st, None, Progress { stuck: Some(None), ..Progress::default() }, &[]), Plan::Wait, "refused: waits for a head event");
    let all = [st.id(0), st.id(1), st.id(2)];
    let at = Progress { at: Some(st.id(0)), ..Progress::default() };
    assert_eq!(sends(&plan_at(&st, None, at, &all)), Some(st.id(1)), "then the next");
}

// spec/sync-ids.md §6 (register; refused for now): one Register out at a time; refused for now (4,
// 12) it waits for its back-off; any other refusal changes no view: nothing until the source's
// step moves.
#[test]
fn register_refusals_spec_sync_ids_6() {
    let st = Steps::new(3);
    let all = [st.id(0), st.id(1), st.id(2)];
    let at0 = Some(st.id(0));
    assert_eq!(plan_at(&st, at0, Progress { out: true, ..Progress::default() }, &all), Plan::Wait);
    assert_eq!(plan_at(&st, at0, Progress { backoff: Some((osis_base::Mono(T0), 0)), ..Progress::default() }, &all), Plan::Wait);
    let stuck = Progress { stuck: Some(at0), ..Progress::default() };
    assert_eq!(plan_at(&st, at0, stuck, &all), Plan::Wait, "refused: waits");
    assert_eq!(sends(&plan_at(&st, Some(st.id(1)), stuck, &all)), Some(st.id(2)), "the head event moved it");
}

// spec/sync-inbox.md §4 (promotion), §3 (what a node must log under S and cannot stamp, it
// deposits), spec/sync-ids.md §6 (a stamped entry of a deposited entry's blob ID replaces it):
// node 0 (admin) rotates S's write secret leaving node 2 (a writer) out, and goes off; node 2,
// standing at the new head with no write key for it, writes: its entry goes to node 1 (keeping S
// unread) deposited. Node 0 comes back beside node 1 alone: it takes the deposit and promotes it
// (stamped in its store under the new head), and node 1 takes the stamped entry in place of the
// deposit (what readers pull).
#[test]
fn a_writer_promotes_a_deposit_spec_sync_inbox_4() {
    use crate::harness::history::{Gives, three, value_ak};
    use osis_base::{Role, Value};
    use osis_engine::Mutation;
    let (mut w, t, s) = three(Gives::Writes, 1);
    w.cap = 20_000;
    assert_eq!(w.engine(1).sync_holder(&s).unwrap(), Some(([t].into(), Holding::Unread)));
    w.power_off(2);
    let a2 = w.node(2).account.unwrap();
    w.write(0, |e| e.rotate_leaving_out(&t, &[Role::Write], &[a2])).unwrap().expect("a rotation");
    w.run();
    let head = w.store(1).head(&s).unwrap().map(|h| h.id());
    w.power_off(0);
    w.power_on(2);
    w.run();
    assert_eq!(w.store(2).head(&s).unwrap().map(|h| h.id()), head, "node 2 stands at the new head");
    let c = w.write(2, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Int(7)).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    let blobs: Vec<BlobId> = w.engine(2).commit_blobs(&c).unwrap().iter().copied().collect();
    let entry = |w: &crate::harness::World, i: usize| blobs.iter().find_map(|b| w.store(i).entry(&s, b).unwrap());
    assert!(entry(&w, 1).is_some_and(|e| e.deposited), "deposited at node 1: {:?}", entry(&w, 1));
    w.power_off(2);
    w.power_on(0);
    w.run();
    assert!(w.engine(0).holds_commit(&c), "node 0 took it from the deposit");
    assert!(entry(&w, 0).is_some_and(|e| e.stamp.is_some() && !e.deposited), "node 0 promoted it: {:?}", entry(&w, 0));
    assert!(entry(&w, 1).is_some_and(|e| e.stamp.is_some() && !e.deposited), "node 1 holds it stamped: {:?}", entry(&w, 1));
    // the author's chain under S decides (`inbox::promotion`): with node 0's entries of a chain
    // commit S carries gone, the entry waits; logged again, it is promoted
    let b = blobs.iter().copied().find(|b| w.store(0).entry(&s, b).unwrap().is_some()).expect("node 0's entry");
    let mut st = w.store(0).clone();
    let promotion = |w: &mut crate::harness::World| {
        let st = w.store(0).clone();
        osis_sync::inbox::promotion(w.engine(0), &st, &s, &c, &b).unwrap()
    };
    assert_eq!(promotion(&mut w), Promotion::Yes);
    let osis_engine::sync::Promote::Yes { chain } = w.engine(0).promotable(&s, &c).unwrap() else { panic!("promotable") };
    let cc = *chain.commits.keys().find(|x| w.engine(0).sync_bodies(x).unwrap().contains_key(&s)).expect("a chain commit S carries");
    let mut gone = Vec::new();
    for x in w.engine(0).commit_blobs(&cc).unwrap().iter() {
        if let Some(e) = st.entry(&s, x).unwrap() {
            gone.push((e, st.bytes(x).unwrap()));
            st.unlog_entry(&s, x).unwrap();
        }
    }
    assert!(!gone.is_empty());
    assert_eq!(promotion(&mut w), Promotion::Wait, "the chain is not under S");
    for (e, bytes) in gone {
        st.log(&s, e, bytes, None).unwrap();
    }
    assert_eq!(promotion(&mut w), Promotion::Yes, "the chain under S again");
}

/// Node 1 (keeping S unread) goes away from both others, back once, and away again. With
/// `removed`, node 0 removes node 1 from the thing, and node 2 hears of it. Then node 2 (a writer
/// left out of S's next rotation, standing at its head) writes with node 0 off: its entry is
/// deposited, owed to the sources keeping S unread. The Deposit items node 2 sends as node 1 is
/// back (node 2 withholds its entries from every stream, so nothing promotes the deposit).
fn deposit_items_to_a_peer_back(removed: bool) -> u64 {
    use crate::harness::history::{Gives, three, value_ak};
    use osis_base::{Role, Value};
    use osis_engine::Mutation;
    let (mut w, t, s) = three(Gives::Writes, 1);
    w.cap = 2_000_000;
    w.partition(0, 1);
    w.partition(1, 2);
    w.advance(1000);
    w.rejoin(0, 1);
    w.rejoin(1, 2);
    w.advance(30_000);
    w.partition(0, 1);
    w.partition(1, 2);
    if removed {
        let _ = crate::harness::play(&mut w, &[crate::harness::Step::Remove(0, 0, 1)], String::new());
        w.run();
    }
    let a2 = w.node(2).account.unwrap();
    w.power_off(2);
    w.write(0, |e| e.rotate_leaving_out(&t, &[Role::Write], &[a2])).unwrap().expect("a rotation");
    w.run();
    w.power_on(2);
    w.run();
    assert_eq!(w.store(2).head(&s).unwrap().map(|h| h.id()), w.store(0).head(&s).unwrap().map(|h| h.id()), "node 2 stands at the new head");
    w.lie(2, Some(crate::harness::lies::Lie::Withhold));
    w.power_off(0);
    let c = w.write(2, |e| {
        let mut m = Mutation::new();
        m.set(t, &value_ak(), &Value::Int(7)).unwrap();
        e.commit(m).unwrap().unwrap()
    });
    w.run();
    let blobs: Vec<BlobId> = w.engine(2).commit_blobs(&c).unwrap().iter().copied().collect();
    assert!(blobs.iter().any(|b| w.store(2).entry(&s, b).unwrap().is_some_and(|e| e.deposited)), "deposited");
    osis_base::costs::take();
    w.rejoin(1, 2);
    w.advance(30_000);
    assert!(w.links_of(2).iter().any(|(_, j)| *j == 1), "they met again");
    osis_base::costs::take().into_iter().filter(|(k, ..)| *k == "inbox: deposit item sent").map(|(.., n)| n).sum()
}

// spec/sync-inbox.md §3 (Sending: to each source of S keeping S unread), spec/sync-opens.md §6
// (ended: judged in the step that applies the change, whether connected or not): a deposit owed to a
// node keeping S unread goes there as it is back; written after that node's right ended while it
// was away, it goes nowhere.
#[test]
fn a_deposit_after_a_removal_while_away_goes_nowhere_spec_sync_inbox_3() {
    assert!(deposit_items_to_a_peer_back(false) >= 1, "owed: it goes as the peer is back");
    assert_eq!(deposit_items_to_a_peer_back(true), 0, "removed while away: nothing goes");
}

// spec/sync-inbox.md §4 Clearing deposits: a stranger flooding an inbox with deposits nobody can
// act on (junk, fires with no expiry or one far off, a blob past the byte bound) leaves at most
// `DEPOSITS_WAITING` entries and `DEPOSITS_WAITING_BYTES` bytes, whatever the flood's size: those
// with no expiry go first, then earliest to expire; under the bounds nothing goes.
#[test]
fn a_deposit_flood_leaves_the_bounds_spec_sync_inbox_4() {
    use osis_base::format::{DEPOSITS_WAITING, DEPOSITS_WAITING_BYTES};
    let blob_of = |i: usize| {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&(i as u64).to_be_bytes());
        BlobId(b)
    };
    let entry = |i: usize, expires: Option<u64>| Entry { blob: blob_of(i), wrap: [0; osis_crypto::WRAP_LEN], stamp: None, deposited: true, own: false, role: false, class: Class::Durable, expires: expires.map(WallMs) };
    let under: Vec<(Entry, u64)> = (0..DEPOSITS_WAITING).map(|i| (entry(i, None), 1)).collect();
    assert!(osis_sync::inbox::to_clear(under).is_empty(), "under the bounds nothing goes");
    for flood in [DEPOSITS_WAITING + 1, 10 * DEPOSITS_WAITING] {
        // every third has no expiry; one blob alone past the byte bound, the first to expire
        let mut idle: Vec<(Entry, u64)> = (0..flood).map(|i| (entry(i, (i % 3 != 0).then_some(T0 + i as u64)), 1_000)).collect();
        idle.push((entry(flood, Some(T0)), DEPOSITS_WAITING_BYTES as u64 + 1));
        let gone: BTreeSet<BlobId> = osis_sync::inbox::to_clear(idle.clone()).into_iter().collect();
        let kept: Vec<&(Entry, u64)> = idle.iter().filter(|(e, _)| !gone.contains(&e.blob)).collect();
        assert!(kept.len() <= DEPOSITS_WAITING, "{flood}: {} kept", kept.len());
        assert!(kept.iter().map(|(_, n)| *n).sum::<u64>() <= DEPOSITS_WAITING_BYTES as u64, "{flood}: bytes kept");
        let latest_gone = idle.iter().filter(|(e, _)| gone.contains(&e.blob)).filter_map(|(e, _)| e.expires).max();
        assert!(kept.iter().all(|(e, _)| e.expires.is_some() && e.expires >= latest_gone), "{flood}: no expiry first, then earliest");
    }
}

// spec/sync-inbox.md §3 (Sending: to each source of S keeping S unread until that source takes
// it there, on each connection), spec/sync-opens.md §3 (Agreement: nothing of S before the
// digests agree): an own deposit goes on a connection of the record only once its digests agreed
// there; unanswered as its connection ends, it goes on the next; taken (answered 0), it goes
// again on the next connection all the same until it is moot (stamped): the store that took it
// may have lost it since (a restart, S shredded and synced again), and nothing it shows says so.
// Refused for now, it is backed off on that connection, and goes at once on the next.
#[test]
fn an_offer_goes_once_agreed_on_each_connection_until_moot_spec_sync_inbox_3() {
    let mut t = T::new();
    let s = sync_id(1);
    let r = [7; 16];
    let sent_of = |t: &T, from: usize| t.deposits_sent().iter().skip(from).map(|x| (x.0, x.3)).collect::<Vec<_>>();
    t.hold(&[(s, Holding::Read)]);
    t.take(conn(1), r);
    t.join(conn(1), s, SourceClass::Store);
    let b = t.deposit(s, 1, Target::Stores);
    assert!(t.deposits_sent().is_empty(), "taken, the digests not agreed: nothing goes");
    t.agree(conn(1));
    assert_eq!(sent_of(&t, 0), vec![(conn(1), b)], "agreed: it goes");
    // unanswered as the connection ends: carried out on the next
    t.close(conn(1));
    t.take(conn(2), r);
    t.join(conn(2), s, SourceClass::Store);
    t.agree(conn(2));
    assert_eq!(sent_of(&t, 1), vec![(conn(2), b)], "carried out on the next connection");
    let id = t.deposits_sent()[1].1;
    t.reply(conn(2), id, T::shared(Code::OK));
    assert_eq!(t.deposits_sent().len(), 2, "taken: done on that connection");
    // the store may lose it while away: offered again on its next connection
    t.close(conn(2));
    t.take(conn(3), r);
    t.join(conn(3), s, SourceClass::Store);
    t.agree(conn(3));
    assert_eq!(sent_of(&t, 2), vec![(conn(3), b)], "taken before: offered again at a reconnect until moot");
    let id = t.deposits_sent()[2].1;
    t.reply(conn(3), id, T::shared(Code::OK));
    // refused for now: backed off on that connection, again at once on the next
    let b2 = t.deposit(s, 2, Target::Stores);
    assert_eq!(sent_of(&t, 3), vec![(conn(3), b2)]);
    let id = t.deposits_sent()[3].1;
    t.reply(conn(3), id, T::shared(Code::DEPOSIT_BUDGET_FULL));
    assert_eq!(t.deposits_sent().len(), 4, "backed off there");
    // stamped: moot, offered nowhere again
    t.offers.remove(&s, &b);
    t.close(conn(3));
    t.take(conn(4), r);
    t.join(conn(4), s, SourceClass::Store);
    t.agree(conn(4));
    assert_eq!(sent_of(&t, 4), vec![(conn(4), b2)], "refused: offered again on the next connection; the moot one not");
}

// spec/sync-inbox.md §3 (one unanswered Deposit item per connection), spec/sync.md §2 (work in
// proportion to change): a peer that never answers costs one item out per connection and holds
// nothing across its reconnects: at n and 10n own deposits alike.
#[test]
fn a_peer_never_answering_holds_nothing_across_reconnects_spec_sync_inbox_3() {
    for n in [3u64, 30] {
        let mut t = T::new();
        let s = sync_id(1);
        t.hold(&[(s, Holding::Read)]);
        for i in 0..n {
            t.deposit(s, 1 + i, Target::Stores);
        }
        for c in 1..10 {
            t.take(conn(c), [7; 16]);
            t.join(conn(c), s, SourceClass::Store);
            t.agree(conn(c));
            t.close(conn(c));
            assert_eq!(t.offers.held(), 0, "nothing kept of a connection gone");
        }
        assert_eq!(t.deposits_sent().len(), 9, "one item out per connection");
    }
}
