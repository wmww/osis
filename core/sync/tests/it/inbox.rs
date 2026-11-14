//! Inbox, deposits, steps and Register (osis_sync::inbox): each rule's decision over plain values
//! (`act_of`, `adds_delta`, `to_clear`, `plan`), and Deposit items out (`Offers`) over a real
//! store and a `Net` that records what is sent. One test per rule of spec/sync-inbox.md §2-§4 and
//! spec/sync-ids.md §6 Steps and Register it implements. The module in a node over the engine
//! (a delivery logged deposited, an inbox blob taken) is tests/it/keep.rs.

use osis_base::format::{DEPOSITS_WAITING, INBOX_LIFETIME_MS};
use osis_base::memo::{Stamped, StampedSet};
use osis_base::{BlobId, CommitId, SyncId, Tid, WallMs};
use osis_crypto::{Epoch, LabelRole, Secret32, SeededRng, SigningSecret, deposit_key, label_role_key};
use osis_engine::labeling::Certs;
use osis_engine::sync::{Holding, InboxOpened, Path, Promote, SyncSet, Taken};
use osis_label::{ClaimSet, Class, Parent, Prefix, Step, StepId, StepKeys};
use osis_proto::{Code, Msg, OfferItem, SharedItem};
use osis_store::{MemoryBackend, MemoryRoot};
use osis_sync::Result;
use osis_sync::inbox::{Act, Facts, Net, Offers, Plan, Progress, Target, act_of, adds_delta, goes_last, plan, to_clear};
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

fn commit(i: u32) -> CommitId {
    let mut b = [0xc0; 32];
    b[..4].copy_from_slice(&i.to_le_bytes());
    CommitId(b)
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
    let (_, bytes) = osis_label::frame(&p, &vec![tag as u8; n], &mut rng).unwrap();
    (osis_label::blob_id(&bytes), bytes)
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
    next: RequestId,
    requests: Vec<(ConnId, RequestId, Msg)>,
    answers: Vec<(ConnId, RequestId, Msg)>,
}

impl Net for FakeNet {
    fn actors(&self, conn: ConnId) -> Vec<Tid> {
        self.actors.get(&conn).cloned().unwrap_or_default()
    }
    fn member(&self, conn: ConnId, s: &SyncId) -> Option<Member> {
        self.members.get(&(conn, *s)).cloned()
    }
    fn head(&self, _conn: ConnId, _s: &SyncId) -> Option<StepId> {
        None
    }
    fn present(&self, conn: ConnId, s: &SyncId, b: &BlobId) -> bool {
        self.present.contains(&(conn, *s, *b))
    }
    fn filter_generation(&self, conn: ConnId) -> u64 {
        self.generation.get(&conn).copied().unwrap_or(0)
    }
    fn shows_deposit_key(&self, conn: ConnId, s: &SyncId, key: &[u8; 32]) -> bool {
        self.shown.contains(&(conn, *s, *key))
    }
    fn source(&self, conn: ConnId) -> Source {
        Source::Conn(conn)
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
/// stamped value as the engine's reads are).
struct T {
    net: FakeNet,
    store: Store,
    offers: Offers,
    keys: Stamped<SyncId, u8>,
    now: u64,
}

impl T {
    fn new() -> T {
        let store = Store::open(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), Box::new(SeededRng::from_u64(7))).unwrap();
        T { net: FakeNet::default(), store, offers: Offers::default(), keys: Stamped::default(), now: T0 }
    }

    fn settle(&mut self) {
        let keys = &self.keys;
        let mut f = |s: &SyncId, _: Option<Tid>| -> Result<Option<SigningSecret>> { Ok(keys.get(s).map(|n| deposit_key(&deposit_seed(*n), s))) };
        for _ in 0..100 {
            if !self.offers.settle(WallMs(self.now), &self.store, &mut self.net, &mut f).unwrap() {
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
        self.store.set_sync_set(&SyncSet { ids: ids.iter().map(|(s, h)| (*s, (THING, *h))).collect(), ..SyncSet::default() });
    }

    fn connect(&mut self, c: ConnId, actors: &[Tid]) {
        self.net.actors.insert(c, actors.to_vec());
        self.offers.connected(c, &self.net);
        self.settle();
    }

    fn join(&mut self, c: ConnId, s: SyncId, class: SourceClass) {
        self.net.members.insert((c, s), Member { class, by: Credential::SyncKey, until: None });
        let _ = Moved::Joined(c, s, osis_sync::opens::Rejoin::Held);
        self.offers.joined(c, &s, &self.net);
        self.settle();
    }

    fn reply(&mut self, c: ConnId, id: RequestId, m: Msg) {
        self.offers.answered(WallMs(self.now), c, id, &m);
        self.settle();
    }

    /// An own deposit of `tag` under S, offered to `target`.
    fn deposit(&mut self, s: SyncId, tag: u64, target: Target) -> BlobId {
        if !self.keys.contains_key(&s) {
            self.keys.insert(s, s.0[0]);
        }
        let (b, bytes) = blob(tag, 64, Some(T0 + INBOX_LIFETIME_MS));
        let e = Entry { blob: b, wrap: [5; 57], stamp: None, deposited: true, own: true, role: false, class: Class::Durable, expires: Some(WallMs(T0 + INBOX_LIFETIME_MS)) };
        assert_eq!(self.store.log(&s, e, Some(bytes), None).unwrap(), Code::OK);
        self.offers.add(s, b, target);
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
                    [OfferItem::Deposit(d)] => Some((*c, *id, d.sync_id, osis_label::blob_id(&d.blob))),
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

// spec/sync-inbox.md §3 (sending): an inbox blob deposited is offered as a Deposit item signed by
// the inbox's deposit key to a peer that may hold the inbox (the recipient proven there), never
// to an unrelated peer.
#[test]
fn inbox_blob_offered_to_recipient_spec_sync_inbox_3() {
    let mut t = T::new();
    t.connect(conn(1), &[tid(9)]);
    t.connect(conn(2), &[tid(0)]);
    let s = sync_id(100);
    let b = t.deposit(s, 1, Target::Recipient(tid(0)));
    assert_eq!(t.deposits_sent().iter().map(|x| (x.0, x.3)).collect::<Vec<_>>(), vec![(conn(2), b)], "only to the recipient's node");
    let Msg::Offer { items, .. } = &t.net.requests[0].2 else { panic!() };
    let [OfferItem::Deposit(d)] = items.as_slice() else { panic!() };
    let head = deposit_key(&deposit_seed(s.0[0]), &s).verifying_key();
    assert!(osis_label::verify_deposit(&head, &d.sync_id, &b, &d.wrap, &d.sig).is_ok());
}

// spec/sync-inbox.md §3 (sending): an inbox blob also goes to a peer whose filter shows the
// inbox's deposit key (a node keeping it unread shows it to every connection,
// spec/sync-opens.md §5 Filter), once that filter arrives; never to one showing another key.
#[test]
fn inbox_blob_offered_where_filter_shows_deposit_key_spec_sync_inbox_3() {
    let mut t = T::new();
    t.connect(conn(1), &[tid(9)]);
    t.connect(conn(2), &[tid(8)]);
    let s = sync_id(100);
    t.deposit(s, 1, Target::Recipient(tid(0)));
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
        t.deposit(sync_id(100), i, Target::Recipient(tid(0)));
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
        t.deposit(sync_id(100), i, Target::Recipient(tid(0)));
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
    t.deposit(sync_id(100), 1, Target::Recipient(tid(0)));
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

const LIFE: u64 = T0 + INBOX_LIFETIME_MS;

/// An inbox blob held deposited, as taking it went.
fn inbox_facts(taken: Option<Taken>, c: u32, writer: bool, expiry: u64) -> Facts {
    let (b, _) = blob(c as u64, 64, Some(expiry));
    let o = taken.map(|taken| InboxOpened { commit: Some(commit(c)), taken, hints: vec![], dial: None });
    Facts { blob: b, deposited: true, own: false, expires: Some(WallMs(expiry)), inbox: Some(o), stamped: None, writer, holding: Some(Holding::Read), promote: None }
}

// spec/sync-inbox.md §2 (stamping in place): a writer of the inbox stamps a deposited inbox blob
// whose commit applied, one per commit, never one whose expiry is more than `INBOX_LIFETIME + 2 ×
// MAX_DRIFT` ahead; an invite request (waiting), a blob nothing opens, or a node not writing the
// inbox stamps none. Taking is judged again as the node's state moves (waiting, then applied).
#[test]
fn writer_stamps_taken_inbox_blob_in_place_spec_sync_inbox_2() {
    let now = WallMs(T0);
    let stamps = |f: &Facts| matches!(act_of(f, now), Act::StampInbox(..));
    let a = inbox_facts(Some(Taken::Applied), 1, true, LIFE);
    assert!(stamps(&a));
    let twin = Facts { stamped: Some(BlobId([9; 32])), ..inbox_facts(Some(Taken::Applied), 1, true, LIFE) };
    assert!(!stamps(&twin), "one blob per commit");
    assert!(stamps(&Facts { stamped: Some(a.blob), ..a.clone() }), "the one stamped stays");
    assert!(!stamps(&inbox_facts(Some(Taken::Applied), 2, true, LIFE + 3 * 60 * 60 * 1000)), "expiry too far ahead");
    assert!(!stamps(&inbox_facts(Some(Taken::Waiting), 3, true, LIFE)), "an invite request stays deposited");
    assert!(!stamps(&inbox_facts(None, 4, true, LIFE)), "nothing here opens it");
    assert!(!stamps(&inbox_facts(Some(Taken::Applied), 5, false, LIFE)), "not a writer of the inbox");
    let Act::Inbox { taken, commit: c, .. } = act_of(&inbox_facts(Some(Taken::Waiting), 6, true, LIFE), now) else { panic!() };
    assert_eq!((taken, c), (Some(Taken::Waiting), Some(commit(6))));
}

/// A deposit under a read S held by a writer, the engine's word on promoting it.
fn deposit_facts(promote: Option<(Promote, bool)>, own: bool) -> Facts {
    let (b, _) = blob(3, 100, None);
    Facts { blob: b, deposited: true, own, expires: None, inbox: None, stamped: None, writer: true, holding: Some(Holding::Read), promote }
}

// spec/sync-inbox.md §4 (promotion): a writer promotes a deposit the engine judges promotable
// (with the author's chain); one judged not yet waits; scenario promote-covered-only-deposit: one
// judged never (its parts a held snapshot carries) stays deposited; a node that does not write S
// is given no promotion (its facts carry none) and promotes nothing.
#[test]
fn writer_promotes_promotable_deposit_spec_sync_inbox_4() {
    let now = WallMs(T0);
    assert_eq!(act_of(&deposit_facts(Some((Promote::Yes { chain: Certs::default() }, true)), false), now), Act::Promote(Certs::default()));
    assert_eq!(act_of(&deposit_facts(Some((Promote::NotYet, false)), false), now), Act::Waiting { never: false });
    assert_eq!(act_of(&deposit_facts(Some((Promote::Never, false)), false), now), Act::Waiting { never: true });
    assert_eq!(act_of(&deposit_facts(None, false), now), Act::Waiting { never: false }, "no writer: nothing to promote");
    assert_eq!(act_of(&deposit_facts(None, true), now), Act::Offer, "an own deposit is offered");
}

// spec/sync-inbox.md §4 (promotion): one stamped copy per delta, however many encryptions are
// deposited: a deposit adds a delta only by a part S must hold that no stamped entry of the
// commit holds.
#[test]
fn one_stamped_copy_per_delta_spec_sync_inbox_4() {
    let need: BTreeSet<usize> = [0, 1].into();
    let stamped = [BTreeSet::from([0])];
    assert!(!adds_delta(&need, &[0].into(), &stamped), "a second copy of part 0");
    assert!(!adds_delta(&need, &[0, 2].into(), &stamped), "part 2 is no part S must hold");
    assert!(adds_delta(&need, &[0, 1].into(), &stamped), "part 1 not held stamped");
    assert!(adds_delta(&need, &[0].into(), &[]), "the first copy");
    let f = deposit_facts(Some((Promote::Yes { chain: Certs::default() }, false)), false);
    assert_eq!(act_of(&f, WallMs(T0)), Act::Waiting { never: false }, "promotable but adding no delta: kept deposited");
}

// spec/sync-inbox.md §4 (clearing): a node holding S's delete key keeps at most
// `DEPOSITS_WAITING` deposits it can do nothing with; past it, those with no expiry (or a later
// one) go first, then the earliest to expire, invite requests last.
#[test]
fn clearing_keeps_at_most_deposits_waiting_spec_sync_inbox_4() {
    let now = WallMs(T0);
    let entry = |tag: u64, expiry: Option<u64>| {
        let (b, _) = blob(tag, 64, expiry);
        Entry { blob: b, wrap: [5; 57], stamp: None, deposited: true, own: false, role: false, class: Class::Durable, expires: expiry.map(WallMs) }
    };
    let requests: Vec<Entry> = (0..4).map(|i| entry(900 + i, Some(LIFE - i))).collect();
    let others: Vec<Entry> = (0..DEPOSITS_WAITING as u64).map(|i| entry(i + 1, if i < 2 { None } else { Some(LIFE + i) })).collect();
    let mut idle: Vec<(Entry, u64, bool)> = requests.iter().map(|e| (e.clone(), 64, true)).collect();
    idle.extend(others.iter().map(|e| (e.clone(), 64, false)));
    let dropped: BTreeSet<BlobId> = to_clear(idle, now).into_iter().collect();
    assert_eq!(dropped.len(), 4);
    assert!(requests.iter().all(|e| !dropped.contains(&e.blob)), "invite requests last");
    assert!(dropped.contains(&others[0].blob) && dropped.contains(&others[1].blob), "no expiry first");
    assert!(dropped.contains(&others[2].blob) && dropped.contains(&others[3].blob), "then the earliest to expire");
}

// spec/sync-inbox.md §4 (clearing: opened invite requests and boxes payloads go last): an inbox
// blob waiting for the user and a boxes payload held as an offer go last; a refused, applied or
// unopened one does not.
#[test]
fn invite_requests_and_offers_go_last_spec_sync_inbox_4() {
    use osis_engine::sync::Taken;
    let inbox = |taken: Option<Taken>| Act::Inbox { stamped: false, taken, commit: None, dial: None, expires: None };
    assert!(goes_last(&inbox(Some(Taken::Waiting))) && goes_last(&inbox(Some(Taken::Offered))));
    assert!(![inbox(Some(Taken::Refused)), inbox(Some(Taken::Applied)), inbox(None), Act::Waiting { never: false }].iter().any(goes_last));
}

/// Steps of one sync ID: genesis and children, as an admin issues them.
struct Steps {
    steps: Vec<(Step, ClaimSet)>,
}

impl Steps {
    fn new(n: usize) -> Steps {
        let admin = Secret32::from_bytes([0xab; 32]);
        let id = osis_label::genesis_label(&admin);
        let d = label_role_key(LabelRole::Delete, &admin);
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
            steps.push(osis_label::register(parent, keys, &[], (&THING, read, &write), (se, &sync), &mut rng).unwrap());
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
    assert_eq!(plan_at(&st, at0, Progress { backoff: Some((WallMs(T0), 0)), ..Progress::default() }, &all), Plan::Wait);
    let stuck = Progress { stuck: Some(at0), ..Progress::default() };
    assert_eq!(plan_at(&st, at0, stuck, &all), Plan::Wait, "refused: waits");
    assert_eq!(sends(&plan_at(&st, Some(st.id(1)), stuck, &all)), Some(st.id(2)), "the head event moved it");
}
