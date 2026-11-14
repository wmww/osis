//! Inbox, deposits, steps and Register (osis_sync::inbox) on a fake engine and fake peers over a
//! real store: the engine facade's calls as stamped values (it is not built yet, branch
//! sync-facade), sessions, opens and streams as a `Net` that records what is sent, so `Inbox`
//! runs as in a node. One test per rule of spec/sync-inbox.md §2-§4 and §6 and spec/sync-ids.md
//! §6 Steps and Register it implements, the inbox scenarios of issues/sync-rewrite.md, and its
//! costs counted at n and 10n.

use osis_base::format::{DEPOSITS_WAITING, INBOX_LIFETIME_MS};
use osis_base::memo::{Stamped, StampedSet};
use osis_base::{BlobId, CommitId, SyncId, Tid, WallMs};
use osis_crypto::{Epoch, LabelRole, Secret32, SeededRng, SigningSecret, deposit_key, label_role_key};
use osis_engine::labeling::Certs;
use osis_engine::sync::{Holding, InboxOpened, PartSet, Path, Promote, SyncSet, Taken};
use osis_label::{ClaimSet, Class, Parent, Prefix, ShareLink, Step, StepId, StepKeys};
use osis_proto::{Code, Msg, OfferItem, SharedItem};
use osis_store::{MemoryBackend, MemoryRoot};
use osis_sync::Result;
use osis_sync::inbox::{Ground, Here, Inbox, Net, Signers};
use osis_sync::opens::{Member, Moved};
use osis_sync::session::{Incoming, RequestId, To};
use osis_sync::store::Source;
use osis_sync::types::{ConnId, Credential, Entry, SourceClass, Waiting};
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

/// The keys of S as a holder of them signs with.
fn write_key(s: &SyncId) -> SigningSecret {
    label_role_key(LabelRole::Write, &Secret32::from_bytes([s.0[0] ^ 0x77; 32]))
}
fn deposit_seed(n: u8) -> Secret32 {
    Secret32::from_bytes([0xd0 ^ n; 32])
}
fn delete_key(s: &SyncId) -> SigningSecret {
    label_role_key(LabelRole::Delete, &Secret32::from_bytes([s.0[0] ^ 0xad; 32]))
}

/// A blob of `n` payload bytes with prefix expiry `expiry` (`tag` makes it distinct).
fn blob(tag: u64, n: usize, expiry: Option<u64>) -> (BlobId, Vec<u8>) {
    let mut rng = SeededRng::from_u64(tag ^ 0x5eed);
    let p = Prefix::new(Prefix::random_salt(&mut rng), expiry.map(WallMs), vec![]).unwrap();
    let (_, bytes) = osis_label::frame(&p, &vec![tag as u8; n], &mut rng).unwrap();
    (osis_label::blob_id(&bytes), bytes)
}

/// The engine as inbox sees it: every value it reads a stamped value.
#[derive(Default)]
struct Fake {
    now: u64,
    deliveries: Stamped<(), Arc<BTreeSet<(CommitId, Tid)>>>,
    taken: Stamped<(CommitId, Tid), bool>,
    names: BTreeMap<(CommitId, Tid), Arc<Vec<SyncId>>>,
    inbox_of: Stamped<Tid, SyncId>,
    sealed: u64,
    /// Per S: (writes it, its deposit seed number, holds its delete key).
    keys: Stamped<SyncId, (bool, Option<u8>, bool)>,
    inboxes: Stamped<(), Arc<BTreeSet<SyncId>>>,
    takes: Stamped<(SyncId, BlobId), InboxOpened>,
    /// What a take wrote and reads back (the engine's waiting row of an untaken blob).
    waiting: Stamped<BlobId, bool>,
    takes_run: u64,
    commits: Stamped<(SyncId, BlobId), CommitId>,
    /// The parts a blob holds (none listed: part 0).
    parts: Stamped<BlobId, PartSet>,
    promote: Stamped<CommitId, Promote>,
    chains: Vec<(SyncId, Certs)>,
    paths: Stamped<SyncId, Arc<Path>>,
    needs: Stamped<StepId, Arc<Vec<BlobId>>>,
    held_links: Vec<Tid>,
    ready: Stamped<Tid, bool>,
    redeemed: Vec<Tid>,
    held_elsewhere: Stamped<CommitId, bool>,
}

impl Ground for Fake {
    fn deliveries(&mut self) -> Result<Arc<BTreeSet<(CommitId, Tid)>>> {
        Ok(self.deliveries.get(&()).cloned().unwrap_or_default())
    }
    fn delivery_taken(&mut self, c: &CommitId, holder: &Tid) -> Result<bool> {
        Ok(self.taken.get(&(*c, *holder)).copied().unwrap_or(false))
    }
    fn delivery_names(&mut self, c: &CommitId, holder: &Tid) -> Result<Arc<Vec<SyncId>>> {
        Ok(self.names.get(&(*c, *holder)).cloned().unwrap_or_default())
    }
    fn inbox_of(&mut self, a: &Tid) -> Result<Option<SyncId>> {
        Ok(self.inbox_of.get(a).copied())
    }
    fn inbox_blob(&mut self, _c: &CommitId, _holder: &Tid, _rng: &mut dyn osis_crypto::NodeRng) -> Result<Option<Vec<u8>>> {
        self.sealed += 1;
        Ok(Some(blob(self.sealed << 16, 64, Some(self.now + INBOX_LIFETIME_MS)).1))
    }
    fn signers(&mut self, s: &SyncId, _actor: Option<&Tid>) -> Result<Signers> {
        let (w, d, del) = self.keys.get(s).copied().unwrap_or((false, None, false));
        Ok(Signers { stamp: w.then(|| write_key(s)), deposit: d.map(|n| deposit_key(&deposit_seed(n), s)), delete: del.then(|| delete_key(s)) })
    }
    fn inboxes(&mut self) -> Result<Arc<BTreeSet<SyncId>>> {
        Ok(self.inboxes.get(&()).cloned().unwrap_or_default())
    }
    fn take_inbox(&mut self, s: &SyncId, b: &BlobId) -> Result<Option<InboxOpened>> {
        self.takes_run += 1;
        let o = self.takes.get(&(*s, *b)).cloned();
        // a command: it writes what it reads, only where that changes it (as the engine's
        // waiting row: written once, left alone when judged again)
        let waits = o.as_ref().is_some_and(|o| o.taken == Taken::Waiting);
        if self.waiting.get(b).copied().unwrap_or(false) != waits {
            self.waiting.insert(*b, waits);
        }
        Ok(o)
    }
    fn blob_commit(&mut self, s: &SyncId, b: &BlobId) -> Result<Option<CommitId>> {
        Ok(self.commits.get(&(*s, *b)).copied())
    }
    fn promotable(&mut self, _s: &SyncId, c: &CommitId) -> Result<Promote> {
        Ok(self.promote.get(c).cloned().unwrap_or(Promote::NotYet))
    }
    fn commit_blobs(&mut self, c: &CommitId) -> Result<Arc<Vec<BlobId>>> {
        Ok(Arc::new(self.commits.iter().filter(|(_, x)| *x == c).map(|((_, b), _)| *b).collect()))
    }
    fn blob_parts(&mut self, b: &BlobId) -> Result<Option<PartSet>> {
        Ok(Some(self.parts.get(b).cloned().unwrap_or_else(|| [0].into())))
    }
    fn body_parts(&mut self, _s: &SyncId, _c: &CommitId) -> Result<Option<PartSet>> {
        Ok(Some([0, 1].into()))
    }
    fn log_chain(&mut self, s: &SyncId, chain: &Certs) -> Result<()> {
        self.chains.push((*s, chain.clone()));
        Ok(())
    }
    fn recorded_path(&mut self, s: &SyncId) -> Result<Option<Arc<Path>>> {
        Ok(self.paths.get(s).cloned())
    }
    fn step_needs(&mut self, _s: &SyncId, step: &StepId) -> Result<Arc<Vec<BlobId>>> {
        Ok(self.needs.get(step).cloned().unwrap_or_default())
    }
    fn hold_link(&mut self, link: &ShareLink) -> Result<()> {
        self.held_links.push(link.k);
        Ok(())
    }
    fn link_ready(&mut self, link: &ShareLink) -> Result<bool> {
        Ok(self.ready.get(&link.k).copied().unwrap_or(false))
    }
    fn redeem(&mut self, link: &ShareLink) -> Result<Option<CommitId>> {
        self.redeemed.push(link.k);
        Ok(Some(commit(0x11)))
    }
    fn held_elsewhere(&mut self, c: &CommitId) -> Result<bool> {
        Ok(self.held_elsewhere.get(c).copied().unwrap_or(false))
    }
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

/// One node's inbox over a real store on a simulated device.
struct T {
    g: Fake,
    net: FakeNet,
    backend: MemoryBackend,
    root: MemoryRoot,
    store: Store,
    inbox: Inbox,
    rng: SeededRng,
}

impl T {
    fn new() -> T {
        let (backend, root) = (MemoryBackend::new(), MemoryRoot::new());
        let store = Store::open(Box::new(backend.clone()), Box::new(root.clone()), Box::new(SeededRng::from_u64(7))).unwrap();
        let g = Fake { now: T0, ..Fake::default() };
        let mut t = T { g, net: FakeNet::default(), backend, root, store, inbox: Inbox::default(), rng: SeededRng::from_u64(9) };
        t.settle();
        t
    }

    fn now(&self) -> WallMs {
        WallMs(self.g.now)
    }

    /// Settles as the driver does: again while it acted.
    fn settle(&mut self) {
        let now = self.now();
        self.store.settle_at(now).unwrap();
        for _ in 0..100 {
            let mut h = Here { g: &mut self.g, store: &mut self.store, now, rng: &mut self.rng };
            if !self.inbox.step(&mut h, &mut self.net).unwrap() {
                return;
            }
        }
        panic!("inbox settle did not end");
    }

    fn advance(&mut self, ms: u64) {
        self.g.now += ms;
        self.settle();
    }

    /// The node restarts over its store: nothing in memory survives.
    fn restart(&mut self) {
        self.store = Store::open(Box::new(self.backend.clone()), Box::new(self.root.clone()), Box::new(SeededRng::from_u64(8))).unwrap();
        self.inbox = Inbox::default();
        self.net = FakeNet::default();
        self.settle();
    }

    fn hold(&mut self, ids: &[(SyncId, Holding)]) {
        self.store.set_sync_set(&SyncSet { ids: ids.iter().map(|(s, h)| (*s, (THING, *h))).collect(), ..SyncSet::default() });
    }

    fn connect(&mut self, c: ConnId, actors: &[Tid]) {
        self.net.actors.insert(c, actors.to_vec());
        self.inbox.proved(c, &self.net);
        self.settle();
    }

    fn join(&mut self, c: ConnId, s: SyncId, class: SourceClass, step: Option<StepId>) {
        self.net.members.insert((c, s), Member { class, by: Credential::SyncKey, until: None, step });
        self.inbox.moved(&Moved::Joined(c, s, osis_sync::opens::Rejoin::Held), &self.net);
        self.settle();
    }

    fn reply(&mut self, c: ConnId, id: RequestId, m: Msg) {
        let now = self.now();
        let mut h = Here { g: &mut self.g, store: &mut self.store, now, rng: &mut self.rng };
        self.inbox.receive(&mut h, &mut self.net, c, Incoming::Reply(To::Inbox, id, m));
        self.settle();
    }

    fn request(&mut self, c: ConnId, id: RequestId, m: Msg) -> Msg {
        let now = self.now();
        let mut h = Here { g: &mut self.g, store: &mut self.store, now, rng: &mut self.rng };
        self.inbox.receive(&mut h, &mut self.net, c, Incoming::Request(id, m));
        self.net.answers.pop().unwrap().2
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

    /// Owes `n` deliveries of commit i to recipient i, whose inbox is sync ID 100 + i.
    fn owe(&mut self, from: u32, n: u32, writes: bool) {
        self.owe_to(from, n, writes, None);
    }

    /// As `owe`, every recipient's inbox `inbox` when given.
    fn owe_to(&mut self, from: u32, n: u32, writes: bool, inbox: Option<SyncId>) {
        let mut set = self.g.deliveries.get(&()).map(|d| (**d).clone()).unwrap_or_default();
        for i in from..from + n {
            let s = inbox.unwrap_or(sync_id(100 + i));
            set.insert((commit(i), tid(i)));
            self.g.inbox_of.insert(tid(i), s);
            self.g.names.insert((commit(i), tid(i)), Arc::new(vec![sync_id(500 + i)]));
            self.g.keys.insert(s, (writes, Some(s.0[0]), false));
        }
        self.g.deliveries.insert((), Arc::new(set));
        self.settle();
    }

    fn entries(&self, s: &SyncId) -> Vec<Entry> {
        self.store.entries(s).unwrap()
    }

    fn shared(code: Code) -> Msg {
        Msg::Shared { id: 0, items: vec![SharedItem::code(code)] }
    }
}

/// Counts of the named cost counters `change` adds.
fn counted<const N: usize>(names: [&str; N], change: impl FnOnce()) -> [u64; N] {
    osis_base::costs::take();
    change();
    let c = osis_base::costs::take();
    names.map(|n| c.iter().filter(|x| x.0 == n).map(|x| x.2).sum())
}

// spec/sync-inbox.md §2 (logging): a sender that does not write the inbox logs the inbox blob
// deposited in its own store and offers it as a Deposit item, signed by the inbox's deposit key,
// to a peer that may hold the inbox (the recipient proven there), never to an unrelated peer.
#[test]
fn inbox_blob_deposited_and_offered_spec_sync_inbox_2() {
    let mut t = T::new();
    t.connect(conn(1), &[tid(9)]);
    t.connect(conn(2), &[tid(0)]);
    t.owe(0, 1, false);
    let e = t.entries(&sync_id(100));
    assert_eq!(e.len(), 1);
    assert!(e[0].deposited && e[0].own && e[0].stamp.is_none());
    let sent = t.deposits_sent();
    assert_eq!(sent, vec![(conn(2), 1, sync_id(100), e[0].blob)], "only to the recipient's node");
    let Msg::Offer { items, .. } = &t.net.requests[0].2 else { panic!() };
    let [OfferItem::Deposit(d)] = items.as_slice() else { panic!() };
    let head = deposit_key(&deposit_seed(sync_id(100).0[0]), &sync_id(100)).verifying_key();
    assert!(osis_label::verify_deposit(&head, &d.sync_id, &e[0].blob, &d.wrap, &d.sig).is_ok());
}

// spec/sync-inbox.md §3 (sending): an inbox blob also goes to a peer whose filter shows the
// inbox's deposit key (a node keeping it unread shows it to every connection,
// spec/sync-opens.md §4 Audiences), once that filter arrives; never to one showing another key.
#[test]
fn inbox_blob_offered_where_filter_shows_deposit_key_spec_sync_inbox_3() {
    let mut t = T::new();
    t.connect(conn(1), &[tid(9)]);
    t.connect(conn(2), &[tid(8)]);
    t.owe(0, 1, false);
    assert!(t.deposits_sent().is_empty(), "no peer may hold the inbox");
    let s = sync_id(100);
    let key = deposit_key(&deposit_seed(s.0[0]), &s).verifying_key().to_bytes();
    t.net.shown.insert((conn(1), s, key));
    t.net.shown.insert((conn(2), s, [7; 32]));
    t.settle();
    assert!(t.deposits_sent().is_empty(), "nothing before the filter that shows it arrives");
    t.net.generation.insert(conn(1), 1);
    t.net.generation.insert(conn(2), 1);
    t.settle();
    let sent: Vec<ConnId> = t.deposits_sent().iter().map(|x| x.0).collect();
    assert_eq!(sent, vec![conn(1)]);
}

// spec/sync-inbox.md §2 (logging): a writer of the inbox logs the blob stamped, filler wrap, and
// offers nothing (readers pull it).
#[test]
fn writer_logs_inbox_blob_stamped_spec_sync_inbox_2() {
    let mut t = T::new();
    t.connect(conn(2), &[tid(0)]);
    t.owe(0, 1, true);
    let e = t.entries(&sync_id(100));
    assert!(e.len() == 1 && !e[0].deposited && e[0].stamp.is_some());
    assert!(osis_label::verify_stamp(&write_key(&sync_id(100)).verifying_key(), &sync_id(100), &e[0].blob, &e[0].wrap, &e[0].stamp.unwrap()).is_ok());
    assert!(t.deposits_sent().is_empty());
}

// spec/sync-inbox.md §2 (re-send): at the blob's prefix expiry the sender seals it again, and the
// blob it replaces is moot (no longer offered).
#[test]
fn resent_at_expiry_spec_sync_inbox_2() {
    let mut t = T::new();
    t.owe(0, 1, false);
    assert_eq!(t.g.sealed, 1);
    t.advance(INBOX_LIFETIME_MS - 1);
    assert_eq!(t.g.sealed, 1, "not before its expiry");
    t.advance(1);
    assert_eq!(t.g.sealed, 2, "sealed again at its expiry");
    t.connect(conn(2), &[tid(0)]);
    let sent = t.deposits_sent();
    assert_eq!(sent.len(), 1, "only the new blob is offered: {sent:?}");
}

// spec/sync-inbox.md §2 (re-send): sooner once the sync ID it went under is no longer the
// recipient's inbox.
#[test]
fn resent_when_inbox_moves_spec_sync_inbox_2() {
    let mut t = T::new();
    t.owe(0, 1, false);
    t.g.keys.insert(sync_id(7), (false, Some(3), false));
    t.g.inbox_of.insert(tid(0), sync_id(7));
    t.settle();
    assert_eq!(t.g.sealed, 2);
    assert_eq!(t.entries(&sync_id(7)).len(), 1);
}

// spec/sync-inbox.md §2 (re-send): no re-send once the sender saw the recipient take it by a
// commit (the engine's sign).
#[test]
fn stops_once_recipient_commits_spec_sync_inbox_2() {
    let mut t = T::new();
    t.owe(0, 1, false);
    t.g.taken.insert((commit(0), tid(0)), true);
    t.settle();
    t.advance(INBOX_LIFETIME_MS);
    assert_eq!(t.g.sealed, 1);
    t.connect(conn(2), &[tid(0)]);
    assert!(t.deposits_sent().is_empty(), "moot once taken");
}

// spec/sync-inbox.md §2 (re-send): no re-send once a sync ID the blob names opens at this node on
// a connection where the recipient is proven; an open where it is not proven is no sign. The sign
// is kept across a restart.
#[test]
fn stops_once_recipient_opens_named_sync_id_spec_sync_inbox_2() {
    let mut t = T::new();
    t.owe(0, 1, false);
    t.connect(conn(1), &[tid(9)]);
    t.join(conn(1), sync_id(500), SourceClass::Reader, None);
    t.advance(INBOX_LIFETIME_MS);
    assert_eq!(t.g.sealed, 2, "an open by another is no sign");
    t.connect(conn(2), &[tid(0)]);
    t.join(conn(2), sync_id(500), SourceClass::Store, None);
    t.restart();
    t.advance(INBOX_LIFETIME_MS);
    assert_eq!(t.g.sealed, 2, "seen taken, across a restart");
}

// spec/sync-inbox.md §2 (re-send): a restart seals nothing again: what was sent is kept with its
// expiry (no per-launch growth).
#[test]
fn restart_seals_nothing_again_spec_sync_inbox_2() {
    let mut t = T::new();
    t.owe(0, 3, false);
    assert_eq!(t.g.sealed, 3);
    t.restart();
    t.restart();
    assert_eq!(t.g.sealed, 3);
    t.advance(INBOX_LIFETIME_MS);
    assert_eq!(t.g.sealed, 6, "each again at its expiry");
}

// spec/sync-inbox.md §2 (re-send): a re-send pass never walks what was sent: a delivery's expiry
// seals that one alone, the same work at n and 10n deliveries owed.
#[test]
fn resend_work_follows_expiry_spec_sync_inbox_2() {
    let half = INBOX_LIFETIME_MS / 2;
    let cost = |n: u32| {
        let mut t = T::new();
        t.owe(0, n, false);
        t.advance(half);
        t.owe(n, 1, false);
        // the n are sealed again at their own expiry
        t.advance(half);
        counted(["inbox: sealed", "inbox: delivery judged"], || t.advance(half))
    };
    let (few, many) = (cost(10), cost(100));
    assert_eq!(few, many, "[sealed, judged] at n and 10n");
    assert_eq!(few, [1, 0], "the later one's expiry seals it alone");
}

// spec/sync-inbox.md §3 (sending): one unanswered Deposit item per connection; the next goes when
// it is answered.
#[test]
fn one_deposit_item_unanswered_per_connection_spec_sync_inbox_3() {
    let mut t = T::new();
    t.owe_to(0, 3, false, Some(sync_id(100)));
    t.connect(conn(2), &[tid(0), tid(1), tid(2)]);
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
    t.owe_to(0, 2, false, Some(sync_id(100)));
    t.connect(conn(2), &[tid(0), tid(1)]);
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
    t.owe(0, 1, false);
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
    t.g.keys.insert(sync_id(100), (false, Some(42), false));
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
    t.g.keys.insert(s, (false, Some(1), false));
    t.connect(conn(1), &[]);
    t.connect(conn(2), &[]);
    t.join(conn(1), s, SourceClass::Reader, None);
    t.join(conn(2), s, SourceClass::Store, None);
    let (b, bytes) = blob(1, 100, None);
    let e = Entry { blob: b, wrap: [5; 57], stamp: None, deposited: true, own: true, role: false, class: Class::Durable, expires: None };
    assert_eq!(t.store.log(&s, e, Some(bytes), None).unwrap(), Code::OK);
    t.settle();
    let sent = t.deposits_sent();
    assert_eq!(sent.iter().map(|x| (x.0, x.3)).collect::<Vec<_>>(), vec![(conn(2), b)]);
    t.reply(conn(2), sent[0].1, T::shared(Code::OK));
    assert_eq!(t.deposits_sent().len(), 1, "answered: done there");
}

/// A node reading and writing S with one deposit of commit 1 held, opened by the engine.
fn writer_with_deposit(promote: Promote) -> (T, SyncId, BlobId) {
    let mut t = T::new();
    let s = sync_id(1);
    t.hold(&[(s, Holding::Read)]);
    t.g.keys.insert(s, (true, Some(1), false));
    let (b, bytes) = blob(3, 100, None);
    t.g.commits.insert((s, b), commit(1));
    t.g.promote.insert(commit(1), promote);
    let e = Entry { blob: b, wrap: [5; 57], stamp: None, deposited: true, own: false, role: false, class: Class::Durable, expires: None };
    t.store.log(&s, e, Some(bytes), None).unwrap();
    t.settle();
    (t, s, b)
}

// spec/sync-inbox.md §4 (promotion): a writer stamps a deposit the engine judges promotable,
// logging the author's chain beside it; one judged not yet is promoted once that moves.
#[test]
fn writer_promotes_promotable_deposit_spec_sync_inbox_4() {
    let (mut t, s, b) = writer_with_deposit(Promote::NotYet);
    assert!(t.store.entry(&s, &b).unwrap().unwrap().deposited);
    t.g.promote.insert(commit(1), Promote::Yes { chain: Certs::default() });
    t.settle();
    let e = t.store.entry(&s, &b).unwrap().unwrap();
    assert!(!e.deposited && e.stamp.is_some(), "promoted");
    assert!(osis_label::verify_stamp(&write_key(&s).verifying_key(), &s, &b, &e.wrap, &e.stamp.unwrap()).is_ok());
    assert_eq!(t.g.chains.len(), 1);
}

// spec/sync-inbox.md §4 (promotion): scenario promote-covered-only-deposit: a deposit the engine
// judges never promotable (its parts a held snapshot carries) stays deposited. The cover judgement
// itself is the engine's (`promotable`): its test needs the facade.
#[test]
fn promote_covered_only_deposit_spec_sync_inbox_4() {
    let (t, s, b) = writer_with_deposit(Promote::Never);
    assert!(t.store.entry(&s, &b).unwrap().unwrap().deposited);
    assert!(t.g.chains.is_empty());
}

// spec/sync-inbox.md §4 (promotion): one stamped copy per delta, however many encryptions are
// deposited: a second deposit of a promoted commit's parts stays deposited (and is clearable);
// one holding a part S must hold that no stamped entry holds is promoted.
#[test]
fn one_stamped_copy_per_delta_spec_sync_inbox_4() {
    let (mut t, s, b) = writer_with_deposit(Promote::Yes { chain: Certs::default() });
    assert!(!t.store.entry(&s, &b).unwrap().unwrap().deposited);
    let deposit = |t: &mut T, tag: u64, parts: PartSet| {
        let (x, bytes) = blob(tag, 100, None);
        t.g.commits.insert((s, x), commit(1));
        t.g.parts.insert(x, parts);
        let e = Entry { blob: x, wrap: [6; 57], stamp: None, deposited: true, own: false, role: false, class: Class::Durable, expires: None };
        t.store.log(&s, e, Some(bytes), None).unwrap();
        t.settle();
        t.store.entry(&s, &x).unwrap().unwrap().deposited
    };
    assert!(deposit(&mut t, 4, [0].into()), "a second copy of part 0");
    assert!(deposit(&mut t, 5, [0, 2].into()), "part 2 is no part S must hold");
    assert!(!deposit(&mut t, 6, [0, 1].into()), "part 1 not held stamped: promoted");
    assert_eq!(t.g.chains.len(), 2);
}

// spec/sync-inbox.md §4 (promotion): a node that does not write S promotes nothing.
#[test]
fn non_writer_promotes_nothing_spec_sync_inbox_4() {
    let mut t = T::new();
    let s = sync_id(1);
    t.hold(&[(s, Holding::Read)]);
    t.g.keys.insert(s, (false, Some(1), false));
    let (b, bytes) = blob(3, 100, None);
    t.g.commits.insert((s, b), commit(1));
    t.g.promote.insert(commit(1), Promote::Yes { chain: Certs::default() });
    let e = Entry { blob: b, wrap: [5; 57], stamp: None, deposited: true, own: false, role: false, class: Class::Durable, expires: None };
    t.store.log(&s, e, Some(bytes), None).unwrap();
    t.settle();
    assert!(t.store.entry(&s, &b).unwrap().unwrap().deposited);
}

/// A node reading inbox S, with inbox blobs deposited there as `takes` says they open.
fn inbox_node(writes: bool) -> (T, SyncId) {
    let mut t = T::new();
    let s = sync_id(1);
    t.hold(&[(s, Holding::Read)]);
    t.g.keys.insert(s, (writes, None, false));
    t.g.inboxes.insert((), Arc::new([s].into()));
    t.settle();
    (t, s)
}

fn deposit_inbox_blob(t: &mut T, s: SyncId, tag: u64, c: CommitId, taken: Taken, expiry: u64) -> BlobId {
    let (b, bytes) = blob(tag, 64, Some(expiry));
    t.g.takes.insert((s, b), InboxOpened { commit: c, taken, hints: vec![], dial: None });
    let e = Entry { blob: b, wrap: [5; 57], stamp: None, deposited: true, own: false, role: false, class: Class::Durable, expires: Some(WallMs(expiry)) };
    assert_eq!(t.store.log(&s, e, Some(bytes), None).unwrap(), Code::OK);
    t.settle();
    b
}

// spec/sync-inbox.md §2 (stamping in place): a writer of the inbox stamps a deposited inbox blob
// whose commit applied, one per commit, never one whose expiry is more than `INBOX_LIFETIME + 2 ×
// MAX_DRIFT` ahead; a node not writing it stamps none.
#[test]
fn writer_stamps_taken_inbox_blob_in_place_spec_sync_inbox_2() {
    let (mut t, s) = inbox_node(true);
    let life = T0 + INBOX_LIFETIME_MS;
    let a = deposit_inbox_blob(&mut t, s, 1, commit(1), Taken::Applied, life);
    let twin = deposit_inbox_blob(&mut t, s, 2, commit(1), Taken::Applied, life);
    let far = deposit_inbox_blob(&mut t, s, 3, commit(2), Taken::Applied, life + 3 * 60 * 60 * 1000);
    let waiting = deposit_inbox_blob(&mut t, s, 4, commit(3), Taken::Waiting, life);
    let stamped = |t: &T, b| t.store.entry(&s, &b).unwrap().unwrap().stamp.is_some();
    assert!(stamped(&t, a));
    assert!(!stamped(&t, twin), "one blob per commit");
    assert!(!stamped(&t, far), "expiry too far ahead");
    assert!(!stamped(&t, waiting), "an invite request stays deposited");
    let (mut r, s) = inbox_node(false);
    let b = deposit_inbox_blob(&mut r, s, 1, commit(1), Taken::Applied, life);
    assert!(!stamped(&r, b));
}

// spec/sync-inbox.md §2 (taking): a blob not taken is judged again as the node's state changes:
// taken once it is (here: the user accepted), then stamped in place by a writer.
#[test]
fn inbox_blob_judged_again_spec_sync_inbox_2() {
    let (mut t, s) = inbox_node(true);
    let b = deposit_inbox_blob(&mut t, s, 1, commit(1), Taken::Waiting, T0 + INBOX_LIFETIME_MS);
    assert!(t.store.entry(&s, &b).unwrap().unwrap().deposited);
    t.g.takes.insert((s, b), InboxOpened { commit: commit(1), taken: Taken::Applied, hints: vec![], dial: None });
    t.settle();
    assert!(t.store.entry(&s, &b).unwrap().unwrap().stamp.is_some());
}

// spec/sync-inbox.md §2 (taking): taking is a command judged again as what it read moves; one
// that writes what it read (the engine's waiting row) is judged once more and then rests: later
// settles take nothing.
#[test]
fn a_take_writing_what_it_read_rests_spec_sync_inbox_2() {
    let (mut t, s) = inbox_node(true);
    deposit_inbox_blob(&mut t, s, 1, commit(1), Taken::Waiting, T0 + INBOX_LIFETIME_MS);
    assert!(t.g.takes_run <= 2, "{}", t.g.takes_run);
    let before = t.g.takes_run;
    t.advance(1);
    t.advance(1);
    assert_eq!(t.g.takes_run, before, "at rest");
}

// spec/sync-inbox.md §2 (taking): scenario inbox-full-walk-scale: a contact's blobs up to the
// caps cost a change O(change): one blob arriving, or one taken, judges that blob alone, at n and
// 10n blobs held.
#[test]
fn inbox_work_follows_change_spec_sync_inbox_2() {
    let cost = |n: u64| {
        let (mut t, s) = inbox_node(true);
        for i in 0..n {
            deposit_inbox_blob(&mut t, s, 100 + i, commit(100 + i as u32), Taken::Waiting, T0 + INBOX_LIFETIME_MS);
        }
        let arrive = counted(["inbox: held judged"], || {
            deposit_inbox_blob(&mut t, s, 1, commit(1), Taken::Waiting, T0 + INBOX_LIFETIME_MS);
        });
        let (b, _) = blob(100, 64, Some(T0 + INBOX_LIFETIME_MS));
        let take = counted(["inbox: held judged"], || {
            t.g.takes.insert((s, b), InboxOpened { commit: commit(100), taken: Taken::Applied, hints: vec![], dial: None });
            t.settle();
        });
        [arrive[0], take[0]]
    };
    let (few, many) = (cost(10), cost(100));
    assert_eq!(few, many, "[arrive, take] at n and 10n");
    assert!(few[0] <= 2 && few[1] <= 3, "{few:?}");
}

// spec/sync-inbox.md §4 (clearing): a node holding S's delete key keeps at most
// `DEPOSITS_WAITING` deposits it can do nothing with; past it, those with no expiry (or a later
// one) go first, then the earliest to expire, invite requests last.
#[test]
fn clearing_keeps_at_most_deposits_waiting_spec_sync_inbox_4() {
    let mut t = T::new();
    let s = sync_id(1);
    t.hold(&[(s, Holding::Read)]);
    t.g.keys.insert(s, (false, None, true));
    t.g.inboxes.insert((), Arc::new([s].into()));
    t.settle();
    let life = T0 + INBOX_LIFETIME_MS;
    let requests: Vec<BlobId> = (0..4).map(|i| deposit_inbox_blob(&mut t, s, 900 + i, commit(900 + i as u32), Taken::Waiting, life - i)).collect();
    let mut others = Vec::new();
    for i in 0..DEPOSITS_WAITING as u64 {
        let expiry = if i < 2 { None } else { Some(life + i) };
        let (b, bytes) = blob(i + 1, 64, expiry);
        let e = Entry { blob: b, wrap: [5; 57], stamp: None, deposited: true, own: false, role: false, class: Class::Durable, expires: expiry.map(WallMs) };
        t.store.log(&s, e, Some(bytes), None).unwrap();
        others.push(b);
    }
    t.settle();
    let held: BTreeSet<BlobId> = t.store.deposits(&s).unwrap().iter().map(|e| e.blob).collect();
    assert_eq!(held.len(), DEPOSITS_WAITING);
    assert!(requests.iter().all(|b| held.contains(b)), "invite requests last");
    assert!(!held.contains(&others[0]) && !held.contains(&others[1]), "no expiry first");
    assert!(!held.contains(&others[2]) && !held.contains(&others[3]), "then the earliest to expire");
    assert!(others[4..].iter().all(|b| held.contains(b)));
}

/// Steps of one sync ID: genesis and children, as an admin issues them.
struct Steps {
    id: SyncId,
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
        Steps { id, steps }
    }
    fn path(&self) -> Arc<Path> {
        Arc::new(Path { steps: self.steps.iter().map(|(s, c)| (s.clone(), Some(c.clone()))).collect() })
    }
    fn id(&self, i: usize) -> StepId {
        self.steps[i].0.id()
    }
}

fn registers(t: &T) -> Vec<(RequestId, StepId)> {
    t.net.requests.iter().filter_map(|(_, id, m)| if let Msg::Register { step, .. } = m { Some((*id, step.id())) } else { None }).collect()
}

// spec/sync-ids.md §6 (steps): a reader registers at a source keeping S unread the recorded steps
// after the source's step, in order, each once the source's stream showed the role commits it
// depends on; nothing at a reader.
#[test]
fn registers_steps_after_source_step_spec_sync_ids_6() {
    let mut t = T::new();
    let st = Steps::new(3);
    let s = st.id;
    t.g.paths.insert(s, st.path());
    let (need, _) = blob(77, 10, None);
    t.g.needs.insert(st.id(1), Arc::new(vec![need]));
    t.connect(conn(1), &[]);
    t.connect(conn(2), &[]);
    t.join(conn(1), s, SourceClass::Reader, Some(st.id(0)));
    t.join(conn(2), s, SourceClass::Store, Some(st.id(0)));
    assert!(registers(&t).is_empty(), "the role commits are not there yet");
    t.net.present.insert((conn(2), s, need));
    t.settle();
    let r = registers(&t);
    assert_eq!(r.iter().map(|x| x.1).collect::<Vec<_>>(), vec![st.id(1)]);
    assert!(t.net.requests.iter().all(|(c, ..)| *c == conn(2)));
    t.reply(conn(2), r[0].0, Msg::Ok { id: r[0].0 });
    assert_eq!(registers(&t).iter().map(|x| x.1).collect::<Vec<_>>(), vec![st.id(1), st.id(2)]);
    let last = registers(&t)[1].0;
    t.reply(conn(2), last, Msg::Ok { id: last });
    assert_eq!(registers(&t).len(), 2, "at the head: nothing more");
}

// spec/sync-ids.md §6 (register refused for now): 4 and 12 register again after a back-off,
// never at once; any other refusal changes no view: nothing until the source's step moves.
#[test]
fn register_refusals_spec_sync_ids_6() {
    let mut t = T::new();
    let st = Steps::new(3);
    let s = st.id;
    t.g.paths.insert(s, st.path());
    t.connect(conn(2), &[]);
    t.join(conn(2), s, SourceClass::Store, Some(st.id(0)));
    let id = registers(&t)[0].0;
    t.reply(conn(2), id, Msg::Error { id, code: Code::RATE_LIMITED });
    assert_eq!(registers(&t).len(), 1, "not at once");
    t.advance(osis_sync::inbox::backoff_ms(0));
    let r = registers(&t);
    assert_eq!(r.len(), 2, "again after the back-off");
    t.reply(conn(2), r[1].0, Msg::Error { id: r[1].0, code: Code::NOT_HEAD_KEY });
    t.advance(60 * 60 * 1000);
    assert_eq!(registers(&t).len(), 2, "refused: waits for the source's step to move");
    t.net.members.insert((conn(2), s), Member { class: SourceClass::Store, by: Credential::SyncKey, until: None, step: Some(st.id(1)) });
    t.settle();
    assert_eq!(registers(&t).last().map(|x| x.1), Some(st.id(2)), "the head event moved it");
}

// spec/sync-ids.md §6 (register only unread): a node keeping S unread takes a Register of the
// child of its head; one reading S refuses it (14); a Delete where S is not open by a store
// credential is refused whole (8).
#[test]
fn serves_register_and_delete_spec_sync_ids_6() {
    let mut t = T::new();
    let st = Steps::new(2);
    let read = Steps { id: sync_id(3), steps: Vec::new() };
    t.hold(&[(st.id, Holding::Unread), (read.id, Holding::Read)]);
    let reg = |i: usize, s: SyncId| Msg::Register { id: 1, sync_id: s, step: st.steps[i].0.clone(), claim_set: Some(st.steps[i].1.clone()) };
    assert_eq!(t.request(conn(1), 1, reg(0, st.id)), Msg::Ok { id: 1 });
    assert_eq!(t.request(conn(1), 2, reg(1, st.id)), Msg::Ok { id: 2 });
    let m = t.request(conn(1), 3, reg(0, read.id));
    assert!(matches!(m, Msg::Error { code, .. } if code == Code::MALFORMED || code == Code::DECLINED), "{m:?}");
    let (b, _) = blob(1, 10, None);
    let item = osis_label::DeleteItem::sign(&delete_key(&st.id), &st.id, b);
    assert_eq!(t.request(conn(1), 4, Msg::Delete { id: 4, sync_id: st.id, items: vec![item] }), Msg::Status { id: 4, codes: vec![Code::NOT_OPEN] });
}

fn link(k: Tid) -> ShareLink {
    ShareLink { seed: Secret32::from_bytes([4; 32]), target: tid(77), k, k_label: sync_id(9), hosts: vec![], peers: vec![osis_label::Peer { dialable: [6; 32], relays: vec!["peer://relay".into()] }], single_use: false }
}

// spec/sync-inbox.md §6 (first contact): scenario redeem-dropped-before-delivery: a redeem whose
// call is dropped, or a restart, before the join reaches the sharer's node still completes: the
// link is kept and L held at every start (its sharer a dial hint) until the join is held at a
// source; the join is written once, when K's roster lists L.
#[test]
fn redeem_survives_restart_spec_sync_inbox_6() {
    let mut t = T::new();
    let k = tid(50);
    let now = t.now();
    let w = t.inbox.redeem_on(&mut Here { g: &mut t.g, store: &mut t.store, now, rng: &mut t.rng }, &link(k));
    assert_eq!(w, Waiting::Pending);
    assert!(t.inbox.dial_hints().iter().any(|h| h.key == [6; 32]));
    t.restart();
    assert_eq!(t.g.held_links, vec![k, k], "L held again after the restart");
    assert!(t.inbox.dial_hints().iter().any(|h| h.key == [6; 32]));
    t.g.ready.insert(k, true);
    t.settle();
    assert_eq!(t.g.redeemed, vec![k]);
    t.restart();
    assert_eq!(t.g.redeemed, vec![k], "the join is written once");
    assert_eq!(t.g.held_links.len(), 3, "L proved until the join is held elsewhere");
    t.g.held_elsewhere.insert(commit(0x11), true);
    t.settle();
    t.restart();
    assert_eq!(t.g.held_links.len(), 3, "done: the link is forgotten");
    assert!(t.inbox.dial_hints().is_empty());
}

// spec/sync-inbox.md §6 (first contact): the redeem-after-rotations scenario
// (issues/osis-tests-depend-on-store-rng.md): K rotating while the join waits (its roster read
// again, ready then not then ready) writes the join once.
#[test]
fn redeem_after_rotations_writes_one_join_spec_sync_inbox_6() {
    let mut t = T::new();
    let k = tid(50);
    let now = t.now();
    t.inbox.redeem_on(&mut Here { g: &mut t.g, store: &mut t.store, now, rng: &mut t.rng }, &link(k));
    t.g.ready.insert(k, true);
    t.settle();
    t.g.ready.insert(k, false);
    t.settle();
    t.g.ready.insert(k, true);
    t.settle();
    assert_eq!(t.g.redeemed, vec![k]);
    let now = t.now();
    let w = t.inbox.redeem_on(&mut Here { g: &mut t.g, store: &mut t.store, now, rng: &mut t.rng }, &link(k));
    assert_eq!(w, Waiting::Done);
}
