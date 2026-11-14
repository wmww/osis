//! The client port, client side (spec/sync-transport.md §6, notes/client-port.md §1, §8): this
//! process's connections to nodes it is a client of (`Remote`, in `Locked::remotes`), each a
//! client connection of this node's sync (`osis_sync::Node::connect`): it proves nothing and
//! shares nothing, and carries the calls `crate::sources` sends there. A call blocks until its
//! Reply; a watch is a subscription whose Reply and Notifies enter this handle's dispatcher queue
//! (`Msg::Deliver`), so its callbacks run on the dispatcher like local ones.
//!
//! **Reconnect** (spec/sync-transport.md §6): a connection that was up and ended is dialed again
//! at once under the same session id: Auth, then each write still unanswered is sent again,
//! marked, and each live watch subscribes again (its Reply tells the value again, as
//! `Origin::Initial`). What a caller sees:
//! - a call while the connection is not up: `Network` at once, not sent (and a dial begins);
//! - a read in flight when it drops: `Network`;
//! - a write in flight when it drops: its one result once reconnected; `OutcomeUnknown` when the
//!   node no longer knows the session, or the redial fails;
//! - a watch: `Err(Network)` when it drops, then the value again once back;
//! - a node that refuses the session (Auth answered Error): `Refused` from every call, for good.
//!
//! State, per connection, in memory, all of it this process's: the calls and writes out (each
//! a caller blocked on it, so bounded by the callers), the live watches (each a `Subscription`
//! the app holds; one dropped goes at its next Notify, with an Unsub).

use super::codec::{self, list, read_from, result_of};
use super::method;
use crate::error::{Error, Result};
use crate::handle::{Locked, ReadOnly};
use crate::share::Address;
use crate::syncing::Status;
use crate::watch::{Change, Delivery, Filter, Msg as Queued, Origin, Subscription, digest};
use osis_base::{Ak, Tid, Value};
use osis_proto::api::Payload;
use osis_proto::{Code, Msg};
use osis_schema::Path;
use osis_sync::ConnId;
use osis_sync::session::RequestId;
use std::collections::BTreeMap;
use std::sync::mpsc::{Receiver, Sender, channel};

/// Who a thin client is (`Osis::connect`): its node's answer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Thin {
    pub me: Tid,
    pub node: Tid,
    pub home: Tid,
}

/// The wait before dialing again a node whose connection could not be made while a watch is
/// on it. Minor: at 0 a node that is down is dialed in a tight loop; at infinity a watch on it
/// stays at `Err(Network)` until this process's next call there.
pub(crate) const REDIAL_MS: u64 = 1_000;

/// Where a connection stands.
#[derive(Clone, Debug)]
enum State {
    Dialing,
    /// Auth or WHOAMI out.
    Authing,
    Up,
    /// Not connected, and why calls fail meanwhile: `Network` (a call dials again) or
    /// `Refused` (for good).
    Down(Error),
}

/// What a request out is for.
enum Asked {
    Auth,
    Whoami,
    Call(Sender<Result<Value>>),
    /// A write, by nonce: its caller waits in `Remote::writes`.
    Write(u64),
    /// A watch's subscription, by its local id, and whoever waits for its first Reply.
    Sub(u64, Option<Sender<Result<()>>>),
    Unsub,
}

/// A write row sent and not answered: its method and args (after the nonce) for a resend.
struct Pending {
    method: u64,
    args: Vec<Value>,
    tx: Sender<Result<Value>>,
}

/// A watch at the node.
struct Watch {
    filter: Value,
    /// Its subscription's id at the node, while live.
    sub: Option<RequestId>,
}

/// What a subscription at a node tells its watch here (`Delivery::Remote`); the watch decodes it
/// as its filter's forms.
#[derive(Clone, Debug)]
pub(crate) enum Pushed {
    /// The Sub's Reply: the filter's value now (again after a reconnect).
    Initial(Value),
    /// A Notify's delivery.
    Delivery(Value),
    /// A delivery above the Sub's `max_reply`: its `source`.
    TooLarge(Value),
    /// The connection was lost (the watch subscribes again once back), or the node refused the
    /// Sub.
    Failed(Error),
}

/// One node this process is a client of.
pub(crate) struct Remote {
    pub addr: Address,
    /// The bearer secret; none for a main session (the unix transport).
    secret: Option<crate::ClientSecret>,
    session: [u8; 16],
    conn: Option<ConnId>,
    state: State,
    /// The connection reached Up since it was dialed: only such a one is dialed again at once
    /// when it ends.
    was_up: bool,
    who: Option<Thin>,
    calls: BTreeMap<RequestId, Asked>,
    nonce: u64,
    writes: BTreeMap<u64, Pending>,
    watches: BTreeMap<u64, Watch>,
    /// `add_remote` waiting for it to come up.
    ready: Vec<tokio::sync::oneshot::Sender<Result<()>>>,
}

impl Remote {
    fn new(addr: Address, secret: Option<crate::ClientSecret>, session: [u8; 16]) -> Remote {
        Remote { addr, secret, session, conn: None, state: State::Down(Error::Network("not connected".into())), was_up: false, who: None, calls: BTreeMap::new(), nonce: 0, writes: BTreeMap::new(), watches: BTreeMap::new(), ready: Vec::new() }
    }
}

/// What a remote's handling reaches beside the remote: the node's sync, its outputs, the
/// dispatcher queue.
struct Cx<'a> {
    db: &'a ReadOnly,
    node: &'a mut osis_sync::Node,
    out: &'a mut Vec<osis_sync::Out>,
    seq: &'a mut u64,
}

/// Runs `f` on remote `i`, with what it reaches; `None` when there is no such remote.
fn with<R>(db: &ReadOnly, l: &mut Locked, i: usize, f: impl FnOnce(&mut Cx<'_>, &mut Remote) -> R) -> Option<R> {
    let Locked { node, out, seq, remotes, .. } = l;
    let r = remotes.get_mut(i)?;
    Some(f(&mut Cx { db, node, out, seq }, r))
}

impl Cx<'_> {
    /// Queues what `r`'s node pushed for local watch `local`.
    fn deliver(&mut self, r: &Remote, local: u64, got: Pushed) {
        *self.seq += 1;
        self.db.inner.dispatch.send(*self.seq, Queued::Deliver(local, Delivery::Remote { from: r.addr.clone(), got }));
    }

    /// Dials `r` again if it is down for the network.
    fn dial(&mut self, r: &mut Remote) {
        if !matches!(r.state, State::Down(Error::Network(_))) {
            return;
        }
        let (c, out) = self.node.connect(r.addr.0.clone());
        self.out.extend(out);
        r.conn = Some(c);
        r.state = State::Dialing;
        r.was_up = false;
    }

    /// Sends `m` on `r`'s connection, for `asked`.
    fn send(&mut self, r: &mut Remote, m: Msg, asked: Asked) -> bool {
        let Some(conn) = r.conn else { return false };
        let Some((id, out)) = self.node.port_request(conn, m) else { return false };
        self.out.extend(out);
        r.calls.insert(id, asked);
        true
    }

    /// `r` is up as `w`: what waited goes, writes without an answer again (marked) and the live
    /// watches subscribe again.
    fn came_up(&mut self, r: &mut Remote, w: Thin) {
        if r.who.is_some_and(|x| x.me != w.me) {
            let e = Error::Refused(format!("{} answers as another actor now", r.addr));
            return self.refused(r, e);
        }
        r.who = Some(w);
        r.state = State::Up;
        r.was_up = true;
        for tx in r.ready.drain(..) {
            let _ = tx.send(Ok(()));
        }
        let resend: Vec<(u64, u64, Vec<Value>)> = r.writes.iter().map(|(n, p)| (*n, p.method, p.args.clone())).collect();
        for (n, method, args) in resend {
            let mut a = vec![Value::uint(n | super::serve::RESENT)];
            a.extend(args);
            self.send(r, Msg::Call { id: 0, max_reply: super::VALUE_REPLY, method, args: a }, Asked::Write(n));
        }
        let subs: Vec<(u64, Value)> = r.watches.iter().filter(|(_, w)| w.sub.is_none()).map(|(k, w)| (*k, w.filter.clone())).collect();
        for (local, filter) in subs {
            if self.db.inner.dispatch.registered(local) {
                self.send(r, Msg::Sub { id: 0, max_reply: super::VALUE_REPLY, filter }, Asked::Sub(local, None));
            } else {
                r.watches.remove(&local);
            }
        }
    }

    /// The node will not take this session: every call fails `e` from now on, and the
    /// connection closes.
    fn refused(&mut self, r: &mut Remote, e: Error) {
        let conn = r.conn.take();
        r.state = State::Down(e.clone());
        self.fail_all(r, &e, &e);
        if let Some(c) = conn {
            let o = self.node.disconnect(c);
            self.out.extend(o);
        }
    }

    /// Every call, write, watch and waiter of `r` is told: calls and watches `e`, writes `w`.
    fn fail_all(&mut self, r: &mut Remote, e: &Error, w: &Error) {
        for tx in r.ready.drain(..) {
            let _ = tx.send(Err(e.clone()));
        }
        for (_, p) in std::mem::take(&mut r.writes) {
            let _ = p.tx.send(Err(w.clone()));
        }
        self.lost(r, e);
    }

    /// The calls out on `r`'s connection are unanswered: each fails `e` (writes stay, for a
    /// resend), and each watch hears `e`.
    fn lost(&mut self, r: &mut Remote, e: &Error) {
        for (_, a) in std::mem::take(&mut r.calls) {
            match a {
                Asked::Call(tx) => {
                    let _ = tx.send(Err(e.clone()));
                }
                Asked::Sub(_, Some(tx)) => {
                    let _ = tx.send(Err(e.clone()));
                }
                _ => {}
            }
        }
        let told: Vec<u64> = r.watches.iter_mut().filter_map(|(k, w)| w.sub.take().map(|_| *k)).collect();
        for local in told {
            self.deliver(r, local, Pushed::Failed(e.clone()));
        }
    }

    /// Why `r` takes no call now; one down for the network is dialed again.
    fn usable(&mut self, r: &mut Remote) -> Result<()> {
        match &r.state {
            State::Up => Ok(()),
            State::Down(e @ Error::Network(_)) => {
                let e = e.clone();
                self.dial(r);
                Err(e)
            }
            State::Down(e) => Err(e.clone()),
            State::Dialing | State::Authing => Err(Error::Network(format!("connecting to {}", r.addr))),
        }
    }
}

fn index(l: &Locked, conn: ConnId) -> Option<usize> {
    l.remotes.iter().position(|r| r.conn == Some(conn))
}

fn by_addr(l: &Locked, at: &Address) -> Result<usize> {
    l.remotes.iter().position(|r| r.addr == *at).ok_or_else(|| Error::Network(format!("not connected to {at}")))
}

/// Runs `f` on the remote holding client connection `conn`.
fn on_conn(db: &ReadOnly, conn: ConnId, f: impl FnOnce(&mut Cx<'_>, &mut Remote)) {
    db.locked(|l| {
        if let Some(i) = index(l, conn) {
            with(db, l, i, f);
        }
    });
}

/// Runs `f` on the remote at `at`; `Network` when there is none.
fn on_addr<R>(db: &ReadOnly, at: &Address, f: impl FnOnce(&mut Cx<'_>, &mut Remote) -> Result<R>) -> Result<R> {
    db.locked(|l| {
        let i = by_addr(l, at)?;
        with(db, l, i, f).unwrap_or_else(|| Err(Error::Network(format!("not connected to {at}"))))
    })
}

/// A client connection is up: its Auth goes.
pub(crate) fn up(db: &ReadOnly, conn: ConnId) {
    on_conn(db, conn, |cx, r| {
        r.state = State::Authing;
        let m = Msg::Auth { id: 0, secret: r.secret.as_ref().map(|s| s.0.clone()), session_id: r.session };
        cx.send(r, m, Asked::Auth);
    });
}

/// The protocol Error answering a request, as the API's.
fn protocol(code: Code) -> Error {
    if code == Code::MALFORMED { Error::Invalid("the node found the request malformed".into()) } else { Error::Refused(format!("the node refused the request (code {})", code.0)) }
}

/// A request's answer as its result.
fn answered(m: Msg) -> Result<Value> {
    match m {
        Msg::Reply { outcome, .. } => result_of(outcome),
        Msg::Ok { .. } => Ok(Value::List(Vec::new())),
        Msg::Error { code, .. } => Err(protocol(code)),
        _ => Err(Error::Invalid("an answer of the wrong kind".into())),
    }
}

/// The answer to request `id` on client connection `conn`.
pub(crate) fn reply(db: &ReadOnly, conn: ConnId, id: RequestId, m: Msg) {
    on_conn(db, conn, |cx, r| {
        let Some(asked) = r.calls.remove(&id) else { return };
        match asked {
            Asked::Auth => match answered(m) {
                Ok(_) => {
                    cx.send(r, Msg::Call { id: 0, max_reply: super::SMALL_REPLY, method: method::WHOAMI, args: Vec::new() }, Asked::Whoami);
                }
                Err(e) => {
                    let e = Error::Refused(format!("{}: {e}", r.addr));
                    cx.refused(r, e);
                }
            },
            Asked::Whoami => match answered(m).and_then(who) {
                Ok(w) => cx.came_up(r, w),
                Err(e) => cx.refused(r, e),
            },
            Asked::Call(tx) => {
                let _ = tx.send(answered(m));
            }
            Asked::Write(nonce) => {
                if let Some(p) = r.writes.remove(&nonce) {
                    let _ = p.tx.send(answered(m));
                }
            }
            Asked::Sub(local, waiter) => {
                let Some(w) = r.watches.get_mut(&local) else { return };
                match (answered(m), waiter) {
                    (Ok(v), waiter) => {
                        w.sub = Some(id);
                        cx.deliver(r, local, Pushed::Initial(v));
                        if let Some(tx) = waiter {
                            let _ = tx.send(Ok(()));
                        }
                    }
                    (Err(e), Some(tx)) => {
                        r.watches.remove(&local);
                        let _ = tx.send(Err(e));
                    }
                    (Err(e), None) => cx.deliver(r, local, Pushed::Failed(e)),
                }
            }
            Asked::Unsub => {}
        }
    });
}

fn who(v: Value) -> Result<Thin> {
    match list(v, "whoami")?.as_slice() {
        [me, node, home] => Ok(Thin { me: codec::tid(me)?, node: codec::tid(node)?, home: codec::tid(home)? }),
        _ => Err(codec::bad("whoami")),
    }
}

/// A connection ended (or its dial failed): one that was up is dialed again at once; one that
/// never came up leaves the remote down, its writes unknown.
pub(crate) fn closed(db: &ReadOnly, conn: ConnId) {
    on_conn(db, conn, |cx, r| {
        let net = Error::Network(format!("connection to {} lost", r.addr));
        r.conn = None;
        if matches!(r.state, State::Down(_)) {
            return;
        }
        let again = r.was_up && matches!(r.state, State::Up);
        r.state = State::Down(net.clone());
        if again {
            cx.lost(r, &net);
            cx.dial(r);
            return;
        }
        cx.fail_all(r, &net, &Error::OutcomeUnknown);
        if !r.watches.is_empty() {
            redial_later(db, r.addr.clone());
        }
    });
}

/// Dials the node at `at` again after `REDIAL_MS`, for its watches (with a runtime).
fn redial_later(db: &ReadOnly, at: Address) {
    let weak = crate::WeakOsis(std::sync::Arc::downgrade(&db.inner));
    db.inner.after(
        std::time::Duration::from_millis(REDIAL_MS),
        Box::new(move || {
            let Some(db) = weak.hold() else { return };
            let _ = on_addr(&db, &at, |cx, r| {
                if !r.watches.is_empty() {
                    cx.dial(r);
                }
                Ok(())
            });
        }),
    );
}

/// A Notify on client connection `conn`.
pub(crate) fn notify(db: &ReadOnly, conn: ConnId, m: Msg) {
    let Msg::Notify { sub_id, payload } = m else { return };
    // tests count what a node tells (no Notify where nothing the actor reads changed)
    osis_base::costs::count("port: notify", 1);
    on_conn(db, conn, |cx, r| {
        let Some((&local, w)) = r.watches.iter().find(|(_, w)| w.sub == Some(sub_id)) else { return };
        let filter = w.filter.clone();
        // a watch the app dropped goes at its next Notify
        if !db.inner.dispatch.registered(local) {
            r.watches.remove(&local);
            cx.send(r, Msg::Unsub { id: 0, sub_id }, Asked::Unsub);
            return;
        }
        match payload {
            Payload::Delivery { value } => cx.deliver(r, local, Pushed::Delivery(value)),
            Payload::TooLarge { source } => cx.deliver(r, local, Pushed::TooLarge(source)),
            // the node dropped it: subscribe again
            Payload::Lapsed => {
                if let Some(w) = r.watches.get_mut(&local) {
                    w.sub = None;
                }
                cx.send(r, Msg::Sub { id: 0, max_reply: super::VALUE_REPLY, filter }, Asked::Sub(local, None));
            }
        }
    });
}

impl ReadOnly {
    /// Waits for what a request's answer sends: on a test network by delivering what it queued,
    /// else blocking.
    fn wait_for<T>(&self, rx: Receiver<Result<T>>) -> Result<T> {
        if let crate::net::Net::Manual { net, .. } = &self.inner.net {
            net.deliver();
            return rx.try_recv().unwrap_or_else(|_| Err(Error::Network("no answer".into())));
        }
        crate::net::blocking(|| rx.recv()).unwrap_or_else(|_| Err(Error::Network("connection closed".into())))
    }

    /// Calls `method` at the node at `at`.
    pub(crate) fn remote_call(&self, at: &Address, method: u64, args: Vec<Value>, max_reply: u64) -> Result<Value> {
        let (tx, rx) = channel();
        on_addr(self, at, |cx, r| {
            cx.usable(r)?;
            if cx.send(r, Msg::Call { id: 0, max_reply, method, args }, Asked::Call(tx)) { Ok(()) } else { Err(Error::Network(format!("connection to {at} lost"))) }
        })?;
        self.wait_for(rx)
    }

    /// Write row `method` at the node at `at` under the next nonce (`args` after it).
    fn remote_nonced(&self, at: &Address, method: u64, args: Vec<Value>) -> Result<Value> {
        let (tx, rx) = channel();
        on_addr(self, at, |cx, r| {
            cx.usable(r)?;
            r.nonce += 1;
            let n = r.nonce;
            let mut a = vec![Value::uint(n)];
            a.extend(args.iter().cloned());
            r.writes.insert(n, Pending { method, args, tx });
            if !cx.send(r, Msg::Call { id: 0, max_reply: super::VALUE_REPLY, method, args: a }, Asked::Write(n)) {
                r.writes.remove(&n);
                return Err(Error::Network(format!("connection to {at} lost")));
            }
            Ok(())
        })?;
        self.wait_for(rx)
    }

    /// `Opt(commit)` as the commit, reporting here.
    fn made(&self, v: Value) -> Result<Option<crate::commits::Commit>> {
        Ok(codec::opt_from(v, "commit")?.map(codec::commit_from).transpose()?.map(|c| c.reporting(self)))
    }

    /// A write at the node at `at`: `args` as `Write::wire` made them.
    pub(crate) fn remote_write(&self, at: &Address, args: Vec<Value>) -> Result<Option<crate::commits::Commit>> {
        let v = self.remote_nonced(at, method::WRITE, args)?;
        self.made(v)
    }

    /// `undo` (`redo`: `redo`) of `scope` at the node at `at`.
    pub(crate) fn remote_undo(&self, at: &Address, scope: &crate::Scope, redo: bool) -> Result<Option<crate::commits::Commit>> {
        let v = self.remote_nonced(at, if redo { method::REDO } else { method::UNDO }, vec![codec::scope_to(scope)])?;
        self.made(v)
    }

    /// `revert` of `id` at the node at `at`.
    pub(crate) fn remote_revert(&self, at: &Address, id: crate::CommitId) -> Result<crate::commits::Commit> {
        let v = self.remote_nonced(at, method::REVERT, vec![codec::commit_ref_to(id)])?;
        Ok(codec::commit_from(v)?.reporting(self))
    }

    /// `undo_target` (`redo`: `redo_target`) of `scope` at the node at `at`.
    pub(crate) fn remote_target(&self, at: &Address, scope: &crate::Scope, redo: bool) -> Result<Option<crate::commits::Commit>> {
        let v = self.remote_call(at, if redo { method::REDO_TARGET } else { method::UNDO_TARGET }, vec![codec::scope_to(scope)], super::VALUE_REPLY)?;
        self.made(v)
    }

    /// The value at `path` of `tid`'s `ak` at the node at `at`, untyped.
    pub(crate) fn remote_get(&self, at: &Address, tid: Tid, ak: &Ak, path: &Path) -> Result<Option<Value>> {
        let v = self.remote_call(at, method::GET, vec![Value::Tid(tid), codec::ak_to(ak), codec::path_to(path)], super::VALUE_REPLY)?;
        read_from(v)?
    }

    /// Who this process is at the node at `at`.
    pub(crate) fn remote_who(&self, at: &Address) -> Option<Thin> {
        self.locked(|l| l.remotes.iter().find(|r| r.addr == *at).and_then(|r| r.who))
    }

    /// Connects to the node at `addr` (`secret`: as a client actor; none: a main session), and
    /// waits until it is up or refused.
    pub(crate) async fn add_remote(&self, addr: Address, secret: Option<crate::ClientSecret>) -> Result<Thin> {
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        self.locked(|l| {
            if l.remotes.iter().any(|r| r.addr == addr) {
                return Err(Error::Invalid(format!("already connected to {addr}")));
            }
            let mut session = [0u8; 16];
            osis_crypto::RngCore::fill_bytes(&mut osis_crypto::OsRng, &mut session);
            let mut r = Remote::new(addr.clone(), secret, session);
            r.ready.push(tx);
            l.remotes.push(r);
            self.inner.has_sources.store(true, std::sync::atomic::Ordering::Release);
            let i = l.remotes.len() - 1;
            with(self, l, i, |cx, r| cx.dial(r));
            Ok(())
        })?;
        let r = match &self.inner.net {
            crate::net::Net::Manual { net, .. } => {
                net.deliver();
                rx.try_recv().unwrap_or_else(|_| Err(Error::Network("no answer".into())))
            }
            // a oneshot receiver is a future any executor polls
            _ => rx.await.unwrap_or_else(|_| Err(Error::Network("no answer".into()))),
        };
        match r.and_then(|()| self.remote_who(&addr).ok_or_else(|| Error::Network("no answer".into()))) {
            Ok(w) => Ok(w),
            Err(e) => {
                self.drop_remote(&addr);
                Err(e)
            }
        }
    }

    /// Ends the connection to `at`; `false`: there was none.
    pub(crate) fn drop_remote(&self, at: &Address) -> bool {
        self.locked(|l| {
            let Ok(i) = by_addr(l, at) else { return false };
            let gone = Error::Network(format!("disconnected from {at}"));
            with(self, l, i, |cx, r| cx.fail_all(r, &gone, &Error::OutcomeUnknown));
            let r = l.remotes.remove(i);
            if let Some(c) = r.conn {
                let o = l.node.disconnect(c);
                l.out.extend(o);
            }
            if l.remotes.is_empty() && l.group_sources.is_empty() {
                self.inner.has_sources.store(false, std::sync::atomic::Ordering::Release);
            }
            true
        })
    }
}

/// One aspect a thing watch tells: its key, value and origin.
type Told = (Ak, Result<Option<Value>>, Origin);

/// A delivery's `limit` (a `[2, source]` Notify of a value filter).
fn limit_of(source: &Value) -> usize {
    source.as_uint().map_or(0, |n| usize::try_from(n).unwrap_or(usize::MAX))
}

/// `[x*]` as exactly `N` values.
fn fixed<const N: usize>(v: Value, what: &str) -> Result<[Value; N]> {
    <[Value; N]>::try_from(list(v, what)?).map_err(|_| codec::bad(what))
}

/// A status as nothing reaches its node now: no connection, each thing not connected.
fn unreachable(s: &Status) -> Status {
    let groups = s.groups.iter().map(|(t, g)| (*t, crate::GroupSync { state: crate::SyncState::NotConnected, not_taking: 0, leaving: g.leaving })).collect();
    Status { connected: 0, groups }
}

/// The statuses of several nodes as one.
fn merged<'a>(all: impl Iterator<Item = &'a Status>) -> Status {
    let mut out = Status::default();
    for s in all {
        out.connected += s.connected;
        for (t, g) in &s.groups {
            crate::syncing::merge(&mut out.groups, *t, g.clone());
        }
    }
    out
}

impl ReadOnly {
    /// How sync stands at this thin client's nodes, merged (`Osis::status`).
    pub(crate) fn remote_status(&self) -> Result<Status> {
        let all: Vec<Address> = self.locked(|l| l.remotes.iter().map(|r| r.addr.clone()).collect());
        let mut out = Vec::new();
        for a in &all {
            out.push(codec::status_from(self.remote_call(a, method::STATUS, Vec::new(), super::VALUE_REPLY)?)?);
        }
        Ok(merged(out.iter()))
    }
}

impl crate::Osis {
    /// A subscription under `filter` at each node of `at`; `f` hears what each pushes. `wait`:
    /// the call waits for every Reply and fails as the first failing Sub; else a node not up
    /// is told as `Pushed::Failed` and subscribed once it comes up.
    fn remote_sub(&self, at: &[Address], filter: Value, wait: bool, mut f: impl FnMut(&crate::Osis, &Address, Pushed) + Send + 'static) -> Result<Subscription> {
        let sub = self.inner.dispatch.register(
            0,
            Filter::Remote,
            Box::new(move |db: &crate::Osis, d: Delivery| {
                if let Delivery::Remote { from, got } = d {
                    f(db, &from, got)
                }
            }),
        );
        let local = sub.id().unwrap_or(0);
        let mut waits = Vec::new();
        for a in at {
            let (tx, rx) = channel();
            on_addr(self, a, |cx, r| {
                let up = cx.usable(r);
                if wait {
                    up.clone()?;
                }
                r.watches.insert(local, Watch { filter: filter.clone(), sub: None });
                if let Err(e) = up {
                    cx.deliver(r, local, Pushed::Failed(e));
                    return Ok(());
                }
                let m = Msg::Sub { id: 0, max_reply: super::VALUE_REPLY, filter: filter.clone() };
                if cx.send(r, m, Asked::Sub(local, wait.then_some(tx))) || !wait { Ok(()) } else { Err(Error::Network(format!("connection to {a} lost"))) }
            })?;
            if wait {
                waits.push(rx);
            }
        }
        for rx in waits {
            self.wait_for(rx)?;
        }
        Ok(sub)
    }

    /// A value watch at the node at `at`: `f` hears the value at `path` of `tid`'s `ak` once,
    /// then each time it reads otherwise (a lost connection as an `Err`, then the value again).
    pub(crate) fn remote_watch(&self, at: &Address, tid: Tid, ak: Ak, path: &Path, mut f: impl FnMut(&crate::Osis, Change<Value>) + Send + 'static) -> Result<Subscription> {
        let filter = Value::List(vec![Value::uint(super::filter::VALUE), Value::Tid(tid), codec::ak_to(&ak), codec::path_to(path)]);
        let mut last = None;
        self.remote_sub(std::slice::from_ref(at), filter, true, move |db, _, got| {
            let (value, origin) = match got {
                Pushed::Initial(v) => (read_from(v).and_then(|r| r), Origin::Initial),
                Pushed::Delivery(v) => match fixed::<2>(v, "delivery").and_then(|[got, o]| Ok((read_from(got)?, codec::origin_from(o)?))) {
                    Ok(x) => x,
                    Err(e) => (Err(e), Origin::Initial),
                },
                Pushed::TooLarge(source) => (Err(Error::TooLarge { limit: limit_of(&source) }), Origin::Initial),
                Pushed::Failed(e) => (Err(e), Origin::Initial),
            };
            let now = digest(&value);
            if value.is_ok() && last == Some(now) {
                return;
            }
            last = Some(now);
            f(db, Change { tid, ak: ak.clone(), value, origin });
        })
    }

    /// `on_thing_change` at the node at `at`: each aspect once, then each change; a lost
    /// connection as an `Err` for each aspect it told, then each that reads otherwise once back.
    pub(crate) fn remote_thing_watch(&self, at: &Address, tid: Tid, mut f: impl FnMut(&crate::Osis, Change<Value>) + Send + 'static) -> Result<Subscription> {
        let filter = Value::List(vec![Value::uint(super::filter::THING), Value::Tid(tid)]);
        let mut last: BTreeMap<Ak, Option<crate::watch::Digest>> = BTreeMap::new();
        self.remote_sub(std::slice::from_ref(at), filter, true, move |db, _, got| {
            let told: Result<Vec<Told>> = match got {
                // every aspect now; one told before and absent now is told absent
                Pushed::Initial(v) => list(v, "aspects").and_then(|all| {
                    let mut now = BTreeMap::new();
                    for a in all {
                        let [k, read] = fixed::<2>(a, "aspect")?;
                        now.insert(codec::ak(&k)?, read_from(read)?);
                    }
                    for k in last.keys() {
                        now.entry(k.clone()).or_insert(Ok(None));
                    }
                    Ok(now.into_iter().map(|(k, v)| (k, v, Origin::Initial)).collect())
                }),
                Pushed::Delivery(v) => fixed::<3>(v, "delivery").and_then(|[k, read, o]| Ok(vec![(codec::ak(&k)?, read_from(read)?, codec::origin_from(o)?)])),
                Pushed::TooLarge(source) => fixed::<2>(source, "source").and_then(|[k, n]| Ok(vec![(codec::ak(&k)?, Err(Error::TooLarge { limit: limit_of(&n) }), Origin::Initial)])),
                Pushed::Failed(e) => Ok(last.keys().map(|k| (k.clone(), Err(e.clone()), Origin::Initial)).collect()),
            };
            let told = told.unwrap_or_else(|e| last.keys().map(|k| (k.clone(), Err(e.clone()), Origin::Initial)).collect());
            for (ak, value, origin) in told {
                crate::read::tell_changed(&mut last, db, Change { tid, ak, value, origin }, &mut f);
            }
        })
    }

    /// `on_grants_change` at the node at `at`: the grants once, then each time they read
    /// otherwise; a lost connection as an `Err`, then the grants again once back.
    pub(crate) fn remote_grants_watch(&self, at: &Address, thing: Tid, mut f: impl FnMut(&crate::Osis, Result<crate::Grants>) + Send + 'static) -> Result<Subscription> {
        let filter = Value::List(vec![Value::uint(super::filter::GRANTS), Value::Tid(thing)]);
        let mut last = None;
        self.remote_sub(std::slice::from_ref(at), filter, true, move |db, _, got| {
            let now = match got {
                Pushed::Initial(v) | Pushed::Delivery(v) => codec::grants_from(v),
                Pushed::TooLarge(source) => Err(Error::TooLarge { limit: limit_of(&source) }),
                Pushed::Failed(e) => Err(e),
            };
            match now {
                Ok(g) if last.as_ref() == Some(&g) => {}
                Ok(g) => {
                    last = Some(g.clone());
                    f(db, Ok(g));
                }
                Err(e) => {
                    last = None;
                    f(db, Err(e));
                }
            }
        })
    }

    /// `on_status_change` at this thin client's nodes: their statuses merged, once and on each
    /// change. A node that cannot be reached shows as not connected, its things each
    /// `NotConnected`; nothing fails.
    pub(crate) fn remote_status_watch(&self, mut f: impl FnMut(&crate::Osis, Status) + Send + 'static) -> Result<Subscription> {
        let all: Vec<Address> = self.locked(|l| l.remotes.iter().map(|r| r.addr.clone()).collect());
        let filter = Value::List(vec![Value::uint(super::filter::STATUS)]);
        let mut each: Vec<(Address, Status)> = Vec::new();
        let mut last: Option<Status> = None;
        self.remote_sub(&all, filter, false, move |db, from, got| {
            let before = each.iter().find(|(a, _)| a == from).map(|(_, s)| s.clone()).unwrap_or_default();
            let now = match got {
                Pushed::Initial(v) | Pushed::Delivery(v) => codec::status_from(v).unwrap_or_else(|_| unreachable(&before)),
                Pushed::TooLarge(_) | Pushed::Failed(_) => unreachable(&before),
            };
            each.retain(|(a, _)| a != from);
            each.push((from.clone(), now));
            let m = merged(each.iter().map(|(_, s)| s));
            if last.as_ref() != Some(&m) {
                last = Some(m.clone());
                f(db, m);
            }
        })
    }
}
