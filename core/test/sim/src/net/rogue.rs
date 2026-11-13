//! Hand-driven dialers (adversaries): a dialer `Session` (osis-proto `examples::Dialer`) connected
//! straight to a host's `Hub`, its requests and the replies exchanged synchronously, no faults. Whatever
//! keys and steps the scenario builds go on the wire as they are: a removed holder's stale opens
//! and steps, frames that are no message. Entries a hostile writer would serve the host are
//! taken into the host's store as its pull takes them (`host_put`).

use super::{End, NetSim, Party, Payload};
use crate::harness::Res;
use osis_base::{BlobId, LabelId, Tid};
use osis_crypto::Secret32;
use osis_label::Step;
use osis_node::labeling::HeadKeys;
use osis_proto::examples::Dialer;
use osis_proto::{Code, LabelStore, Message, SessionOutput};
use osis_host::HubOutput;
use std::collections::VecDeque;

/// Exchanges one session may cause before it is called a storm.
const ROGUE_STORM: usize = 100_000;

pub struct Rogue {
    pub s: usize,
    hc: u64,
    pub dialer: Dialer,
    /// Every message its session handed up so far (answers, the host's requests and pushes).
    pub events: Vec<Message>,
    pub closed: bool,
}

/// What a scenario knows of a label to act on it by hand.
#[derive(Clone)]
pub struct LabelKeys {
    pub g: Tid,
    pub label: LabelId,
    pub head: Step,
    pub keys: HeadKeys,
    /// Newest read secret held (wraps).
    pub read: Option<Secret32>,
}

/// An entry a writer stamped: blob, wrap and stamp.
pub struct Stamped {
    pub id: BlobId,
    pub blob: Vec<u8>,
    pub wrap: [u8; osis_crypto::WRAP_LEN],
    pub stamp: osis_crypto::Signature,
}

impl NetSim {
    /// Bytes as if host `s` sent them to node `n` on its open connections there (a lying
    /// host's word, in order after what is in flight); how many connections got them.
    pub fn host_says(&mut self, s: usize, n: usize, bytes: &[u8]) -> usize {
        let to: Vec<(u64, End)> = self
            .links
            .iter()
            .filter_map(|(id, l)| match (l.dialer, l.acceptor) {
                (End::Node(x, c), End::Hub(y, _)) | (End::Hub(y, _), End::Node(x, c)) if x == n && y == s => Some((*id, End::Node(x, c))),
                _ => None,
            })
            .collect();
        for (id, e) in &to {
            self.send(*id, *e, Payload::Bytes(bytes.to_vec()));
        }
        to.len()
    }

    /// Commit `c` is an adversary's counter reuse under an honest node's key: the honest-node
    /// counter check skips it.
    pub fn equivocation(&mut self, c: osis_base::CommitId) {
        self.check.equivocations.insert(c);
    }

    /// A hand-driven session of an adversary at host `s` (Hellos exchanged).
    pub fn rogue(&mut self, s: usize) -> Res<Rogue> {
        let key = self.hosts.get(s).map(|x| x.key).ok_or_else(|| self.fail(format!("no host {s}")))?;
        let hc = self.next_hub_conn;
        self.next_hub_conn += 1;
        let mut challenge = [0u8; 32];
        for c in challenge.chunks_mut(8) {
            c.copy_from_slice(&self.dice.u64().to_le_bytes());
        }
        let mut peer = [0u8; 32];
        peer[..8].copy_from_slice(&self.dice.u64().to_le_bytes());
        let mut r = Rogue { s, hc, dialer: Dialer::new(key, challenge), events: Vec::new(), closed: false };
        let now = self.now();
        let out = self.hosts.get_mut(s).and_then(|x| x.hub.as_mut()).map(|h| h.accept(now, hc, key, osis_host::Remote::key(peer))).unwrap_or_default();
        let start = r.dialer.start(now);
        self.pump(&mut r, out, start)?;
        if r.dialer.session.binding().is_none() {
            return Err(self.fail(format!("rogue session at host {s} not ready: {:?}", r.events)));
        }
        Ok(r)
    }

    /// A stamped entry of `label` taken into host `s`'s store as its pull from the writer takes
    /// one (`session::pulled`: the stamp checked under the head's keys, then the store's rules);
    /// its node sync then serves it. The code (a relay-only blob passed on: OK).
    pub fn host_put(&mut self, s: usize, label: LabelId, e: &Stamped) -> Res<Code> {
        let now = self.now();
        let hub = self.hub(s).ok_or_else(|| self.fail(format!("host {s} is down")))?;
        let taken = {
            let mut st = hub.store();
            match st.head_keys(&label) {
                Ok(Some(k)) => osis_proto::session::pulled(&mut *st, now, &label, &k, &e.blob, e.wrap, e.stamp, &mut false),
                Ok(None) => Ok(osis_proto::session::Taken::Code(Code::UNKNOWN_LABEL)),
                Err(x) => Err(x),
            }
        };
        let code = match taken.map_err(|x| self.fail(format!("host {s} put: {x}")))? {
            osis_proto::session::Taken::Code(c) => c,
            osis_proto::session::Taken::Relay(_) => Code::OK,
        };
        self.note(format!("host {s} took {:?} by hand: {code:?}", e.id));
        self.host_feed(s, osis_node::sync::Event::Local)?;
        Ok(code)
    }

    /// A Deposit item of `label` taken at host `s` as its node sync takes one from a peer
    /// (`session::deposit`: the signature under the head's deposit key, then the store's budget,
    /// rates and caps). The code.
    pub fn host_deposit(&mut self, s: usize, label: LabelId, blob: &[u8], wrap: osis_proto::msg::Wrap, sig: &osis_crypto::Signature) -> Res<Code> {
        let now = self.now();
        let hub = self.hub(s).ok_or_else(|| self.fail(format!("host {s} is down")))?;
        let taken = {
            let mut st = hub.store();
            match st.head_keys(&label) {
                Ok(Some(k)) => osis_proto::session::deposit(&mut *st, now, &label, &k, blob, wrap, sig, &mut false).map(|x| x.0),
                Ok(None) => Ok(Code::UNKNOWN_LABEL),
                Err(x) => Err(x),
            }
        };
        let code = taken.map_err(|x| self.fail(format!("host {s} deposit: {x}")))?;
        self.host_feed(s, osis_node::sync::Event::Local)?;
        Ok(code)
    }

    /// The deposit budget of `label` at host `s` in entries (spec/sync.md §5: its policy's
    /// factor over the head's claims).
    pub fn host_deposit_budget(&mut self, s: usize, label: LabelId) -> Res<u64> {
        let hub = self.hub(s).ok_or_else(|| self.fail(format!("host {s} is down")))?;
        let st = hub.store();
        let head = st.head(&label).ok().flatten().ok_or_else(|| self.fail("no head"))?;
        let claims = st.claim_set(&label, &head).ok().flatten().map_or(0, |c| c.claims.len() as u64);
        Ok(st.policy().deposit_factor.max(1) * (64 + 4 * claims))
    }

    /// Sends one request (under an id the dialer picks); returns the messages it caused.
    pub fn rogue_do(&mut self, r: &mut Rogue, req: impl FnOnce(osis_proto::msg::Id) -> Message) -> Res<Vec<Message>> {
        self.report.rogue_sent = self.report.rogue_sent.saturating_add(1);
        let k = r.events.len();
        let (id, out) = r.dialer.request(self.now(), req);
        self.pump(r, Vec::new(), out)?;
        let evs: Vec<Message> = r.events.get(k..).map(|x| x.to_vec()).unwrap_or_default();
        let refused = evs.iter().filter(|e| matches!(e, Message::Error { id: x, .. } if *x == id)).count();
        self.report.rogue_refused = self.report.rogue_refused.saturating_add(refused as u64);
        Ok(evs)
    }

    /// Raw bytes on the connection (a frame the session would never write).
    pub fn rogue_raw(&mut self, r: &mut Rogue, bytes: Vec<u8>) -> Res<Vec<Message>> {
        self.report.rogue_sent = self.report.rogue_sent.saturating_add(1);
        let k = r.events.len();
        let now = self.now();
        let out = self.hosts.get_mut(r.s).and_then(|x| x.hub.as_mut()).map(|h| h.input(now, r.hc, bytes)).unwrap_or_default();
        self.pump(r, out, Vec::new())?;
        Ok(r.events.get(k..).map(|x| x.to_vec()).unwrap_or_default())
    }

    pub fn rogue_close(&mut self, r: &mut Rogue) {
        let out = self.hosts.get_mut(r.s).and_then(|x| x.hub.as_mut()).map(|h| h.closed(r.hc)).unwrap_or_default();
        if let Err(e) = self.hub_out(r.s, out) {
            self.note(format!("host {} hub: {e:?}", r.s));
        }
        r.closed = true;
    }

    /// Exchanges until neither side has anything to say, starting from what the hub and the
    /// dialer put out.
    fn pump(&mut self, r: &mut Rogue, hub: Vec<HubOutput>, dialer: Vec<SessionOutput>) -> Res<()> {
        let mut from_dialer: VecDeque<SessionOutput> = dialer.into();
        let mut from_hub: VecDeque<HubOutput> = hub.into();
        let mut k = 0usize;
        loop {
            k += 1;
            if k > ROGUE_STORM {
                return Err(self.fail("rogue session storm"));
            }
            let now = self.now();
            if let Some(o) = from_hub.pop_front() {
                match o {
                    HubOutput::Send(hc, b) if hc == r.hc => {
                        if !r.closed {
                            from_dialer.extend(r.dialer.bytes(now, b));
                        }
                    }
                    HubOutput::Close(hc) if hc == r.hc => r.closed = true,
                    other => self.hub_out(r.s, vec![other])?,
                }
                continue;
            }
            if let Some(o) = from_dialer.pop_front() {
                match o {
                    SessionOutput::Send(b) => {
                        if r.closed || !self.hosts.get(r.s).is_some_and(|x| x.up) {
                            continue;
                        }
                        let out = self.hosts.get_mut(r.s).and_then(|x| x.hub.as_mut()).map(|h| h.input(now, r.hc, b)).unwrap_or_default();
                        from_hub.extend(out);
                    }
                    SessionOutput::Close => {
                        if !r.closed {
                            self.rogue_close(r);
                        }
                    }
                    SessionOutput::Peer(m) => {
                        self.note(format!("rogue at s{}: {}", r.s, format!("{m:?}").chars().take(140).collect::<String>()));
                        r.events.push(*m);
                    }
                    other => self.note(format!("rogue at s{}: {}", r.s, format!("{other:?}").chars().take(140).collect::<String>())),
                }
                continue;
            }
            return Ok(());
        }
    }

    /// The keys node `n` holds for group `g`'s label at host `s`'s current head.
    pub fn label_keys(&mut self, n: usize, s: usize, g: &Tid) -> Res<LabelKeys> {
        let gl = self.sync(n)?.labels().into_iter().find(|(t, _)| t == g).map(|x| x.1).ok_or_else(|| self.fail(format!("node {n} knows no label of {g}")))?;
        let hub = self.hub(s).ok_or_else(|| self.fail(format!("host {s} is down")))?;
        let head = hub.store().head(&gl.id).ok().flatten();
        let head = head.and_then(|h| hub.store().step(&gl.id, &h).ok().flatten());
        let head = head.ok_or_else(|| self.fail(format!("host {s} holds no head of {:?}", gl.id)))?;
        let keys = self.engine(n)?.head_keys(g, gl.index, &head);
        let keys = keys.map_err(|x| self.fail(format!("head keys: {x}")))?;
        let read = self.engine(n)?.epochs(g).and_then(|x| x.read.newest_held().map(|y| y.1.clone()));
        Ok(LabelKeys { g: *g, label: gl.id, head, keys, read })
    }

    /// Whether node `n` may reach host `s`.
    pub fn reaches(&self, n: usize, s: usize) -> bool {
        !self.is_blocked(Party::N(n), Party::S(s))
    }
}
