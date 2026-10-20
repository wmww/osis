//! Hand-driven client sessions (adversaries): an osis-proto `ClientSession` connected straight to
//! a server's `Hub`, its requests and the replies exchanged synchronously, no faults. Whatever
//! keys, blobs, wraps and stamps the scenario builds go on the wire as they are: a removed
//! member's stale steps and replays, malformed blobs, deposit floods.

use super::{End, NetSim, Party, Payload};
use crate::harness::Res;
use osis_core::{LabelId, Tid};
use osis_crypto::{Secret32, SigningSecret};
use osis_label::Step;
use osis_node::labeling::HeadKeys;
use osis_proto::{ClientConfig, ClientEvent, ClientInput, ClientOutput, ClientSession, Command, LabelStore};
use osis_server::HubOutput;
use std::collections::VecDeque;

/// Exchanges one session may cause before it is called a storm.
const ROGUE_STORM: usize = 100_000;

pub struct Rogue {
    pub s: usize,
    hc: u64,
    pub session: ClientSession,
    /// Every event so far.
    pub events: Vec<ClientEvent>,
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
    pub deposit: Option<SigningSecret>,
}

impl NetSim {
    /// Bytes as if server `s` sent them to node `n` on its open connections there (a lying
    /// server's word, in order after what is in flight); how many connections got them.
    pub fn server_says(&mut self, s: usize, n: usize, bytes: &[u8]) -> usize {
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

    /// Commits signed by node `n`'s key that reuse its counters are an adversary's: the honest-node
    /// counter check skips its author.
    pub fn equivocator(&mut self, n: usize) -> Res<()> {
        let t = self.tid(n)?;
        self.check.equivocators.insert(t);
        Ok(())
    }

    /// A hand-driven session of an adversary at server `s` (Hellos exchanged).
    pub fn rogue(&mut self, s: usize) -> Res<Rogue> {
        let key = self.servers.get(s).map(|x| x.key).ok_or_else(|| self.fail(format!("no server {s}")))?;
        let hc = self.next_hub_conn;
        self.next_hub_conn += 1;
        let mut challenge = [0u8; 32];
        for c in challenge.chunks_mut(8) {
            c.copy_from_slice(&self.dice.u64().to_le_bytes());
        }
        let mut peer = [0u8; 32];
        peer[..8].copy_from_slice(&self.dice.u64().to_le_bytes());
        let mut r = Rogue { s, hc, session: ClientSession::new(ClientConfig { peer_static_key: key, challenge }), events: Vec::new(), closed: false };
        let now = self.now();
        let out = self.servers.get_mut(s).and_then(|x| x.hub.as_mut()).map(|h| h.accept(now, hc, peer)).unwrap_or_default();
        self.pump(&mut r, out, vec![ClientInput::Start])?;
        if !r.session.is_ready() {
            return Err(self.fail(format!("rogue session at server {s} not ready: {:?}", r.events)));
        }
        Ok(r)
    }

    /// Sends one command; returns the events it caused.
    pub fn rogue_do(&mut self, r: &mut Rogue, cmd: Command) -> Res<Vec<ClientEvent>> {
        self.report.rogue_sent = self.report.rogue_sent.saturating_add(1);
        let k = r.events.len();
        self.pump(r, Vec::new(), vec![ClientInput::Command(cmd)])?;
        let evs: Vec<ClientEvent> = r.events.get(k..).map(|x| x.to_vec()).unwrap_or_default();
        let refused = evs.iter().filter(|e| matches!(e, ClientEvent::Refused { .. })).count();
        self.report.rogue_refused = self.report.rogue_refused.saturating_add(refused as u64);
        Ok(evs)
    }

    /// Raw bytes on the connection (a frame the session would never write).
    pub fn rogue_raw(&mut self, r: &mut Rogue, bytes: Vec<u8>) -> Res<Vec<ClientEvent>> {
        self.report.rogue_sent = self.report.rogue_sent.saturating_add(1);
        let k = r.events.len();
        let now = self.now();
        let out = self.servers.get_mut(r.s).and_then(|x| x.hub.as_mut()).map(|h| h.input(now, r.hc, bytes)).unwrap_or_default();
        self.pump(r, out, Vec::new())?;
        Ok(r.events.get(k..).map(|x| x.to_vec()).unwrap_or_default())
    }

    pub fn rogue_close(&mut self, r: &mut Rogue) {
        if let Some(h) = self.servers.get_mut(r.s).and_then(|x| x.hub.as_mut()) {
            h.closed(r.hc);
        }
        r.closed = true;
    }

    /// Exchanges until neither side has anything to say.
    fn pump(&mut self, r: &mut Rogue, hub: Vec<HubOutput>, client: Vec<ClientInput>) -> Res<()> {
        let mut to_client: VecDeque<ClientInput> = client.into();
        let mut to_hub: VecDeque<Vec<u8>> = VecDeque::new();
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
                    HubOutput::Send(hc, b) if hc == r.hc => to_client.push_back(ClientInput::Bytes(b)),
                    HubOutput::Close(hc) if hc == r.hc => r.closed = true,
                    other => self.hub_out(r.s, vec![other])?,
                }
                continue;
            }
            if let Some(b) = to_hub.pop_front() {
                if r.closed || !self.servers.get(r.s).is_some_and(|x| x.up) {
                    continue;
                }
                let out = self.servers.get_mut(r.s).and_then(|x| x.hub.as_mut()).map(|h| h.input(now, r.hc, b)).unwrap_or_default();
                from_hub.extend(out);
                continue;
            }
            if let Some(i) = to_client.pop_front() {
                if r.closed {
                    continue;
                }
                for o in r.session.handle(now, i) {
                    match o {
                        ClientOutput::Send(b) => to_hub.push_back(b),
                        ClientOutput::Close => self.rogue_close(r),
                        ClientOutput::SetTimer(_) => {}
                        ClientOutput::Event(e) => {
                            self.note(format!("rogue at s{}: {}", r.s, format!("{e:?}").chars().take(140).collect::<String>()));
                            r.events.push(e);
                        }
                    }
                }
                continue;
            }
            return Ok(());
        }
    }

    /// The keys node `n` holds for group `g`'s label at server `s`'s current head.
    pub fn label_keys(&mut self, n: usize, s: usize, g: &Tid) -> Res<LabelKeys> {
        let gl = self.sync(n)?.labels().into_iter().find(|(t, _)| t == g).map(|x| x.1).ok_or_else(|| self.fail(format!("node {n} knows no label of {g}")))?;
        let hub = self.hub(s).ok_or_else(|| self.fail(format!("server {s} is down")))?;
        let head = hub.store().head(&gl.id).ok().flatten().and_then(|h| hub.store().step(&gl.id, &h).ok().flatten());
        let head = head.ok_or_else(|| self.fail(format!("server {s} holds no head of {:?}", gl.id)))?;
        let keys = self.engine(n)?.head_keys(g, gl.index, &head);
        let keys = keys.map_err(|x| self.fail(format!("head keys: {x}")))?;
        let read = self.engine(n)?.epochs(g).and_then(|x| x.read.newest_held().map(|y| y.1.clone()));
        let deposit = keys.deposit.clone();
        Ok(LabelKeys { g: *g, label: gl.id, head, keys, read, deposit })
    }

    /// Whether node `n` may reach server `s`.
    pub fn reaches(&self, n: usize, s: usize) -> bool {
        !self.is_blocked(Party::N(n), Party::S(s))
    }
}
