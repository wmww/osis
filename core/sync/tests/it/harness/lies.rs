//! Hostile peers as honest nodes whose frames pass through a lie (notes/sync-test-harness.md,
//! hostile peers are scripted nodes): the node runs the product's sync with its own keys; the
//! world splits its outgoing bytes into frames (`osis_proto::FrameDecoder`), passes each message
//! after the Hello through the lie and encodes what comes out with the real encoder. A lie can
//! also answer what the node hears (a refusal, a `full` event). It can only send what the node
//! could build: it signs nothing, so it lies only in its own log and its own answers. The
//! network itself never alters content (`Loss` is content-blind).

use osis_base::{BlobId, SyncId};
use osis_proto::msg::flow;
use osis_proto::{Code, Event, Flow, FrameDecoder, Msg, Stream, encode_frame};
use osis_sync::{ConnId, Out};
use std::collections::{BTreeMap, BTreeSet};

/// A lie (the library of hostile peers the simulations use).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lie {
    /// Holds every request open: sends no reply (a request it gets is never answered).
    Hold,
    /// Lies in its own log by omission: its stream and pull replies show no added entry.
    Withhold,
    /// Lies in its own log: shows each entry it adds as deleted.
    Forget,
    /// Says it is full for every sync ID it is shown an entry of (spec/sync-streams.md §4 Full),
    /// once per connection, while it takes them all.
    Full,
    /// Refuses every role entry it is shown (spec/sync-streams.md §4 Refused, code 1), while it
    /// takes them.
    RefuseRoles,
}

/// One connection's frames each way.
#[derive(Clone, Default)]
struct Frames {
    out: FrameDecoder,
    out_hello: bool,
    heard: FrameDecoder,
    heard_hello: bool,
}

/// A node's lie and its state: frames per connection, what it owes each connection.
#[derive(Clone)]
pub struct Liar {
    pub lie: Lie,
    conns: BTreeMap<ConnId, Frames>,
    /// `full` told, per (connection, S).
    told: BTreeSet<(ConnId, SyncId)>,
    /// Messages the lie sends next on each connection.
    owed: BTreeMap<ConnId, Vec<Msg>>,
}

/// Each (S, entry added) of a message.
fn added(m: &Msg) -> Vec<(SyncId, BlobId)> {
    let events = match m {
        Msg::Stream(s) => &s.events,
        Msg::PullReply(r) => &r.events,
        _ => return Vec::new(),
    };
    events.iter().filter_map(|(s, e)| added_id(e).map(|b| (*s, b))).collect()
}

fn added_id(e: &Event) -> Option<BlobId> {
    match e {
        Event::Added { blob_id, .. } => Some(*blob_id),
        _ => None,
    }
}

/// A Stream with no cursor carrying `events`.
fn bare_stream(events: Vec<(SyncId, Event)>) -> Msg {
    Msg::Stream(Box::new(Stream { events, cursor: None, report: false, seq: 0 }))
}

impl Liar {
    pub fn new(lie: Lie) -> Liar {
        Liar { lie, conns: BTreeMap::new(), told: BTreeSet::new(), owed: BTreeMap::new() }
    }

    /// The node hears `bytes` on `conn`; `role(S, blob)` says whether an entry is a role entry.
    pub fn heard(&mut self, conn: ConnId, bytes: &[u8], role: &dyn Fn(&SyncId, &BlobId) -> bool) {
        if !matches!(self.lie, Lie::Full | Lie::RefuseRoles) {
            return;
        }
        let f = self.conns.entry(conn).or_default();
        f.heard.push(bytes);
        let mut msgs = Vec::new();
        while let Ok(Some(body)) = f.heard.next_frame() {
            if !std::mem::replace(&mut f.heard_hello, true) {
                continue;
            }
            msgs.extend(Msg::decode(&body).ok());
        }
        for (s, b) in msgs.iter().flat_map(added) {
            let event = match self.lie {
                Lie::Full if self.told.insert((conn, s)) => Event::Full(true),
                Lie::RefuseRoles if role(&s, &b) => Event::Refused(b, Code::REFUSED),
                _ => continue,
            };
            self.owed.entry(conn).or_default().push(bare_stream(vec![(s, event)]));
        }
    }

    /// The lie applied to one message the node sends.
    fn told(&self, m: Msg) -> Vec<Msg> {
        match (self.lie, m) {
            (Lie::Hold, m) if flow(m.kind()) == Some(Flow::Reply) => Vec::new(),
            (Lie::Withhold | Lie::Forget, Msg::Stream(mut s)) => {
                s.events = self.log(s.events);
                vec![Msg::Stream(s)]
            }
            (Lie::Withhold | Lie::Forget, Msg::PullReply(mut r)) => {
                r.events = self.log(r.events);
                vec![Msg::PullReply(r)]
            }
            (_, m) => vec![m],
        }
    }

    fn log(&self, events: Vec<(SyncId, Event)>) -> Vec<(SyncId, Event)> {
        events
            .into_iter()
            .filter_map(|(s, e)| match (self.lie, e) {
                (Lie::Withhold, Event::Added { .. }) => None,
                (Lie::Forget, Event::Added { blob_id, .. }) => Some((s, Event::Deleted(blob_id))),
                (_, e) => Some((s, e)),
            })
            .collect()
    }

    /// The node's outputs as the lie sends them: each Send's frames after the Hello through the
    /// lie (a partial frame waits for its rest), then what the lie owes each connection.
    pub fn rewrite(&mut self, out: Vec<Out>) -> Vec<Out> {
        let mut res = Vec::with_capacity(out.len());
        for o in out {
            let Out::Send(conn, bytes) = o else {
                if let Out::Close(c) = &o {
                    self.closed(*c);
                }
                res.push(o);
                continue;
            };
            let f = self.conns.entry(conn).or_default();
            f.out.push(&bytes);
            let mut bodies = Vec::new();
            while let Ok(Some(body)) = f.out.next_frame() {
                let hello = !std::mem::replace(&mut f.out_hello, true);
                bodies.push((hello, body));
            }
            let mut sent = Vec::new();
            for (hello, body) in bodies {
                match (hello, Msg::decode(&body)) {
                    (false, Ok(m)) => {
                        for m in self.told(m) {
                            sent.extend(encode_frame(&m.encode()));
                        }
                    }
                    _ => sent.extend(encode_frame(&body)),
                }
            }
            if self.conns.get(&conn).is_some_and(|f| f.out_hello) {
                for m in self.owed.remove(&conn).unwrap_or_default() {
                    sent.extend(encode_frame(&m.encode()));
                }
            }
            if !sent.is_empty() {
                res.push(Out::Send(conn, sent));
            }
        }
        // owed on a connection the node sent nothing on this step
        let owed: Vec<ConnId> = self.owed.keys().copied().filter(|c| self.conns.get(c).is_some_and(|f| f.out_hello)).collect();
        for c in owed {
            let bytes: Vec<u8> = self.owed.remove(&c).unwrap_or_default().iter().flat_map(|m| encode_frame(&m.encode())).collect();
            if !bytes.is_empty() {
                res.insert(0, Out::Send(c, bytes));
            }
        }
        res
    }

    fn closed(&mut self, c: ConnId) {
        self.conns.remove(&c);
        self.owed.remove(&c);
        self.told.retain(|(x, _)| *x != c);
    }
}
