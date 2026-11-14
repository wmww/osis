//! Relay-only entries (spec/sync-compaction.md §2 Relay-only commits, spec/sync-ids.md §6
//! Relay-only, spec/sync-streams.md §4 Relay-only entries): an ephemeral signal goes as a Stream
//! with no cursor to every peer sharing S, and each node holding S passes on what it takes, never
//! to the peer it came from. Nothing is held: a node remembers only which it took (`RelayGate`,
//! in memory: a restart forgets it).

use super::{Ctx, Streams};
use crate::types::{ConnId, Entry};
use osis_base::{BlobId, SyncId};
use osis_engine::sync::{Holding, RelayOpened};
use osis_label::Prefix;
use osis_proto::{Event, Msg, RelayVerdict, Stream};

impl Streams {
    /// This node's own relay-only commits, sealed per read sync ID, pushed to every peer sharing
    /// it; taken once here too, so one coming back is dropped.
    pub(super) fn send_relays(&mut self, ctx: &mut Ctx) -> crate::types::Result<bool> {
        let relays = ctx.ground.own_relays()?;
        let acted = !relays.is_empty();
        for r in relays {
            let expiry = Prefix::parse(&r.bytes).ok().and_then(|p| p.expiry()).map(|t| t.0);
            if self.relays.admit(&r.sync_id, &r.blob, r.bytes.len(), expiry, ctx.now.0) != RelayVerdict::Push {
                continue;
            }
            let stamp = ctx.ground.stamp(&r.sync_id, &r.blob, &r.wrap);
            self.pass_on(ctx, None, r.sync_id, r.blob, r.bytes, r.wrap, stamp);
        }
        Ok(acted)
    }

    /// A relay-only blob that came in a Stream with no cursor from `conn` (a member there): taken
    /// once, within its expiry and S's rate (`RelayGate`); a node reading S delivers a verified
    /// new one and passes it on, a node keeping S unread passes on what it takes.
    pub(super) fn relay_in(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, e: Entry, bytes: Vec<u8>) {
        let Some(holding) = ctx.store.holding(&s) else { return };
        if self.relays.admit(&s, &e.blob, bytes.len(), e.expires.map(|t| t.0), ctx.now.0) != RelayVerdict::Push {
            return;
        }
        if holding == Holding::Read {
            match ctx.ground.open_relay(&s, &e, &bytes) {
                Ok(RelayOpened::New) => {}
                Ok(_) => return,
                Err(err) => return self.failed(Err(err)),
            }
        }
        self.pass_on(ctx, Some(conn), s, e.blob, bytes, e.wrap, e.stamp);
    }

    /// Pushes a relay-only entry to every connection where S is a member and not ended, but
    /// `from`: one whose push does not fit is not pushed there (spec/sync-streams.md §2).
    #[allow(clippy::too_many_arguments)]
    fn pass_on(&mut self, ctx: &mut Ctx, from: Option<ConnId>, s: SyncId, b: BlobId, bytes: Vec<u8>, wrap: crate::types::Wrap, stamp: Option<osis_proto::Stamp>) {
        let to: Vec<ConnId> = self.holders.get(&s).into_iter().flatten().copied().filter(|c| Some(*c) != from).collect();
        for c in to {
            if ctx.shared.members(c).get(&s).is_none_or(|m| m.until.is_some()) {
                continue;
            }
            let ev = Event::Added { blob_id: b, blob: Some(bytes.clone()), wrap, stamp };
            ctx.wire.push(c, Msg::Stream(Box::new(Stream { events: vec![(s, ev)], cursor: None, report: false, seq: 0 })));
        }
    }
}
