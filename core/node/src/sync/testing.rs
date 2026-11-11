//! Test hooks: `#[doc(hidden)] pub` because osis-node's and osis's tests call them.

use super::SyncEngine;
use crate::Event;
use osis_engine::Result;
use std::sync::Arc;

impl SyncEngine {
    /// Tests only: an exact copy of this sync engine as it stands, on `clock` (the copy's node's
    /// wall clock), sharing no mutable state with it (notes/testing.md, Copied worlds): its
    /// engine (`Engine::test_copy`), connections, work sets, caches and memos, its rng going on
    /// with the same stream. It goes on exactly as this one would given the same inputs. Its
    /// engine-event receiver holds the events this one's had not read (`&mut`: this one's is
    /// replaced by one holding them too). Never in a product: the copy is the same node twice,
    /// one identity, session and rng stream, so the two would reuse nonces, counters and
    /// commit IDs. Inside a world copy (`osis_base::copying`) with the nodes beside it.
    #[doc(hidden)]
    #[allow(clippy::clone_on_copy)]
    pub fn test_copy(&mut self, clock: Arc<dyn osis_base::Clock>) -> Result<SyncEngine> {
        osis_base::copying::copying(|| {
            let mut engine = self.engine.test_copy(clock)?;
            let pending: Vec<Event> = self.events.try_iter().collect();
            self.events = self.engine.test_subscribe_with(pending.clone(), true);
            let events = engine.test_subscribe_with(pending, true);
            // the engine's copy shares this copy of the store (`osis_store::test_copy_shared`)
            let hub_store = osis_store::test_copy_shared(&self.hub_store, engine.clock())?;
            Ok(SyncEngine {
                hub_store,
                engine,
                forget_seeded: self.forget_seeded.clone(),
                pending_seeded: self.pending_seeded.clone(),
                unvouched_reported: self.unvouched_reported.clone(),
                events,
                rng: self.rng.test_copy(),
                cfg: self.cfg.clone(),
                conns: self.conns.clone(),
                next_conn: self.next_conn.clone(),
                retry: self.retry.clone(),
                redialed: self.redialed.clone(),
                stand_in: self.stand_in.clone(),
                redeeming: self.redeeming.clone(),
                state: self.state.clone(),
                seq: self.seq.clone(),
                passes: self.passes.clone(),
                wake: self.wake.clone(),
                last_synced: self.last_synced.clone(),
                last_tick: self.last_tick.clone(),
                diagnostics: self.diagnostics.clone(),
                outbox: self.outbox.clone(),
                deposit_room: self.deposit_room.clone(),
                local_inbox: self.local_inbox.clone(),
                tree_wants: self.tree_wants.clone(),
                body_links: self.body_links.clone(),
                inbox_opened: self.inbox_opened.clone(),
                vetted: self.vetted.clone(),
                hint_failed: self.hint_failed.clone(),
                inbox_copied: self.inbox_copied.clone(),
                inbox_moved: self.inbox_moved.clone(),
                secrets_counted: self.secrets_counted.clone(),
                reading_counted: self.reading_counted.clone(),
                unsettled_memo: self.unsettled_memo.clone(),
                relink_backoff: self.relink_backoff.clone(),
                relink_pending: self.relink_pending.clone(),
                relink_at: self.relink_at.clone(),
                retired_at: self.retired_at.clone(),
                deferred: self.deferred.clone(),
                genuine: self.genuine.clone(),
                reread_boxes: self.reread_boxes.clone(),
                start_look: self.start_look.clone(),
                redelivered: self.redelivered.clone(),
                awaits_secrets: self.awaits_secrets.clone(),
                retry_inbox: self.retry_inbox.clone(),
                inbox_awaits: self.inbox_awaits.clone(),
                inbox_plain: self.inbox_plain.clone(),
                unchecked_swept: self.unchecked_swept.clone(),
                settle_at: self.settle_at.clone(),
                local_dirty: self.local_dirty.clone(),
                local_last: self.local_last.clone(),
                local_any: self.local_any.clone(),
                local_expiry: self.local_expiry.clone(),
                local_work: self.local_work.clone(),
                deposit_seen: self.deposit_seen.clone(),
                capped: self.capped.clone(),
                stranded_sent: self.stranded_sent.clone(),
                stranded_on: self.stranded_on.clone(),
                stranded_asks: self.stranded_asks.clone(),
                resealed: self.resealed.clone(),
                suspects_sent: self.suspects_sent.clone(),
                suspects_gen: self.suspects_gen.clone(),
                suspects_due: self.suspects_due.clone(),
                repair_state: self.repair_state.clone(),
                links_failed: self.links_failed.clone(),
                joined_touched: self.joined_touched.clone(),
                joined_failed: self.joined_failed.clone(),
                tied: self.tied.clone(),
                first: self.first.clone(),
                left: self.left.clone(),
                unsubscribe: self.unsubscribe.clone(),
                synced: self.synced.clone(),
                synced_of: self.synced_of.clone(),
                wall: self.wall.clone(),
                covered_judged: self.covered_judged.clone(),
                stats: self.stats.clone(),
                records: self.records.clone(),
                streams: self.streams.clone(),
                changed_due: self.changed_due.clone(),
                changed_gen: self.changed_gen.clone(),
                changed_moved: self.changed_moved.clone(),
                touched: self.touched.clone(),
                served: self.served.clone(),
                hub_conns: self.hub_conns.clone(),
                lan: self.lan.clone(),
                lan_rotate: self.lan_rotate.clone(),
                reach_account: self.reach_account.clone(),
                served_cache: self.served_cache.clone(),
                unread: self.unread.clone(),
                charges: self.charges.clone(),
                own_keys: self.own_keys.clone(),
                blob_sizes: self.blob_sizes.clone(),
                swept: self.swept.clone(),
                peer_cache: self.peer_cache.clone(),
                peer_received: self.peer_received.clone(),
                peer_passes: self.peer_passes.clone(),
                sources_gen: self.sources_gen.clone(),
                shared_dirty: self.shared_dirty.clone(),
                role_change: self.role_change.clone(),
                pass_wanted: self.pass_wanted.clone(),
                started: self.started.clone(),
                rotation_at: self.rotation_at.clone(),
                placed_cache: self.placed_cache.clone(),
                placed_waiting: self.placed_waiting.clone(),
                rotated: self.rotated.clone(),
                keeps: self.keeps.clone(),
                clients_moved: self.clients_moved.clone(),
                prefix_checked: self.prefix_checked.clone(),
                memory: self.memory.clone(),
                refusals: self.refusals.clone(),
                hosting: self.hosting.clone(),
            })
        })
    }
}
