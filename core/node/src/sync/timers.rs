//! Time and catching up: periodic re-syncs, the next wake, starting a Sync, running the passes
//! marked.

use super::*;

impl SyncEngine {
    /// The open, synced labels marked dirty that may pass now.
    pub(super) fn dirty_labels(&self) -> Vec<(ConnId, LabelId)> {
        let todo: Vec<(ConnId, LabelId)> = self
            .conns
            .iter()
            .flat_map(|(id, c)| c.labels.iter().filter(|(_, l)| l.dirty && l.phase == Phase::Open && l.ready()).map(move |(lid, _)| (*id, *lid)))
            .collect();
        // no pass before a fill has what judging needs, on any connection: it would ask what it
        // lacks at once, out of the fill's order (`read_first`)
        todo.into_iter().filter(|(_, l)| !self.fill_first_waits(l)).collect()
    }

    /// Runs passes for open, synced labels marked dirty.
    pub(super) fn run_dirty(&mut self, out: &mut Vec<Action>) -> Result<()> {
        self.vet_inbox_hints()?;
        self.add_new_labels(out)?;
        // a hint is done once the thing's `label.0` names the label
        let hints: Vec<(LabelId, Tid)> = self.state.hints.iter().map(|(l, h)| (*l, h.thing)).collect();
        for (l, t) in hints {
            if self.engine.labels_of(&t).iter().any(|x| x.id == l) {
                self.state.remove_hint(&l);
            }
        }
        self.end_idle_links();
        for (conn, label) in self.dirty_labels() {
            if let Some(l) = self.lc_mut(conn, &label) {
                l.dirty = false;
            }
            self.pass(conn, label, out)?;
        }
        if self.local_dirty {
            self.local_passes()?;
        }
        Ok(())
    }

    /// Session pings, periodic re-syncs and retries.
    pub(super) fn timers(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let (now, corrected) = (self.raw_now(), self.now());
        // the clock went back: resyncs count from now, not from a time still ahead
        self.local_last = self.local_last.min(now);
        for l in self.conns.values_mut().flat_map(|c| c.labels.values_mut()) {
            l.last_sync = l.last_sync.min(now);
        }
        // what waited for a time (a copy left to its author, a relay wait, a step's back-off)
        let later = self.settle_at.split_off(&now.saturating_add(1));
        let due: BTreeSet<LabelId> = std::mem::replace(&mut self.settle_at, later).into_values().flatten().collect();
        if !due.is_empty() {
            self.mark_labels(&due);
            // a fill waiting on a batch looks again: it may have gone stale (`fill_more`)
            let fills: Vec<(ConnId, LabelId)> = self.conns.iter().flat_map(|(id, c)| due.iter().filter(|l| c.labels.get(l).is_some_and(|x| x.fill.is_some())).map(move |l| (*id, *l))).collect();
            for (conn, l) in fills {
                self.fill_more(conn, l, out)?;
            }
        }
        let due: Vec<ConnId> = self.conns.iter().filter(|(_, c)| c.timer.is_some_and(|t| t <= now)).map(|(id, _)| *id).collect();
        for conn in due {
            if let Some(c) = self.conns.get_mut(&conn) {
                c.timer = None;
                let o = c.session.handle(now, ClientInput::Timer);
                self.outputs(conn, o, out)?;
            }
        }
        self.stream_retry(out)?;
        self.shared_retry(out)?;
        let resync: Vec<(ConnId, LabelId)> = self
            .conns
            .iter()
            .flat_map(|(id, c)| {
                c.labels.iter().filter(|(_, l)| l.phase == Phase::Open && !l.syncing && l.last_sync.saturating_add(self.cfg.resync_ms) <= now).map(move |(lid, _)| (*id, *lid))
            })
            .collect();
        // labels no key opened, and registrations refused for now once their back-off passed: try
        // again from scratch
        let again = |l: &LConn| match l.phase {
            Phase::Failed => l.last_sync.saturating_add(self.cfg.resync_ms) <= now,
            Phase::Refused { retry_at } => retry_at <= now,
            _ => false,
        };
        let reopen: Vec<(ConnId, LabelId, Tid)> = self.conns.iter().flat_map(|(id, c)| c.labels.iter().filter(|(_, l)| again(l)).map(move |(lid, l)| (*id, *lid, l.group))).collect();
        for (conn, label, g) in reopen {
            if let Some(c) = self.conns.get_mut(&conn) {
                c.req.reopens.remove(&label);
            }
            // every thing a hint names this label under gets a new turn; not at a refusal's
            // retry (its back-off is short, and a host named by a sender could cut every round)
            if self.lc(conn, &label).is_some_and(|x| x.phase == Phase::Failed) {
                let hints = self.hint_failed.len();
                self.hint_failed.retain(|x| x.0 != label);
                if self.hint_failed.len() != hints {
                    self.vetted = None;
                }
            }
            self.start_label(conn, g, label, out)?;
        }
        if self.local_any && self.local_last.saturating_add(self.cfg.resync_ms) <= now && (self.local_work.is_empty() || self.local_work.values().any(|w| w.resync_due(corrected))) {
            self.local_dirty = true;
        }
        for (conn, label) in resync {
            if self.needs_sync(conn, &label) {
                self.sync_label(conn, label, out)?;
                continue;
            }
            // an upload the host refused for the label's cap goes again once per resync while the
            // body is held (spec/sync.md §9: room appears there without a word to anyone)
            let capped = self.conns.get(&conn).is_some_and(|c| self.capped.range((c.host, label, osis_base::BlobId([0; 32]))..=(c.host, label, osis_base::BlobId([0xff; 32]))).next().is_some());
            if let Some(l) = self.lc_mut(conn, &label) {
                // subscribed: a pass when something waits for it (`Work::resync_due`: what a pass
                // left, a timed bound); unsubscribed, the Sync's end uploads those
                l.last_sync = now;
                l.dirty |= l.fill.is_some() || l.work.resync_due(corrected) || capped;
            }
        }
        Ok(())
    }

    /// When the next Tick is wanted (raw wall ms): session timers, one tick per `resync_ms` while
    /// anything is open (a label's own resync only when something waits for it), served sessions'
    /// idle ends, redials, inbox retries and the engine's retention (expiry, purge floor) and
    /// lost-access timers. Never before `MIN_WAKE_MS` after the last Tick, so an item due but not
    /// serviceable yet cannot spin (and later events do not push a due wake back).
    pub(super) fn next_wake(&mut self) -> Option<u64> {
        let now = self.raw_now();
        let mut t: Option<u64> = None;
        let mut at = |x: u64| t = Some(t.map_or(x, |y: u64| y.min(x)));
        let resync = self.cfg.resync_ms;
        if self.local_any || self.conns.values().any(|c| !c.labels.is_empty()) {
            at(self.last_tick.saturating_add(resync));
        }
        for c in self.conns.values() {
            if let Some(x) = c.timer {
                at(x);
            }
            for l in c.labels.values() {
                // a label waiting for a reply re-syncs after it; a quiet one needs no time of its
                // own, what comes due for it waits for the next tick
                if (l.phase == Phase::Open && !l.syncing && (!l.synced || !self.cfg.subscribe || l.fill.is_some() || !l.work.quiet())) || l.phase == Phase::Failed {
                    at(l.last_sync.saturating_add(resync));
                }
                if let Phase::Refused { retry_at } = l.phase {
                    at(retry_at);
                }
            }
        }
        if let Some(x) = self.serve_wake() {
            at(x);
        }
        if let Some(x) = self.stream_wake().into_iter().chain(self.shared_wake()).min() {
            at(x);
        }
        for (_, x) in self.retry.values() {
            at(*x);
        }
        if let Some(x) = self.settle_at.keys().next() {
            at(*x);
        }
        let skew = self.now() as i64 - now as i64;
        // a corrected time as a raw one
        let raw = |x: u64| (x as i64).saturating_sub(skew).max(0) as u64;
        // a pending grant keeping a leaver's actor ages out (`drop_left`)
        if let Some(x) = self.left.as_ref().and_then(|l| l.recheck_at()) {
            at(raw(x));
        }
        // a pending grant keeping a lost actor ages out (`drop_lost_due`)
        if let Some(x) = self.engine.next_lost_due() {
            at(raw(x));
        }
        // an unsent delivery (`at` 0) waits on placement, which wakes by its own events and bound
        if let Some(x) = self.state.sent_inbox.values().filter(|s| s.at != 0).map(|s| s.at.saturating_add(osis_base::format::INBOX_LIFETIME_MS)).min() {
            at(raw(x));
        }
        // a due inbox blob goes once its host's connection is ready (an event of its own)
        for o in self.outbox.values().filter(|o| o.sent.is_none() && o.after > now) {
            at(o.after);
        }
        if let Ok(Some(x)) = self.engine.next_timer() {
            at(raw(x));
        }
        if let Ok(Some(x)) = self.engine.next_link_expiry() {
            at(raw(x));
        }
        t.map(|x| x.max(self.last_tick.saturating_add(MIN_WAKE_MS)))
    }

    /// Whether open label `label` on `conn` needs a Sync to catch up: without a subscription, not
    /// synced since it opened, or not reconciled since this node started or a memory snapshot
    /// fell invalid (`memory`). Otherwise pushes bring what the host gets.
    pub(super) fn needs_sync(&self, conn: ConnId, label: &LabelId) -> bool {
        let Some(c) = self.conns.get(&conn) else { return false };
        let Some(l) = c.labels.get(label) else { return false };
        let unreconciled = !self.memory.reconciled.contains(&(c.host, *label)) && self.state.cursors.contains_key(&(c.host, *label));
        !self.cfg.subscribe || unreconciled || !l.synced
    }

    /// Catches up at the caller's word (an app's refresh, at any rate): a label that needs it syncs,
    /// a live one only judges again: a Sync of every label costs a round trip per two (each may
    /// answer `MAX_MESSAGE`, `osis_proto::client::WINDOW`) and shows `Syncing`. A connection
    /// quiet for `retry_ms` gets a ping: after a network change it may be dead with nothing in flight
    /// to find out by (the stall timeout), and a live label would hear nothing.
    pub fn refresh(&mut self) -> Vec<Action> {
        let mut out = Vec::new();
        let (now, quiet) = (self.raw_now(), self.cfg.retry_ms);
        let conns: Vec<ConnId> = self.conns.keys().copied().collect();
        for conn in conns {
            let Some(c) = self.conns.get_mut(&conn) else { continue };
            let o = c.session.ping_if_quiet(now, quiet);
            if let Err(e) = self.outputs(conn, o, &mut out) {
                self.diag(format!("sync: {e}"));
            }
        }
        let open: Vec<(ConnId, LabelId)> = self.conns.iter().flat_map(|(id, c)| c.labels.iter().filter(|(_, l)| l.phase == Phase::Open && !l.syncing).map(move |(lid, _)| (*id, *lid))).collect();
        for (conn, label) in open {
            if self.needs_sync(conn, &label) {
                if let Err(e) = self.sync_label(conn, label, &mut out) {
                    self.diag(format!("sync: {e}"));
                }
            } else if let Some(l) = self.lc_mut(conn, &label) {
                l.dirty = true;
            }
        }
        out.extend(self.handle(Event::Local));
        out
    }

    /// Syncs every open label at every connection now, live or not, and asks every reader's
    /// stream: when this returns' replies are in, this node has heard all its sources had
    /// (`wait_synced`, a demotion's pre-sync).
    pub fn sync_now(&mut self) -> Vec<Action> {
        let mut out = Vec::new();
        if let Err(e) = self.stream_ask_all(&mut out) {
            self.diag(format!("sync: {e}"));
        }
        let todo: Vec<(ConnId, LabelId)> = self.conns.iter().flat_map(|(id, c)| c.labels.iter().filter(|(_, l)| l.phase == Phase::Open && !l.syncing).map(move |(lid, _)| (*id, *lid))).collect();
        for (conn, label) in todo {
            if let Err(e) = self.sync_label(conn, label, &mut out) {
                self.diag(format!("sync: {e}"));
            }
        }
        let _ = self.state.flush(&mut self.engine);
        out
    }

    /// Starts a cursor sync of an open label.
    pub(crate) fn sync_label(&mut self, conn: ConnId, label: LabelId, out: &mut Vec<Action>) -> Result<()> {
        let now = self.raw_now();
        let Some(c) = self.conns.get_mut(&conn) else { return Ok(()) };
        let host = c.host;
        let Some(l) = c.labels.get_mut(&label) else { return Ok(()) };
        // a fill past its listing goes on, its end brings what came meanwhile; a pass now and then
        if l.fill.as_ref().is_some_and(|f| f.listed()) {
            l.dirty = true;
            l.last_sync = now;
            return self.fill_more(conn, label, out);
        }
        l.fill = None;
        l.syncing = true;
        l.last_sync = now;
        let cursor = self.state.cursors.get(&(host, label)).copied();
        // the first sync of a label at a host since start reconciles the live sets first: the
        // memory entries a cursor already passed are in no memory here after a start
        // (spec/sync.md §9); the cursor stays for what follows (a replay from no cursor lists
        // everything: nothing to reconcile after it). Marked reconciled when the reply arrives
        // (`reconciled`): a connection ending first reconciles again on the next one
        if cursor.is_none() {
            self.memory.reconciled.insert((host, label));
        }
        if cursor.is_some() && !self.memory.reconciled.contains(&(host, label)) {
            if self.memory.reconciling.contains(&(conn, label)) {
                return Ok(());
            }
            let ids = self.state.present_at(&host, &label);
            self.memory.reconciling.insert((conn, label));
            return self.command(conn, Command::Reconcile { label, ids }, out);
        }
        // a replay lists the live entries only: presence starts over from it (a cursor lost in a
        // crash otherwise kept entries a wiped host no longer holds "present" for good)
        if cursor.is_none() {
            for b in self.state.present_at(&host, &label) {
                self.state.set_present(host, label, b, false);
            }
        }
        // a first sync lists, then fetches in the wraps' order (`fill`)
        let inline_limit = if cursor.is_none() || self.state.filling.contains(&(host, label)) {
            self.fill_start(conn, label);
            0
        } else {
            self.cfg.inline_limit
        };
        // the memory entries held, listed once per connection: the host asks for those it
        // lacks (presence of a memory entry is per connection, spec/sync.md §9)
        let gained = self.memory_gained(conn, label);
        self.command(conn, Command::Sync { label, cursor, inline_limit, entries: Vec::new(), gained }, out)
    }
}
