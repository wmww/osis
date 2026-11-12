//! Time and catching up: periodic re-syncs, the next wake, starting a Sync, running the passes
//! marked.

use super::*;

impl SyncEngine {
    /// Whether a pass is due (`passes`).
    pub(crate) fn passes_due(&self) -> bool {
        self.pass_due || !self.due_labels.is_empty() || !self.fill_due.is_empty()
    }

    /// Runs the passes when one is due.
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
        if self.passes_due() {
            self.passes(out)?;
        }
        Ok(())
    }

    /// Session pings, periodic re-syncs and retries.
    pub(super) fn timers(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let now = self.now();
        // the clock went back: resyncs count from now, not from a time still ahead
        self.passed_at = self.passed_at.min(now);
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
        // a pass when something waits for it (`Work::resync_due`: what a pass left, a timed
        // bound), or a fill under way; the streams bring what peers get
        let filling = self.conns.values().any(|c| c.labels.values().any(|l| l.fill.is_some()));
        if self.passing && self.passed_at.saturating_add(self.cfg.resync_ms) <= now && (self.work.is_empty() || filling || self.work.values().any(|w| w.resync_due(now))) {
            self.pass_due = true;
            // a fill under way passes at each resync (`passes`)
            let filling: Vec<LabelId> = self.conns.values().flat_map(|c| c.labels.iter().filter(|(_, x)| x.fill.is_some()).map(|(l, _)| *l)).collect();
            self.fill_due.extend(filling);
        }
        Ok(())
    }

    /// When the next Tick is wanted (wall ms): session timers, one tick per `resync_ms` while
    /// anything is open (a label's own resync only when something waits for it), served sessions'
    /// idle ends, redials, inbox retries and the engine's retention (expiry, purge floor) and
    /// lost-access timers. Never before `MIN_WAKE_MS` after the last Tick, so an item due but not
    /// serviceable yet cannot spin (and later events do not push a due wake back).
    pub(super) fn next_wake(&mut self) -> Option<u64> {
        let now = self.now();
        let mut t: Option<u64> = None;
        let mut at = |x: u64| t = Some(t.map_or(x, |y: u64| y.min(x)));
        let resync = self.cfg.resync_ms;
        if self.passing || self.conns.values().any(|c| !c.labels.is_empty()) {
            at(self.last_tick.saturating_add(resync));
        }
        for c in self.conns.values() {
            if let Some(x) = c.timer {
                at(x);
            }
            for l in c.labels.values() {
                // a label waiting for a reply re-syncs after it; a quiet one needs no time of its
                // own, what comes due for it waits for the next tick
                if (l.phase == Phase::Open && l.fill.is_some()) || l.phase == Phase::Failed {
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
        // a pending grant keeping a leaver's actor ages out (`drop_left`)
        if let Some(x) = self.left.as_ref().and_then(|l| l.recheck_at()) {
            at(x);
        }
        // a pending grant keeping a lost actor ages out (`drop_lost_due`)
        if let Some(x) = self.engine.next_lost_due() {
            at(x);
        }
        // an unsent delivery (`at` 0) waits on placement, which wakes by its own events and bound
        if let Some(x) = self.state.sent_inbox.values().filter(|s| s.at != 0).map(|s| s.at.saturating_add(osis_base::format::INBOX_LIFETIME_MS)).min() {
            at(x);
        }
        // a due inbox blob goes once its host's connection is ready (an event of its own)
        for o in self.outbox.values().filter(|o| o.sent.is_none() && o.after > now) {
            at(o.after);
        }
        if let Ok(Some(x)) = self.engine.next_timer() {
            at(x);
        }
        if let Ok(Some(x)) = self.engine.next_link_expiry() {
            at(x);
        }
        if let Some((x, _, _)) = self.state.by_expiry.first() {
            at(*x);
        }
        t.map(|x| x.max(self.last_tick.saturating_add(MIN_WAKE_MS)))
    }

    /// Catches up at the caller's word (an app's refresh, at any rate): every open label judges
    /// again (the streams bring what their sources get, so nothing is asked). A connection
    /// quiet for `retry_ms` gets a ping: after a network change it may be dead with nothing in flight
    /// to find out by (the stall timeout), and a live label would hear nothing.
    pub fn refresh(&mut self) -> Vec<Action> {
        let mut out = Vec::new();
        let (now, quiet) = (self.now(), self.cfg.retry_ms);
        let conns: Vec<ConnId> = self.conns.keys().copied().collect();
        for conn in conns {
            let Some(c) = self.conns.get_mut(&conn) else { continue };
            let o = c.session.ping_if_quiet(now, quiet);
            if let Err(e) = self.outputs(conn, o, &mut out) {
                self.diag(format!("sync: {e}"));
            }
        }
        self.pass_due = true;
        out.extend(self.handle(Event::Local));
        out
    }

    /// Asks every stream (readers' and those of peers that cannot read L): when this returns' replies are in, this node has
    /// heard all its sources had (`wait_synced`, a demotion's pre-sync).
    pub fn sync_now(&mut self) -> Vec<Action> {
        let mut out = Vec::new();
        if let Err(e) = self.stream_ask_all(&mut out) {
            self.diag(format!("sync: {e}"));
        }
        let _ = self.state.flush(&mut self.engine);
        out
    }

}
