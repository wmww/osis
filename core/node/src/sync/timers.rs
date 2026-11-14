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
        // a hint is done once the thing syncs the label (its `label.0` names it and this node
        // syncs the thing): a `label.0` kept from an earlier hold (a link redeemed before, its
        // read access lost since) names it with nothing synced, and the hint's open goes on
        let synced: BTreeSet<(Tid, LabelId)> = self.labels().into_iter().map(|(t, l)| (t, l.id)).collect();
        let hints: Vec<(LabelId, Tid)> = self.state.hints.iter().map(|(l, h)| (*l, h.thing)).collect();
        for (l, t) in hints {
            if synced.contains(&(t, l)) {
                self.state.remove_hint(&l);
            }
        }
        self.end_idle_links();
        self.sources_moved();
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
        for d in self.conns.values_mut().filter_map(|c| c.dial.as_mut()) {
            d.since = d.since.min(now);
        }
        self.dials_timed_out(out);
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
        // dialed connections' pings (`PING_INTERVAL_MS`); none while one is unanswered: the
        // oldest request is what the stall clock times, and a peer that never answers would
        // otherwise gather one more every interval
        let due: Vec<ConnId> = self.conns.iter().filter(|(_, c)| c.is_ready() && c.dial.as_ref().is_some_and(|d| d.next_ping <= now)).map(|(id, _)| *id).collect();
        for conn in due {
            let Some(c) = self.conns.get_mut(&conn) else { continue };
            let pinging = c.pending.values().any(|p| matches!(p, conn::Pending::Ping { .. }));
            if let Some(d) = c.dial.as_mut() {
                d.next_ping = now.saturating_add(osis_proto::hello::PING_INTERVAL_MS);
            }
            if !pinging {
                self.ping(conn, out);
            }
        }
        self.stream_retry(out)?;
        self.shared_retry(out)?;
        // a label still waiting at a peer that cannot read it `resync_ms` after its walk is tested and
        // walked again: a refused Hit or an ended registration need not change the peer's filter
        let rewalk: Vec<ConnId> = self
            .conns
            .iter_mut()
            .filter_map(|(id, c)| {
                let due: Vec<LabelId> = c.labels.iter().filter(|(_, l)| l.phase.is_testing() && l.registering.is_none() && l.last_sync.saturating_add(self.cfg.resync_ms) <= now).map(|(l, _)| *l).collect();
                for l in &due {
                    c.req.walked.remove(l);
                }
                (!due.is_empty()).then_some(*id)
            })
            .collect();
        for conn in rewalk {
            self.shared_retest(conn, out)?;
        }
        // labels no key opened, and registrations refused for now once their back-off passed: try
        // again from scratch
        let again = |l: &LabelAt| match l.phase {
            Phase::Failed { .. } => l.last_sync.saturating_add(self.cfg.resync_ms) <= now,
            Phase::Refused { retry_at } => retry_at <= now,
            _ => false,
        };
        let reopen: Vec<(ConnId, LabelId, Tid)> = self.conns.iter().flat_map(|(id, c)| c.labels.iter().filter(|(_, l)| again(l)).map(move |(lid, l)| (*id, *lid, l.group))).collect();
        for (conn, label, g) in reopen {
            // every thing a hint names this label under gets a new turn; not at a refusal's
            // retry (its back-off is short, and a host named by a sender could cut every round)
            if self.label_at(conn, &label).is_some_and(|x| x.phase.is_failed()) {
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

    /// When the next Tick is wanted (wall ms): dialed connections' pings, one tick per `resync_ms` while
    /// anything is open (a label's own resync only when something waits for it), clients'
    /// `until`s, redials, inbox retries and the engine's retention (expiry, purge floor) and
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
            if let Some(d) = c.dial.as_ref().filter(|_| c.is_ready()) {
                at(d.next_ping);
            }
            // a dial not up closes at its bound (`dials_timed_out`)
            if let Some(d) = c.dial.as_ref().filter(|_| !c.up()) {
                at(d.since.saturating_add(conn::DIAL_TIMEOUT_MS));
            }
            for l in c.labels.values() {
                // a label not open re-tries after `resync_ms`; an open one needs no time of its
                // own (a fill's stalled batch wakes by `settle_by`), what comes due for it waits
                // for the next tick
                if l.phase.is_failed() || (l.phase.is_testing() && l.registering.is_none()) {
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
        for (_, x, _) in self.retry.values() {
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
    /// again (the streams bring what their sources get, so nothing is asked). A dialed connection
    /// with no request of this node's out and nothing sent or heard for `retry_ms` gets a ping:
    /// after a network change it may be dead with nothing in flight to find out by (the stall
    /// timeout), and a live label would hear nothing; polling a live one sends nothing.
    pub fn refresh(&mut self) -> Vec<Action> {
        let mut out = Vec::new();
        let (now, quiet) = (self.now(), self.cfg.retry_ms);
        let quiet: Vec<ConnId> = self.conns.iter().filter(|(_, c)| c.pending.is_empty() && c.heard.saturating_add(quiet) <= now).map(|(id, _)| *id).collect();
        for conn in quiet {
            self.ping(conn, &mut out);
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
