//! Heartbeats, what they report (spec/permissions.md §4; spec/sync.md §7), and the re-seals and
//! repairs they lead to.

use super::*;

impl SyncEngine {
    /// Repair (spec/sync.md §7): for each aspect another node's newest heartbeat under the label
    /// reports suspect (`Work::beats`), of a thing in the label this node may write, whose
    /// state digest here differs from the reported one: a snapshot of it from this node's whole
    /// state, an ordinary compaction snapshot (it joins with the others', never resurrects
    /// expired or purged values). Once per reported entry (heartbeat commit, aspect): each node
    /// beats at most once per `HEARTBEAT_MIN_INTERVAL` per label; and once per state per node
    /// reporting (`repair_state`). Every entry acted on is a
    /// diagnostic, so silent repairs hide nothing.
    pub(super) fn repair_suspects(&mut self, w: &mut Work) -> Result<()> {
        let seen_ak = Ak::new("seen.0").map_err(|_| crate::Error::Misuse("ak"))?;
        for node in std::mem::take(&mut w.beats_repair) {
            let Some(c) = w.beats.get(&node).and_then(|s| s.iter().next_back()).map(|x| x.1) else { continue };
            let _s = crate::costs::span("heartbeat: read");
            let Some(v) = self.engine.part_value(&c, &node, &seen_ak)? else { continue };
            let Ok(seen) = <ct::Seen as osis_schema::Codec>::from_value(&v) else { continue };
            // read again: the closure may yet grow to a suspect's thing
            if !seen.suspect.is_empty() {
                w.beats_repair.insert(node);
            }
            for s in seen.suspect {
                let Ok(ak) = Ak::new(&s.ak) else { continue };
                if !w.closure.contains(&s.thing) || ct::is_role_class(ak.as_str()) || ak.as_str() == "created.0" || !self.repaired.insert((c, s.thing, ak.clone())) {
                    continue;
                }
                if self.engine.role_on(&s.thing) < Some(Role::Write) {
                    continue;
                }
                let mine = self.engine.state_digest(&s.thing, &ak)?;
                if mine.is_none() || mine == Some(s.digest) {
                    self.repair_diag(node, s.thing, None, format!("suspect {} {} reported by {node}: same state here", s.thing, s.ak));
                    continue;
                }
                // a report no snapshot can settle: another from this same state repairs nothing more
                // for this node; another node may have dropped that snapshot before its own flip
                if self.repair_state.get(&(node, s.thing, ak.clone())) == mine.as_ref() {
                    self.repair_diag(node, s.thing, None, format!("suspect {} {} reported by {node}: already snapshotted from this state", s.thing, s.ak));
                    continue;
                }
                match self.engine.snapshot(&s.thing, &ak) {
                    // holding no state, this writer has nothing to snapshot
                    Ok(None) => self.repair_diag(node, s.thing, None, format!("suspect {} {} reported by {node}: no state here", s.thing, s.ak)),
                    Ok(snap) => {
                        if let Some(d) = self.engine.state_digest(&s.thing, &ak)? {
                            self.repair_state.insert((node, s.thing, ak.clone()), d);
                        }
                        self.repair_diag(node, s.thing, snap, format!("suspect {} {} reported by {node}: re-snapshotted", s.thing, s.ak));
                    }
                    Err(e) => self.diag(format!("repair of {} {}: {e}", s.thing, s.ak)),
                }
            }
        }
        Ok(())
    }

    pub(super) fn repair_diag(&mut self, node: Tid, thing: Tid, commit: Option<CommitId>, detail: String) {
        let now = self.engine.now();
        self.engine.core.events.diagnostic(crate::events::Diagnostic { kind: crate::events::DiagnosticKind::Repair, tids: vec![node, thing], commit, peer: Some(node), detail }, now);
    }

    /// Re-seals decided at the end of a complete pass of the actor's labels (spec/permissions.md
    /// §3): holders seen without a box at a current epoch (`Engine::reseal_due`) and holders
    /// whose node's heartbeat under the label reports it stranded (§4); delivered by inbox and
    /// placed under the actor's labels like any role commit.
    pub(super) fn reseal(&mut self, g: &Tid, l: LabelId, w: &mut Work) -> Result<()> {
        let Some(a) = self.engine.core.secret_actor(g) else { return Ok(()) };
        if self.engine.core.is_key_actor(&a) {
            return Ok(());
        }
        if !self.complete_pass(&a) {
            // the wait for peers ending may be all it lacks
            if !self.peers_waited(&a) {
                self.settle_by(self.peer_wait_end(&a), l);
            }
            return Ok(());
        }
        // the complete pass was checked just above
        struct Passed;
        impl crate::flows::SyncState for Passed {
            fn complete_pass(&self, _: &Tid) -> bool {
                true
            }
        }
        // plain things under `a` with holders: secrets of their own again
        for (t, r) in self.engine.own_secrets_due(&a, &Passed)? {
            match r {
                Ok(done) => self.take_done(done)?,
                Err(e) => self.diag(format!("secrets of its own for {t}: {e}")),
            }
        }
        // the newest heartbeat of each node under the label, when it reports it stranded
        // (`Work::beats`); before the boxes `reseal_due` adds, which would box a stranded holder
        // lacking one twice
        for node in std::mem::take(&mut w.beats_reseal) {
            let Some(c) = w.beats.get(&node).and_then(|s| s.iter().next_back()).map(|x| x.1) else { continue };
            if self.resealed.contains(&c) || !self.engine.get_typed(&node, &ct::SEEN)?.is_some_and(|s| s.stranded) {
                continue;
            }
            self.resealed.insert(c);
            // the holder of the actor the node reads through: itself or up its record chain
            let holders: BTreeSet<Tid> = self.engine.core.current_holders(&a).into_iter().map(|x| x.0).collect();
            // a node that may not re-seal that holder leaves it to one that may
            let holder = self.engine.record_chain(&node).find(|t| holders.contains(t));
            if let Some(t) = holder
                && let Ok(done) = self.engine.reshare(&a, &t)
            {
                self.take_done(done)?;
            }
        }
        match self.engine.reseal_due(&a, &Passed) {
            Ok(done) => self.take_done(done)?,
            Err(e) => self.diag(format!("re-seal of {a}: {e}")),
        }
        Ok(())
    }

    /// A heartbeat under `l` at most once per `HEARTBEAT_MIN_INTERVAL` (spec/permissions.md §4),
    /// skipped by deposit when the budget is tight.
    pub(super) fn heartbeat(&mut self, g: &Tid, l: LabelId, keys: &HeadKeys, tight: bool, closure: &BTreeSet<Tid>) -> Result<()> {
        if !self.cfg.heartbeats {
            return Ok(());
        }
        let now = self.now();
        if self.state.beats.get(&l).is_some_and(|t| t.saturating_add(HEARTBEAT_MIN_INTERVAL_MS) > now) {
            return Ok(());
        }
        if !keys.is_writer() && tight {
            return Ok(());
        }
        let suspect = self.suspects_under(closure)?;
        let Some(c) = self.heartbeat_commit(false, suspect)? else { return Ok(()) };
        let ais = BTreeSet::from([0usize]);
        let mut placed = false;
        if let Some(b) = self.engine.part_body(&c, &ais)? {
            placed |= self.place(g, l, &b, true)?.is_some();
        }
        if placed {
            self.state.set_beat(l, now);
        }
        Ok(())
    }

    /// The aspects of things in a label's `closure` this node flags suspect, with their keyed
    /// state digests (spec/permissions.md §4): the most recently flagged first, at most
    /// `MAX_HEARTBEAT_SUSPECTS`; an aspect with no digest here (no creation record) waits until
    /// it has one. Only the label's things: its readers learn nothing of others.
    pub(super) fn suspects_under(&mut self, closure: &BTreeSet<Tid>) -> Result<BTreeSet<ct::Suspect>> {
        let mut flagged: Vec<(Tid, Ak, u64, u8)> = self.engine.suspects()?.into_iter().filter(|x| closure.contains(&x.0)).collect();
        flagged.sort_by_key(|x| std::cmp::Reverse(x.2));
        let mut out = BTreeSet::new();
        for (tid, ak, _, _) in flagged {
            if out.len() >= osis_base::format::MAX_HEARTBEAT_SUSPECTS {
                break;
            }
            if let Some(digest) = self.engine.state_digest(&tid, &ak)? {
                out.insert(ct::Suspect { thing: tid, ak: ak.as_str().to_string(), digest });
            }
        }
        Ok(out)
    }

    /// A `seen.0` commit on this node reporting `suspect` (spec/permissions.md §4): reused
    /// within the interval, whatever it reports (at most one heartbeat per interval; a flag
    /// raised since waits for the next).
    pub(crate) fn heartbeat_commit(&mut self, stranded: bool, suspect: BTreeSet<ct::Suspect>) -> Result<Option<CommitId>> {
        let me = self.engine.tid();
        let now = self.now();
        if !stranded
            // its own newest: anyone's header may list this node's `seen.0`
            && let Some(c) = self.engine.latest_by(&me, "seen.0", Some(&me))
            && let Some(h) = self.engine.header(&c)
            && h.ts.wall_ms().0.saturating_add(HEARTBEAT_MIN_INTERVAL_MS) > now
            && self.engine.get_typed(&me, &ct::SEEN).ok().flatten().is_some_and(|s| !s.stranded)
        {
            return Ok(Some(c));
        }
        // `ts` of the commit: the HLC's next wall time (spec/permissions.md §4)
        let ts = now.max(self.engine.core.hlc.last().wall_ms().0);
        let life = self.cfg.heartbeat_lifetime_ms.clamp(osis_base::format::HEARTBEAT_MIN_LIFETIME_MS, osis_base::format::HEARTBEAT_MAX_LIFETIME_MS);
        let mut m = crate::Mutation::new();
        // whole: a field left to an earlier heartbeat would go when that one expires (spec/crdt.md §9)
        m.replace(me, &ct::SEEN, &ct::Seen { ts: WallMs(ts), stranded, suspect })?;
        m.expires(me, &ct::SEEN, WallMs(ts.saturating_add(life)))?;
        self.engine.commit(m)
    }

    /// A stranded heartbeat (spec/permissions.md §4; spec/sync.md §5): the label cannot be read
    /// here; deposited, wrapped under the newest established read secret held, no open needed.
    /// Only under the deposit key of the host's head as this node knows it: a deposit seed that
    /// does not derive it (an actor whose `keys.0` has not arrived yet, a link's K seen as
    /// deriving from its first admin) is refused, so nothing is sent.
    pub(crate) fn stranded(&mut self, conn: ConnId, g: Tid, l: LabelId, out: &mut Vec<crate::sync::Action>) -> Result<()> {
        if self.state.stranded.get(&l).is_some_and(|t| t.saturating_add(HEARTBEAT_MIN_INTERVAL_MS) > self.now()) {
            return Ok(());
        }
        let Some(host) = self.conns.get(&conn).map(|c| c.host) else { return Ok(()) };
        let Some(head) = self.lc(conn, &l).and_then(|x| x.head.clone()).or_else(|| self.state.heads.get(&(host, l)).cloned()) else { return Ok(()) };
        let Some(seed) = self.engine.deposit_seed(&g)? else { return Ok(()) };
        let d = osis_crypto::deposit_key(&seed, &l);
        if d.verifying_key() != head.keys.deposit {
            return Ok(());
        }
        let Some(secret) = self.engine.stranded_secret(&g) else { return Ok(()) };
        let Some(c) = self.heartbeat_commit(true, BTreeSet::new())? else { return Ok(()) };
        if let Some(b) = self.engine.part_body(&c, &BTreeSet::from([0usize]))?
            && let Some(s) = self.engine.seal_to(&b, osis_label::Class::Durable, &secret, &mut *self.rng)?
        {
            let wrap = osis_crypto::wrap(&secret, &s.id, &s.key, b.order)?;
            let sig = osis_label::sign_deposit(&d, &l, &s.id, &wrap);
            self.command(conn, Command::Deposit { label: l, blob: s.blob, wrap, sig }, out)?;
        }
        let now = self.now();
        self.state.set_stranded(l, now);
        Ok(())
    }
}
