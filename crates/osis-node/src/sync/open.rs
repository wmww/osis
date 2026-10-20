//! Opening a label at a server (spec/sync.md §2, §5): the sync key of the head, else the newest
//! recorded step this node holds the key of; a superseded key or a claim answered with the next
//! step is a walk, each step verified under its parent's delete key; a server lacking the label
//! gets the recorded path registered; a refused claim places a stranded heartbeat. An opened head
//! not recorded in `/label` is checked against the server's path.

use super::{ConnId, LConn, Phase, SyncEngine};
use crate::error::Result;
use crate::labeling::{GroupLabel, HeadKeys};
use osis_core::{LabelId, Tid};
use osis_crypto::{LabelRole, SigningSecret, X25519Secret, label_role_key, role_kem};
use osis_label::{ClaimSet, Step, StepId};
use osis_proto::{Code, Command, OpenKey};
use osis_schema::core_types::SecretBox;
use osis_crdt::{Op, PathOp, PathSeg};
use osis_schema::Codec;
use std::collections::BTreeMap;

/// Reopens of one label on one connection before backing off to the retry timer.
const MAX_REOPENS: u32 = 3;

/// Hint labels: indexes tried for the sync key when only the label ID is known.
const HINT_INDEXES: u64 = 4;

/// An open attempt.
#[derive(Clone)]
pub(crate) enum Try {
    /// The sync key of a step (`step`: its ID when recorded).
    Sync { step: Option<Step>, index: u64, key: SigningSecret },
    /// A claim at a step.
    Claim { step: Step, key: SigningSecret },
    /// A key actor this node holds (a recovery or link key) by its static entry; the head's
    /// entry box gives the read secret (spec/sync.md §2, §5).
    Static { kem: osis_crypto::KemSecret, key: SigningSecret },
}

impl Try {
    fn open_key(&self) -> OpenKey {
        match self {
            Try::Sync { key, .. } => OpenKey::Sync(key.clone()),
            Try::Claim { step, key } => OpenKey::Claim { step: step.id(), key: key.clone() },
            Try::Static { key, .. } => OpenKey::Static(key.clone()),
        }
    }
    fn step(&self) -> Option<&Step> {
        match self {
            Try::Sync { step, .. } => step.as_ref(),
            Try::Claim { step, .. } => Some(step),
            Try::Static { .. } => None,
        }
    }
}

/// Depth of each step from the genesis step (unreachable steps: none).
fn depths(gl: &GroupLabel) -> BTreeMap<StepId, usize> {
    let mut d = BTreeMap::new();
    for id in gl.steps.keys() {
        let mut n = 0usize;
        let mut cur = Some(*id);
        while let Some(c) = cur {
            let Some((s, _)) = gl.steps.get(&c) else { break };
            n += 1;
            cur = s.prev;
            if n > gl.steps.len() {
                break;
            }
        }
        d.insert(*id, n);
    }
    d
}

impl SyncEngine {
    /// X25519 keys this node may be listed by in a claim set: its own, and the read-role KEM
    /// key of every held read epoch of the actors it holds secrets of (spec/sync.md §2).
    fn claim_keys(&self) -> Vec<X25519Secret> {
        let mut v = vec![self.engine.identity().keys().kem.x25519().clone()];
        for e in self.engine.core.secrets.values() {
            for (_, s) in e.read.held_newest_first() {
                v.push(role_kem(s).x25519().clone());
            }
        }
        v
    }

    /// The group label `l` as recorded, or a hint's.
    pub(crate) fn group_label(&mut self, g: &Tid, l: &LabelId) -> Option<GroupLabel> {
        self.engine.group_labels(g).ok()?.into_iter().find(|x| x.id == *l)
    }

    /// Open attempts in order: the known head, recorded steps deepest first by sync key, then
    /// by claim key; for a hint, guessed indexes.
    fn tries(&mut self, server: &[u8; 32], g: &Tid, l: &LabelId) -> (Option<u64>, Vec<Try>) {
        let epochs = self.engine.epochs(g);
        let held: Vec<osis_crypto::Secret32> = epochs.as_ref().map(|e| e.read.held_newest_first().into_iter().map(|(_, s)| s.clone()).collect()).unwrap_or_default();
        let sync_key = |step: &Step, index: u64| held.iter().map(|s| label_role_key(LabelRole::Sync, s, index)).find(|k| k.verifying_key() == step.keys.sync);
        let Some(gl) = self.group_label(g, l) else {
            let mut v = Vec::new();
            for index in 0..HINT_INDEXES {
                for s in &held {
                    v.push(Try::Sync { step: None, index, key: label_role_key(LabelRole::Sync, s, index) });
                }
            }
            v.extend(self.static_tries().into_iter().map(|(_, x)| x));
            return (None, v);
        };
        let index = gl.index;
        let mut v = Vec::new();
        if let Some(h) = self.state.heads.get(&(*server, *l)).cloned()
            && let Some(key) = sync_key(&h, index)
        {
            v.push(Try::Sync { step: Some(h), index, key });
        }
        let d = depths(&gl);
        let mut steps: Vec<(&Step, &Option<ClaimSet>)> = gl.steps.values().map(|(s, c)| (s, c)).collect();
        steps.sort_by_key(|(s, _)| std::cmp::Reverse(d.get(&s.id()).copied().unwrap_or(0)));
        for (s, _) in &steps {
            if let Some(key) = sync_key(s, index)
                && !v.iter().any(|t| matches!(t, Try::Sync { key: k, .. } if k.verifying_key() == key.verifying_key()))
            {
                v.push(Try::Sync { step: Some((*s).clone()), index, key });
            }
        }
        let xs = self.claim_keys();
        for (s, set) in &steps {
            for x in &xs {
                let Ok(key) = s.claim_key(x) else { continue };
                match set {
                    Some(set) if !set.contains(&key.verifying_key().to_bytes()) => {}
                    _ => v.push(Try::Claim { step: (*s).clone(), key }),
                }
            }
        }
        // a key actor's signing key goes only where it is listed: elsewhere it would link labels
        // and name the key to the server
        let members = self.engine.get_typed(g, &osis_schema::core_types::MEMBERS).ok().flatten().unwrap_or_default();
        v.extend(self.static_tries().into_iter().filter(|(t, _)| members.contains_key(t)).map(|(_, x)| x));
        (Some(index), v)
    }

    /// Static-entry opens for the key actors this node holds that are not nodes, by tid.
    fn static_tries(&self) -> Vec<(Tid, Try)> {
        self.engine.core.key_actors.iter().map(|(t, id)| (*t, Try::Static { kem: id.keys().kem.clone(), key: id.keys().signing.clone() })).collect()
    }

    /// Follows a label known only by ID and servers (a recovery card's home label, a link's
    /// label): opened by guessed index or by a held key actor's static entry.
    pub fn follow(&mut self, thing: Tid, label: LabelId, servers: Vec<osis_label::Address>) -> Vec<super::Action> {
        self.state.add_hint(label, super::state::Hint { thing, servers });
        self.handle(super::Event::Local)
    }

    pub(crate) fn start_label(&mut self, conn: ConnId, g: Tid, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return Ok(()) };
        let (index, tries) = self.tries(&server, &g, &l);
        let lc = LConn {
            group: g,
            index,
            phase: Phase::Opening,
            tries,
            tried_claim: false,
            head: None,
            keys: HeadKeys::default(),
            syncing: false,
            synced: false,
            dirty: false,
            registering: None,
            budget: None,
            last_sync: 0,
            path: Vec::new(),
            walk: None,
            entry_box: None,
            writers: Vec::new(),
        };
        if let Some(c) = self.conns.get_mut(&conn) {
            c.labels.insert(l, lc);
        }
        self.try_next(conn, l, out)
    }

    /// Sends the next open attempt; none left: failed (stranded after a refused claim).
    fn try_next(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) else { return Ok(()) };
        if lc.tries.is_empty() {
            lc.phase = Phase::Failed;
            lc.last_sync = self.clock.now_wall_ms().0;
            let (g, claimed) = (lc.group, lc.tried_claim);
            if claimed {
                self.stranded(conn, g, l, out)?;
            }
            return Ok(());
        }
        lc.phase = Phase::Opening;
        let key = lc.tries.first().map(Try::open_key);
        if matches!(lc.tries.first(), Some(Try::Claim { .. })) {
            lc.tried_claim = true;
        }
        if let Some(key) = key {
            self.command(conn, Command::Open { label: l, key }, out)?;
        }
        Ok(())
    }

    fn current_try(&self, conn: ConnId, l: &LabelId) -> Option<Try> {
        self.conns.get(&conn)?.labels.get(l)?.tries.first().cloned()
    }

    /// Opened at `head`: accept it when recorded or known, else verify the server's path.
    pub(crate) fn opened(&mut self, conn: ConnId, l: LabelId, head: Step, entry_box: Option<SecretBox>, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return Ok(()) };
        let Some(lc) = self.conns.get(&conn).and_then(|c| c.labels.get(&l)) else { return Ok(()) };
        let g = lc.group;
        let tried = lc.tries.first().cloned();
        // a static entry: the head's entry box carries the read secret of the registered epoch;
        // a sealed box is unauthenticated, so the head's path is verified first and the secret
        // must derive the head's sync key (`path_steps`, `static_secret`)
        if let (Some(Try::Static { .. }), Some(b)) = (&tried, entry_box)
            && let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l))
        {
            lc.entry_box = Some(b);
            lc.phase = Phase::Verifying;
            lc.head = Some(head);
            lc.path.clear();
            return self.command(conn, Command::Path { label: l, after: None }, out);
        }
        if let Some(Try::Sync { step: None, index, .. }) = &tried
            && let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l))
        {
            lc.index = Some(*index);
        }
        let recorded = self.group_label(&g, &l).is_some_and(|gl| gl.steps.contains_key(&head.id()));
        let known = self.state.heads.get(&(server, l)).is_some_and(|h| h.id() == head.id());
        let tried_step = tried.as_ref().and_then(Try::step).is_some_and(|s| s.id() == head.id());
        let walked = self.conns.get(&conn).and_then(|c| c.labels.get(&l)).is_some_and(|x| x.walk.is_some());
        if !walked && (recorded || known || tried_step) {
            return self.accept_head(conn, l, head, out);
        }
        if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
            lc.phase = Phase::Verifying;
            lc.head = Some(head);
            lc.path.clear();
        }
        self.command(conn, Command::Path { label: l, after: None }, out)
    }

    pub(crate) fn path_steps(&mut self, conn: ConnId, l: LabelId, steps: Vec<Step>, more: bool, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) else { return Ok(()) };
        // an opened head confirmed: steps registered since the Open reply move it on (the
        // session follows `more`)
        if lc.phase == Phase::Open {
            for s in steps {
                self.new_head(conn, l, s, out)?;
            }
            let open = self.conns.get(&conn).and_then(|c| c.labels.get(&l)).is_some_and(|x| x.phase == Phase::Open);
            if more && !open {
                self.command(conn, Command::StopPath { label: l }, out)?;
            }
            return Ok(());
        }
        if lc.phase != Phase::Verifying {
            // pages nobody waits for any more: stop following them
            if more {
                self.command(conn, Command::StopPath { label: l }, out)?;
            }
            return Ok(());
        }
        // each page verified as it comes, so a server's bad path is never buffered (spec/sync.md
        // §5: each step under its parent's delete key, the genesis step against the label ID)
        let mut ok = true;
        for s in steps {
            ok = match lc.path.last() {
                None => s.label == l && s.verify_genesis().is_ok(),
                Some(p) => s.verify_child(p).is_ok(),
            };
            if !ok {
                break;
            }
            lc.path.push(s);
        }
        if more && ok {
            return Ok(());
        }
        let path = std::mem::take(&mut lc.path);
        let head = lc.head.take();
        let g = lc.group;
        lc.walk = None;
        let entry_box = lc.entry_box.take();
        if ok {
            for st in &path {
                if !lc.writers.contains(&st.keys.write) {
                    lc.writers.push(st.keys.write);
                }
            }
        }
        match (ok, head) {
            (true, Some(h)) if path.last().map(Step::id) == Some(h.id()) => {
                self.record_steps(&g, &l, &path, None)?;
                if let Some(b) = entry_box
                    && !self.static_secret(conn, l, &g, &h, &b)?
                {
                    return self.drop_try(conn, l, out);
                }
                self.accept_head(conn, l, h, out)
            }
            _ => {
                self.diag("server path does not verify".into());
                if more {
                    self.command(conn, Command::StopPath { label: l }, out)?;
                }
                let now = self.raw_now();
                if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
                    lc.phase = Phase::Failed;
                    lc.last_sync = now;
                }
                Ok(())
            }
        }
    }

    /// Learns the read secret a verified head's entry box carries for the static entry tried,
    /// when it derives the head's sync key (spec/sync.md §2: the step boxes the read secret of
    /// its epoch; anything else is a forged box). False when it does not.
    fn static_secret(&mut self, conn: ConnId, l: LabelId, g: &Tid, head: &Step, b: &SecretBox) -> Result<bool> {
        let Some(Try::Static { kem, .. }) = self.current_try(conn, &l) else { return Ok(false) };
        let index = self.conns.get(&conn).and_then(|c| c.labels.get(&l)).and_then(|x| x.index);
        let (e, secret) = match osis_label::open_entry_box(b, head, osis_label::EntryKey::Kem(&kem)) {
            Ok((Some(e), secret)) => (e, secret),
            Ok((None, _)) => {
                self.diag("entry box without its epoch".into());
                return Ok(false);
            }
            Err(e) => {
                self.diag(format!("entry box: {e}"));
                return Ok(false);
            }
        };
        let indexes: Vec<u64> = match index {
            Some(i) => vec![i],
            None => (0..HINT_INDEXES).collect(),
        };
        let Some(i) = indexes.into_iter().find(|i| osis_label::match_secret(&head.keys.sync, LabelRole::Sync, *i, [&secret]).is_some()) else {
            self.diag("entry box secret does not derive the head's sync key".into());
            return Ok(false);
        };
        if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
            lc.index = Some(i);
        }
        self.engine.learn_read_secret(g, e, secret)?;
        Ok(true)
    }

    /// The head is good: derive its keys, subscribe, sync.
    fn accept_head(&mut self, conn: ConnId, l: LabelId, head: Step, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return Ok(()) };
        let Some(lc) = self.conns.get(&conn).and_then(|c| c.labels.get(&l)) else { return Ok(()) };
        let (g, index) = (lc.group, lc.index.unwrap_or(0));
        let keys = self.engine.head_keys(&g, index, &head)?;
        self.state.set_head(server, l, &head);
        self.reopens.remove(&(conn, l));
        let head_id = head.id();
        if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
            lc.phase = Phase::Open;
            lc.head = Some(head);
            lc.keys = keys;
            lc.tries.clear();
        }
        if self.cfg.subscribe {
            self.command(conn, Command::Subscribe { labels: vec![l] }, out)?;
        }
        // a step registered between the Open reply and the subscription is in neither the
        // pushes nor a cursor-less replay: ask for the path after the opened head
        self.command(conn, Command::Path { label: l, after: Some(head_id) }, out)?;
        self.sync_label(conn, l, out)
    }

    /// An Open matched a superseded step: `step` is its child. Verify it under the parent and
    /// walk on (spec/sync.md §5).
    pub(crate) fn stale_step(&mut self, conn: ConnId, l: LabelId, step: Step, out: &mut Vec<super::Action>) -> Result<()> {
        let tried = self.current_try(conn, &l);
        let parent = tried.as_ref().and_then(Try::step).cloned();
        let Some(parent) = parent else {
            // a hinted label (no recorded steps, so no parent to verify under): walk on, and
            // verify the server's whole path once a key opens it (`opened`)
            if let Some(Try::Sync { step: None, index, .. }) = &tried
                && let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l))
            {
                lc.index = Some(*index);
                lc.walk = Some(step.clone());
                return self.walk_on(conn, l, step, out);
            }
            self.diag("step reply to an open without a known step".into());
            return self.drop_try(conn, l, out);
        };
        if step.verify_child(&parent).is_err() {
            self.diag("walked step does not verify under its parent".into());
            return self.drop_try(conn, l, out);
        }
        let Some(lc) = self.conns.get(&conn).and_then(|c| c.labels.get(&l)) else { return Ok(()) };
        let g = lc.group;
        self.record_steps(&g, &l, &[parent, step.clone()], None)?;
        self.walk_on(conn, l, step, out)
    }

    /// Continues a walk at `step` (verified): its sync key if held, else claims on it.
    fn walk_on(&mut self, conn: ConnId, l: LabelId, step: Step, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(lc) = self.conns.get(&conn).and_then(|c| c.labels.get(&l)) else { return Ok(()) };
        let (g, index) = (lc.group, lc.index.unwrap_or(0));
        let mut front = Vec::new();
        if let Some(e) = self.engine.epochs(&g)
            && let Some(s) = e.read.held_newest_first().into_iter().map(|(_, s)| label_role_key(LabelRole::Sync, s, index)).find(|k| k.verifying_key() == step.keys.sync)
        {
            front.push(Try::Sync { step: Some(step.clone()), index, key: s });
        }
        for x in self.claim_keys() {
            if let Ok(key) = step.claim_key(&x) {
                front.push(Try::Claim { step: step.clone(), key });
            }
        }
        if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
            lc.tries.remove(0);
            front.append(&mut lc.tries);
            lc.tries = front;
        }
        self.try_next(conn, l, out)
    }

    fn drop_try(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l))
            && !lc.tries.is_empty()
        {
            lc.tries.remove(0);
        }
        self.try_next(conn, l, out)
    }

    /// A request about `l` was refused.
    pub(crate) fn refused(&mut self, conn: ConnId, l: Option<LabelId>, kind: u64, code: Code, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(l) = l else { return Ok(()) };
        // an upload or deposit refused whole goes again at a later pass; a timed delete too
        if matches!(kind, 10 | 12) {
            self.sent.retain(|(c, x, _), _| *c != conn || *x != l);
        }
        if kind == 14 {
            self.timed_sent.retain(|(c, x, _)| *c != conn || *x != l);
            self.deleting.retain(|(c, x, _), _| *c != conn || *x != l);
        }
        let phase = self.conns.get(&conn).and_then(|c| c.labels.get(&l)).map(|x| x.phase.clone());
        match (kind, phase) {
            (4, Some(Phase::Opening)) if code == Code::UNKNOWN_LABEL => self.register_path(conn, l, out),
            (4, Some(Phase::Opening)) => self.drop_try(conn, l, out),
            (7, _) => {
                if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
                    lc.registering = None;
                }
                self.reopen(conn, l, out)
            }
            (15, _) | (17, _) | (8, _) if code == Code::NOT_OPENED || code == Code::UNKNOWN_LABEL => self.reopen(conn, l, out),
            // the opened head is no longer on the server's path
            (8, Some(Phase::Open)) => self.reopen(conn, l, out),
            (15, _) => {
                if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
                    lc.syncing = false;
                }
                self.diag(format!("sync refused: code {}", code.0));
                Ok(())
            }
            _ => {
                self.diag(format!("request kind {kind} refused: code {}", code.0));
                Ok(())
            }
        }
    }

    /// Starts opening `l` on `conn` again from scratch.
    /// More than `MAX_REOPENS` in a row (refused registrations, stale heads) waits for the
    /// retry timer instead.
    pub(crate) fn reopen(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(g) = self.conns.get(&conn).and_then(|c| c.labels.get(&l)).map(|x| x.group) else { return Ok(()) };
        let n = self.reopens.entry((conn, l)).or_insert(0);
        *n += 1;
        if *n > MAX_REOPENS {
            let now = self.raw_now();
            if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
                lc.phase = Phase::Failed;
                lc.last_sync = now;
            }
            self.diag(format!("label {l:?}: reopened {MAX_REOPENS} times, retrying later"));
            return Ok(());
        }
        self.start_label(conn, g, l, out)
    }

    /// The server does not hold the label: register the recorded path from the genesis step
    /// along the deepest branch (relayable by any node, spec/sync.md §5), then open.
    fn register_path(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(g) = self.conns.get(&conn).and_then(|c| c.labels.get(&l)).map(|x| x.group) else { return Ok(()) };
        let Some(gl) = self.group_label(&g, &l) else { return self.drop_try(conn, l, out) };
        let d = depths(&gl);
        let Some(tip) = d.iter().max_by_key(|(id, n)| (**n, std::cmp::Reverse(**id))).map(|(id, _)| *id) else { return self.drop_try(conn, l, out) };
        let mut path = Vec::new();
        let mut cur = Some(tip);
        while let Some(c) = cur {
            let Some((s, set)) = gl.steps.get(&c) else { break };
            path.push((s.clone(), set.clone()));
            cur = s.prev;
            if path.len() > gl.steps.len() {
                break;
            }
        }
        path.reverse();
        if path.first().is_none_or(|(s, _)| s.prev.is_some()) {
            return self.drop_try(conn, l, out);
        }
        if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
            lc.phase = Phase::Registering;
            lc.path = path.iter().map(|(s, _)| s.clone()).collect();
        }
        for (step, claim_set) in path {
            self.command(conn, Command::Register { label: l, step, claim_set }, out)?;
        }
        Ok(())
    }

    /// A Register was accepted: the next step of a path registration, or the child step a pass
    /// issued.
    pub(crate) fn registered(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) else { return Ok(()) };
        if lc.phase == Phase::Registering {
            if !lc.path.is_empty() {
                lc.path.remove(0);
            }
            if lc.path.is_empty() {
                return self.reopen(conn, l, out);
            }
            return Ok(());
        }
        let Some((step, set)) = lc.registering.take() else { return Ok(()) };
        let g = lc.group;
        let parent = lc.head.clone();
        let mut steps = Vec::new();
        if let Some(p) = parent {
            steps.push(p);
        }
        steps.push(step.clone());
        self.record_steps(&g, &l, &steps, Some((step.id(), set)))?;
        self.accept_registered(conn, l, step, out)
    }

    fn accept_registered(&mut self, conn: ConnId, l: LabelId, step: Step, out: &mut Vec<super::Action>) -> Result<()> {
        let Some(server) = self.conns.get(&conn).map(|c| c.server) else { return Ok(()) };
        let Some(lc) = self.conns.get(&conn).and_then(|c| c.labels.get(&l)) else { return Ok(()) };
        let (g, index) = (lc.group, lc.index.unwrap_or(0));
        let keys = self.engine.head_keys(&g, index, &step)?;
        self.state.set_head(server, l, &step);
        if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
            lc.head = Some(step);
            lc.keys = keys;
            lc.dirty = true;
        }
        self.run_dirty(out)
    }

    /// A Register was answered with the server's head: open again (the head changed under us).
    pub(crate) fn head_reply(&mut self, conn: ConnId, l: LabelId, _head: Step, out: &mut Vec<super::Action>) -> Result<()> {
        if let Some(lc) = self.conns.get_mut(&conn).and_then(|c| c.labels.get_mut(&l)) {
            lc.registering = None;
        }
        self.reopen(conn, l, out)
    }

    /// Records steps in `/label` of `g` when this node may write it (an admin; spec/sync.md
    /// §2, §5: "records the steps in /label"). Steps already recorded are left alone.
    pub(crate) fn record_steps(&mut self, g: &Tid, l: &LabelId, steps: &[Step], claims: Option<(StepId, ClaimSet)>) -> Result<()> {
        let Some(gl) = self.group_label(g, l) else { return Ok(()) };
        let new: Vec<&Step> = steps.iter().filter(|s| !gl.steps.contains_key(&s.id())).collect();
        if new.is_empty() || self.engine.role_on(g) < Some(osis_core::Role::Admin) {
            return Ok(());
        }
        let mut m = crate::Mutation::new();
        for s in new {
            let set = claims.as_ref().filter(|(id, _)| *id == s.id()).map(|(_, c)| c);
            let rec = osis_label::step_record(s, set);
            let path = vec![PathSeg::Key(l.to_value()), PathSeg::Field(1), PathSeg::Key(s.id().0.to_value())];
            m.op(*g, &osis_schema::core_types::LABEL, PathOp { path, op: Op::Set(rec.to_value()) })?;
        }
        self.engine.commit(m)?;
        Ok(())
    }
}
