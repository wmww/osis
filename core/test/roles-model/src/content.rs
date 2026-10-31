//! Layer 2 (spec/permissions.md §5.2; spec/commits.md §4): content validity per
//! delta, given each thing's write timeline for one author X. A thing's timeline is a list of
//! events on X's role (grant, explicit demotion below write by a revoker, `until` expiry).
//! A content commit by X carries one delta per thing it touches; a compaction snapshot by an
//! authorized writer W carries the deltas W had received by its `ts`. A node syncs some of
//! the things and may be compacted (holds a snapshot instead of the bodies it covers; it
//! judges by the dots and `ts` the snapshot carries, so it loses nothing but earlier
//! snapshots it dropped). Scenarios only; validity is a pure function of the held set, so
//! delivery order cannot matter, and the checks are compacted vs uncompacted and partial
//! syncing.

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Ev {
    Grant(u32),
    /// Explicit demotion below write at `t` by a revoker that had received X's commits
    /// with receipt time `< t` (its frontier).
    Revoke { t: u32, revoker: usize },
    /// `until` expiry at `t`: a departure that audits nothing.
    Until(u32),
}

pub struct Commit {
    pub t: u32,
    pub things: Vec<usize>,
    /// [node] receipt time.
    pub recv: Vec<u32>,
}

pub struct Snap {
    pub thing: usize,
    pub t: u32,
    /// Commits whose delta on `thing` it carries.
    pub carries: Vec<usize>,
}

pub struct World {
    /// Per thing, X's role events (in time order; X starts without write).
    pub timeline: Vec<Vec<Ev>>,
    pub commits: Vec<Commit>,
}

impl World {
    /// X holds write on `thing` at `t`.
    fn authorized(&self, thing: usize, t: u32) -> bool {
        let mut on = false;
        for e in &self.timeline[thing] {
            match *e {
                Ev::Grant(g) if g <= t => on = true,
                Ev::Revoke { t: r, .. } | Ev::Until(r) if r <= t => on = false,
                _ => {}
            }
        }
        on
    }

    fn now(&self, thing: usize) -> bool {
        self.authorized(thing, u32::MAX)
    }

    /// X's newest explicit demotion below write on `thing`.
    fn newest_revoke(&self, thing: usize) -> Option<(u32, usize)> {
        self.timeline[thing].iter().rev().find_map(|e| if let Ev::Revoke { t, revoker } = *e { Some((t, revoker)) } else { None })
    }

    /// §5.2 on its own: valid if X held write at its ts and no explicit demotion followed;
    /// else iff the newest explicit demotion's frontier covers it; a re-grant (X holds write
    /// now) validates everything.
    pub fn own_valid(&self, c: usize, thing: usize) -> bool {
        let cm = &self.commits[c];
        if self.now(thing) {
            return true;
        }
        match self.newest_revoke(thing) {
            Some((t, revoker)) if t > cm.t || !self.authorized(thing, cm.t) => cm.recv[revoker] < t,
            _ => self.authorized(thing, cm.t),
        }
    }

    /// Snapshots vouch for nothing (§5.2): the delta is judged on its own whatever snapshots
    /// carry it. (The rejected "stands iff X was authorized at the snapshot's ts" rule was
    /// `snaps.iter().any(|s| s.carries.contains(&c) && self.authorized(thing, s.t)) || own`.)
    pub fn valid(&self, c: usize, thing: usize, snaps: &[&Snap]) -> bool {
        debug_assert!(snaps.iter().all(|s| s.thing < self.timeline.len()));
        self.own_valid(c, thing)
    }

    /// The rejected snapshot-authority rule, kept to show its divergence.
    pub fn valid_snapshot_authority(&self, c: usize, thing: usize, snaps: &[&Snap]) -> bool {
        snaps.iter().any(|s| s.thing == thing && s.carries.contains(&c) && self.authorized(thing, s.t)) || self.own_valid(c, thing)
    }

    /// The rejected per-commit rule as a node syncing `synced` evaluates it: a commit is
    /// invalid if any delta on a thing it syncs is invalid (it cannot judge the others).
    pub fn per_commit_valid(&self, c: usize, synced: &[usize]) -> bool {
        self.commits[c].things.iter().filter(|t| synced.contains(t)).all(|&t| self.own_valid(c, t))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LATE: u32 = 1000;
    /// Nodes: 0 revoker A, 1 writer W1, 2 writer W2, 3 reader.
    const A: usize = 0;

    fn commit(t: u32, things: &[usize], recv: &[(usize, u32)]) -> Commit {
        let mut r = vec![LATE; 4];
        for &(n, tn) in recv {
            r[n] = tn;
        }
        Commit { t, things: things.to_vec(), recv: r }
    }

    /// Reference scenario: X's edit at t=3, unseen by A, who revokes at t=4; X's edit at t=5.
    /// Both invalid: an edit made while authorized still needs the revoke's frontier (the
    /// literal "authorized at its ts is valid" would keep the first, and a backdated forgery).
    /// Seen by A: the first stands. Re-granted: both stand.
    #[test]
    fn frontier_decides_pre_revoke_edits() {
        let w = World { timeline: vec![vec![Ev::Grant(0), Ev::Revoke { t: 4, revoker: A }]], commits: vec![commit(3, &[0], &[]), commit(5, &[0], &[])] };
        assert_eq!((w.own_valid(0, 0), w.own_valid(1, 0)), (false, false));
        let w = World { commits: vec![commit(3, &[0], &[(A, 3)]), commit(5, &[0], &[])], ..w };
        assert_eq!((w.own_valid(0, 0), w.own_valid(1, 0)), (true, false));
        let w = World { timeline: vec![vec![Ev::Grant(0), Ev::Revoke { t: 4, revoker: A }, Ev::Grant(8)]], ..w };
        assert_eq!((w.own_valid(0, 0), w.own_valid(1, 0)), (true, true));
        // `until` audits nothing: edits inside the edge's life stand, later ones do not.
        let w = World { timeline: vec![vec![Ev::Grant(0), Ev::Until(4)]], commits: vec![commit(3, &[0], &[]), commit(5, &[0], &[])] };
        assert_eq!((w.own_valid(0, 0), w.own_valid(1, 0)), (true, false));
    }

    /// Per-delta validity: X's commit at t=3 touches things 0 and 1; X is revoked on thing 0
    /// at t=4 by A, who had not received it. Nodes syncing 0, 1 or both agree per thing:
    /// invalid on 0, valid on 1. Per commit, a node syncing both would drop the delta on 1
    /// while a node syncing only 1 keeps it.
    #[test]
    fn per_delta_validity() {
        let w = World { timeline: vec![vec![Ev::Grant(0), Ev::Revoke { t: 4, revoker: A }], vec![Ev::Grant(0)]], commits: vec![commit(3, &[0, 1], &[])] };
        for synced in [vec![0], vec![1], vec![0, 1]] {
            for &t in &synced {
                assert_eq!(w.valid(0, t, &[]), t == 1, "synced {synced:?} thing {t}");
            }
        }
        assert!(w.per_commit_valid(0, &[1]));
        assert!(!w.per_commit_valid(0, &[0, 1]));
    }

    /// Snapshots vouch for nothing: X's edit at t=3, A revokes at t=5 without having received
    /// it. A snapshot by W1 at t=4 or t=6 carrying it changes nothing: invalid everywhere.
    #[test]
    fn snapshots_vouch_for_nothing() {
        let w = World { timeline: vec![vec![Ev::Grant(0), Ev::Revoke { t: 5, revoker: A }]], commits: vec![commit(3, &[0], &[(1, 3)])] };
        for st in [4, 6] {
            let s = Snap { thing: 0, t: st, carries: vec![0] };
            assert!(!w.valid(0, 0, &[&s]), "snapshot at {st}");
            assert!(!w.valid(0, 0, &[]));
        }
        // Re-granted: valid with or without a snapshot.
        let w = World { timeline: vec![vec![Ev::Grant(0), Ev::Revoke { t: 5, revoker: A }, Ev::Grant(9)]], ..w };
        let s = Snap { thing: 0, t: 6, carries: vec![0] };
        assert!(w.valid(0, 0, &[&s]) && w.valid(0, 0, &[]));
    }

    /// Snapshot of a snapshot: W1 compacts at t=4 carrying X's edit, W2 at t=8 carrying it
    /// from W1. Under the rejected snapshot-authority rule a node that dropped W1's snapshot as
    /// covered read the edit invalid while one still holding it read it valid. With snapshots
    /// vouching for nothing every held set agrees.
    #[test]
    fn snapshot_of_snapshot_converges() {
        let w = World { timeline: vec![vec![Ev::Grant(0), Ev::Revoke { t: 5, revoker: A }]], commits: vec![commit(3, &[0], &[(1, 3)])] };
        let s1 = Snap { thing: 0, t: 4, carries: vec![0] };
        let s2 = Snap { thing: 0, t: 8, carries: vec![0] };
        assert!(w.valid_snapshot_authority(0, 0, &[&s1, &s2]) != w.valid_snapshot_authority(0, 0, &[&s2]));
        let held: [&[&Snap]; 4] = [&[], &[&s1], &[&s2], &[&s1, &s2]];
        assert!(held.iter().all(|h| !w.valid(0, 0, h)));
        let w = World { timeline: vec![vec![Ev::Grant(0), Ev::Revoke { t: 5, revoker: A }, Ev::Grant(9)]], ..w };
        assert!(held.iter().all(|h| w.valid(0, 0, h)));
    }
}
