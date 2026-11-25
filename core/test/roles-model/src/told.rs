//! A removed node learns its removal (spec/sync-opens.md §4 Departed, §6; spec/sync-streams.md §4):
//! a reader judging a peer departed opens the thing's sync ID toward it only ended, on any read
//! secret it holds of an epoch not covering every departure, and serves it the thing's role entries
//! alone, up to the first rotation superseding that epoch.
//!
//! The world: account A with nodes N0 (admin, the remover), N1 (a member), N2 (the removed node), N3
//! (paired by N0, maybe after the removal), and X, a stranger. Events: syncs of two nodes (each
//! side serving the other what it judges it may hold, repeated until nothing moves, as testing again
//! after a close does on a connection), N1 or N2 writing content at the epoch it holds, N0 rotating
//! A (boxing every member it knows) or pairing N3, N0's removal of N2 (its rotation boxes N2 nothing),
//! and N0's reset (it is gone: no designated device). A node learning its removal erases A.
//!
//! Rules (`ToldRules`): `spec`, and controls `close` (a departed peer is opened nothing: the rule
//! before), `fire` (closed, and the remover alone tells N2 by meeting it: a fire on its node thing),
//! `newest` (only the newest epoch below the removal's is shown), `full` (served content too, up to
//! the same point), `late` (served up to the server's log end). Properties:
//! - `told`: N2 learns its removal from any member that holds it and syncs with it, the remover gone
//!   or not;
//! - `notice`: what a node judging N2 departed serves it is role entries logged there no later than
//!   the removal: it gains nothing but its notice.

use crate::Findings;

pub const N0: usize = 0;
pub const N1: usize = 1;
pub const N2: usize = 2;
pub const N3: usize = 3;
pub const X: usize = 4;
pub const NODES: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Ev {
    Sync(usize, usize),
    Write(usize),
    Rotate,
    Pair,
    Reset,
    Remove,
    Skip,
}

#[derive(Clone, Debug)]
pub struct ToldWorld {
    pub evs: Vec<Ev>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ToldRules {
    Spec,
    Close,
    Fire,
    Newest,
    Full,
    Late,
}

impl ToldRules {
    pub fn named(mode: &str) -> Option<ToldRules> {
        let rest = mode.strip_prefix("told").unwrap_or(mode);
        Some(match rest.strip_prefix("-exh").unwrap_or(rest) {
            "" => ToldRules::Spec,
            "-close" => ToldRules::Close,
            "-fire" => ToldRules::Fire,
            "-newest" => ToldRules::Newest,
            "-full" => ToldRules::Full,
            "-late" => ToldRules::Late,
            _ => return None,
        })
    }
}

/// An entry of A: a role entry (a rotation making epoch `epoch` boxed to `boxed`, the removal of N2
/// among them; N3's grant) or content at an epoch.
#[derive(Clone, Copy, Debug)]
struct Entry {
    role: bool,
    epoch: usize,
    /// A rotation: the members it boxes the new epoch to.
    boxed: Option<[bool; NODES]>,
    removes: bool,
    pairs: bool,
}

struct State {
    entries: Vec<Entry>,
    /// Each node's log: entry indices in the order first logged.
    log: [Vec<usize>; NODES],
    gone: [bool; NODES],
    erased: [bool; NODES],
    epochs: usize,
}

impl State {
    fn holds(&self, n: usize, e: usize) -> bool {
        self.log[n].contains(&e)
    }
    fn holds_where(&self, n: usize, f: impl Fn(&Entry) -> bool) -> Option<usize> {
        self.log[n].iter().position(|&e| f(&self.entries[e]))
    }
    fn knows_removal(&self, n: usize) -> bool {
        self.holds_where(n, |e| e.removes).is_some()
    }
    fn paired(&self, n: usize) -> bool {
        self.holds_where(n, |e| e.pairs).is_some()
    }
    /// The epochs whose secrets node n holds: 0 for the first three, each rotation boxing it.
    fn secrets(&self, n: usize) -> Vec<usize> {
        let mut out: Vec<usize> = if n <= N2 { vec![0] } else { vec![] };
        for &e in &self.log[n] {
            let x = &self.entries[e];
            if x.boxed.is_some_and(|b| b[n]) {
                out.push(x.epoch);
            }
            // a pairing boxes every epoch its maker held
            if x.pairs && n == N3 {
                out.extend(0..=x.epoch);
            }
        }
        out.sort();
        out.dedup();
        out
    }
    fn epoch(&self, n: usize) -> Option<usize> {
        self.secrets(n).last().copied()
    }
    /// Whether n holds A, as it judges it.
    fn member(&self, n: usize) -> bool {
        !self.gone[n] && !self.erased[n] && match n {
            N0 | N1 => true,
            N2 => !self.knows_removal(N2),
            N3 => self.paired(N3),
            _ => false,
        }
    }
    fn take(&mut self, n: usize, es: &[usize]) {
        for &e in es {
            if !self.holds(n, e) {
                self.log[n].push(e);
            }
        }
        if n == N2 && self.knows_removal(N2) {
            self.erased[N2] = true;
            self.log[N2].clear();
        }
    }
    fn add(&mut self, n: usize, x: Entry) {
        self.entries.push(x);
        let i = self.entries.len() - 1;
        self.log[n].push(i);
    }
}

pub type ToldStats = Findings<ToldWorld>;

pub fn told_check(w: &ToldWorld, r: ToldRules, st: &mut ToldStats) {
    if w.evs.iter().filter(|e| **e == Ev::Remove).count() != 1 {
        return;
    }
    st.worlds += 1;
    let mut s = State { entries: vec![], log: Default::default(), gone: [false; NODES], erased: [false; NODES], epochs: 0 };
    let mut fails = vec![];
    let mut could = false;
    for &ev in &w.evs {
        match ev {
            Ev::Skip => {}
            Ev::Reset => s.gone[N0] = true,
            Ev::Write(n) => {
                if let (true, Some(epoch)) = (s.member(n), s.epoch(n)) {
                    s.add(n, Entry { role: false, epoch, boxed: None, removes: false, pairs: false });
                }
            }
            Ev::Rotate | Ev::Remove => {
                if s.gone[N0] {
                    if ev == Ev::Remove {
                        return;
                    }
                    continue;
                }
                s.epochs += 1;
                let mut boxed = [false; NODES];
                for n in [N0, N1, N2, N3] {
                    boxed[n] = match n {
                        N2 => !s.knows_removal(N0) && ev != Ev::Remove,
                        N3 => s.paired(N0),
                        _ => true,
                    };
                }
                s.add(N0, Entry { role: true, epoch: s.epochs, boxed: Some(boxed), removes: ev == Ev::Remove, pairs: false });
            }
            Ev::Pair => {
                if s.gone[N0] || s.paired(N0) {
                    continue;
                }
                s.add(N0, Entry { role: true, epoch: s.epochs, boxed: None, removes: false, pairs: true });
                let all = s.log[N0].clone();
                s.take(N3, &all);
            }
            Ev::Sync(u, v) => {
                for (a, b) in [(u, v), (v, u)] {
                    if b == N2 && a != X && s.member(a) && s.knows_removal(a) && s.member(N2) {
                        could = true;
                    }
                }
                // each side serves the other until nothing moves
                loop {
                    let before = s.log.clone();
                    for (a, b) in [(u, v), (v, u)] {
                        serve(&mut s, a, b, r, &mut fails);
                    }
                    if s.log == before {
                        break;
                    }
                }
            }
        }
    }
    if could && !s.erased[N2] {
        fails.push(format!("told: N2 synced with a member holding its removal and did not learn it"));
    }
    st.failed(fails, w);
}

/// Server `a` serves node `b` what it judges `b` may hold, where `b` opens toward `a`.
fn serve(s: &mut State, a: usize, b: usize, r: ToldRules, fails: &mut Vec<String>) {
    if !s.member(a) || !s.member(b) {
        return;
    }
    // `b` opens on its own proof that `a` may hold A: a member it knows (N3 proves by its grant's copies)
    if a == X {
        return;
    }
    let departed = b == N2 && s.knows_removal(a);
    let reader = match b {
        N0 | N1 => true,
        N2 => !departed,
        N3 => s.paired(a),
        _ => false,
    };
    if reader {
        let all = s.log[a].clone();
        s.take(b, &all);
        return;
    }
    if !departed {
        return;
    }
    let rpos = s.holds_where(a, |e| e.removes).unwrap();
    let removal_epoch = s.entries[s.log[a][rpos]].epoch;
    let served: Vec<usize> = match r {
        ToldRules::Close => vec![],
        ToldRules::Fire => {
            // the remover's fire on N2's node thing: the removal, from the remover alone
            if a == N0 { vec![s.log[a][rpos]] } else { vec![] }
        }
        _ => {
            // a shows its secrets of epochs below the removal's (only the newest: `newest`); N2 hits
            // on the one it holds
            let shown: Vec<usize> = s.secrets(a).into_iter().filter(|&e| e < removal_epoch).collect();
            let shown = if r == ToldRules::Newest { shown.last().into_iter().copied().collect() } else { shown };
            let Some(e) = s.epoch(b).filter(|e| shown.contains(e)) else { return };
            // until: the first rotation superseding e, as logged at a; the log's end (`late`)
            let until = match r {
                ToldRules::Late => s.log[a].len() - 1,
                _ => s.holds_where(a, |x| x.boxed.is_some() && x.epoch > e).unwrap_or(s.log[a].len() - 1),
            };
            s.log[a][..=until].iter().copied().filter(|&x| r == ToldRules::Full || r == ToldRules::Late || s.entries[x].role).collect()
        }
    };
    for &x in &served {
        let pos = s.log[a].iter().position(|&y| y == x).unwrap();
        if !s.entries[x].role || pos > rpos {
            fails.push(format!("notice: node {a}, judging N2 departed, served it an entry {} its removal: {:?}", if pos > rpos { "logged after" } else { "of content before" }, s.entries[x]));
        }
    }
    s.take(b, &served);
}

/// Events a slot draws from: syncs of every pair, writes by N1 and N2, a rotation, a pairing, the
/// remover's reset, nothing.
pub fn alphabet() -> Vec<Ev> {
    let mut out = vec![];
    for u in 0..NODES {
        for v in u + 1..NODES {
            out.push(Ev::Sync(u, v));
        }
    }
    out.extend([Ev::Write(N1), Ev::Write(N2), Ev::Rotate, Ev::Pair, Ev::Reset, Ev::Skip]);
    out
}

pub const SLOTS: usize = 5;

/// The family's size: every event in each of `SLOTS` slots, and the removal before any of them or
/// after the last.
pub fn family_size() -> usize {
    alphabet().len().pow(SLOTS as u32) * (SLOTS + 1)
}

pub fn told_family(mut k: usize) -> ToldWorld {
    let al = alphabet();
    let at = k % (SLOTS + 1);
    k /= SLOTS + 1;
    let mut evs = vec![];
    for i in 0..SLOTS {
        if i == at {
            evs.push(Ev::Remove);
        }
        evs.push(al[k % al.len()]);
        k /= al.len();
    }
    if at == SLOTS {
        evs.push(Ev::Remove);
    }
    ToldWorld { evs }
}

pub fn told_run(samples: u64, mode: &str) -> u64 {
    let Some(r) = ToldRules::named(mode) else {
        eprintln!("unknown mode {mode}");
        return 1;
    };
    let st: ToldStats = crate::family_on_every_core(family_size(), samples.max(1) as usize, |k, st: &mut ToldStats| told_check(&told_family(k), r, st));
    st.print(mode);
    for (f, w) in &st.fail {
        println!("{f}\n  world: {w:?}");
    }
    st.failures
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ev::*;

    fn kinds(evs: Vec<Ev>, r: ToldRules) -> Vec<String> {
        let mut st = ToldStats::default();
        told_check(&ToldWorld { evs }, r, &mut st);
        st.kinds.keys().cloned().collect()
    }

    /// N0 removes N2 and is reset; N2 meets N1 alone. Spec: N1 tells it. Closed (the rule before),
    /// or told by the remover's fire alone, it never learns.
    #[test]
    fn a_removed_node_learns_from_a_member_the_remover_gone() {
        let w = vec![Sync(N0, N1), Remove, Sync(N0, N1), Reset, Sync(N1, N2)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w.clone(), ToldRules::Close), ["told"]);
        assert_eq!(kinds(w, ToldRules::Fire), ["told"]);
    }

    /// N2 misses a rotation before its removal: it holds an older epoch than the one the removal
    /// supersedes. Showing every epoch below the removal's, a member tells it (twice opened on one
    /// connection); showing only the newest, it never learns.
    #[test]
    fn a_removed_node_an_epoch_behind_learns() {
        let w = vec![Rotate, Remove, Sync(N0, N1), Sync(N1, N2)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w, ToldRules::Newest), ["told"]);
    }

    /// N1 writes before and after it holds the removal; N2 is served its role entries up to the
    /// removal alone. Served content, or up to the log's end, it gains more than its notice.
    #[test]
    fn a_removed_node_gains_nothing_but_its_notice() {
        let w = vec![Write(N1), Remove, Sync(N0, N1), Write(N1), Sync(N1, N2)];
        assert!(kinds(w.clone(), ToldRules::Spec).is_empty());
        assert_eq!(kinds(w.clone(), ToldRules::Full), ["notice"]);
        assert_eq!(kinds(w, ToldRules::Late), ["notice"]);
    }

    /// A node paired after the removal tells N2; a stranger opens nothing.
    #[test]
    fn a_node_paired_after_the_removal_tells_and_a_stranger_cannot() {
        assert!(kinds(vec![Remove, Pair, Reset, Sync(N2, X), Sync(N2, N3)], ToldRules::Spec).is_empty());
        assert_eq!(kinds(vec![Remove, Pair, Reset, Sync(N2, N3)], ToldRules::Fire), ["told"]);
    }

    /// Every 101st family world (`-- 1 told-exh` runs them all): spec holds; each control fails
    /// its property.
    #[test]
    #[ignore = "property"]
    fn told_family_holds_plain() {
        let run = |r: ToldRules| crate::family_on_every_core(family_size(), 101, |k, st: &mut ToldStats| told_check(&told_family(k), r, st));
        let st = run(ToldRules::Spec);
        assert!(st.worlds > 0 && st.failures == 0, "{:?}", st.fail);
        for (r, kind) in [(ToldRules::Close, "told"), (ToldRules::Fire, "told"), (ToldRules::Newest, "told"), (ToldRules::Full, "notice"), (ToldRules::Late, "notice")] {
            assert!(run(r).kinds.contains_key(kind), "{r:?}");
        }
    }
}
