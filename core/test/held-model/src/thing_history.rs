//! The thing-level history judgment (issues/thing-history.md): history is set per thing by
//! `retention^.0`, never per write. One aspect of one thing; times are wall ms. `evaluate` judges
//! every replaced body by `out` over the thing's held valid settings (`Outcome::out`); `Eager`
//! and `history` here are the greenfield small worlds `tests/it/spec_thing_history.rs` checks.
//!
//! The rule: a replaced body leaves history at the first moment, at or after it was replaced,
//! at which the setting then in force does not keep it; from then it is out for good.

pub type Ms = u64;
pub const NEVER: Ms = u64::MAX;

/// What a setting says for the aspect (its own entry, else the default, else `None`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Opt {
    /// No history promised.
    None,
    /// Kept `after` ms past replaced and/or until `until`, the later (`until` `NEVER`: for good).
    Keep { after: Ms, until: Ms },
    /// Purge on replace.
    Purge,
}

/// A valid held setting: in force from `ts` until the next one by `(ts, id)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Setting {
    pub ts: Ms,
    pub id: u32,
    pub opt: Opt,
}

/// The settings in key order, each as it reads. `one_way`: once purge on replace was in force,
/// a later keep reads as `None` (the rule that makes late dating safe; `false` shows why).
pub fn timeline(settings: &[Setting], one_way: bool) -> Vec<Setting> {
    let mut s = settings.to_vec();
    s.sort();
    let mut purged = false;
    for x in &mut s {
        match x.opt {
            Opt::Purge => purged = true,
            Opt::Keep { .. } if purged && one_way => x.opt = Opt::None,
            _ => {}
        }
    }
    s
}

/// The moment a body replaced at `r` leaves history; `NEVER` if no held setting ends it.
pub fn out(settings: &[Setting], one_way: bool, r: Ms) -> Ms {
    let tl = timeline(settings, one_way);
    // before the first setting nothing is promised: in force from the beginning of time
    let mut spans = vec![(0, Opt::None)];
    spans.extend(tl.iter().map(|s| (s.ts, s.opt)));
    let mut best = NEVER;
    for (i, (from, opt)) in spans.iter().enumerate() {
        let to = spans.get(i + 1).map_or(NEVER, |n| n.0);
        let bound = match opt {
            Opt::Keep { after, until } => r.saturating_add(*after).max(*until),
            _ => r,
        };
        let e = bound.max(*from).max(r);
        if e < to {
            best = best.min(e);
        }
    }
    best
}

/// Whether a body replaced at `r` is in history at `now`: it leaves later than it was replaced
/// (a body replaced under no history or purge on replace is out when replaced, whenever that is:
/// AMBIGUITIES 68), and not yet.
pub fn kept(settings: &[Setting], one_way: bool, r: Ms, now: Ms) -> bool {
    let o = out(settings, one_way, r);
    o > r && now < o
}

/// The setting in force at wall time `t` (the newest by key with `ts <= t`), as it reads.
pub fn in_force(settings: &[Setting], one_way: bool, t: Ms) -> Opt {
    timeline(settings, one_way).iter().rev().find(|s| s.ts <= t).map_or(Opt::None, |s| s.opt)
}

/// Whether a body replaced at `r` falls under purge on replace: the writers' duty to cover it.
pub fn purge_owed(settings: &[Setting], one_way: bool, r: Ms) -> bool {
    in_force(settings, one_way, r) == Opt::Purge
}

/// A register write: body `id` stamped `ts` (stamps distinct). `fire`: a signal's, replaced
/// when written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Body {
    pub ts: Ms,
    pub id: u32,
    pub fire: bool,
}

/// When `b` was replaced, from the bodies held: a fire at its own `ts`, a value at the `ts` of
/// the earliest held body stamped after it (spec/commits.md §5 Bodies and deaths); `None`: live.
pub fn replaced_at(held: &[Body], b: &Body) -> Option<Ms> {
    if b.fire {
        return Some(b.ts);
    }
    held.iter().filter(|o| !o.fire && (o.ts, o.id) > (b.ts, b.id)).map(|o| o.ts).min()
}

/// The history a node shows at `now`: its held replaced bodies still in their window.
pub fn history(settings: &[Setting], one_way: bool, held: &[Body], now: Ms) -> Vec<u32> {
    let mut v: Vec<u32> = held.iter().filter(|b| replaced_at(held, b).is_some_and(|r| kept(settings, one_way, r, now))).map(|b| b.id).collect();
    v.sort();
    v
}

/// A node that drops every body the moment it is out (the earliest any rule allows), keeps
/// what it dropped dropped, and takes no copy of a body that is out. It dates by what it holds:
/// a dropped body dates nothing (spec/commits.md §5 Bodies and deaths).
#[derive(Clone, Debug, Default)]
pub struct Eager {
    pub settings: Vec<Setting>,
    pub held: Vec<Body>,
    pub dropped: Vec<u32>,
}

impl Eager {
    pub fn setting(&mut self, s: Setting, one_way: bool, now: Ms) {
        self.settings.push(s);
        self.act(one_way, now);
    }
    pub fn body(&mut self, b: Body, one_way: bool, now: Ms) {
        if self.dropped.contains(&b.id) || self.held.contains(&b) {
            return;
        }
        self.held.push(b);
        self.act(one_way, now);
    }
    pub fn act(&mut self, one_way: bool, now: Ms) {
        let held = self.held.clone();
        let (settings, dropped) = (&self.settings, &mut self.dropped);
        self.held.retain(|b| {
            let gone = replaced_at(&held, b).is_some_and(|r| out(settings, one_way, r) <= now);
            if gone {
                dropped.push(b.id);
            }
            !gone
        });
    }
    pub fn history(&self, one_way: bool, now: Ms) -> Vec<u32> {
        let mut v: Vec<u32> = self.held.iter().filter(|b| replaced_at(&self.held, b).is_some_and(|r| kept(&self.settings, one_way, r, now))).map(|b| b.id).collect();
        v.sort();
        v
    }
}
