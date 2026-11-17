//! The thing-level history judgment (spec/commits.md §5 The setting): history is set per thing by
//! `retention^.0`, never per write, and judged by the current setting alone: the newest held
//! valid one. One aspect of one thing; times are wall ms. `Outcome` (`model.rs`) judges every
//! replaced body by `out`; `Eager` and `history` here are the greenfield small worlds
//! `tests/it/spec_thing_history.rs` checks.
//!
//! The rule: a replaced body is in history while the current setting keeps it, counted from when
//! it was replaced. Purge on replace is the one thing that needs the past, and the current
//! setting carries it: an entry's `floor` (`purge_before`) puts every body written before it under
//! purge on replace, and a writer replacing a purge-on-replace entry sets it to its own stamp
//! (`written_after`), carrying any earlier one on.

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

/// A valid held setting, current while no held valid one sorts after it by `(ts, id)`. `floor`:
/// a body written before it is under purge on replace (0: none).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Setting {
    pub ts: Ms,
    pub id: u32,
    pub opt: Opt,
    pub floor: Ms,
}

/// The setting a writer holding `prev` (its current) writes at `ts` with option `opt`: purge on
/// replace is one way, so a writer replacing a purge-on-replace entry sets the floor to its own
/// stamp, and every writer carries the floor it holds.
pub fn written_after(prev: Option<&Setting>, ts: Ms, id: u32, opt: Opt) -> Setting {
    let floor = prev.map_or(0, |p| if p.opt == Opt::Purge { ts.max(p.floor) } else { p.floor });
    Setting { ts, id, opt, floor }
}

/// What a node judges by (the design, and the negative controls the tests show fail).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// The floor, against the stamps of the body's writes.
    Floor,
    /// No floor: purge on replace by the current setting alone, covered at once by writers.
    NoFloor,
    /// The floor against the body's replaced-at (which a node holding fewer bodies dates later).
    FloorByReplaced,
}

/// The current setting: the newest held, by `(ts, id)`.
pub fn current(settings: &[Setting]) -> Option<Setting> {
    settings.iter().max().copied()
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

/// Whether `b`, replaced at `r`, is under the floor of `s`.
fn floored(s: &Setting, rule: Rule, b: &Body, r: Ms) -> bool {
    match rule {
        Rule::Floor => b.ts < s.floor,
        Rule::NoFloor => false,
        Rule::FloorByReplaced => r < s.floor,
    }
}

/// Whether value body `b`, replaced at `r`, is under purge on replace by `cur`: the entry purges
/// on replace, or it was written before the floor. Writers cover it at once and every node drops
/// it once covered, whatever it holds later.
pub fn under_purge(cur: Option<Setting>, rule: Rule, b: &Body, r: Ms) -> bool {
    !b.fire && cur.is_some_and(|s| s.opt == Opt::Purge || floored(&s, rule, b, r))
}

/// The moment `b`, replaced at `r`, leaves history by `cur` (a body under purge on replace, or
/// under no keep entry, when replaced).
pub fn out(cur: Option<Setting>, rule: Rule, b: &Body, r: Ms) -> Ms {
    match cur {
        Some(s) if !floored(&s, rule, b, r) => match s.opt {
            Opt::Keep { after, until } => r.saturating_add(after).max(until).max(r),
            _ => r,
        },
        _ => r,
    }
}

/// Whether `b`, replaced at `r`, is in history at `now`: it leaves later than it was replaced
/// (one replaced under no history or purge on replace never is: AMBIGUITIES 68), and not yet.
pub fn kept(cur: Option<Setting>, rule: Rule, b: &Body, r: Ms, now: Ms) -> bool {
    let o = out(cur, rule, b, r);
    o > r && now < o
}

/// Until when live body `b` is kept (spec/commits.md §5 Kept while live): while a replacement of
/// it then would be kept. A D: for good; a T alone: to T; else 0 (a cover drops it at once).
pub fn live_until(cur: Option<Setting>, b: &Body) -> Ms {
    match cur {
        Some(s) if b.ts >= s.floor => match s.opt {
            Opt::Keep { after, .. } if after > 0 => NEVER,
            Opt::Keep { until, .. } => until,
            _ => 0,
        },
        _ => 0,
    }
}

/// The history a node holding `settings` and `held` shows at `now`.
pub fn history(settings: &[Setting], rule: Rule, held: &[Body], now: Ms) -> Vec<u32> {
    let cur = current(settings);
    let mut v: Vec<u32> = held.iter().filter(|b| replaced_at(held, b).is_some_and(|r| kept(cur, rule, b, r, now))).map(|b| b.id).collect();
    v.sort();
    v
}

/// The oracle of what purge on replace promises, from the whole world: `b` was replaced (by every
/// body written) while the setting then in force by stamp (every setting written) purged on
/// replace. Read from the past the nodes never keep.
pub fn purged(all_settings: &[Setting], all: &[Body], b: &Body) -> bool {
    let Some(r) = replaced_at(all, b) else { return false };
    let mut s = all_settings.to_vec();
    s.sort();
    !b.fire && s.iter().rev().find(|x| x.ts <= r).is_some_and(|x| x.opt == Opt::Purge)
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
    pub fn setting(&mut self, s: Setting, rule: Rule, now: Ms) {
        self.settings.push(s);
        self.act(rule, now);
    }
    pub fn body(&mut self, b: Body, rule: Rule, now: Ms) {
        if self.dropped.contains(&b.id) || self.held.contains(&b) {
            return;
        }
        self.held.push(b);
        self.act(rule, now);
    }
    pub fn act(&mut self, rule: Rule, now: Ms) {
        let held = self.held.clone();
        let cur = current(&self.settings);
        let dropped = &mut self.dropped;
        self.held.retain(|b| {
            let gone = replaced_at(&held, b).is_some_and(|r| out(cur, rule, b, r) <= now);
            if gone {
                dropped.push(b.id);
            }
            !gone
        });
    }
    pub fn history(&self, rule: Rule, now: Ms) -> Vec<u32> {
        history(&self.settings, rule, &self.held, now)
    }
}
