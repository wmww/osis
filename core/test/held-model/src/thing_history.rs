//! The thing-level history judgment (spec/commits.md §5 The setting): history is set per thing by
//! `retention^.0`, never per write, and judged by the current setting: the newest held valid one.
//! One aspect of one thing; times are wall ms. `Outcome` (`model.rs`) judges every replaced body
//! by `out`; `Eager` and `history` here are the greenfield small worlds
//! `tests/it/spec_thing_history.rs` checks.
//!
//! The rule: a replaced body is in history while the current setting keeps it, counted from when
//! it was replaced. Purge on replace is the one thing that needs the past, and the settings carry
//! it as a floor: a body written before the floor is under purge on replace. The floor joins by
//! maximum over every held setting (`joined_floor`): each one's own `floor`, and for a
//! purge-on-replace one the stamp of the next held setting (where no held floor already passes
//! its own stamp). A writer writes the joined floor of what it holds into its setting
//! (`written_after`), so a setting written by an admin that never held a concurrent purging one
//! loses nothing at a node holding both, and once a setting carries the join the older ones add
//! nothing.

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

/// The setting a writer holding `held` writes at `ts` (after every held one) with option `opt`:
/// its floor is the joined floor of `held` and itself (`joined_floor`), so a writer replacing a
/// purge-on-replace entry sets it to at least its own stamp. Under `Rule::NoJoin` it carries its
/// current setting's alone.
pub fn written_after(held: &[Setting], ts: Ms, id: u32, opt: Opt, rule: Rule) -> Setting {
    let new = Setting { ts, id, opt, floor: 0 };
    let floor = match rule {
        Rule::NoJoin => newest(held).map_or(0, |p| if p.opt == Opt::Purge { ts.max(p.floor) } else { p.floor }),
        _ => joined_floor(&[held, &[new]].concat(), rule),
    };
    Setting { floor, ..new }
}

/// What a node judges by (the design, and the negative controls the tests show fail).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// The joined floor, against the stamps of the body's writes.
    Floor,
    /// The current setting's floor alone, carried by each writer from its current setting only.
    NoJoin,
    /// No floor: purge on replace by the current setting alone, covered at once by writers.
    NoFloor,
    /// The joined floor against the body's replaced-at (which a node holding fewer bodies dates
    /// later).
    FloorByReplaced,
}

/// The newest held setting, by `(ts, id)`.
pub fn newest(settings: &[Setting]) -> Option<Setting> {
    settings.iter().max().copied()
}

/// The floor joined over `settings` (spec/commits.md §5 One way): the greatest of every held
/// setting's own floor and, for each purge-on-replace setting but the newest, the stamp of the
/// next held one by key, unless a held floor is already past its own stamp (every floor is the
/// stamp of a setting written after the purging one, so it covers all that was replaced while
/// that one was in force). Under `Rule::NoJoin`, the newest's floor alone.
pub fn joined_floor(settings: &[Setting], rule: Rule) -> Ms {
    let mut s = settings.to_vec();
    s.sort();
    if rule == Rule::NoJoin {
        return s.last().map_or(0, |x| x.floor);
    }
    let base = s.iter().map(|x| x.floor).max().unwrap_or(0);
    let ended = s.windows(2).filter(|w| w[0].opt == Opt::Purge && base <= w[0].ts).map(|w| w[1].ts);
    ended.fold(base, Ms::max)
}

/// The current setting a node holding `settings` judges by: the newest, with the joined floor.
pub fn current(settings: &[Setting], rule: Rule) -> Option<Setting> {
    newest(settings).map(|s| Setting { floor: joined_floor(settings, rule), ..s })
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
        Rule::Floor | Rule::NoJoin => b.ts < s.floor,
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
    let cur = current(settings, rule);
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
        let cur = current(&self.settings, rule);
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
