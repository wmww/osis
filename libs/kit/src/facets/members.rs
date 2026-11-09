//! A set of things: from `ui:collection.0`, a `tag.0` thing, or a group with members.

use crate::store::Reader;
use crate::schema::{Arrange, COLLECTION, CREATING, WEEK};
use crate::store::Data;
use crate::view::source::{items, of};
use crate::view::{Act, Action, Block, Chip, Cx, Do, Facet, Icon, Input, Mark, Offer, Placed, Run, Section, Summary, Config, ViewSpec, arrange};
use osis::core::{TAG, Tag};
use osis::{Member, Result, Tid};

pub struct MembersFacet;
pub static FACET: MembersFacet = MembersFacet;

/// Colours a new tag takes, in turn.
pub const TAG_COLORS: [&str; 8] = ["#ef4444", "#f59e0b", "#22c55e", "#06b6d4", "#3b82f6", "#8b5cf6", "#ec4899", "#64748b"];

fn start(d: &Data, w: &mut osis::Write<'_>, t: Tid, g: Tid) -> Result<()> {
    let c = TAG_COLORS.get(d.all_tags()?.len() % TAG_COLORS.len()).map(|c| c.to_string());
    w.at(t, TAG).set(&Tag { color: c })?;
    w.group(g).add(Member::Subgroup(t))
}

#[derive(Clone, Debug, PartialEq)]
struct SetWeek(String, i64);
impl Action for SetWeek {
    fn run(&self, act: &Act, _: &Input) -> Result<()> {
        if self.1 == 0 { act.clear_state(WEEK, &self.0) } else { act.set_state(WEEK, &self.0, &self.1) }
    }
}

/// How the viewer arranges a set.
#[derive(Clone, Debug, PartialEq)]
struct SetArranged(Tid, Arrange);
impl Action for SetArranged {
    fn run(&self, act: &Act, _: &Input) -> Result<()> {
        act.set_arranged(self.0, &self.1)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct MoveFavorite;
impl Action for MoveFavorite {
    fn run(&self, act: &Act, input: &Input) -> Result<()> {
        let Input::Reorder { from, to } = input else { return Ok(()) };
        act.move_favorite(*from, *to)
    }
}

impl Facet for MembersFacet {
    fn id(&self) -> &'static str {
        "members"
    }
    fn claims(&self, ak: &str) -> bool {
        ak == "ui:collection.0" || ak == "tag.0"
    }
    /// `collection.0` or `tag.0`, or a group that holds something.
    fn applies(&self, cx: &Reader, t: Tid) -> Result<bool> {
        Ok(cx.aspects(t)?.iter().any(|a| self.claims(a)) || !cx.db.members(t)?.is_empty())
    }
    fn summarize(&self, cx: &Reader, t: Tid, s: &mut Summary) -> Result<()> {
        let view = cx.db.at(t, COLLECTION).get()?;
        let is_tag = cx.has(t, "tag.0")?;
        s.words.insert(0, if view.is_some() { "Collection" } else if is_tag { "Tag" } else { "Group" }.into());
        let v = of(cx, t)?;
        s.mark = Mark::Icon(match (view.is_some(), &v.arrange) {
            (true, Arrange::Days) => Icon::Calendar,
            (true, Arrange::Cards) => Icon::People,
            (true, Arrange::Outline) => Icon::Tags,
            (true, _) => Icon::Recent,
            (false, _) => Icon::Tag,
        });
        if view.is_some() && matches!(v.arrange, Arrange::Rows) {
            s.sub = "Last touched first".into();
            return Ok(());
        }
        let n = crate::view::source::count(cx, t)?;
        s.sub = format!("{n} {}", if n == 1 { "item" } else { "items" });
        Ok(())
    }
    fn show(&self, cx: &Cx, t: Tid) -> Result<Section> {
        let view = of(cx, t)?;
        let arranged = cx.arranged(t)?.unwrap_or_else(|| view.arrange.clone());
        let week = cx.state(WEEK, &cx.path())?.unwrap_or(0);
        let its = items(cx, t)?;
        let favorites = matches!(view.source, crate::schema::CollectionSource::Favorites);
        let run = Run { new: (favorites && cx.config().get("cols").is_none()).then(|| Do::new(ToggleCreating)), reorder: favorites.then(|| Do::new(MoveFavorite)), ..Run::default() };
        let cfg = cx.config();
        let mut blocks = Vec::new();
        let arranged = cfg.get("arrange").and_then(arrange_named).unwrap_or(arranged);
        let run = Run { cols: cfg.get("cols").and_then(|c| c.parse().ok()).unwrap_or(0), ..run };
        let choices = [(Arrange::Cards, "Cards", Icon::Tag), (Arrange::Rows, "Rows", Icon::List), (Arrange::Days, "Days", Icon::Calendar), (Arrange::Outline, "Outline", Icon::Tags), (Arrange::Stream, "Stream", Icon::Recent)];
        let chips: Vec<Chip> = choices.into_iter().map(|(a, label, icon)| Chip::choice(icon, label, a == arranged, Do::new(SetArranged(t, a)))).collect();
        if !cfg.flag("no_chooser") {
            blocks.push(Block::Chips(chips));
        }
        if matches!(arranged, Arrange::Days) {
            use crate::time::{DAY, fmt_day, monday_of, now_local};
            let monday = monday_of(now_local()) + week * 7 * DAY;
            blocks.push(Block::Chips(vec![Chip::action(Icon::Back, "Earlier", Do::new(SetWeek(cx.path(), week - 1))), Chip::action(Icon::Calendar, "This week", Do::new(SetWeek(cx.path(), 0))), Chip::action(Icon::Plus, "Later", Do::new(SetWeek(cx.path(), week + 1)))]));
            blocks.push(Block::Label(format!("{} – {}", fmt_day(monday / DAY), fmt_day(monday / DAY + 6))));
        }
        let placed = if let (Some(e), true) = (&view.element, matches!(arranged, Arrange::Cards | Arrange::Rows)) {
            let spec_of = |x: Tid| ViewSpec { view_type: e.view_type.clone(), subject: x, config: Config(e.config.clone()) };
            Placed::Views { cols: run.cols, views: its.iter().map(|x| (format!("element:{x}"), spec_of(*x))).collect() }
        } else {
            arrange::place(cx, &its, &view, &arranged, week, run)?
        };
        let empty = match &placed {
            Placed::Cards(r) | Placed::Rows(r) => r.entries.is_empty() && r.new.is_none(),
            Placed::Stream(v) => v.is_empty(),
            Placed::Views { views, .. } => views.is_empty(),
            _ => false,
        };
        if empty {
            blocks.push(Block::Line("Nothing here yet.".into()));
        }
        blocks.push(Block::Entries(placed));
        Ok(Section::of(blocks))
    }
    fn offers(&self, cx: &Reader, t: Option<Tid>) -> Result<Vec<Offer>> {
        Ok(match t {
            Some(t) if cx.has(t, "tag.0")? => Vec::new(),
            _ => vec![Offer { id: "tag", label: "Tag", icon: Icon::Tag, set: start }],
        })
    }
}

/// An arrangement by its config name.
fn arrange_named(s: &str) -> Option<Arrange> {
    Some(match s {
        "cards" => Arrange::Cards,
        "rows" => Arrange::Rows,
        "days" => Arrange::Days,
        "outline" => Arrange::Outline,
        "stream" => Arrange::Stream,
        _ => return None,
    })
}

/// Shows or hides the list of what can be made new.
#[derive(Clone, Debug, PartialEq)]
pub struct ToggleCreating;
impl Action for ToggleCreating {
    fn run(&self, act: &Act, _: &Input) -> Result<()> {
        if creating(act)? { act.clear_state(CREATING, "shell") } else { act.set_state(CREATING, "shell", &true) }
    }
}

/// Whether the list of what can be made new is shown.
pub fn creating(cx: &Reader) -> Result<bool> {
    Ok(cx.state(CREATING, "shell")?.unwrap_or(false))
}
