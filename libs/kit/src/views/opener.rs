//! The opener: selects a content view by fit, offers tabs, holds the thing's chrome and nests the
//! content view. Everything else comes through specs: a content view never knows it was opened.

use super::ViewType;
use crate::view::{Act, Action, Block, Chip, Cx, Do, Icon, Input, Open, Section, Tab, ViewSpec};
use crate::schema::{MENU, RAW as RAW_ON};
use osis::{Result, Tid};

/// Switches between raw and the designed view, in this window only.
#[derive(Clone, Debug, PartialEq)]
struct ToggleRaw(String);

impl Action for ToggleRaw {
    fn run(&self, act: &Act, _: &Input) -> Result<()> {
        if act.state(RAW_ON, &self.0)?.unwrap_or(false) { act.clear_state(RAW_ON, &self.0) } else { act.set_state(RAW_ON, &self.0, &true) }
    }
}

/// Selects a content view, remembered per account.
#[derive(Clone, Debug, PartialEq)]
struct ViewAs(Tid, &'static str);

impl Action for ViewAs {
    fn run(&self, act: &Act, _: &Input) -> Result<()> {
        act.set_viewed_as(self.0, self.1)
    }
}

/// Deletes a thing. Its pending typing is committed first: after the delete a session keeps
/// typing uncommitted rather than recreate the thing.
#[derive(Clone, Debug, PartialEq)]
struct Delete(Tid);

impl Action for Delete {
    fn run(&self, act: &Act, _: &Input) -> Result<()> {
        act.window.sessions.commit(self.0)?;
        act.delete(self.0)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ToggleMenu(String);
impl Action for ToggleMenu {
    fn run(&self, act: &Act, _: &Input) -> Result<()> {
        if act.state(MENU, &self.0)?.unwrap_or(false) { act.clear_state(MENU, &self.0) } else { act.set_state(MENU, &self.0, &true) }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ToggleFavorite(Tid);
impl Action for ToggleFavorite {
    fn run(&self, act: &Act, _: &Input) -> Result<()> {
        act.toggle_favorite(self.0)
    }
}

/// The content views offered for `t`, default first: a view accounting only for what every thing
/// has (a name) is no real alternative unless it is all there is.
fn fitting(cx: &Cx, t: Tid) -> Result<Vec<&'static ViewType>> {
    let carried = cx.aspects(t)?;
    let mut scored = Vec::new();
    for (i, v) in cx.registry.views.iter().enumerate() {
        let Some(fits) = v.fits else { continue };
        if !fits(cx, t)? {
            continue;
        }
        let (mut total, mut own) = (0usize, 0usize);
        for ak in carried.iter() {
            if let Some(f) = v.parts.iter().filter_map(|p| cx.registry.facet(p.facet)).find(|f| f.claims(ak)) {
                total += 1;
                own += usize::from(!f.universal());
            }
        }
        scored.push((total, own, i, *v));
    }
    scored.sort_by_key(|(total, _, i, _)| (usize::MAX - *total, *i));
    let well: Vec<&'static ViewType> = scored.iter().filter(|x| x.1 > 0 || x.3.always_offered).map(|x| x.3).collect();
    Ok(if well.is_empty() { scored.into_iter().map(|x| x.3).take(1).collect() } else { well })
}

fn selected(cx: &Cx, node: &str, t: Tid, fits: &[&'static ViewType]) -> Result<&'static ViewType> {
    if cx.state(RAW_ON, node)?.unwrap_or(false) {
        return Ok(&super::RAW);
    }
    if let Some(id) = cx.viewed_as(t)?
        && let Some(v) = fits.iter().find(|v| v.id == id)
    {
        return Ok(v);
    }
    Ok(fits.first().copied().unwrap_or(&super::RAW))
}

fn opener(cx: &Cx, spec: &ViewSpec) -> Result<Section> {
    let t = spec.subject;
    let node = cx.path();
    let fits = fitting(cx, t)?;
    let view = selected(cx, &node, t, &fits)?;
    let mut blocks = Vec::new();
    let chrome_on = !spec.config.flag("no_chrome");
    if chrome_on {
        let bar = ViewSpec { view_type: "bar".into(), subject: t, config: spec.config.clone().with("opener", &node) };
        blocks.push(Block::View { key: "bar".into(), spec: bar });
    }
    if fits.len() > 1 {
        blocks.push(Block::Tabs(fits.iter().map(|v| Tab { label: v.label.to_string(), current: v.id == view.id, press: Do::new(ViewAs(t, v.id)) }).collect()));
    }
    let child = ViewSpec { view_type: view.id.into(), subject: t, config: spec.config.clone() };
    let key = format!("content:{}", view.id);
    // the child's node, so `sync` finds it built; a memo of its own, so what changes in the child
    // other than having a foot leaves the opener alone
    let has_foot = *cx.memo(("has_foot", super::child_path(&node, &key), child.clone()), |r, (_, path, child)| Ok(!super::render(r, path, child)?.foot.is_empty()))?;
    let below = if chrome_on { vec![Block::View { key: "chrome".into(), spec: ViewSpec::new("chrome", t) }] } else { Vec::new() };
    blocks.push(Block::Filled { key, spec: child, has_foot, plain: !chrome_on, below });
    Ok(Section::of(blocks))
}

fn bar(cx: &Cx, spec: &ViewSpec) -> Result<Section> {
    let t = spec.subject;
    let opener = spec.config.get("opener").unwrap_or_default().to_string();
    let open = cx.state(MENU, &opener)?.unwrap_or(false);
    let raw_on = cx.state(RAW_ON, &opener)?.unwrap_or(false);
    let mut menu = Vec::new();
    if open {
        menu.push(Chip::action(Icon::List, if raw_on { "Back to view" } else { "All fields" }, Do::new(ToggleRaw(opener.clone()))));
        menu.push(Chip::action(Icon::Trash, "Delete", Do::new(Delete(t))));
    }
    let descriptor = cx.summary(t)?.words.join(" · ");
    let back = spec.config.flag("back").then(|| Do::new(Open(None)));
    Ok(Section::of(vec![Block::Bar { back, descriptor, favorite: cx.is_favorite(t)?, star: Do::new(ToggleFavorite(t)), more: Do::new(ToggleMenu(opener)), menu }]))
}

pub static OPENER: ViewType = ViewType { id: "opener", label: "Opener", fits: None, parts: &[], always_offered: false, custom: Some(opener) };
pub static BAR: ViewType = ViewType { id: "bar", label: "Bar", fits: None, parts: &[], always_offered: false, custom: Some(bar) };

/// A spec opening `t` through the opener.
pub fn open_spec(t: Tid) -> ViewSpec {
    ViewSpec::new("opener", t)
}
