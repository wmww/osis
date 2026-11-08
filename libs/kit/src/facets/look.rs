//! `ui:theme.0` and `ui:mode.0`: how the app looks, a section of the account group's page.

use crate::schema::Mode;
use crate::view::{Action, Block, Cx, Do, Facet, Icon, Input, Mark, Pick, Section, Summary};
use osis::{Result, Tid};
use crate::theme::Theme;

pub struct LookFacet;
pub static FACET: LookFacet = LookFacet;

#[derive(Clone, Debug, PartialEq)]
struct SetTheme(&'static str);
impl Action for SetTheme {
    fn run(&self, cx: &Cx<'_>, _: &Input) -> Result<()> {
        cx.data.set_theme(self.0)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct SetMode(Mode);
impl Action for SetMode {
    fn run(&self, cx: &Cx<'_>, _: &Input) -> Result<()> {
        cx.data.set_mode(self.0.clone())
    }
}

fn hex(c: crate::masonry::peniko::Color) -> String {
    let r = c.to_rgba8();
    format!("#{:02x}{:02x}{:02x}", r.r, r.g, r.b)
}

impl Facet for LookFacet {
    fn id(&self) -> &'static str {
        "look"
    }
    fn claims(&self, ak: &str) -> bool {
        ak == "ui:theme.0" || ak == "ui:mode.0"
    }
    /// The app group always can choose its look, chosen or not.
    fn applies(&self, cx: &Cx<'_>, t: Tid) -> Result<bool> {
        cx.data.is_app(t)
    }
    fn summarize(&self, _: &Cx<'_>, _: Tid, s: &mut Summary) -> Result<()> {
        s.name = "osis".into();
        s.words.insert(0, "Settings".into());
        Ok(())
    }
    fn show(&self, cx: &Cx<'_>, _t: Tid) -> Result<Section> {
        let (theme, mode) = cx.data.look()?;
        let current = theme.unwrap_or_else(|| "frost".into());
        let themes = Theme::defaults()
            .iter()
            .map(|th| Pick { label: th.name.to_string(), mark: Mark::Initials(th.name.chars().take(1).collect()), tint: Some(hex(crate::theme::mix(th.surface.of(cx.dark), th.background.of(!cx.dark), 0.7))), current: th.id == current, press: Do::new(SetTheme(th.id)) })
            .collect();
        let modes = [(Mode::Auto, "Auto", Icon::Recent), (Mode::Light, "Light", Icon::Eye), (Mode::Dark, "Dark", Icon::Star)]
            .into_iter()
            .map(|(m, name, icon)| Pick { label: name.into(), mark: Mark::Icon(icon), tint: None, current: m == mode, press: Do::new(SetMode(m)) })
            .collect();
        Ok(Section::of(vec![Block::Label("Look".into()), Block::Pick { cols: 0, options: themes }, Block::Pick { cols: 3, options: modes }]))
    }
}
