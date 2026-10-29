//! A tile: one thing or scope as a card (grids) or a row (rails, lists), or the dashed "new"
//! card. An icon square (a line icon or initials) in the thing's colour, its name and a line
//! under it. Cards take the theme's fill, slant, shadow and gloss; rows are flat until hovered or
//! current. Emits `Press` when clicked (or Enter/Space when focused).

use super::{Press, fill_glossy, shadow};
use crate::icons::Icon;
use crate::text;
use crate::theme::{Look, fade, mix, neutral};
use masonry::accesskit::{Node, Role};
use masonry::core::keyboard::{Key, NamedKey};
use masonry::core::{AccessCtx, AccessEvent, BoxConstraints, BrushIndex, ChildrenIds, EventCtx, LayoutCtx, PaintCtx, PointerEvent, PropertiesMut, PropertiesRef, RegisterCtx, TextEvent, Update, UpdateCtx, Widget, WidgetMut};
use masonry::kurbo::{Affine, Point, Rect, RoundedRect, Size, Stroke};
use masonry::parley::Layout;
use masonry::peniko::{Color, Fill};
use masonry::vello::Scene;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TileStyle {
    Card,
    Row,
    New,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TileIcon {
    Icon(Icon),
    Initials(String),
}

type Texts = (Layout<BrushIndex>, Layout<BrushIndex>, Option<Layout<BrushIndex>>);

pub struct Tile {
    style: TileStyle,
    icon: TileIcon,
    name: String,
    sub: String,
    tint: Option<Color>,
    current: bool,
    look: Arc<Look>,
    /// Name, sub line and initials, laid out.
    texts: Option<Texts>,
}

impl Tile {
    pub fn new(style: TileStyle, icon: TileIcon, name: &str, sub: &str, tint: Option<Color>, look: Arc<Look>) -> Tile {
        Tile { style, icon, name: name.into(), sub: sub.into(), tint, current: false, look, texts: None }
    }

    pub fn current(mut self, on: bool) -> Self {
        self.current = on;
        self
    }

    pub fn set_current(this: &mut WidgetMut<'_, Self>, on: bool) {
        if this.widget.current != on {
            this.widget.current = on;
            this.ctx.request_paint_only();
        }
    }

    fn sp(&self, px: f64) -> f64 {
        self.look.sp(px)
    }

    fn icon_size(&self) -> f64 {
        match self.style {
            TileStyle::Row => 30.0,
            _ => 38.0,
        }
    }

    fn pad(&self) -> (f64, f64) {
        match self.style {
            TileStyle::Row => (self.sp(6.0), self.sp(8.0)),
            _ => (self.sp(14.0), self.sp(14.0)),
        }
    }

    fn radius(&self) -> f64 {
        match self.style {
            TileStyle::Row => self.look.theme.radius * 0.55,
            _ => self.look.theme.radius,
        }
    }

    /// Whether the card's text is white (filled cards only; rows sit on the panel).
    fn white(&self) -> bool {
        self.style == TileStyle::Card && self.look.on_card_white()
    }
}

impl Widget for Tile {
    type Action = Press;

    fn on_pointer_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &PointerEvent) {
        match event {
            PointerEvent::Down(..) => {
                ctx.capture_pointer();
                ctx.request_paint_only();
            }
            PointerEvent::Up(..) => {
                if ctx.is_active() && ctx.is_hovered() {
                    ctx.submit_action::<Press>(Press);
                }
                ctx.request_paint_only();
            }
            _ => {}
        }
    }

    fn on_text_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &TextEvent) {
        if let TextEvent::Keyboard(k) = event
            && k.state.is_up()
            && (matches!(&k.key, Key::Character(c) if c == " ") || k.key == Key::Named(NamedKey::Enter))
        {
            ctx.submit_action::<Press>(Press);
        }
    }

    fn on_access_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &AccessEvent) {
        if event.action == masonry::accesskit::Action::Click {
            ctx.submit_action::<Press>(Press);
        }
    }

    fn update(&mut self, ctx: &mut UpdateCtx<'_>, _props: &mut PropertiesMut<'_>, event: &Update) {
        if matches!(event, Update::HoveredChanged(_) | Update::ActiveChanged(_) | Update::FocusChanged(_)) {
            ctx.request_paint_only();
        }
    }

    fn register_children(&mut self, _ctx: &mut RegisterCtx<'_>) {}

    fn layout(&mut self, ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        let look = self.look.clone();
        let (fcx, lcx) = ctx.text_contexts();
        let name_w = look.weight(600.0, 75.0, 400.0, 800.0);
        let (ns, ss) = match self.style {
            TileStyle::Row => (14.0, 12.0),
            _ => (15.0, 12.5),
        };
        let name = if self.name.is_empty() { "Untitled" } else { &self.name };
        let n = text::layout(fcx, lcx, &look, name, ns, name_w, None);
        let s = text::layout(fcx, lcx, &look, &self.sub, ss, 400.0, None);
        let ini = match &self.icon {
            TileIcon::Initials(i) => Some(text::layout(fcx, lcx, &look, i, if self.style == TileStyle::Row { 11.0 } else { 13.0 }, 700.0, None)),
            TileIcon::Icon(_) => None,
        };
        let line = f64::from(n.height()) + if self.sub.is_empty() { 0.0 } else { f64::from(s.height()) };
        self.texts = Some((n, s, ini));
        let (pv, ph) = self.pad();
        let ic = self.icon_size();
        let want = match self.style {
            TileStyle::Row => Size::new(bc.max().width.min(400.0), ic.max(line) + 2.0 * pv),
            _ => Size::new(bc.max().width.min(240.0), (ic + self.sp(14.0) + line + 2.0 * pv).max(self.sp(112.0))),
        };
        let _ = ph;
        let size = bc.constrain(want);
        if self.style == TileStyle::Card {
            let b = look.theme.shadow_blur;
            let (dx, dy) = look.shadow_offset(1.0);
            ctx.set_paint_insets(masonry::kurbo::Insets::new((b - dx).max(0.0), (b - dy).max(0.0), (b + dx).max(0.0), (b + dy).max(0.0)));
        }
        size
    }

    fn paint(&mut self, ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, scene: &mut Scene) {
        let look = self.look.clone();
        let size = ctx.size();
        let hovered = ctx.is_hovered();
        let pressed = ctx.is_active();
        let tint = self.tint.unwrap_or_else(neutral);
        let rect = RoundedRect::from_rect(size.to_rect(), self.radius());
        // cards lean by the theme's slant about their centre; text stays upright
        let k = look.theme.slant.to_radians().tan();
        let skew = Affine::translate((size.height * 0.5 * k, 0.0)) * Affine::skew(-k, 0.0);
        match self.style {
            TileStyle::Card => {
                shadow(scene, &look, rect, 1.0, skew);
                let mut fill = look.card(Some(tint));
                if hovered {
                    fill = mix(fill, if look.dark { Color::WHITE } else { Color::BLACK }, 0.05);
                }
                if pressed {
                    fill = mix(fill, tint, 0.2);
                }
                fill_glossy(scene, &look, rect, fill, skew);
            }
            TileStyle::Row => {
                let amt = if self.current { (0.05 + look.theme.fill * 0.95).max(0.2) } else if hovered { 0.12 } else { 0.0 };
                if amt > 0.0 {
                    let base = if self.current { look.main } else { tint };
                    scene.fill(Fill::NonZero, skew, fade(base, amt), None, &rect);
                }
            }
            TileStyle::New => {
                let c = fade(look.fg, if hovered { 0.55 } else { 0.35 });
                let r = Rect::from_origin_size((0.75, 0.75), (size.width - 1.5, size.height - 1.5)).to_rounded_rect(self.radius());
                scene.stroke(&Stroke::new(1.5).with_dashes(0.0, [6.0, 4.0]), skew, c, None, &r);
            }
        }
        let (pv, ph) = self.pad();
        let ic = self.icon_size();
        let white = self.white();
        let fg = if white { Color::WHITE } else { look.fg };
        let muted = if white { fade(Color::WHITE, 0.82) } else { look.muted };
        // the icon square
        let ir = RoundedRect::from_rect(Rect::from_origin_size((ph, pv), (ic, ic)), ic * 0.5 * look.theme.icon_round.clamp(0.0, 1.0));
        let (icon_bg, icon_fg) = match self.style {
            TileStyle::New => (None, muted),
            _ if white => (Some(fade(Color::WHITE, 0.22)), Color::WHITE),
            _ => (Some(mix(tint, Color::WHITE, 0.2)), Color::WHITE),
        };
        if let Some(bg) = icon_bg {
            scene.fill(Fill::NonZero, Affine::IDENTITY, bg, None, &ir);
        }
        let Some((n, s, ini)) = &self.texts else { return };
        match (&self.icon, ini) {
            (TileIcon::Initials(_), Some(l)) => {
                let at = Point::new(ph + (ic - f64::from(l.width())) / 2.0, pv + (ic - f64::from(l.height())) / 2.0);
                text::draw(scene, l, at, icon_fg);
            }
            (TileIcon::Icon(i), _) => {
                let isz = if self.style == TileStyle::Row { 17.0 } else { 20.0 };
                i.paint(scene, (ph + (ic - isz) / 2.0, pv + (ic - isz) / 2.0), isz, icon_fg, false);
            }
            _ => {}
        }
        // name and sub line, clipped to the tile
        let sh = if self.sub.is_empty() { 0.0 } else { f64::from(s.height()) };
        let (tx, ty) = match self.style {
            TileStyle::Row => (ph + ic + self.sp(10.0), (size.height - f64::from(n.height()) - sh) / 2.0),
            _ => (ph, size.height - pv - f64::from(n.height()) - sh),
        };
        let clip = Rect::new(tx, 0.0, size.width - ph.min(8.0), size.height);
        scene.push_clip_layer(Affine::IDENTITY, &clip);
        text::draw(scene, n, Point::new(tx, ty), fg);
        text::draw(scene, s, Point::new(tx, ty + f64::from(n.height())), muted);
        scene.pop_layer();
    }

    fn accessibility_role(&self) -> Role {
        Role::Button
    }

    fn accessibility(&mut self, _ctx: &mut AccessCtx<'_>, _props: &PropertiesRef<'_>, node: &mut Node) {
        node.set_label(format!("{}: {}", if self.name.is_empty() { "Untitled" } else { &self.name }, self.sub));
        node.add_action(masonry::accesskit::Action::Click);
    }

    fn children_ids(&self) -> ChildrenIds {
        ChildrenIds::new()
    }

    fn accepts_focus(&self) -> bool {
        true
    }
}
