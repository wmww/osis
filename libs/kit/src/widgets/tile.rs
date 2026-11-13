//! A tile: one thing or scope as a card (grids) or a row (rails, lists), or the dashed "new"
//! card. An icon square (a line icon or initials) in the thing's colour, its name and a line
//! under it. Cards draw the theme's card colours in the thing's own colour, slanted, with the
//! tile shadow; rows are flat until hovered, and the current row is a card. Emits `Press` when
//! clicked (or Enter/Space when focused).

use super::{Press, brighten, fill_card, lean, shadow};
use crate::icons::Icon;
use crate::text;
use crate::theme::{Card, Look, fade};
use masonry::accesskit::{Node, Role};
use masonry::core::keyboard::{Key, NamedKey};
use masonry::core::{AccessCtx, AccessEvent, BoxConstraints, BrushIndex, ChildrenIds, EventCtx, LayoutCtx, PaintCtx, PointerEvent, PropertiesMut, PropertiesRef, RegisterCtx, TextEvent, Update, UpdateCtx, Widget, WidgetMut};
use masonry::kurbo::{Affine, Point, Rect, RoundedRect, Size, Stroke};
use masonry::parley::Layout;
use masonry::peniko::{Color, Fill};
use masonry::vello::Scene;
use std::sync::Arc;

/// The least width a row is useful at, before spacing: its icon and a few words of its name. Lists
/// put rows side by side only at this width each, and the rail is a column of rows this wide (Minor:
/// below it names cut sooner; 0 squeezes rows to their icons and always shows the rail, infinity
/// never puts rows side by side and never shows the rail).
pub const ROW_MIN: f64 = 220.0;

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
    /// No icon: a thin bar in the tile's colour (dense lists such as calendar days).
    Bar,
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
    /// Where the pointer went down, and whether it has moved far since.
    down: Option<Point>,
    dragged: bool,
}

impl Tile {
    pub fn new(style: TileStyle, icon: TileIcon, name: &str, sub: &str, tint: Option<Color>, look: Arc<Look>) -> Tile {
        Tile { style, icon, name: name.into(), sub: sub.into(), tint, current: false, look, texts: None, down: None, dragged: false }
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
        if self.icon == TileIcon::Bar {
            return 3.0;
        }
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
            TileStyle::Row => self.look.radius() * 0.55,
            _ => self.look.radius(),
        }
    }

    /// Whether it is drawn as a card (a card, or the current row).
    fn is_card(&self) -> bool {
        self.style == TileStyle::Card || self.style == TileStyle::Row && self.current
    }
}

impl Widget for Tile {
    type Action = Press;

    fn on_pointer_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &PointerEvent) {
        match event {
            PointerEvent::Down(e) => {
                self.down = Some(ctx.local_position(e.state.position));
                self.dragged = false;
                ctx.capture_pointer();
                ctx.request_paint_only();
            }
            PointerEvent::Move(e) => {
                // moved past a tremble: a drag (a reorderable grid above may take it), not a click
                if let Some(d) = self.down
                    && (ctx.local_position(e.current.position) - d).hypot() > 6.0
                {
                    self.dragged = true;
                }
            }
            PointerEvent::Up(..) => {
                if ctx.is_active() && !self.dragged && ctx.is_hovered() {
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
        let name_w = look.name_weight();
        let (ns, ss) = match self.style {
            TileStyle::Row => (look.text_px(14.0), look.text_px(12.0)),
            _ => (look.text_px(15.0), look.text_px(12.5)),
        };
        let name = if self.name.is_empty() { "Untitled" } else { &self.name };
        // a bar tile (dense lists) wraps its name to the width instead of cutting it
        let wrap = (self.icon == TileIcon::Bar && bc.is_width_bounded()).then(|| (bc.max().width - 2.0 * self.pad().1 - self.icon_size() - self.sp(7.0)).max(20.0) as f32);
        let n = text::layout(fcx, lcx, &look, name, ns, name_w, wrap);
        let s = text::layout(fcx, lcx, &look, &self.sub, ss, look.text_weight(), None);
        let ini = match &self.icon {
            TileIcon::Initials(i) => Some(text::layout(fcx, lcx, &look, i, if self.style == TileStyle::Row { 11.0 } else { 13.0 }, 700.0, None)),
            TileIcon::Icon(_) | TileIcon::Bar => None,
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
        if self.style != TileStyle::New {
            let b = look.shadow_blur(1.0);
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
        let card: Card = look.card(self.tint);
        let rect = RoundedRect::from_rect(size.to_rect(), self.radius());
        // cards lean by the theme's slant about their centre; text stays upright
        let skew = lean(look.shear(), size);
        match self.style {
            TileStyle::Card => {
                shadow(scene, &look, rect, (1.0, 1.0), look.shadow, skew);
                let c = if hovered || pressed { Card { top: brighten(card.top), bottom: brighten(card.bottom), ..card } } else { card };
                fill_card(scene, &look, rect, &c, skew);
            }
            TileStyle::Row if self.current => {
                shadow(scene, &look, rect, (0.75, 1.0), look.shadow, skew);
                fill_card(scene, &look, rect, &card, skew);
            }
            TileStyle::Row => {
                if hovered {
                    scene.fill(Fill::NonZero, skew, fade(look.fg, if pressed { 0.12 } else { 0.07 }), None, &rect);
                }
            }
            TileStyle::New => {
                let c = fade(look.fg, if hovered { 0.55 } else { 0.35 });
                let r = Rect::from_origin_size((0.75, 0.75), (size.width - 1.5, size.height - 1.5)).to_rounded_rect(self.radius());
                scene.stroke(&Stroke::new(1.5).with_dashes(0.0, [6.0, 4.0]), skew, c, None, &r);
            }
        }
        // keyboard focus is always visible: Space and Enter press what it rings
        if ctx.is_focus_target() {
            let ring = RoundedRect::from_rect(size.to_rect().inset(-1.5), (self.radius() - 1.5).max(0.0));
            scene.stroke(&Stroke::new(2.0), skew, look.main, None, &ring);
        }
        let (pv, ph) = self.pad();
        let ic = self.icon_size();
        let on_card = self.is_card();
        let white = on_card && look.on_card_white();
        let (fg, muted) = if on_card { (card.fg, card.muted) } else { (look.fg, look.muted) };
        let tint = self.tint.unwrap_or(look.main);
        // the icon square, leaning with the slant less as it gets round; its glyph upright
        let ir = RoundedRect::from_rect(Rect::from_origin_size((0.0, 0.0), (ic, ic)), ic * 0.5 * look.icon_round());
        let ixf = Affine::translate((ph, pv)) * lean(look.icon_shear(), Size::new(ic, ic));
        let (icon_bg, icon_fg) = match self.style {
            TileStyle::New => (None, muted),
            _ if on_card => (Some(card.icon_bg), card.icon_fg),
            _ => (Some(tint), Color::WHITE),
        };
        if self.icon == TileIcon::Bar {
            let bar = RoundedRect::from_rect(Rect::new(ph, pv, ph + ic, size.height - pv), 1.5);
            scene.fill(Fill::NonZero, Affine::IDENTITY, if white { Color::WHITE } else { tint }, None, &bar);
        } else if let Some(bg) = icon_bg {
            scene.fill(Fill::NonZero, ixf, bg, None, &ir);
            // the current row's icon is ringed where its text is white
            if self.style == TileStyle::Row && self.current && white {
                scene.stroke(&Stroke::new(2.0), ixf, fade(Color::WHITE, 0.8), None, &ir.rect().inset(1.0).to_rounded_rect(ic * 0.5 * look.icon_round() + 1.0));
            }
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
            TileStyle::Row => (ph + ic + self.sp(if self.icon == TileIcon::Bar { 7.0 } else { 10.0 }), (size.height - f64::from(n.height()) - sh) / 2.0),
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
