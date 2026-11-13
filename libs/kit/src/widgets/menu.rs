//! kit's own selection menu, for a platform without one: a layer over the window (`Menu`, its
//! root, takes the whole window but no pointer, so what is outside the menu stays reachable)
//! holding one `MenuItem` per command. Its shape follows where it goes: beside a selection, a row
//! above it (below when there is no room above); at a pointer, a column dropping from it (flipped
//! to fit). The items take no focus and no press: the menu acts on the focused field, so `Input`
//! takes presses on it (`input::Input`), and a screen reader's click reports `MenuPick`.

use crate::platform::{Place, SelectionMenu};
use crate::text;
use crate::theme::{Look, fade};
use masonry::accesskit::{Node, Role};
use masonry::core::{AccessCtx, AccessEvent, BoxConstraints, BrushIndex, ChildrenIds, EventCtx, LayoutCtx, NewWidget, PaintCtx, PropertiesMut, PropertiesRef, RegisterCtx, TextCommand, Update, UpdateCtx, Widget, WidgetPod, WidgetRef};
use masonry::kurbo::{Affine, Point, Rect, RoundedRect, Size, Stroke};
use masonry::parley::Layout;
use masonry::peniko::Fill;
use masonry::vello::Scene;
use std::sync::Arc;

/// A menu item picked by a screen reader (pointer presses go through `Input`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MenuPick(pub TextCommand);

/// What an item says.
pub fn label(c: TextCommand) -> &'static str {
    match c {
        TextCommand::Cut => "Cut",
        TextCommand::Copy => "Copy",
        TextCommand::Paste => "Paste",
        TextCommand::SelectAll => "Select all",
    }
}

pub struct Menu {
    at: Place,
    items: Vec<WidgetPod<MenuItem>>,
    look: Arc<Look>,
    /// The menu's box (window coordinates: the layer sits at the origin), from the last layout.
    bounds: Rect,
}

impl Menu {
    pub fn new(menu: &SelectionMenu, look: Arc<Look>) -> Menu {
        let items = menu.items.iter().map(|&c| NewWidget::new(MenuItem { command: c, look: look.clone(), text: None }).to_pod()).collect();
        Menu { at: menu.at, items, look, bounds: Rect::ZERO }
    }

    /// The menu's box in the window.
    pub fn bounds(&self) -> Rect {
        self.bounds
    }

    /// The command of the item at `p` (window), in the menu `w` (a `Menu` layer root).
    pub fn item_at(w: &WidgetRef<'_, dyn Widget>, p: Point) -> Option<TextCommand> {
        w.children().into_iter().find(|c| c.ctx().bounding_rect().contains(p)).and_then(|c| c.downcast::<MenuItem>().map(|i| i.inner().command))
    }
}

impl Widget for Menu {
    type Action = masonry::core::NoAction;

    fn register_children(&mut self, ctx: &mut RegisterCtx<'_>) {
        for c in &mut self.items {
            ctx.register_child(c);
        }
    }

    fn layout(&mut self, ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        let window = bc.max();
        let pad = self.look.sp(4.0);
        let row = matches!(self.at, Place::Selection(_));
        let loose = BoxConstraints::new(Size::ZERO, window);
        let sizes: Vec<Size> = self.items.iter_mut().map(|c| ctx.run_layout(c, &loose)).collect();
        let widest = sizes.iter().fold(0.0_f64, |w, s| w.max(s.width));
        let (w, h) = if row {
            (sizes.iter().map(|s| s.width).sum::<f64>(), sizes.iter().fold(0.0_f64, |h, s| h.max(s.height)))
        } else {
            (widest, sizes.iter().map(|s| s.height).sum::<f64>())
        };
        let size = Size::new(w + 2.0 * pad, h + 2.0 * pad);
        let gap = self.look.sp(8.0);
        let fit = |v: f64, len: f64, room: f64| v.min(room - len).max(0.0);
        let origin = match self.at {
            Place::Selection(r) => {
                let above = r.y0 - gap - size.height;
                let y = if above >= 0.0 { above } else { r.y1 + gap };
                Point::new(fit(r.center().x - size.width / 2.0, size.width, window.width), fit(y, size.height, window.height))
            }
            Place::Pointer(p) => {
                let x = if p.x + size.width > window.width { p.x - size.width } else { p.x + 1.0 };
                let y = if p.y + size.height > window.height { p.y - size.height } else { p.y + 1.0 };
                Point::new(fit(x, size.width, window.width), fit(y, size.height, window.height))
            }
        };
        self.bounds = Rect::from_origin_size(origin, size);
        let mut at = origin + (pad, pad);
        for (c, s) in self.items.iter_mut().zip(&sizes) {
            if row {
                ctx.place_child(c, at);
                at.x += s.width;
            } else {
                // a column's items take its whole width
                let s = ctx.run_layout(c, &BoxConstraints::tight(Size::new(widest, s.height)));
                ctx.place_child(c, at);
                at.y += s.height;
            }
        }
        window
    }

    fn paint(&mut self, _ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, scene: &mut Scene) {
        let look = &*self.look;
        let r = RoundedRect::from_rect(self.bounds, (look.radius() * 0.8).min(self.bounds.height() / 2.0));
        super::shadow(scene, look, r, (1.0, 1.0), look.shadow, Affine::IDENTITY);
        scene.fill(Fill::NonZero, Affine::IDENTITY, look.surface, None, &r);
        scene.stroke(&Stroke::new(1.0), Affine::IDENTITY, look.outline, None, &r);
    }

    fn accepts_pointer_interaction(&self) -> bool {
        false
    }

    fn accessibility_role(&self) -> Role {
        Role::Menu
    }

    fn accessibility(&mut self, _ctx: &mut AccessCtx<'_>, _props: &PropertiesRef<'_>, _node: &mut Node) {}

    fn children_ids(&self) -> ChildrenIds {
        self.items.iter().map(|c| c.id()).collect()
    }
}

pub struct MenuItem {
    command: TextCommand,
    look: Arc<Look>,
    text: Option<Layout<BrushIndex>>,
}

impl Widget for MenuItem {
    type Action = MenuPick;

    fn on_access_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &AccessEvent) {
        if event.action == masonry::accesskit::Action::Click {
            ctx.submit_action::<MenuPick>(MenuPick(self.command));
        }
    }

    fn update(&mut self, ctx: &mut UpdateCtx<'_>, _props: &mut PropertiesMut<'_>, event: &Update) {
        if matches!(event, Update::HoveredChanged(_)) {
            ctx.request_paint_only();
        }
    }

    fn register_children(&mut self, _ctx: &mut RegisterCtx<'_>) {}

    fn layout(&mut self, ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        let look = self.look.clone();
        let (fcx, lcx) = ctx.text_contexts();
        let l = text::layout(fcx, lcx, &look, label(self.command), look.text_px(14.0), look.text_weight(), None);
        // a touch-sized target
        let s = Size::new(f64::from(l.width()) + look.sp(28.0), look.sp(40.0).max(f64::from(l.height())));
        self.text = Some(l);
        bc.constrain(s)
    }

    fn paint(&mut self, ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, scene: &mut Scene) {
        let look = &*self.look;
        let size = ctx.size();
        if ctx.is_hovered() {
            let r = RoundedRect::from_rect(size.to_rect(), look.radius() * 0.6);
            scene.fill(Fill::NonZero, Affine::IDENTITY, fade(look.fg, 0.07), None, &r);
        }
        if let Some(l) = &self.text {
            let at = Point::new(look.sp(14.0), (size.height - f64::from(l.height())) / 2.0);
            text::draw(scene, l, at, look.fg);
        }
    }

    fn accessibility_role(&self) -> Role {
        Role::MenuItem
    }

    fn accessibility(&mut self, _ctx: &mut AccessCtx<'_>, _props: &PropertiesRef<'_>, node: &mut Node) {
        node.set_label(label(self.command));
        node.add_action(masonry::accesskit::Action::Click);
    }

    fn children_ids(&self) -> ChildrenIds {
        ChildrenIds::new()
    }
}
