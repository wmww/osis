//! A borderless icon button (back, favorite, delete, ...): the icon on a faint hover fill;
//! `on` fills the icon in the accent colour (a set favorite). Emits `Press`.

use super::Press;
use crate::icons::Icon;
use crate::theme::{Look, fade};
use masonry::accesskit::{Node, Role};
use masonry::core::keyboard::{Key, NamedKey};
use masonry::core::{AccessCtx, AccessEvent, BoxConstraints, ChildrenIds, EventCtx, LayoutCtx, PaintCtx, PointerEvent, PropertiesMut, PropertiesRef, RegisterCtx, TextEvent, Update, UpdateCtx, Widget, WidgetMut};
use masonry::kurbo::{Affine, RoundedRect, Size};
use masonry::peniko::Fill;
use masonry::vello::Scene;
use std::sync::Arc;

pub struct IconButton {
    icon: Icon,
    label: String,
    on: bool,
    look: Arc<Look>,
}

impl IconButton {
    pub fn new(icon: Icon, label: &str, look: Arc<Look>) -> IconButton {
        IconButton { icon, label: label.into(), on: false, look }
    }

    pub fn on(mut self, on: bool) -> Self {
        self.on = on;
        self
    }

    pub fn set_on(this: &mut WidgetMut<'_, Self>, on: bool) {
        if this.widget.on != on {
            this.widget.on = on;
            this.ctx.request_render();
        }
    }
}

impl Widget for IconButton {
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

    fn layout(&mut self, _ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        bc.constrain(Size::new(40.0, 40.0))
    }

    fn paint(&mut self, ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, scene: &mut Scene) {
        let look = &*self.look;
        let size = ctx.size();
        if ctx.is_hovered() || ctx.is_focus_target() {
            let r = RoundedRect::from_rect(size.to_rect(), look.theme.radius * 0.6);
            scene.fill(Fill::NonZero, Affine::IDENTITY, fade(look.fg, if ctx.is_active() { 0.12 } else { 0.07 }), None, &r);
        }
        if ctx.is_focus_target() {
            let r = RoundedRect::from_rect(size.to_rect().inset(-1.0), look.theme.radius * 0.6);
            scene.stroke(&masonry::kurbo::Stroke::new(2.0), Affine::IDENTITY, look.accent, None, &r);
        }
        let s = 20.0;
        let c = if self.on { look.accent } else { look.fg };
        self.icon.paint(scene, ((size.width - s) / 2.0, (size.height - s) / 2.0), s, c, self.on);
    }

    fn accessibility_role(&self) -> Role {
        Role::Button
    }

    fn accessibility(&mut self, _ctx: &mut AccessCtx<'_>, _props: &PropertiesRef<'_>, node: &mut Node) {
        node.set_label(self.label.clone());
        node.add_action(masonry::accesskit::Action::Click);
    }

    fn children_ids(&self) -> ChildrenIds {
        ChildrenIds::new()
    }

    fn accepts_focus(&self) -> bool {
        true
    }
}
