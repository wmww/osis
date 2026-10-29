//! The window's root: paints the theme's background behind one child (the screen), and reports
//! its size so the app can pick a layout by width. A new background colour (a new main colour)
//! fades in over `FADE_NS`: the one motion the look allows (notes/theming.md).

use crate::backdrop;
use crate::theme::Look;
use masonry::accesskit::{Node, Role};
use masonry::core::{AccessCtx, BoxConstraints, ChildrenIds, LayoutCtx, NewWidget, PaintCtx, PropertiesMut, PropertiesRef, RegisterCtx, UpdateCtx, Widget, WidgetMut, WidgetPod};
use masonry::peniko::Color;
use masonry::kurbo::{Point, Size};
use masonry::vello::Scene;
use std::sync::Arc;

/// How long the background takes to fade to a new colour. At 0 it jumps; long fades lag
/// behind navigation.
const FADE_NS: f64 = 600_000_000.0;

/// The root's size changed (logical px).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Resized(pub Size);

pub struct Root {
    child: WidgetPod<dyn Widget>,
    look: Arc<Look>,
    /// Places the background's decorations (hashed from the open thing).
    seed: u64,
    size: Size,
    /// The colour faded from and how far the fade is (0..1).
    fade: Option<(Color, f64)>,
}

impl Root {
    pub fn new(child: NewWidget<impl Widget + ?Sized>, look: Arc<Look>) -> Root {
        Root { child: child.erased().to_pod(), look, seed: 0, size: Size::ZERO, fade: None }
    }

    /// Replaces the screen.
    pub fn set_child(this: &mut WidgetMut<'_, Self>, child: NewWidget<impl Widget + ?Sized>) {
        let old = std::mem::replace(&mut this.widget.child, child.erased().to_pod());
        this.ctx.remove_child(old);
        this.ctx.children_changed();
        this.ctx.request_layout();
    }

    pub fn child_mut<'t>(this: &'t mut WidgetMut<'_, Self>) -> WidgetMut<'t, dyn Widget> {
        this.ctx.get_mut(&mut this.widget.child)
    }

    pub fn set_look(this: &mut WidgetMut<'_, Self>, look: Arc<Look>, seed: u64) {
        if *this.widget.look != *look || this.widget.seed != seed {
            let shown = this.widget.shown_bg();
            if shown != look.bg {
                this.widget.fade = Some((shown, 0.0));
                this.ctx.request_anim_frame();
            }
            this.widget.look = look;
            this.widget.seed = seed;
            this.ctx.request_paint_only();
        }
    }
}

impl Root {
    /// The background colour shown now (mid-fade: between the old and the look's).
    fn shown_bg(&self) -> Color {
        match self.fade {
            Some((from, t)) => crate::theme::mix(from, self.look.bg, t * t * (3.0 - 2.0 * t)),
            None => self.look.bg,
        }
    }
}

impl Widget for Root {
    type Action = Resized;

    fn on_anim_frame(&mut self, ctx: &mut UpdateCtx<'_>, _props: &mut PropertiesMut<'_>, interval: u64) {
        if let Some((from, t)) = self.fade {
            let t = t + interval as f64 / FADE_NS;
            self.fade = if t >= 1.0 { None } else { Some((from, t)) };
            if self.fade.is_some() {
                ctx.request_anim_frame();
            }
            ctx.request_paint_only();
        }
    }

    fn register_children(&mut self, ctx: &mut RegisterCtx<'_>) {
        ctx.register_child(&mut self.child);
    }

    fn layout(&mut self, ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        let size = bc.max();
        ctx.run_layout(&mut self.child, &BoxConstraints::tight(size));
        ctx.place_child(&mut self.child, Point::ORIGIN);
        if size != self.size {
            self.size = size;
            ctx.submit_action::<Resized>(Resized(size));
        }
        size
    }

    fn paint(&mut self, ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, scene: &mut Scene) {
        backdrop::paint(scene, &self.look, self.shown_bg(), ctx.size(), self.seed);
    }

    fn accessibility_role(&self) -> Role {
        Role::GenericContainer
    }

    fn accessibility(&mut self, _ctx: &mut AccessCtx<'_>, _props: &PropertiesRef<'_>, _node: &mut Node) {}

    fn children_ids(&self) -> ChildrenIds {
        ChildrenIds::from_slice(&[self.child.id()])
    }
}
