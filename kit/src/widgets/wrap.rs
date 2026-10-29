//! Children at their own width, left to right, wrapping onto new lines (chips).

use crate::theme::Look;
use masonry::accesskit::{Node, Role};
use masonry::core::{AccessCtx, BoxConstraints, ChildrenIds, LayoutCtx, NewWidget, PaintCtx, PropertiesMut, PropertiesRef, RegisterCtx, Widget, WidgetPod};
use masonry::kurbo::{Point, Size};
use masonry::vello::Scene;
use std::sync::Arc;

pub struct Wrap {
    children: Vec<WidgetPod<dyn Widget>>,
    look: Arc<Look>,
}

impl Wrap {
    pub fn new(look: Arc<Look>) -> Wrap {
        Wrap { children: Vec::new(), look }
    }

    pub fn with_child(mut self, child: NewWidget<impl Widget + ?Sized>) -> Self {
        self.children.push(child.erased().to_pod());
        self
    }
}

impl Widget for Wrap {
    type Action = masonry::core::NoAction;

    fn register_children(&mut self, ctx: &mut RegisterCtx<'_>) {
        for c in &mut self.children {
            ctx.register_child(c);
        }
    }

    fn layout(&mut self, ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        let gap = self.look.sp(6.0);
        let width = if bc.is_width_bounded() { bc.max().width } else { f64::INFINITY };
        let (mut x, mut y, mut line_h, mut used) = (0.0_f64, 0.0_f64, 0.0_f64, 0.0_f64);
        for c in &mut self.children {
            let s = ctx.run_layout(c, &BoxConstraints::new(Size::ZERO, Size::new(width, f64::INFINITY)));
            if x > 0.0 && x + s.width > width {
                x = 0.0;
                y += line_h + gap;
                line_h = 0.0;
            }
            ctx.place_child(c, Point::new(x, y));
            x += s.width + gap;
            used = used.max(x - gap);
            line_h = line_h.max(s.height);
        }
        bc.constrain(Size::new(if width.is_finite() { width } else { used }, y + line_h))
    }

    fn paint(&mut self, _ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, _scene: &mut Scene) {}

    fn accessibility_role(&self) -> Role {
        Role::List
    }

    fn accessibility(&mut self, _ctx: &mut AccessCtx<'_>, _props: &PropertiesRef<'_>, _node: &mut Node) {}

    fn children_ids(&self) -> ChildrenIds {
        self.children.iter().map(|c| c.id()).collect()
    }
}
