//! A grid of tiles: as many equal columns as fit at `min` width each, rows as tall as their
//! tallest tile.

use crate::theme::Look;
use masonry::accesskit::{Node, Role};
use masonry::core::{AccessCtx, BoxConstraints, ChildrenIds, LayoutCtx, NewWidget, PaintCtx, PropertiesMut, PropertiesRef, RegisterCtx, Widget, WidgetMut, WidgetPod};
use masonry::kurbo::{Point, Size};
use masonry::vello::Scene;
use std::sync::Arc;

pub struct TileGrid {
    children: Vec<WidgetPod<dyn Widget>>,
    look: Arc<Look>,
    /// Least column width, px.
    min: f64,
    /// Most columns (0: no limit).
    max_cols: usize,
    /// Space between tiles before spacing, px.
    gap: f64,
}

impl TileGrid {
    pub fn new(look: Arc<Look>, min: f64) -> TileGrid {
        TileGrid { children: Vec::new(), look, min, max_cols: 0, gap: 12.0 }
    }

    /// At most `n` columns (a list: 1).
    pub fn max_cols(mut self, n: usize) -> Self {
        self.max_cols = n;
        self
    }

    pub fn gap(mut self, px: f64) -> Self {
        self.gap = px;
        self
    }

    pub fn with_child(mut self, child: NewWidget<impl Widget + ?Sized>) -> Self {
        self.children.push(child.erased().to_pod());
        self
    }

    pub fn len(&self) -> usize {
        self.children.len()
    }

    pub fn is_empty(&self) -> bool {
        self.children.is_empty()
    }

    pub fn add_child(this: &mut WidgetMut<'_, Self>, child: NewWidget<impl Widget + ?Sized>) {
        this.widget.children.push(child.erased().to_pod());
        this.ctx.children_changed();
        this.ctx.request_layout();
    }

    pub fn clear(this: &mut WidgetMut<'_, Self>) {
        for c in std::mem::take(&mut this.widget.children) {
            this.ctx.remove_child(c);
        }
        this.ctx.request_layout();
    }
}

impl Widget for TileGrid {
    type Action = masonry::core::NoAction;

    fn register_children(&mut self, ctx: &mut RegisterCtx<'_>) {
        for c in &mut self.children {
            ctx.register_child(c);
        }
    }

    fn layout(&mut self, ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        let gap = self.look.sp(self.gap);
        let width = if bc.is_width_bounded() { bc.max().width } else { self.min * 3.0 + gap * 2.0 };
        let mut cols = (((width + gap) / (self.min + gap)).floor() as usize).max(1);
        if self.max_cols > 0 {
            cols = cols.min(self.max_cols);
        }
        let cw = ((width - gap * (cols as f64 - 1.0)) / cols as f64).max(0.0);
        let mut y = 0.0;
        for row in self.children.chunks_mut(cols) {
            let mut h: f64 = 0.0;
            for c in row.iter_mut() {
                let s = ctx.run_layout(c, &BoxConstraints::new(Size::new(cw, 0.0), Size::new(cw, f64::INFINITY)));
                h = h.max(s.height);
            }
            // a second pass makes the row's tiles equally tall
            for (i, c) in row.iter_mut().enumerate() {
                ctx.run_layout(c, &BoxConstraints::tight(Size::new(cw, h)));
                ctx.place_child(c, Point::new(i as f64 * (cw + gap), y));
            }
            y += h + gap;
        }
        let height = if self.children.is_empty() { 0.0 } else { y - gap };
        bc.constrain(Size::new(width, height))
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
