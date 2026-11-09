//! A windowed list that scrolls itself. It holds only the rows it was given (a window around the
//! viewport, `Cx::list`), keeps its place by the row at the top so a row arriving above does not
//! move the view, and pins to the end while following it. As the viewport nears the edge of what is
//! loaded it asks for a new window (`ListAction::Moved`); the shell asks the graph and applies
//! the difference. Rows go in columns like a tile grid (a row marked `span` runs the full width).
//! Dragging a row emits `ListAction::Reorder`. A bar at the right shows and moves the position:
//! over the whole list where its length is known (`ListAction::Jump`), else over what is loaded.
//!
//! Masonry's `VirtualScroll` is not used: its dense ids cannot shift when a row is inserted above,
//! and it cannot pin the last row to the bottom of the viewport.

use crate::theme::Look;
use masonry::accesskit::{Action, Node, Role};
use masonry::core::keyboard::{Key, KeyState, NamedKey};
use masonry::core::{AccessCtx, AccessEvent, BoxConstraints, ChildrenIds, EventCtx, LayoutCtx, NewWidget, PaintCtx, PointerEvent, PointerScrollEvent, PropertiesMut, PropertiesRef, RegisterCtx, ScrollDelta, TextEvent, Update, UpdateCtx, Widget, WidgetMut, WidgetPod};
use masonry::kurbo::{Affine, Point, Rect, Size};
use masonry::peniko::Fill;
use masonry::vello::Scene;
use std::sync::Arc;

/// What the list asks of the shell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListAction {
    /// Show a new window: `before` rows before the row at index `anchor` and `after` from it on.
    /// `stuck`: following the end, so no anchor is meant.
    Moved { anchor: usize, before: usize, after: usize, stuck: bool },
    /// A row was dragged from `from` to `to` (rows of the list; `first` not added).
    Reorder { from: usize, to: usize },
    /// Show the window around the row at index `row` of the whole list.
    Jump { row: usize, before: usize, after: usize },
}

/// How far (logical px) a press moves before it is a drag: below, a tremble stays a click.
const SLOP: f64 = 6.0;
/// How many viewports of rows a window holds beyond the screen, each way (Minor: more loads less
/// often and builds more rows; 0 shows an edge while it loads, infinity is the whole list).
const MARGIN: f64 = 1.0;
/// Least rows a window holds each way (Minor: fewer loads more often on a fast wheel; 0 follows
/// the viewport margin alone, infinity is the whole list).
const MIN_SIDE: usize = 16;
/// Height a list takes where its parent leaves height unbounded (Minor: a list placed in a
/// non-filling slot scrolls at this height; 0 shows nothing, infinity would load everything).
const UNBOUNDED: f64 = 480.0;
/// Width kept for the bar (Minor: 0 could not be grabbed, infinity leaves no room for rows).
const GUTTER: f64 = 12.0;
/// The shortest the bar's thumb gets (Minor: below it a long list's thumb is hard to grab).
const MIN_THUMB: f64 = 24.0;
/// What one arrow key or wheel notch moves (Minor: a scrolling speed).
const LINE: f64 = 60.0;

/// The bar, from the last layout (the list's own coordinates).
#[derive(Clone, Copy)]
struct Bar {
    x: f64,
    thumb: f64,
    y: f64,
    track: f64,
    /// Rows a track's length covers, when the whole list's length is known.
    rows: Option<f64>,
}

pub struct VirtualList {
    children: Vec<WidgetPod<dyn Widget>>,
    spans: Vec<bool>,
    look: Arc<Look>,
    min: f64,
    max_cols: usize,
    gap: f64,
    /// Rows at the end that do not take part in reordering; `None`: not reorderable.
    fixed: Option<usize>,
    /// Each row's rect on screen, from the last layout.
    rects: Vec<Rect>,
    press: Option<(usize, Point)>,
    drop: Option<usize>,
    /// The index of the first row in the whole list, for columns that stay put as it scrolls.
    first: usize,
    more_before: bool,
    more_after: bool,
    /// The row at the top, and how far past its top the viewport starts.
    anchor: usize,
    offset: f64,
    /// Opens at the end and stays while there (a list that follows its end).
    follow: bool,
    /// At the end now: new rows keep it there.
    stuck: bool,
    /// The last window asked for, so one is not asked for twice.
    asked: Option<ListAction>,
    /// Rows in the whole list, when known.
    total: Option<usize>,
    /// A row the bar or a key asked for, until a window holding it arrives.
    jump: Option<usize>,
    /// A jump just landed: the patch that brought it must not move the view back.
    jumped: bool,
    bar: Option<Bar>,
    /// Holding the thumb, this far below its top.
    grab: Option<f64>,
    top: f64,
    max_top: f64,
    vh: f64,
}

impl VirtualList {
    pub fn new(look: Arc<Look>, min: f64, max_cols: usize, gap: f64, follow: bool) -> VirtualList {
        VirtualList { children: Vec::new(), spans: Vec::new(), look, min, max_cols, gap, fixed: None, rects: Vec::new(), press: None, drop: None, first: 0, more_before: false, more_after: false, anchor: 0, offset: 0.0, follow, stuck: follow, asked: None, total: None, jump: None, jumped: false, bar: None, grab: None, top: 0.0, max_top: 0.0, vh: 0.0 }
    }

    pub fn reorderable(mut self, fixed: usize) -> Self {
        self.fixed = Some(fixed);
        self
    }

    pub fn with_child(mut self, child: NewWidget<dyn Widget>, span: bool) -> Self {
        self.children.push(child.to_pod());
        self.spans.push(span);
        self
    }

    /// Where a list made fresh starts: the row at `anchor` at the top, when a window names one.
    pub fn anchored(mut self, anchor: Option<usize>, first: usize, total: Option<usize>, more_before: bool, more_after: bool) -> Self {
        self.total = total;
        if let Some(a) = anchor {
            self.anchor = a;
            self.stuck = false;
        }
        self.first = first;
        self.more_before = more_before;
        self.more_after = more_after;
        self
    }

    /// The index of the row at the top.
    pub fn anchor(&self) -> usize {
        self.anchor
    }

    /// Keeps the view on the row now at `i` (rows moved under it); `None`: that row left, so the
    /// view goes to the top of what is shown (the window starts over there too).
    pub fn set_anchor(this: &mut WidgetMut<'_, Self>, i: Option<usize>) {
        if std::mem::take(&mut this.widget.jumped) {
            return;
        }
        this.widget.anchor = i.unwrap_or(0);
        if i.is_none() {
            this.widget.offset = 0.0;
        }
        this.ctx.request_layout();
    }

    /// What is known of the list around the rows.
    pub fn set_window(this: &mut WidgetMut<'_, Self>, first: usize, total: Option<usize>, more_before: bool, more_after: bool, spans: Vec<bool>, fixed: usize) {
        // what was asked for has been answered: the next edge reached may ask the same again
        this.widget.asked = None;
        this.widget.first = first;
        this.widget.more_before = more_before;
        this.widget.more_after = more_after;
        this.widget.spans = spans;
        this.widget.total = total;
        if let Some(j) = this.widget.jump.filter(|j| *j >= first && *j < first + this.widget.children.len()) {
            this.widget.anchor = j - first;
            this.widget.offset = 0.0;
            this.widget.jump = None;
            this.widget.jumped = true;
        }
        if this.widget.fixed.is_some() {
            this.widget.fixed = Some(fixed);
        }
        this.ctx.request_layout();
    }

    /// Lays the rows out in lines of `width`: their tops, and the height (one gap past the last).
    fn place_rows(&mut self, ctx: &mut LayoutCtx<'_>, width: f64, gap: f64) -> (Vec<f64>, f64) {
        let mut cols = (((width + gap) / (self.min + gap)).floor() as usize).max(1);
        if self.max_cols > 0 {
            cols = cols.min(self.max_cols);
        }
        let cw = ((width - gap * (cols as f64 - 1.0)) / cols as f64).max(0.0);
        // lines in list coordinates; columns from `first` stay put while the window moves, unless
        // labels break the grid
        let aligned = !self.spans.iter().any(|s| *s);
        let mut tops: Vec<f64> = Vec::with_capacity(self.children.len());
        let mut y = 0.0;
        self.rects.clear();
        let mut i = 0;
        while i < self.children.len() {
            let span = self.spans.get(i).copied().unwrap_or(false);
            let take = if span {
                1
            } else {
                let room = if aligned { cols - (self.first + i) % cols } else { cols };
                let mut n = 1;
                while n < room && i + n < self.children.len() && !self.spans.get(i + n).copied().unwrap_or(false) {
                    n += 1;
                }
                n
            };
            let line_w = if span { width } else { cw };
            let mut h: f64 = 0.0;
            for c in self.children.iter_mut().skip(i).take(take) {
                let s = ctx.run_layout(c, &BoxConstraints::new(Size::new(line_w, 0.0), Size::new(line_w, f64::INFINITY)));
                h = h.max(s.height);
            }
            for (k, c) in self.children.iter_mut().skip(i).take(take).enumerate() {
                if take > 1 {
                    ctx.run_layout(c, &BoxConstraints::tight(Size::new(line_w, h)));
                }
                tops.push(y);
                self.rects.push(Rect::from_origin_size(Point::new(k as f64 * (cw + gap), y), (line_w, h)));
            }
            y += h + gap;
            i += take;
        }
        (tops, y)
    }

    fn movable(&self) -> usize {
        self.children.len().saturating_sub(self.fixed.unwrap_or(0))
    }

    fn drop_at(&self, p: Point) -> usize {
        let n = self.movable();
        self.rects.iter().take(n).position(|r| p.y < r.y0 || (p.y < r.y1 && p.x < r.center().x)).unwrap_or(n)
    }

    /// Moves the view by `d`; `false` when it is already at that edge of the whole list.
    fn scroll(&mut self, d: f64) -> bool {
        if (d < 0.0 && self.top <= 0.0 && !self.more_before) || (d > 0.0 && self.top >= self.max_top && !self.more_after) {
            return false;
        }
        self.offset += d;
        self.stuck = false;
        true
    }

    /// Asks for the window around `row` of the whole list, or just goes there if it is loaded.
    fn go_to_row(&mut self, ctx: &mut EventCtx<'_>, row: usize) {
        if row >= self.first && row < self.first + self.children.len() {
            self.anchor = row - self.first;
            self.offset = 0.0;
            self.stuck = false;
            self.jump = None;
            ctx.request_layout();
        } else if self.jump != Some(row) {
            let want = ((self.vh * MARGIN / 40.0).ceil() as usize).max(MIN_SIDE);
            self.jump = Some(row);
            ctx.submit_action::<ListAction>(ListAction::Jump { row, before: want, after: want * 2 });
        }
    }

    /// The thumb's top is at `y`: goes where that says.
    fn drag_bar(&mut self, ctx: &mut EventCtx<'_>, y: f64) {
        let Some(b) = self.bar else { return };
        let frac = (y / (b.track - b.thumb).max(1.0)).clamp(0.0, 1.0);
        match b.rows {
            Some(rows) => self.go_to_row(ctx, (frac * rows).round() as usize),
            None => {
                self.anchor = 0;
                self.offset = frac * self.max_top;
                self.stuck = false;
                ctx.request_layout();
            }
        }
    }

    fn end_drag(this: &mut WidgetMut<'_, Self>) {
        this.widget.press = None;
        if this.widget.drop.take().is_some() {
            this.ctx.request_paint_only();
        }
    }
}

impl crate::list::ListWidget for VirtualList {
    fn insert_row(this: &mut WidgetMut<'_, Self>, i: usize, row: NewWidget<dyn Widget>) {
        let i = i.min(this.widget.children.len());
        this.widget.children.insert(i, row.to_pod());
        this.widget.spans.insert(i, false);
        Self::end_drag(this);
        this.ctx.children_changed();
        this.ctx.request_layout();
    }
    fn remove_row(this: &mut WidgetMut<'_, Self>, i: usize) {
        if i < this.widget.children.len() {
            let c = this.widget.children.remove(i);
            this.widget.spans.remove(i);
            this.ctx.remove_child(c);
            Self::end_drag(this);
            this.ctx.request_layout();
        }
    }
}

impl Widget for VirtualList {
    type Action = ListAction;

    fn on_pointer_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &PointerEvent) {
        match event {
            PointerEvent::Scroll(PointerScrollEvent { delta, .. }) => {
                let d = match delta {
                    ScrollDelta::PixelDelta(p) => -p.to_logical::<f64>(ctx.get_scale_factor()).y,
                    ScrollDelta::LineDelta(_, y) => f64::from(-*y) * 60.0,
                    _ => 0.0,
                };
                // at its edge the wheel goes on to whatever scrolls this list
                if d != 0.0 && self.scroll(d) {
                    ctx.request_layout();
                    ctx.set_handled();
                }
            }
            PointerEvent::Down(e) if self.bar.is_some_and(|b| ctx.local_position(e.state.position).x >= b.x) => {
                let y = ctx.local_position(e.state.position).y;
                ctx.capture_pointer();
                ctx.request_focus();
                let b = self.bar.unwrap_or(Bar { x: 0.0, thumb: 0.0, y: 0.0, track: 0.0, rows: None });
                let on_thumb = y >= b.y && y < b.y + b.thumb;
                let grab = if on_thumb { y - b.y } else { b.thumb / 2.0 };
                self.grab = Some(grab);
                if !on_thumb {
                    self.drag_bar(ctx, y - grab);
                }
            }
            PointerEvent::Move(e) if self.grab.is_some() => {
                let y = ctx.local_position(e.current.position).y;
                let grab = self.grab.unwrap_or(0.0);
                self.drag_bar(ctx, y - grab);
            }
            PointerEvent::Up(..) | PointerEvent::Cancel(..) if self.grab.is_some() => self.grab = None,
            _ if self.fixed.is_none() => {
                if matches!(event, PointerEvent::Down(_)) {
                    ctx.request_focus();
                }
            }
            PointerEvent::Down(e) => {
                ctx.request_focus();
                let p = ctx.local_position(e.state.position);
                let n = self.movable();
                self.press = self.rects.iter().take(n).position(|r| r.contains(p)).map(|i| (i, p));
                self.drop = None;
            }
            PointerEvent::Move(e) => {
                let Some((_, start)) = self.press else { return };
                let p = ctx.local_position(e.current.position);
                if self.drop.is_some() || (p - start).hypot() > SLOP {
                    let d = Some(self.drop_at(p));
                    if d != self.drop {
                        self.drop = d;
                        ctx.request_paint_only();
                    }
                }
            }
            PointerEvent::Up(..) => {
                if let (Some((from, _)), Some(d)) = (self.press, self.drop) {
                    // the index in the order without the dragged row
                    let to = if d > from { d - 1 } else { d };
                    if to != from {
                        ctx.submit_action::<ListAction>(ListAction::Reorder { from, to });
                    }
                    ctx.request_paint_only();
                }
                self.press = None;
                self.drop = None;
            }
            PointerEvent::Cancel(..) => {
                self.press = None;
                if self.drop.take().is_some() {
                    ctx.request_paint_only();
                }
            }
            _ => {}
        }
    }

    fn on_text_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &TextEvent) {
        let TextEvent::Keyboard(k) = event else { return };
        if k.state != KeyState::Down {
            return;
        }
        let d = match &k.key {
            Key::Named(NamedKey::ArrowUp) => -LINE,
            Key::Named(NamedKey::ArrowDown) => LINE,
            Key::Named(NamedKey::PageUp) => -self.vh * 0.9,
            Key::Named(NamedKey::PageDown) => self.vh * 0.9,
            Key::Named(NamedKey::Home) => {
                if self.total.is_some() {
                    self.go_to_row(ctx, 0);
                    ctx.set_handled();
                    return;
                }
                f64::NEG_INFINITY
            }
            Key::Named(NamedKey::End) => {
                ctx.set_handled();
                if self.follow {
                    self.stuck = true;
                    ctx.request_layout();
                } else if let Some(t) = self.total {
                    self.go_to_row(ctx, t.saturating_sub(1));
                } else {
                    self.offset = f64::MAX / 2.0;
                    self.stuck = false;
                    ctx.request_layout();
                }
                return;
            }
            _ => return,
        };
        let d = if d.is_infinite() { -self.top - self.vh * (self.children.len() as f64 + 1.0) } else { d };
        if self.scroll(d) {
            ctx.request_layout();
            ctx.set_handled();
        }
    }

    fn on_access_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &AccessEvent) {
        let d = match event.action {
            Action::ScrollUp => -self.vh * 0.9,
            Action::ScrollDown => self.vh * 0.9,
            _ => return,
        };
        if self.scroll(d) {
            ctx.request_layout();
            ctx.set_handled();
        }
    }

    fn update(&mut self, ctx: &mut UpdateCtx<'_>, _props: &mut PropertiesMut<'_>, event: &Update) {
        // a row got focus off-screen: bring it in
        if let Update::RequestPanToChild(r) = event {
            let d = if r.y0 < 0.0 { r.y0 } else { (r.y1 - self.vh).max(0.0) };
            if d != 0.0 {
                self.offset += d;
                self.stuck = false;
                ctx.request_layout();
            }
        }
    }

    fn accepts_focus(&self) -> bool {
        true
    }

    fn register_children(&mut self, ctx: &mut RegisterCtx<'_>) {
        for c in &mut self.children {
            ctx.register_child(c);
        }
    }

    fn layout(&mut self, ctx: &mut LayoutCtx<'_>, _props: &mut PropertiesMut<'_>, bc: &BoxConstraints) -> Size {
        let gap = self.look.sp(self.gap);
        let width = if bc.is_width_bounded() { bc.max().width } else { self.min * 3.0 + gap * 2.0 };
        let bounded = bc.max().height.is_finite();
        let vh = if bounded { bc.max().height } else { UNBOUNDED };
        // rows narrow for the bar once there is more than fits
        let (mut tops, mut y) = self.place_rows(ctx, width, gap);
        let scrolls = self.more_before || self.more_after || (y - gap) > vh;
        if scrolls {
            (tops, y) = self.place_rows(ctx, (width - GUTTER).max(0.0), gap);
        }
        let content = if self.children.is_empty() { 0.0 } else { y - gap };
        let height = if bounded { vh } else { content.min(vh) };
        let max_top = (content - height).max(0.0);
        self.anchor = self.anchor.min(self.children.len().saturating_sub(1));
        let anchor_top = tops.get(self.anchor).copied().unwrap_or(0.0);
        // going past what is loaded stops at its edge until the new window arrives
        let mut top = if self.stuck { max_top } else { (anchor_top + self.offset).clamp(0.0, max_top) };
        if self.follow && !self.more_after && top >= max_top - 0.5 {
            self.stuck = true;
            top = max_top;
        }
        // the row at the top of the viewport is the new anchor
        let at = tops.iter().rposition(|t| *t <= top).unwrap_or(0);
        self.anchor = at;
        self.offset = top - tops.get(at).copied().unwrap_or(0.0);
        for (c, r) in self.children.iter_mut().zip(self.rects.iter_mut()) {
            *r = r.with_origin(Point::new(r.x0, r.y0 - top));
            ctx.place_child(c, r.origin());
        }
        ctx.set_clip_path(Size::new(width, height).to_rect());
        (self.top, self.max_top, self.vh) = (top, max_top, height);
        self.bar = scrolls.then(|| {
            let n = self.children.len().max(1) as f64;
            let (seen, at, rows) = match self.total {
                // rows on screen, of the whole list
                Some(t) if t > 0 => {
                    let line = (content / n).max(1.0);
                    let row = self.first as f64 + self.anchor as f64 + self.offset / line;
                    let seen = (height / line).min(t as f64);
                    let span = (t as f64 - seen).max(1.0);
                    (seen / t as f64, row / span, Some(span))
                }
                _ => (height / content.max(height), top / max_top.max(1.0), None),
            };
            let thumb = (height * seen).clamp(MIN_THUMB.min(height), height);
            Bar { x: width - GUTTER, thumb, y: at.clamp(0.0, 1.0) * (height - thumb), track: height, rows }
        });
        // the rows wanted around the viewport, from their measured height
        let n = self.children.len();
        if n > 0 && !self.stuck {
            let mean = (content / n as f64).max(1.0);
            let want_before = ((vh * MARGIN / mean).ceil() as usize).max(MIN_SIDE);
            let want_after = ((vh * (1.0 + MARGIN) / mean).ceil() as usize + 1).max(MIN_SIDE);
            let (have_before, have_after) = (self.anchor, n - self.anchor);
            let short = (self.more_before && have_before * 2 < want_before) || (self.more_after && have_after * 2 < want_after);
            let long = have_before > want_before * 2 + 1 || have_after > want_after * 2 + 1;
            if short || long {
                let ask = ListAction::Moved { anchor: self.anchor, before: want_before, after: want_after, stuck: false };
                if self.asked != Some(ask) {
                    self.asked = Some(ask);
                    ctx.submit_action::<ListAction>(ask);
                }
            }
        } else if self.stuck && self.more_after {
            // scrolled onto the end of a window that is not the list's end: follow it from the end
            let ask = ListAction::Moved { anchor: self.anchor, before: 0, after: 0, stuck: true };
            if self.asked != Some(ask) {
                self.asked = Some(ask);
                ctx.submit_action::<ListAction>(ask);
            }
        }
        bc.constrain(Size::new(width, height))
    }

    fn paint(&mut self, _ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, scene: &mut Scene) {
        if let Some(b) = self.bar {
            let r = Rect::new(b.x + 3.0, b.y, b.x + 9.0, b.y + b.thumb);
            let c = self.look.fg.multiply_alpha(if self.grab.is_some() { 0.55 } else { 0.3 });
            scene.fill(Fill::NonZero, Affine::IDENTITY, c, None, &r.to_rounded_rect(3.0));
        }
        let Some(d) = self.drop else { return };
        let (r, after) = match (self.rects.get(d), d.checked_sub(1).and_then(|i| self.rects.get(i))) {
            (Some(r), _) if d < self.movable() => (*r, false),
            (_, Some(r)) => (*r, true),
            _ => return,
        };
        let g = self.look.sp(self.gap) / 2.0;
        let bar = if r.width() > r.height() * 3.0 {
            let y = if after { r.y1 + g } else { r.y0 - g };
            Rect::new(r.x0, y - 1.5, r.x1, y + 1.5)
        } else {
            let x = if after { r.x1 + g } else { r.x0 - g };
            Rect::new(x - 1.5, r.y0, x + 1.5, r.y1)
        };
        scene.fill(Fill::NonZero, Affine::IDENTITY, self.look.accent, None, &bar.to_rounded_rect(1.5));
    }

    fn accessibility_role(&self) -> Role {
        Role::List
    }

    fn accessibility(&mut self, _ctx: &mut AccessCtx<'_>, _props: &PropertiesRef<'_>, node: &mut Node) {
        node.set_clips_children();
        node.add_action(Action::ScrollUp);
        node.add_action(Action::ScrollDown);
        if let Some(t) = self.total {
            node.set_size_of_set(t);
        }
    }

    fn children_ids(&self) -> ChildrenIds {
        self.children.iter().map(|c| c.id()).collect()
    }
}
