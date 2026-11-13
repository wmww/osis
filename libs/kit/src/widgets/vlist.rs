//! A windowed list that scrolls itself, and its page with it (`Page`): what is above it on its
//! page and below it are its leading and trailing parts, so one position runs through the head,
//! the rows and the foot. It holds only the rows it was given (a window around the viewport,
//! `Cx::list`), keeps its place by the part at the top (the head, the first row of a line, the
//! foot) so a row arriving above does not move the view, and pins to the end while following it.
//! A list that is not a scroller (in another list's row, or a page's second list) is laid out
//! whole: the rows of the window it was built with, at their own height. As the viewport nears the edge of what is
//! loaded it asks for a new window (`ListAction::Moved`); the shell asks the graph and applies
//! the difference. Rows go in columns like a tile grid (a row marked `span` runs the full width).
//! Dragging a row (a mouse drag, or a touch after a long press picks it up) emits
//! `ListAction::Reorder`; a touch drag otherwise scrolls (kit `input`). A bar at the right shows and moves the position:
//! over the whole list where its length is known (`ListAction::Jump`), else over what is loaded.
//!
//! Masonry's `VirtualScroll` is not used: its dense ids cannot shift when a row is inserted above,
//! and it cannot pin the last row to the bottom of the viewport.

use crate::theme::Look;
use masonry::accesskit::{Action, Node, Role};
use masonry::core::keyboard::{Key, KeyState, NamedKey};
use masonry::core::{AccessCtx, AccessEvent, BoxConstraints, ChildrenIds, EventCtx, LayoutCtx, NewWidget, PaintCtx, PointerButton, PointerEvent, PointerScrollEvent, PropertiesMut, PropertiesRef, RegisterCtx, TextEvent, Update, UpdateCtx, Widget, WidgetMut, WidgetPod};
use masonry::kurbo::{Affine, Point, Rect, Size};
use masonry::peniko::Fill;
use masonry::vello::Scene;
use std::sync::Arc;
use super::page::{self, LinkRef, into_view, lock};

/// Paints a bar's thumb in the gutter at `x`.
pub(crate) fn paint_thumb(scene: &mut Scene, look: &Look, x: f64, y: f64, h: f64, held: bool) {
    let r = Rect::new(x + 3.0, y, x + 9.0, y + h);
    let c = look.fg.multiply_alpha(if held { 0.55 } else { 0.3 });
    scene.fill(Fill::NonZero, Affine::IDENTITY, c, None, &r.to_rounded_rect(3.0));
}

thread_local! {
    /// Rows laid out by lists on this thread (`testing::rows_laid_out`).
    pub(crate) static LAID_OUT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

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
/// Width kept for the bar (Minor: 0 could not be grabbed, infinity leaves no room for rows).
pub const GUTTER: f64 = 12.0;
/// The shortest the bar's thumb gets (Minor: below it a long list's thumb is hard to grab).
pub(crate) const MIN_THUMB: f64 = 24.0;
/// What one arrow key or wheel notch moves (Minor: a scrolling speed).
pub(crate) const LINE: f64 = 60.0;

/// The bar, from the last layout (the list's coordinates).
#[derive(Clone, Copy)]
struct Bar {
    x: f64,
    track: Track,
    /// The whole list's length and a row's mean height, when known.
    est: Option<(usize, f64)>,
    /// The estimated range of the position the track covers.
    range: f64,
}

/// The bar as drawn: its track (the part of the list its page shows) and thumb.
#[derive(Clone, Copy)]
pub(crate) struct Track {
    pub start: f64,
    pub len: f64,
    pub thumb: f64,
    pub y: f64,
}

/// Which part of the page's one scroll is at the top.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Part {
    /// What is above the list (`offset` into it).
    Head,
    /// The line of rows starting at `anchor`.
    Rows,
    /// What is below the list.
    Foot,
}

pub struct VirtualList {
    children: Vec<WidgetPod<dyn Widget>>,
    spans: Vec<bool>,
    look: Arc<Look>,
    /// Least column width before spacing, px.
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
    /// The part at the top, the row at the top (`Part::Rows`), and how far past its top the
    /// viewport starts.
    part: Part,
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
    /// A move into what is above the list while rows before the window are not loaded: where in
    /// the head to land once they are (windows load towards the start until then).
    to_head: Option<f64>,
    /// From the last layout: it scrolls (its page's or its own), the one position and its range,
    /// the viewport's height (the page's), and the list's own height.
    scroller: bool,
    t: f64,
    t_min: f64,
    t_max: f64,
    v: f64,
    vh: f64,
    /// The page this list holds (`Page`), from the last layout.
    page: Option<LinkRef>,
}

impl VirtualList {
    pub fn new(look: Arc<Look>, min: f64, max_cols: usize, gap: f64, follow: bool) -> VirtualList {
        VirtualList { children: Vec::new(), spans: Vec::new(), look, min, max_cols, gap, fixed: None, rects: Vec::new(), press: None, drop: None, first: 0, more_before: false, more_after: false, part: Part::Head, anchor: 0, offset: 0.0, follow, stuck: follow, asked: None, total: None, jump: None, jumped: false, bar: None, grab: None, to_head: None, scroller: false, t: 0.0, t_min: 0.0, t_max: 0.0, v: 0.0, vh: 0.0, page: None }
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
            (self.part, self.anchor) = (Part::Rows, a);
            self.stuck = false;
        }
        self.first = first;
        self.more_before = more_before;
        self.more_after = more_after;
        self
    }

    /// The index of the row at the top (the first with the head there, the last with the foot).
    pub fn anchor(&self) -> usize {
        self.anchor
    }

    /// Keeps the view on the row now at `i` (rows moved under it); `None`: that row left, so the
    /// view goes to the top of what is shown (the window starts over there too). The head or the
    /// foot at the top stays there.
    pub fn set_anchor(this: &mut WidgetMut<'_, Self>, i: Option<usize>) {
        if std::mem::take(&mut this.widget.jumped) || this.widget.part != Part::Rows {
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
            (this.widget.part, this.widget.anchor, this.widget.offset) = (Part::Rows, j - first, 0.0);
            this.widget.jump = None;
            this.widget.jumped = true;
        }
        if this.widget.fixed.is_some() {
            this.widget.fixed = Some(fixed);
        }
        this.ctx.request_layout();
    }

    /// Moves the one position by `d` (its page sends what it was asked to scroll).
    pub(crate) fn scroll_by(this: &mut WidgetMut<'_, Self>, d: f64) {
        if this.widget.scroll(d) {
            this.ctx.request_layout();
        }
    }

    /// Brings what is `d` away into view (its page asks for what is on it): into the head across
    /// rows not loaded yet, once they are.
    pub(crate) fn bring_by(this: &mut WidgetMut<'_, Self>, d: f64) {
        let w = &mut *this.widget;
        let head = (w.more_before && w.t + d < w.t_min - 0.5).then(|| (w.t + d).max(0.0));
        let moved = w.scroll(d);
        w.to_head = head;
        if moved || head.is_some() {
            this.ctx.request_layout();
        }
    }

    /// Lays the rows out in lines of `width`: their tops, and the height (one gap past the last).
    fn place_rows(&mut self, ctx: &mut LayoutCtx<'_>, width: f64, gap: f64) -> (Vec<f64>, f64) {
        let min = self.look.sp(self.min);
        let mut cols = (((width + gap) / (min + gap)).floor() as usize).max(1);
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
            LAID_OUT.with(|n| n.set(n.get() + take as u64));
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

    /// Moves the one position by `d` within what is loaded; `false` when it is already at that
    /// edge (or the list does not scroll).
    fn scroll(&mut self, d: f64) -> bool {
        if !self.scroller {
            return false;
        }
        self.to_head = None;
        let to = (self.t + d).clamp(self.t_min, self.t_max);
        if (to - self.t).abs() < 0.01 {
            return false;
        }
        self.offset += to - self.t;
        self.t = to;
        self.stuck = false;
        if let Some(p) = &self.page {
            let mut l = lock(p);
            (l.t, l.moved) = (to, true);
        }
        true
    }

    /// Puts the one position at `t` (clamped to what is loaded at the next layout).
    fn set_t(&mut self, ctx: &mut EventCtx<'_>, t: f64) {
        (self.part, self.anchor, self.offset) = (Part::Head, 0, t);
        self.to_head = None;
        self.stuck = false;
        ctx.request_layout();
    }

    /// Asks for the window around `row` of the whole list, or just goes there if it is loaded.
    fn go_to_row(&mut self, ctx: &mut EventCtx<'_>, row: usize) {
        if row >= self.first && row < self.first + self.children.len() {
            (self.part, self.anchor, self.offset) = (Part::Rows, row - self.first, 0.0);
            self.stuck = false;
            self.jump = None;
            ctx.request_layout();
        } else if self.jump != Some(row) {
            let want = ((self.v * MARGIN / 40.0).ceil() as usize).max(MIN_SIDE);
            self.jump = Some(row);
            ctx.submit_action::<ListAction>(ListAction::Jump { row, before: want, after: want * 2 });
        }
    }

    /// The thumb's top is at `y`: goes where that says, over the whole list where its length is
    /// known.
    fn drag_bar(&mut self, ctx: &mut EventCtx<'_>, y: f64) {
        let Some(b) = self.bar else { return };
        let frac = ((y - b.track.start) / (b.track.len - b.track.thumb).max(1.0)).clamp(0.0, 1.0);
        let at = frac * b.range;
        let Some((total, mean)) = b.est else {
            return self.set_t(ctx, self.t_min + at);
        };
        let a = self.t - self.top();
        let before = self.first as f64 * mean;
        let row = ((at - a) / mean).floor();
        if row < 0.0 && self.more_before {
            self.go_to_row(ctx, 0);
        } else if row >= total as f64 && self.more_after {
            self.go_to_row(ctx, total.saturating_sub(1));
        } else {
            let row = row.clamp(0.0, total.saturating_sub(1) as f64) as usize;
            if row < self.first || row >= self.first + self.children.len() {
                self.go_to_row(ctx, row);
            } else {
                self.set_t(ctx, at - before);
            }
        }
    }

    /// How far the rows are scrolled inside the list's own box.
    fn top(&self) -> f64 {
        self.rects.first().map_or(0.0, |r| -r.y0).max(0.0)
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
                // at its edge, or not a scroller, the wheel goes on to the page
                if self.scroll(page::wheel(delta, ctx.get_scale_factor())) {
                    ctx.request_layout();
                    ctx.set_handled();
                }
            }
            PointerEvent::Down(e) if self.bar.is_some_and(|b| ctx.local_position(e.state.position).x >= b.x) => {
                let y = ctx.local_position(e.state.position).y;
                ctx.capture_pointer();
                ctx.request_focus();
                let Some(b) = self.bar.map(|b| b.track) else { return };
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
            PointerEvent::Up(..) | PointerEvent::Cancel(..) if self.grab.is_some() => {
                self.grab = None;
                ctx.request_paint_only();
            }
            _ if self.fixed.is_none() => {
                if matches!(event, PointerEvent::Down(_)) {
                    ctx.request_focus();
                }
            }
            PointerEvent::Down(e) => {
                ctx.request_focus();
                let p = ctx.local_position(e.state.position);
                let n = self.movable();
                // a drag is the primary button's, or a touch's after a long press
                let drags = matches!(e.button, None | Some(PointerButton::Primary)) || masonry::core::is_long_press(e);
                self.press = self.rects.iter().take(n).position(|r| drags && r.contains(p)).map(|i| (i, p));
                self.drop = None;
                // a long press picks the row up at once (a mouse picks it up once it moves)
                if masonry::core::is_long_press(e)
                    && let Some((i, _)) = self.press
                {
                    self.drop = Some(i);
                    ctx.capture_pointer();
                    ctx.set_handled();
                    ctx.request_paint_only();
                }
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
        if k.state != KeyState::Down || !self.scroller {
            return;
        }
        let d = match &k.key {
            Key::Named(NamedKey::ArrowUp) => -LINE,
            Key::Named(NamedKey::ArrowDown) => LINE,
            Key::Named(NamedKey::PageUp) => -self.v * 0.9,
            Key::Named(NamedKey::PageDown) => self.v * 0.9,
            Key::Named(NamedKey::Home) => {
                ctx.set_handled();
                if !self.more_before {
                    self.set_t(ctx, 0.0);
                } else if self.total.is_some() {
                    self.go_to_row(ctx, 0);
                } else {
                    (self.part, self.anchor, self.offset) = (Part::Rows, 0, 0.0);
                    self.stuck = false;
                    ctx.request_layout();
                }
                return;
            }
            Key::Named(NamedKey::End) => {
                ctx.set_handled();
                if self.follow {
                    self.stuck = true;
                    ctx.request_layout();
                } else if let (true, Some(t)) = (self.more_after, self.total) {
                    self.go_to_row(ctx, t.saturating_sub(1));
                } else {
                    (self.part, self.offset) = (Part::Foot, f64::MAX / 2.0);
                    self.stuck = false;
                    ctx.request_layout();
                }
                return;
            }
            _ => return,
        };
        if self.scroll(d) {
            ctx.request_layout();
            ctx.set_handled();
        }
    }

    fn on_access_event(&mut self, ctx: &mut EventCtx<'_>, _props: &mut PropertiesMut<'_>, event: &AccessEvent) {
        let d = match event.action {
            Action::ScrollUp => -self.v * 0.9,
            Action::ScrollDown => self.v * 0.9,
            _ => return,
        };
        if self.scroll(d) {
            ctx.request_layout();
            ctx.set_handled();
        }
    }

    fn update(&mut self, ctx: &mut UpdateCtx<'_>, _props: &mut PropertiesMut<'_>, event: &Update) {
        // a row got focus off-screen: bring it in (a page brings in what is on it, this one too)
        if let Update::RequestPanToChild(r) = event
            && self.page.is_none()
            && self.scroll(into_view(r.y0, r.y1, self.vh))
        {
            ctx.request_layout();
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
        let width = if bc.is_width_bounded() { bc.max().width } else { self.look.sp(self.min) * 3.0 + gap * 2.0 };
        let height = |y: f64, n: usize| if n == 0 { 0.0 } else { y - gap };
        // the first list laid out on a page holds it: while the page measures, it reports its
        // rows' height at the page's width
        let me = ctx.widget_id();
        self.page = page::current().filter(|p| {
            let mut l = lock(p);
            if l.measuring && l.list.is_none() {
                l.list = Some(me);
            }
            l.list == Some(me)
        });
        let measuring = self.page.as_ref().is_some_and(|p| lock(p).measuring);
        self.scroller = self.page.is_some() || bc.is_height_bounded();
        if measuring || !self.scroller {
            // whole: every row it holds at its own height
            let (tops, y) = self.place_rows(ctx, width, gap);
            for (c, t) in self.children.iter_mut().zip(tops) {
                ctx.place_child(c, Point::new(0.0, t));
            }
            let content = height(y, self.children.len());
            if let Some(p) = &self.page {
                let mut l = lock(p);
                (l.rows, l.whole) = (content, !(self.more_before || self.more_after));
            }
            if !self.scroller {
                self.bar = None;
                ctx.set_clip_path(Size::new(width, content).to_rect());
            }
            return bc.constrain(Size::new(width, content));
        }
        // a page's list is as tall as its page says
        let (a, b, v, vh) = match &self.page {
            Some(p) => {
                let l = lock(p);
                (l.a, l.b, l.v, bc.constrain(Size::new(width, l.vh)).height)
            }
            None => (0.0, 0.0, bc.max().height, bc.max().height),
        };
        // rows narrow for the bar once there is more than fits (by a pixel: layout places on
        // whole pixels, and a page laying the list out whole gives it its height to a fraction)
        let (mut tops, mut y) = self.place_rows(ctx, width, gap);
        let over = self.more_before || self.more_after || a + height(y, self.children.len()) + b > v + 0.5;
        if over {
            (tops, y) = self.place_rows(ctx, (width - GUTTER).max(0.0), gap);
        }
        let n = self.children.len();
        let r = height(y, n);
        // the one position: the head (`a` tall), the rows (`r`), the foot (`b`), seen `v` at a time;
        // what is not loaded cannot be reached until its window arrives
        let t_min = if self.more_before { a } else { 0.0 };
        let t_max = if self.more_after { a + (r - vh).max(0.0) } else { a + r + b - v }.max(t_min);
        self.anchor = self.anchor.min(n.saturating_sub(1));
        // on the way to the head: the start of what is loaded until the start of the list is
        match self.to_head {
            Some(o) if !self.more_before => {
                (self.part, self.offset, self.stuck, self.to_head) = (Part::Head, o, false, None);
            }
            Some(_) => (self.part, self.anchor, self.offset, self.stuck) = (Part::Rows, 0, 0.0, false),
            None => {}
        }
        let base = match self.part {
            Part::Head => 0.0,
            Part::Rows => a + tops.get(self.anchor).copied().unwrap_or(0.0),
            Part::Foot => a + r,
        };
        let mut t = if self.stuck { t_max } else { (base + self.offset).clamp(t_min, t_max) };
        if self.follow && !self.more_after && t >= t_max - 0.5 {
            self.stuck = true;
            t = t_max;
        }
        // the part at the top is the new anchor: a row is the first of its line, so the same rows
        // show when the lines rewrap at another width
        if t < a {
            (self.part, self.anchor, self.offset) = (Part::Head, 0, t);
        } else if t < a + r {
            let line = tops.iter().copied().filter(|y| *y <= t - a).fold(0.0, f64::max);
            let at = tops.iter().position(|y| *y == line).unwrap_or(0);
            (self.part, self.anchor, self.offset) = (Part::Rows, at, t - a - line);
        } else {
            (self.part, self.anchor, self.offset) = (Part::Foot, n.saturating_sub(1), t - a - r);
        }
        // the rows move inside the list while it covers the viewport, the page around it else
        let top = (t - a).clamp(0.0, (r - vh).max(0.0));
        let s = t - top;
        for (c, rect) in self.children.iter_mut().zip(self.rects.iter_mut()) {
            *rect = rect.with_origin(Point::new(rect.x0, rect.y0 - top));
            ctx.place_child(c, rect.origin());
        }
        ctx.set_clip_path(Size::new(width, vh).to_rect());
        (self.t, self.t_min, self.t_max, self.v, self.vh) = (t, t_min, t_max, v, vh);
        if let Some(p) = &self.page {
            let mut l = lock(p);
            (l.s, l.t, l.t_min, l.t_max, l.r, l.vh) = (s, t, t_min, t_max, r, vh);
        }
        // one bar, over the part of the list the page shows: the position over the whole list
        // where its length is known
        self.bar = (over && t_max - t_min > 0.5 || self.more_before || self.more_after).then(|| {
            let mean = if n > 0 { r / n as f64 } else { 1.0 };
            let est = self.total.filter(|t| *t > 0).map(|t| (t, mean.max(1.0)));
            let (before, rows) = match est {
                Some((total, mean)) => (self.first as f64 * mean, total as f64 * mean),
                None => (0.0, r),
            };
            let whole = a + rows + b;
            let range = (whole - v).max(1.0);
            let start = (s - a).clamp(0.0, vh);
            let len = (s - a + v).clamp(start, vh) - start;
            let thumb = (len * (v / whole).min(1.0)).clamp(MIN_THUMB.min(len), len);
            let at = ((t + before) / range).clamp(0.0, 1.0);
            Bar { x: width - GUTTER, track: Track { start, len, thumb, y: start + at * (len - thumb) }, est, range }
        });
        // the rows wanted around the viewport, from their measured height
        if n > 0 && !self.stuck {
            let mean = (r / n as f64).max(1.0);
            let want_before = ((v * MARGIN / mean).ceil() as usize).max(MIN_SIDE);
            let want_after = ((v * (1.0 + MARGIN) / mean).ceil() as usize + 1).max(MIN_SIDE);
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
        bc.constrain(Size::new(width, vh))
    }

    // the bar runs over the part of the list its page shows, outside the list's own clip
    fn post_paint(&mut self, _ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, scene: &mut Scene) {
        if let Some(b) = self.bar {
            paint_thumb(scene, &self.look, b.x, b.track.y, b.track.thumb, self.grab.is_some());
        }
    }

    fn paint(&mut self, _ctx: &mut PaintCtx<'_>, _props: &PropertiesRef<'_>, scene: &mut Scene) {
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
        // scrollable exactly when it shows its bar
        if self.bar.is_some() {
            node.add_action(Action::ScrollUp);
            node.add_action(Action::ScrollDown);
        }
        if let Some(t) = self.total {
            node.set_size_of_set(t);
        }
    }

    fn children_ids(&self) -> ChildrenIds {
        self.children.iter().map(|c| c.id()).collect()
    }
}
