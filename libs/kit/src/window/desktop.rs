//! The desktop shell: masonry_winit with one window. Its `Platform`: masonry_winit's clipboard,
//! no selection menu of its own, and gesture thresholds of its own (winit exposes the system's
//! none). The soft keyboard is the input method's: masonry_winit allows it while a text field has
//! the focus (`set_ime_allowed`), which on Wayland is also the on-screen keyboard's request, so an
//! on-screen keyboard there follows focus, not the keyboard rule (winit has one switch for both;
//! tying it to the rule would stop input methods typing into a field focused without a click).

use super::Waker;
use crate::masonry::core::PointerEvent;
use crate::platform::{Platform, SelectionMenu, Thresholds};
use crate::render::Started;
use std::time::Duration;
use masonry::app::RenderRoot;
use masonry::core::{ErasedAction, NewWidget, Widget, WidgetId};
use masonry::dpi::LogicalSize;
use masonry_winit::app::{AppDriver, Clipboard, DriverCtx, EventLoop, EventLoopProxy, MasonryState, MasonryUserEvent, NewWindow, WindowId};
use masonry_winit::winit::dpi::PhysicalSize;
use masonry_winit::winit::error::EventLoopError;
use masonry_winit::winit::window::{Theme, Window};

/// The action the desktop waker delivers through the event loop.
#[derive(Debug)]
struct Wakeup;

/// An event loop with one window to come.
pub struct App {
    event_loop: EventLoop,
    window: WindowId,
    wake_id: WidgetId,
}

impl App {
    pub fn new() -> Result<App, EventLoopError> {
        Ok(App { event_loop: EventLoop::with_user_event().build()?, window: WindowId::next(), wake_id: WidgetId::next() })
    }

    /// A waker for osis's `Dispatcher::Pump` and the UI's own posts.
    pub fn waker(&self) -> Waker {
        let (proxy, window, widget): (EventLoopProxy, _, _) = (self.event_loop.create_proxy(), self.window, self.wake_id);
        // fails only once the loop has exited
        Waker::new(move || drop(proxy.send_event(MasonryUserEvent::Action(window, Box::new(Wakeup), widget))))
    }

    /// Opens the window with `root` and runs `ui` until it closes.
    pub fn run(self, title: &str, size: (f64, f64), root: NewWidget<dyn Widget>, ui: Started) -> Result<(), EventLoopError> {
        let attrs = Window::default_attributes().with_title(title).with_resizable(true).with_inner_size(LogicalSize::new(size.0, size.1));
        let w = NewWindow::new_with_id(self.window, attrs, root).with_base_color(ui.base_color());
        masonry_winit::app::run_with(self.event_loop, vec![w], Desktop { ui, window: self.window }, masonry::theme::default_property_set())
    }
}

/// The desktop's gesture thresholds. Each is Minor: past it a double click counts as two clicks,
/// or two clicks as one double click (0: no double clicks; infinity: every click counts on); long
/// press and touch slop decide tap, long press or drag for a touch (0: every touch a drag or a
/// long press; infinity: none). The double click as Windows' default; the rest as Android's.
const THRESHOLDS: Thresholds = Thresholds {
    double_tap: Duration::from_millis(500),
    double_tap_slop: 4.0,
    long_press: Duration::from_millis(400),
    touch_slop: 8.0,
};

/// The desktop's `Platform`.
struct DesktopPlatform(Clipboard);

impl Platform for DesktopPlatform {
    fn clipboard(&mut self) -> Option<String> {
        self.0.get()
    }
    fn set_clipboard(&mut self, text: String) {
        self.0.set(text);
    }
    fn keyboard(&mut self, _wanted: bool) {}
    fn show_selection_menu(&mut self, _menu: &SelectionMenu) -> bool {
        false
    }
    fn hide_selection_menu(&mut self) {}
    fn thresholds(&self) -> Thresholds {
        THRESHOLDS
    }
}

/// `Started` (the UI, or why its store could not open) as masonry_winit's driver.
struct Desktop {
    ui: Started,
    window: WindowId,
}

impl Desktop {
    /// Runs `f` on the window's root with its scale and the system's dark mode, then keeps the
    /// window's clear colour the look's.
    fn with(&mut self, w: &mut masonry_winit::app::Window, f: impl FnOnce(&mut Started, &mut RenderRoot, f64, bool)) {
        let (scale, dark) = (w.handle().scale_factor(), w.handle().theme() == Some(Theme::Dark));
        f(&mut self.ui, w.render_root(), scale, dark);
        *w.base_color() = self.ui.base_color();
    }
}

impl AppDriver for Desktop {
    /// The window exists now; wakes before it were dropped by masonry_winit, so `start` runs
    /// what is due.
    fn on_start(&mut self, state: &mut MasonryState<'_>) {
        let platform = Box::new(DesktopPlatform(state.clipboard()));
        let w = state.window(self.window);
        self.with(w, |ui, root, scale, dark| ui.start(root, platform, scale, dark));
    }

    fn on_resized(&mut self, _w: WindowId, ctx: &mut DriverCtx<'_, '_>, _size: PhysicalSize<u32>) {
        self.with(ctx.window(self.window), |ui, root, scale, _| ui.resized(root, scale));
    }

    fn on_theme_changed(&mut self, _w: WindowId, ctx: &mut DriverCtx<'_, '_>, theme: Theme) {
        self.with(ctx.window(self.window), |ui, root, _, _| ui.theme_changed(root, theme == Theme::Dark));
    }

    fn on_pointer_event(&mut self, _w: WindowId, ctx: &mut DriverCtx<'_, '_>, event: PointerEvent) {
        self.with(ctx.window(self.window), |ui, root, _, _| ui.pointer(root, event));
    }

    fn on_clipboard_store(&mut self, _w: WindowId, _ctx: &mut DriverCtx<'_, '_>, text: String) {
        self.ui.copy(text);
    }

    fn on_paste(&mut self, _w: WindowId, ctx: &mut DriverCtx<'_, '_>) {
        self.with(ctx.window(self.window), |ui, root, _, _| ui.paste(root));
    }

    fn on_action(&mut self, _w: WindowId, ctx: &mut DriverCtx<'_, '_>, id: WidgetId, action: ErasedAction) {
        let w = ctx.window(self.window);
        if action.is::<Wakeup>() {
            self.with(w, |ui, root, _, _| ui.wake(root));
        } else {
            self.with(w, |ui, root, _, _| ui.action(root, id, action));
        }
    }
}
