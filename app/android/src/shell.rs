//! The UI behind the view, on the UI thread: Masonry's `RenderRoot` with kit's `Started` (the
//! UI, or why its store could not open), drawn by
//! `Gpu`, fed the view's events, with the keyboard's input connection over the focused text.
//!
//! Every view callback runs to its end here and leaves `Effect`s for the view, made after the
//! shell is released: some re-enter it (`restartInput` asks the view for a new input connection
//! at once).

use crate::gpu::Gpu;
use crate::input::{self, Motion};
use ndk::native_window::NativeWindow;
use osis_kit::ime::{Seen, Sync, Tell, android};
use osis_kit::masonry::app::{RenderRoot, RenderRootOptions, RenderRootSignal, WindowSizePolicy};
use osis_kit::masonry::core::keyboard::{Key, KeyState, KeyboardEvent, Modifiers, NamedKey};
use osis_kit::masonry::core::{Handled, Ime, ImeText, TextEdit, TextEvent, WindowEvent};
use osis_kit::masonry::dpi::PhysicalSize;
use osis_kit::platform::{Platform, SelectionMenu, Thresholds};
use osis_kit::render::{Started, tree};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::time::Instant;

/// What the shell asks of the view.
pub enum Effect {
    /// Draw on the next frame.
    Frame,
    ShowKeyboard,
    HideKeyboard,
    /// `restartInput`: the keyboard starts over from the text as it is.
    Restart,
    /// `updateSelection`: selection start and end, composing start and end, in UTF-16 units.
    Selection([i32; 4]),
    SetClipboard(String),
}

/// Android's `Platform`: the clipboard over JNI, the keyboard through the view (its effects wait
/// in `fx` for the shell to hand them over after its own), no selection menu yet.
struct Android {
    fx: Rc<RefCell<Vec<Effect>>>,
    thresholds: Thresholds,
}

impl Platform for Android {
    fn clipboard(&mut self) -> Option<String> {
        crate::clipboard()
    }
    fn set_clipboard(&mut self, text: String) {
        self.fx.borrow_mut().push(Effect::SetClipboard(text));
    }
    fn keyboard(&mut self, wanted: bool) {
        self.fx.borrow_mut().push(if wanted { Effect::ShowKeyboard } else { Effect::HideKeyboard });
    }
    fn show_selection_menu(&mut self, _menu: &SelectionMenu) -> bool {
        false
    }
    fn hide_selection_menu(&mut self) {}
    fn thresholds(&self) -> Thresholds {
        self.thresholds
    }
}

pub struct Shell {
    root: RenderRoot,
    signals: Receiver<RenderRootSignal>,
    ui: Started,
    gpu: Gpu,
    scale: f64,
    sync: Sync,
    /// The keyboard's open batch edits: it is told about changes when the last ends.
    batch: u32,
    pending: Tell,
    /// When the last animation frame was drawn, while animating.
    animating: Option<Instant>,
    /// What the UI asked of the platform, handed to `fx` after the shell's own effects.
    platform_fx: Rc<RefCell<Vec<Effect>>>,
    pub fx: Vec<Effect>,
}

impl Shell {
    pub fn new(ui: Started, scale: f64, dark: bool, thresholds: Thresholds) -> Shell {
        let (tx, signals) = channel();
        let opts = RenderRootOptions {
            default_properties: Arc::new(osis_kit::masonry::theme::default_property_set()),
            use_system_fonts: true,
            size_policy: WindowSizePolicy::User,
            size: PhysicalSize::new(0, 0),
            scale_factor: scale,
            test_font: None,
        };
        let root = RenderRoot::new(tree(ui.look()), move |s| drop(tx.send(s)), opts);
        let platform_fx = Rc::new(RefCell::new(Vec::new()));
        let mut sh = Shell { root, signals, ui, gpu: Gpu::new(), scale, sync: Sync::default(), batch: 0, pending: Tell::Nothing, animating: None, platform_fx: platform_fx.clone(), fx: Vec::new() };
        let platform = Box::new(Android { fx: platform_fx, thresholds });
        sh.ui.start(&mut sh.root, platform, scale, dark);
        sh.pump();
        sh
    }

    /// Drops the UI and closes its store (`Started::close`).
    pub fn close(self) -> osis::Result<osis::Close> {
        self.ui.close()
    }

    // --- the view

    pub fn surface(&mut self, window: NativeWindow, width: u32, height: u32) {
        self.root.handle_window_event(WindowEvent::Resize(PhysicalSize::new(width, height)));
        self.ui.resized(&mut self.root, self.scale);
        if let Err(e) = self.gpu.attach(window, width, height) {
            log::error!("surface: {e}");
        }
        self.pump();
        self.fx.push(Effect::Frame);
    }

    pub fn surface_gone(&mut self) {
        self.gpu.detach();
    }

    pub fn frame(&mut self) {
        let now = Instant::now();
        let elapsed = self.animating.map(|t| now.duration_since(t)).unwrap_or_default();
        self.root.handle_window_event(WindowEvent::AnimFrame(elapsed));
        self.pump();
        if self.gpu.attached() && self.root.size().width > 0 {
            let (scene, _) = self.root.redraw();
            self.gpu.render(&scene, self.scale, self.ui.base_color());
        }
        self.animating = self.root.needs_anim().then_some(now);
        if self.animating.is_some() {
            self.fx.push(Effect::Frame);
        }
    }

    pub fn touch(&mut self, m: &Motion<'_>) -> bool {
        let events = input::pointer_events(m, self.scale);
        let handled = !events.is_empty();
        for e in events {
            self.ui.pointer(&mut self.root, e);
        }
        self.pump();
        handled
    }

    pub fn key(&mut self, action: i32, keycode: i32, unicode: i32, meta: i32, repeat: i32) -> bool {
        let Some(k) = input::key_event(action, keycode, unicode, meta, repeat) else { return false };
        let handled = self.root.handle_text_event(TextEvent::Keyboard(k));
        self.input_done();
        handled == Handled::Yes
    }

    pub fn focus(&mut self, focused: bool) {
        self.root.handle_text_event(TextEvent::WindowFocusChange(focused));
        self.pump();
    }

    pub fn insets(&mut self, insets: [f64; 4]) {
        self.ui.set_insets(&mut self.root, insets);
        self.pump();
    }

    pub fn config(&mut self, scale: f64, dark: bool) {
        if scale != self.scale {
            self.scale = scale;
            self.root.handle_window_event(WindowEvent::Rescale(scale));
            self.ui.resized(&mut self.root, scale);
        }
        self.ui.theme_changed(&mut self.root, dark);
        self.pump();
    }

    pub fn wake(&mut self) {
        self.ui.wake(&mut self.root);
        self.pump();
    }

    pub fn back(&mut self) -> bool {
        let r = self.ui.back(&mut self.root);
        self.pump();
        r
    }

    /// Runs what the UI's signals ask for, then keeps the keyboard's picture of the text true.
    fn pump(&mut self) {
        let (mut session, mut frame) = (false, false);
        while let Ok(s) = self.signals.try_recv() {
            match s {
                RenderRootSignal::Action(a, id) => self.ui.action(&mut self.root, id, a),
                RenderRootSignal::StartIme | RenderRootSignal::EndIme => session = true,
                RenderRootSignal::RequestRedraw | RenderRootSignal::RequestAnimFrame => frame = true,
                RenderRootSignal::ClipboardStore(s) => self.ui.copy(s),
                RenderRootSignal::ClipboardRead => self.ui.paste(&mut self.root),
                RenderRootSignal::NewLayer(w, at) => self.root.add_layer(w, at),
                RenderRootSignal::RemoveLayer(id) => self.root.remove_layer(id),
                RenderRootSignal::RepositionLayer(id, at) => self.root.reposition_layer(id, at),
                _ => {}
            }
        }
        if session {
            // a field gained or lost the keyboard: a new session either way
            self.sync.started(Seen::of(&self.root));
            self.pending = Tell::Nothing;
            // the new session reads the text and selection afresh: what input already told goes
            self.fx.retain(|e| !matches!(e, Effect::Restart | Effect::Selection(_)));
            self.fx.push(Effect::Restart);
            self.ui.text_focus(&mut self.root);
        } else {
            let t = self.sync.after_app(Seen::of(&self.root));
            self.tell(t);
        }
        // after the restart: the keyboard shows for the new input connection
        self.fx.append(&mut self.platform_fx.borrow_mut());
        if frame {
            self.fx.push(Effect::Frame);
        }
    }

    /// After the keyboard's own input (an edit or a key event): it knows the text it changed.
    fn input_done(&mut self) {
        let t = self.sync.after_input(Seen::of(&self.root));
        self.tell(t);
        self.pump();
    }

    fn tell(&mut self, t: Tell) {
        let t = match (self.pending, t) {
            (Tell::Restart, _) | (_, Tell::Restart) => Tell::Restart,
            (Tell::Selection, _) | (_, Tell::Selection) => Tell::Selection,
            _ => Tell::Nothing,
        };
        if self.batch > 0 {
            self.pending = t;
            return;
        }
        self.pending = Tell::Nothing;
        match t {
            Tell::Nothing => {}
            Tell::Selection => {
                if let Some((_, f)) = self.root.focused_ime_text() {
                    self.fx.push(Effect::Selection(android::offsets(f)));
                }
            }
            Tell::Restart => self.fx.push(Effect::Restart),
        }
    }

    // --- the input connection

    fn focused(&self) -> Option<&dyn ImeText> {
        self.root.focused_ime_text().map(|(_, t)| t)
    }

    /// Whether a text field has the keyboard.
    pub fn editing(&self) -> bool {
        self.focused().is_some()
    }

    /// A new input connection: inputType, imeOptions, the selection, the caps mode.
    pub fn editor_info(&mut self) -> Option<[i32; 5]> {
        let t = self.focused()?;
        let (input_type, ime_options) = android::editor_info(t.hints());
        let [a, f, ..] = android::offsets(t);
        let caps = android::caps_mode(t, input_type);
        self.sync.started(Seen::of(&self.root));
        self.batch = 0;
        self.pending = Tell::Nothing;
        Some([input_type, ime_options, a.min(f), a.max(f), caps])
    }

    pub fn text(&self) -> Option<String> {
        self.focused().map(|t| t.text().to_string())
    }

    pub fn offsets(&self) -> [i32; 4] {
        self.focused().map_or([0, 0, -1, -1], android::offsets)
    }

    pub fn text_before(&self, n: i32) -> Option<String> {
        self.focused().map(|t| android::text_before_cursor(t, n).to_string())
    }

    pub fn text_after(&self, n: i32) -> Option<String> {
        self.focused().map(|t| android::text_after_cursor(t, n).to_string())
    }

    pub fn selected_text(&self) -> Option<String> {
        self.focused().and_then(|t| android::selected_text(t).map(str::to_string))
    }

    pub fn caps_mode(&self, req: i32) -> i32 {
        self.focused().map_or(0, |t| android::caps_mode(t, req))
    }

    /// Applies the keyboard's edit, made against the text as it is now.
    pub fn edit(&mut self, f: impl FnOnce(&dyn ImeText) -> Option<TextEdit>) -> bool {
        let Some(t) = self.focused() else { return false };
        if let Some(e) = f(t) {
            self.root.handle_text_event(TextEvent::Ime(Ime::Edit(e)));
        }
        self.input_done();
        true
    }

    /// The keyboard's action key (Search, Send, Done...): Enter, as a hardware keyboard sends it.
    pub fn editor_action(&mut self) -> bool {
        if self.focused().is_none() {
            return false;
        }
        self.root.handle_text_event(TextEvent::key_down(Key::Named(NamedKey::Enter)));
        self.root.handle_text_event(TextEvent::key_up(Key::Named(NamedKey::Enter)));
        self.input_done();
        true
    }

    /// The keyboard's Select all, Cut, Copy and Paste buttons: the field's own shortcuts (Ctrl
    /// with `letter`), as a hardware keyboard sends them. True when the field took it.
    pub fn shortcut(&mut self, letter: &str) -> bool {
        if self.focused().is_none() {
            return false;
        }
        let mut took = false;
        for state in [KeyState::Down, KeyState::Up] {
            let k = KeyboardEvent { state, key: Key::Character(letter.into()), modifiers: Modifiers::CONTROL, ..Default::default() };
            took |= self.root.handle_text_event(TextEvent::Keyboard(k)) == Handled::Yes;
        }
        self.input_done();
        took
    }

    pub fn batch(&mut self, begin: bool) -> bool {
        if begin {
            self.batch += 1;
        } else if self.batch > 0 {
            self.batch -= 1;
            if self.batch == 0 {
                self.tell(Tell::Nothing);
            }
        }
        true
    }

    pub fn close_connection(&mut self) {
        self.batch = 0;
        self.tell(Tell::Nothing);
    }
}
