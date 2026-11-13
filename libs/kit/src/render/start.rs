//! Starting the UI, the same on every shell: make the store dir, open the store in it, the app's
//! `Data` over it, its main group, then `Ui`. A store that cannot open (before stability, data an
//! older build wrote may not load) shows why instead, in the app's look, with one way on: start
//! fresh, which moves the store aside to a sibling path (kept, never deleted), says where, and
//! opens a new one in its place. With nothing at the path there is nothing to move and no action.

use super::{Attached, ROOT, Ui, set_root_insets};
use crate::input::Input as Pointers;
use crate::masonry::app::RenderRoot;
use crate::masonry::core::{ErasedAction, NewWidget, PointerEvent, Properties, Widget, WidgetId};
use crate::masonry::peniko::Color;
use crate::masonry::properties::Padding;
use crate::masonry::properties::types::{CrossAxisAlignment, Length};
use crate::masonry::widgets::Flex;
use crate::platform::Platform;
use crate::store::Data;
use crate::theme::{Look, Theme};
use crate::widgets::style::{self, Text};
use crate::widgets::{Chip, ChipMark, ChipPress, Page, Panel, PanelKind, Root};
use crate::window::Waker;
use osis::{Address, Osis};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// What a shell starts the UI with: the store's dir (made if missing), the peers a store made
/// there syncs with (or an existing one lacks), the shell's waker, and the app's `Data` over an
/// opened store (an error shows on the failure screen).
pub struct Start {
    pub dir: PathBuf,
    pub peers: Vec<Address>,
    pub waker: Waker,
    pub data: Box<dyn Fn(Osis) -> Result<Data, String>>,
}

impl Start {
    /// The UI over the store in `dir`, or the screen saying why it could not open.
    pub fn open(self) -> Started {
        let shown = match self.ui() {
            Ok(ui) => Shown::Ui(Box::new(ui)),
            Err(e) => Shown::Failed(Failed::new(e, &self.dir)),
        };
        Started { start: self, shown, attached: None, scale: 1.0, dark: false, insets: [0.0; 4] }
    }

    fn ui(&self) -> Result<Ui, String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
        let w = self.waker.clone();
        // the store's own errors name it
        let db = crate::store::open(&self.dir, self.peers.clone(), Arc::new(move || w.wake())).map_err(|e| e.to_string())?;
        let data = (self.data)(db)?;
        data.main_group().map_err(|e| e.to_string())?;
        Ui::new(data, self.waker.clone()).map_err(|e| e.to_string())
    }
}

/// What a shell started: the UI over its store, or the screen saying why the store could not
/// open. The shell hosts it as it would `Ui`: the same calls, on the UI thread.
pub struct Started {
    start: Start,
    shown: Shown,
    /// The platform and pointer input while the failure screen shows (`Ui` holds its own).
    attached: Option<Attached>,
    scale: f64,
    /// The system's dark mode.
    dark: bool,
    insets: [f64; 4],
}

enum Shown {
    Ui(Box<Ui>),
    Failed(Failed),
}

struct Failed {
    error: String,
    /// Where start fresh moves the store; `None`: nothing is there to move.
    aside: Option<PathBuf>,
    look: Arc<Look>,
    /// The start fresh button, once shown.
    fresh: Option<WidgetId>,
}

impl Failed {
    fn new(error: String, dir: &Path) -> Failed {
        Failed { error, aside: aside(dir), look: Arc::new(Look::new(&Theme::named(None), false, None)), fresh: None }
    }

    /// Shows the failure screen under the root, in the default theme.
    fn show(&mut self, rr: &mut RenderRoot, dark: bool) {
        self.look = Arc::new(Look::new(&Theme::named(None), dark, None));
        let look = self.look.clone();
        let mut col = Flex::column().cross_axis_alignment(CrossAxisAlignment::Fill).with_gap(Length::px(look.sp(18.0)));
        col = col.with_child(style::heading(&look, "osis", Text::Brand)).with_child(style::prose(&look, "The store could not be opened", Text::Title));
        let error = NewWidget::new(Panel::new(style::prose(&look, &self.error, Text::Body), look.clone(), PanelKind::Inset, (12.0, 14.0)));
        col = col.with_child(error);
        self.fresh = None;
        if let Some(to) = &self.aside {
            let says = format!("Start fresh keeps it, moved to {}, and opens a new, empty store in its place.", to.display());
            let chip = NewWidget::new(Chip::new("Start fresh", None, ChipMark::None, look.clone()));
            self.fresh = Some(chip.id());
            col = col.with_child(style::prose(&look, &says, Text::Muted)).with_child(NewWidget::new(Flex::row().with_child(chip)));
        }
        let col = NewWidget::new_with_props(col, Properties::new().with(Padding::from_vh(look.sp(48.0), look.sp(16.0))));
        let w: NewWidget<dyn Widget> = NewWidget::new(Page::new(col, look.clone())).erased();
        rr.edit_widget_with_tag(ROOT, |mut r| {
            Root::set_look(&mut r, look, 0);
            Root::set_child(&mut r, w);
        });
    }
}

/// The first free sibling of `dir` named after it (`store.old`, then `store.old-2`, ...); `None`
/// when nothing is at `dir` or it has no name.
fn aside(dir: &Path) -> Option<PathBuf> {
    dir.symlink_metadata().ok()?;
    let dir = std::path::absolute(dir).ok()?;
    let name = dir.file_name()?.to_string_lossy().into_owned();
    (1u64..).map(|n| dir.with_file_name(if n == 1 { format!("{name}.old") } else { format!("{name}.old-{n}") })).find(|p| p.symlink_metadata().is_err())
}

/// Moves `from` to `to`, never replacing what is there: a dir's rename replaces at most an empty
/// dir (POSIX); anything else is linked at `to` (failing when taken), then unlinked at `from`.
fn move_aside(from: &Path, to: &Path) -> std::io::Result<()> {
    if from.symlink_metadata()?.is_dir() {
        std::fs::rename(from, to)
    } else {
        std::fs::hard_link(from, to)?;
        std::fs::remove_file(from)
    }
}

impl Started {
    /// Why the store could not open, while the failure screen shows.
    pub fn error(&self) -> Option<&str> {
        match &self.shown {
            Shown::Failed(f) => Some(&f.error),
            Shown::Ui(_) => None,
        }
    }

    /// Drops the UI and closes its store, returning once it can be opened again (dropping alone
    /// leaves it locked until the node's runtime has shut down). `StillOpen` while something
    /// else holds a handle.
    pub fn close(self) -> osis::Result<osis::Close> {
        match self.shown {
            Shown::Ui(ui) => {
                let db = ui.data.db.clone();
                drop(ui);
                db.close()
            }
            Shown::Failed(_) => Ok(osis::Close::Closed),
        }
    }

    /// Start fresh: the store goes aside (to the path the screen named, unless that was taken
    /// since: then the screen names the next free one) and a new one opens in its place.
    fn start_fresh(&mut self, rr: &mut RenderRoot) {
        let Shown::Failed(f) = &mut self.shown else { return };
        let Some(to) = f.aside.clone() else { return };
        if let Err(e) = move_aside(&self.start.dir, &to) {
            match e.kind() {
                std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::DirectoryNotEmpty => f.aside = aside(&self.start.dir),
                _ => f.error = format!("could not move {} to {}: {e}", self.start.dir.display(), to.display()),
            }
        } else {
            match self.start.ui() {
                Ok(ui) => return self.run(rr, ui),
                Err(e) => *f = Failed::new(e, &self.start.dir),
            }
        }
        f.show(rr, self.dark);
    }

    /// Hands the window to `ui`, with what the shell has told so far.
    fn run(&mut self, rr: &mut RenderRoot, mut ui: Ui) {
        if let Some(a) = self.attached.take() {
            ui.attach(a.platform, self.scale, self.dark);
        }
        ui.set_insets(rr, self.insets);
        ui.wake(rr);
        self.shown = Shown::Ui(Box::new(ui));
    }
}

/// `Ui`'s shell calls (render/mod.rs), each passed on to it or answered by the failure screen.
impl Started {
    /// The first look, for the initial root widget.
    pub fn look(&self) -> Arc<Look> {
        match &self.shown {
            Shown::Ui(ui) => ui.look(),
            Shown::Failed(f) => f.look.clone(),
        }
    }

    /// As `Ui::start`.
    pub fn start(&mut self, rr: &mut RenderRoot, platform: Box<dyn Platform>, scale: f64, dark: bool) {
        crate::fonts::register(rr);
        (self.scale, self.dark) = (scale, dark);
        match &mut self.shown {
            Shown::Ui(ui) => ui.attach(platform, scale, dark),
            Shown::Failed(f) => {
                self.attached = Some(Attached { input: Pointers::new(platform.thresholds()), platform });
                f.show(rr, dark);
            }
        }
    }

    pub fn resized(&mut self, rr: &mut RenderRoot, scale: f64) {
        match &mut self.shown {
            Shown::Ui(ui) => ui.resized(rr, scale),
            Shown::Failed(_) => {
                self.scale = scale;
                set_root_insets(rr, scale, self.insets);
            }
        }
    }

    pub fn theme_changed(&mut self, rr: &mut RenderRoot, dark: bool) {
        self.dark = dark;
        match &mut self.shown {
            Shown::Ui(ui) => ui.theme_changed(rr, dark),
            Shown::Failed(f) => f.show(rr, dark),
        }
    }

    pub fn back(&mut self, rr: &mut RenderRoot) -> bool {
        match &mut self.shown {
            Shown::Ui(ui) => ui.back(rr),
            Shown::Failed(_) => false,
        }
    }

    pub fn set_insets(&mut self, rr: &mut RenderRoot, insets: [f64; 4]) {
        match &mut self.shown {
            Shown::Ui(ui) => ui.set_insets(rr, insets),
            Shown::Failed(_) => {
                self.insets = insets;
                set_root_insets(rr, self.scale, insets);
            }
        }
    }

    pub fn pointer(&mut self, rr: &mut RenderRoot, e: PointerEvent) {
        match (&mut self.shown, self.attached.as_mut()) {
            (Shown::Ui(ui), _) => ui.pointer(rr, e),
            (Shown::Failed(_), Some(a)) => a.input.pointer(rr, &mut *a.platform, e),
            (Shown::Failed(_), None) => drop(rr.handle_pointer_event(e)),
        }
    }

    pub fn text_focus(&mut self, rr: &mut RenderRoot) {
        match (&mut self.shown, self.attached.as_mut()) {
            (Shown::Ui(ui), _) => ui.text_focus(rr),
            (Shown::Failed(_), Some(a)) => a.input.text_focus(rr, &mut *a.platform),
            (Shown::Failed(_), None) => {}
        }
    }

    pub fn paste(&mut self, rr: &mut RenderRoot) {
        match (&mut self.shown, self.attached.as_mut()) {
            (Shown::Ui(ui), _) => ui.paste(rr),
            (Shown::Failed(_), Some(a)) => crate::input::paste(rr, &mut *a.platform),
            (Shown::Failed(_), None) => {}
        }
    }

    pub fn copy(&mut self, text: String) {
        match (&mut self.shown, self.attached.as_mut()) {
            (Shown::Ui(ui), _) => ui.copy(text),
            (Shown::Failed(_), Some(a)) => a.platform.set_clipboard(text),
            (Shown::Failed(_), None) => {}
        }
    }

    pub fn base_color(&self) -> Color {
        match &self.shown {
            Shown::Ui(ui) => ui.base_color(),
            Shown::Failed(f) => f.look.bg,
        }
    }

    pub fn wake(&mut self, rr: &mut RenderRoot) {
        if let Shown::Ui(ui) = &mut self.shown {
            ui.wake(rr);
        }
    }

    pub fn action(&mut self, rr: &mut RenderRoot, id: WidgetId, action: ErasedAction) {
        match &mut self.shown {
            Shown::Ui(ui) => ui.action(rr, id, action),
            Shown::Failed(f) => {
                if f.fresh == Some(id) && action.downcast_ref::<ChipPress>().is_some() {
                    self.start_fresh(rr);
                }
            }
        }
    }
}
